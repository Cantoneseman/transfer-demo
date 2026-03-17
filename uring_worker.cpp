#include "uring_worker.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <numa.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <thread>

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

UringWorker::UringWorker(int target_fd, const struct sockaddr_in& dest)
    : target_fd_(target_fd), dest_(dest)
{
    int ret = io_uring_queue_init(kQueueDepth, &ring_, 0);
    if (ret < 0) {
        std::fprintf(stderr, "io_uring_queue_init: %s\n", std::strerror(-ret));
        std::abort();
    }
}

UringWorker::~UringWorker()
{
    request_stop();
    if (thread_.joinable())
        thread_.join();
    io_uring_queue_exit(&ring_);
}

// ---------------------------------------------------------------------------
// NUMA-0 affinity
// ---------------------------------------------------------------------------

void UringWorker::pin_to_numa0()
{
    if (numa_available() < 0)
        return;

    struct bitmask* mask = numa_allocate_cpumask();
    if (numa_node_to_cpus(0, mask) == 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        for (unsigned i = 0; i < mask->size; ++i) {
            if (numa_bitmask_isbitset(mask, i))
                CPU_SET(i, &cpuset);
        }
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }
    numa_bitmask_free(mask);

    numa_set_preferred(0);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

void UringWorker::start_loop(Queue* queue)
{
    running_.store(true, std::memory_order_release);
    thread_ = std::thread(&UringWorker::worker_entry, this, queue);
}

// ---------------------------------------------------------------------------
// Main worker loop
// ---------------------------------------------------------------------------

void UringWorker::worker_entry(Queue* queue)
{
    pin_to_numa0();

    while (running_.load(std::memory_order_acquire)) {
        IovecDescriptor* desc = nullptr;
        if (queue->pop(desc)) {
            submit_descriptor(desc);
        } else {
            std::this_thread::yield();
        }
        reap_completions();
    }

    // drain remaining CQEs before exit
    reap_completions();
}

// ---------------------------------------------------------------------------
// SQE submission with MSG_ZEROCOPY
// ---------------------------------------------------------------------------

void UringWorker::submit_descriptor(IovecDescriptor* desc)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (!sqe) {
        io_uring_submit(&ring_);
        reap_completions();
        sqe = io_uring_get_sqe(&ring_);
        if (!sqe) {
            std::fprintf(stderr, "SQE exhaustion after flush\n");
            return;
        }
    }

    struct msghdr msg{};
    msg.msg_name = &dest_;
    msg.msg_namelen = sizeof(dest_);
    msg.msg_iov = desc->iov;
    msg.msg_iovlen = desc->iovcnt;

    io_uring_prep_sendmsg(sqe, target_fd_, &msg, 0);
    io_uring_sqe_set_data(sqe, static_cast<void*>(desc));
    io_uring_submit(&ring_);
}

// ---------------------------------------------------------------------------
// CQE reaping with zero-copy notification handling
// ---------------------------------------------------------------------------

void UringWorker::reap_completions()
{
    struct io_uring_cqe* cqe = nullptr;

    while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
        auto* desc = static_cast<IovecDescriptor*>(io_uring_cqe_get_data(cqe));

        if (cqe->flags & IORING_CQE_F_NOTIF) {
            if (desc) {
                int prev = desc->ref_count.fetch_sub(1, std::memory_order_acq_rel);
                std::printf("[Uring] DMA completion notify, ref_count %d -> %d\n",
                            prev, prev - 1);
                if (prev == 1) {
                    std::printf("[Memory] ref_count=0, triggering safe release %p\n",
                                static_cast<void*>(desc));
                    delete desc;
                }
            }
        } else {
            if (cqe->res < 0) {
                std::fprintf(stderr, "[Uring] sendmsg error: %s\n",
                             std::strerror(-cqe->res));
            } else {
                std::printf("[Uring] sendmsg OK, %d bytes sent\n", cqe->res);
            }
            if (desc) {
                int prev = desc->ref_count.fetch_sub(1, std::memory_order_acq_rel);
                std::printf("[Uring] Send completion, ref_count %d -> %d\n",
                            prev, prev - 1);
                if (prev == 1) {
                    std::printf("[Memory] ref_count=0, triggering safe release %p\n",
                                static_cast<void*>(desc));
                    delete desc;
                }
            }
        }

        io_uring_cqe_seen(&ring_, cqe);
    }
}
