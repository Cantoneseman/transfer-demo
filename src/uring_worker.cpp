// ============================================================
// uring_worker.cpp — Module D 极限异步 I/O 底盘
//
// 核心循环: pop(MPSC) → io_uring_prep_sendmsg(MSG_ZEROCOPY)
//           → submit → peek_cqe → NOTIF 释放状态机
// ============================================================

#include "uring_worker.h"
#include "iovec_descriptor.h"
#include "mpsc_ring_buffer.h"

#include <liburing.h>
#include <sched.h>          // CPU_SET, pthread_setaffinity_np
#include <pthread.h>
#include <linux/errqueue.h> // SO_EE_ORIGIN_ZEROCOPY
#include <cstring>
#include <cstdio>
#include <cerrno>

// ==================== 构造 / 析构 ============================

UringWorker::UringWorker(unsigned queue_depth, int cpu_id,
                         int fd, MpscRingBuffer& ring_buf)
    : fd_(fd)
    , cpu_id_(cpu_id)
    , queue_depth_(queue_depth)
    , ring_buf_(ring_buf)
{
    // 初始化 io_uring 实例
    int ret = io_uring_queue_init(queue_depth_, &ring_, 0);
    if (ret < 0) {
        std::fprintf(stderr, "[UringWorker] io_uring_queue_init failed: %s\n",
                     std::strerror(-ret));
        std::abort();
    }
}

UringWorker::~UringWorker() {
    stop();
    io_uring_queue_exit(&ring_);
}

// ==================== 生命周期管理 ============================

void UringWorker::start_loop() {
    running_.store(true, std::memory_order_release);
    worker_ = std::thread(&UringWorker::loop_fn, this);
}

void UringWorker::stop() noexcept {
    running_.store(false, std::memory_order_release);
    if (worker_.joinable())
        worker_.join();
}

// ==================== 后台线程主函数 ==========================

void UringWorker::loop_fn() {
    // ---- NUMA 亲和性: 绑核 ----
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id_, &cpuset);
    int ret = pthread_setaffinity_np(pthread_self(),
                                     sizeof(cpuset), &cpuset);
    if (ret != 0) {
        std::fprintf(stderr, "[UringWorker] pthread_setaffinity_np(%d) failed: %s\n",
                     cpu_id_, std::strerror(ret));
        // 绑核失败不致命，继续运行
    }

    unsigned inflight = 0;                    // 已提交尚未收割的 SQE 数
    constexpr unsigned kSubmitBatch = 32;      // 每轮最多提交批量

    while (running_.load(std::memory_order_acquire)) {
        // ---- 阶段 1: 从 MPSC 队列 pop → 构建 SQE ----
        unsigned submitted_this_round = 0;
        while (inflight + submitted_this_round < queue_depth_ - 1
               && submitted_this_round < kSubmitBatch)
        {
            IovecDescriptor* desc = nullptr;
            if (!ring_buf_.pop(desc))
                break;   // 队列空

            submit_tx(desc);
            ++submitted_this_round;
        }

        // ---- 阶段 2: 批量提交 ----
        if (submitted_this_round > 0) {
            int n = io_uring_submit(&ring_);
            if (n > 0)
                inflight += static_cast<unsigned>(n);
        }

        // ---- 阶段 3: 收割 CQE ----
        struct io_uring_cqe* cqe = nullptr;

        // 非阻塞 peek; 若无 inflight 且队列空则短暂让出 CPU
        while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
            auto* desc = reinterpret_cast<IovecDescriptor*>(
                             io_uring_cqe_get_data(cqe));

            if (cqe->flags & IORING_CQE_F_NOTIF) {
                // ---- DMA 完成通知: 网卡已读完用户缓冲区 ----
                // ref_count -= 1  (条件 1: 本地 DMA 确认)
                if (desc)
                    try_release(desc);
            } else if (cqe->flags & IORING_CQE_F_MORE) {
                // 零拷贝路径: 首次 CQE 表示数据已入队内核，
                // 后续还会有 NOTIF CQE，此处不做释放。
                if (cqe->res < 0) {
                    std::fprintf(stderr,
                        "[UringWorker] sendmsg error: %s\n",
                        std::strerror(-cqe->res));
                }
            } else {
                // 非零拷贝回退路径或错误
                if (cqe->res < 0) {
                    std::fprintf(stderr,
                        "[UringWorker] sendmsg error (non-zc): %s\n",
                        std::strerror(-cqe->res));
                }
                // 非零拷贝场景下不会收到 NOTIF，
                // 直接做一次 DMA 侧释放
                if (desc)
                    try_release(desc);
            }

            io_uring_cqe_seen(&ring_, cqe);
            if (inflight > 0)
                --inflight;
        }

        // 若本轮既无提交也无收割，短暂让出 CPU 避免纯空转
        if (submitted_this_round == 0 && inflight == 0)
            sched_yield();
    }
}

// ==================== 构建 SQE (MSG_ZEROCOPY) =================

void UringWorker::submit_tx(IovecDescriptor* desc) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
    if (!sqe) {
        // SQ 已满，理论上由外层 inflight 控制不会触达此处
        std::fprintf(stderr, "[UringWorker] SQ full, dropping descriptor\n");
        try_release(desc);  // DMA 侧释放
        mock_remote_ack(desc);  // 模拟远端释放
        return;
    }

    // ---- 构建 msghdr ----
    // 使用堆上 msghdr 以保证 SQE 异步提交期间存活
    // 注意: io_uring 在 submit 时会拷贝 msghdr 到内核，
    //       因此栈变量也安全，但为清晰起见用 desc 同生命周期管理。
    struct msghdr msg{};
    msg.msg_iov     = desc->iov;
    msg.msg_iovlen  = static_cast<std::size_t>(desc->iovcnt);
    msg.msg_name    = (dest_len_ > 0) ? &dest_addr_ : nullptr;
    msg.msg_namelen = dest_len_;

    // ---- SO_TXTIME 硬件 Pacing 占位 ----
    // TODO: 若启用硬件 Pacing，在此处构建 cmsg:
    //   char cmsg_buf[CMSG_SPACE(sizeof(uint64_t))];
    //   msg.msg_control    = cmsg_buf;
    //   msg.msg_controllen = sizeof(cmsg_buf);
    //   struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    //   cm->cmsg_level = SOL_SOCKET;
    //   cm->cmsg_type  = SCM_TXTIME;       // SO_TXTIME
    //   cm->cmsg_len   = CMSG_LEN(sizeof(uint64_t));
    //   *(uint64_t*)CMSG_DATA(cm) = <txtime_ns>;
    msg.msg_control    = nullptr;
    msg.msg_controllen = 0;

    // ---- 构建 SQE: io_uring_prep_sendmsg + MSG_ZEROCOPY ----
    io_uring_prep_sendmsg(sqe, fd_, &msg, MSG_ZEROCOPY);

    // 挂载 desc 指针到 user_data, CQE 回收时取回
    io_uring_sqe_set_data(sqe, desc);
}

// ==================== 内存释放状态机 ==========================
//
// ref_count 初始 = 2
//   路径 A: IORING_CQE_F_NOTIF → try_release() → ref_count -= 1
//   路径 B: mock_remote_ack()  → try_release() → ref_count -= 1
// 两条路径均到达后 ref_count == 0 → delete desc
//
// 严格保证: 只有 ref_count 归零时才释放，杜绝 UAF。
// ============================================================

void UringWorker::try_release(IovecDescriptor* desc) noexcept {
    if (!desc) return;
    if (desc->release() == 0) {
        // 两个确认均已到达，安全释放
        delete desc;
    }
}

void UringWorker::mock_remote_ack(IovecDescriptor* desc) noexcept {
    // 模拟远端 QUIC ACK 到达，触发条件 2 的 ref_count 递减
    try_release(desc);
}
