#pragma once

#include "mpsc_ring_buffer.h"
#include <liburing.h>
#include <netinet/in.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

#ifndef IORING_CQE_F_NOTIF
#define IORING_CQE_F_NOTIF (1U << 2)
#endif

class UringWorker {
public:
    static constexpr std::size_t kQueueDepth = 4096;
    static constexpr std::size_t kRingCapacity = 8192;

    using Queue = MpscRingBuffer<kRingCapacity>;

    explicit UringWorker(int target_fd, const struct sockaddr_in& dest);
    ~UringWorker();

    UringWorker(const UringWorker&) = delete;
    UringWorker& operator=(const UringWorker&) = delete;

    void start_loop(Queue* queue);
    void request_stop() noexcept { running_.store(false, std::memory_order_release); }

private:
    void worker_entry(Queue* queue);
    void pin_to_numa0();
    void submit_descriptor(IovecDescriptor* desc);
    void reap_completions();

    struct io_uring ring_{};
    int target_fd_;
    struct sockaddr_in dest_;
    std::atomic<bool> running_{false};
    std::thread thread_;
};
