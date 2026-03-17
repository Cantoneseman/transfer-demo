#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <sys/uio.h>
#include <type_traits>

#ifdef __cpp_lib_hardware_interference_size
inline constexpr std::size_t kCacheLineSize = std::hardware_destructive_interference_size;
#else
inline constexpr std::size_t kCacheLineSize = 64;
#endif

struct IovecDescriptor {
    struct iovec* iov;
    int iovcnt;
    std::atomic<int> ref_count{2};

    IovecDescriptor() noexcept : iov(nullptr), iovcnt(0) {}
    IovecDescriptor(struct iovec* v, int cnt) noexcept : iov(v), iovcnt(cnt) {}

    IovecDescriptor(const IovecDescriptor&) = delete;
    IovecDescriptor& operator=(const IovecDescriptor&) = delete;
};

template <std::size_t Capacity>
class MpscRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    static constexpr std::size_t kMask = Capacity - 1;

    struct alignas(kCacheLineSize) Slot {
        std::atomic<IovecDescriptor*> ptr{nullptr};
        std::atomic<uint32_t> flag{0};
    };

    alignas(kCacheLineSize)
        std::atomic<std::size_t> head_{0};

    alignas(kCacheLineSize)
        std::atomic<std::size_t> tail_{0};

    Slot slots_[Capacity];

public:
    MpscRingBuffer() noexcept {
        head_.store(0, std::memory_order_relaxed);
        tail_.store(0, std::memory_order_relaxed);
        for (std::size_t i = 0; i < Capacity; ++i) {
            slots_[i].ptr.store(nullptr, std::memory_order_relaxed);
            slots_[i].flag.store(0, std::memory_order_relaxed);
        }
        std::atomic_thread_fence(std::memory_order_release);
    }

    bool push(IovecDescriptor* desc) noexcept {
        std::size_t h = head_.load(std::memory_order_relaxed);
        for (;;) {
            std::size_t t = tail_.load(std::memory_order_acquire);
            if (h - t >= Capacity)
                return false;
            if (head_.compare_exchange_weak(h, h + 1,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                Slot& slot = slots_[h & kMask];
                slot.ptr.store(desc, std::memory_order_relaxed);
                slot.flag.store(1, std::memory_order_release);
                return true;
            }
        }
    }

    bool pop(IovecDescriptor*& desc) noexcept {
        std::size_t t = tail_.load(std::memory_order_relaxed);
        Slot& slot = slots_[t & kMask];
        if (slot.flag.load(std::memory_order_acquire) == 0)
            return false;
        desc = slot.ptr.load(std::memory_order_relaxed);
        slot.ptr.store(nullptr, std::memory_order_relaxed);
        slot.flag.store(0, std::memory_order_release);
        tail_.store(t + 1, std::memory_order_release);
        return true;
    }
};
