#pragma once
// ============================================================
// MpscRingBuffer — 多生产者单消费者无锁环形队列
//
// 设计要点:
//   1. 容量必须是 2 的幂，用位掩码替代取模。
//   2. 生产者通过 CAS 抢占 head 槽位，写入后置 flag=READY。
//   3. 消费者按序检查 tail 槽位的 flag，就绪则读取并推进 tail。
//   4. 全程无 mutex / condition_variable，满足数据面零阻塞约束。
//   5. head / tail / 每个 Slot 各占独立缓存行，消除伪共享。
// ============================================================

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <new>

struct IovecDescriptor;   // 前向声明

// ---------- 缓存行大小常量 ----------
#ifdef __cpp_lib_hardware_interference_size
inline constexpr std::size_t kCacheLineSize =
    std::hardware_destructive_interference_size;
#else
inline constexpr std::size_t kCacheLineSize = 64;
#endif

// ============================================================
class MpscRingBuffer {
public:
    // capacity 必须是 2 的幂
    explicit MpscRingBuffer(std::size_t capacity)
        : capacity_(capacity)
        , mask_(capacity - 1)
        , head_(0)
        , tail_(0)
    {
        assert((capacity >= 2) && "capacity must be >= 2");
        assert((capacity & mask_) == 0 && "capacity must be power of 2");
        slots_ = new Slot[capacity_]();   // 值初始化 flag=0
    }

    ~MpscRingBuffer() { delete[] slots_; }

    // 不可拷贝 / 不可移动
    MpscRingBuffer(const MpscRingBuffer&)            = delete;
    MpscRingBuffer& operator=(const MpscRingBuffer&) = delete;

    // ----------------------------------------------------------
    // push (多生产者安全)
    //   1. CAS 抢占 head 位置。
    //   2. 写入描述符指针。
    //   3. flag.store(READY, release) 通知消费者。
    // 返回 false 表示队列已满（背压信号）。
    // ----------------------------------------------------------
    bool push(IovecDescriptor* desc) noexcept {
        std::size_t pos;
        for (;;) {
            pos = head_.load(std::memory_order_relaxed);

            // 满检测：head - tail >= capacity 说明所有槽位都被占用
            // acquire 确保看到消费者最新的 tail 推进
            if (pos - tail_.load(std::memory_order_acquire) >= capacity_)
                return false;

            // CAS 抢占 pos 槽位
            if (head_.compare_exchange_weak(
                    pos, pos + 1,
                    std::memory_order_relaxed,
                    std::memory_order_relaxed))
                break;
            // CAS 失败 → 另一个生产者先抢到了，循环重试
        }

        // 此刻 [pos] 已被当前线程独占，安全写入
        Slot& slot = slots_[pos & mask_];
        slot.desc  = desc;

        // release：保证 desc 写入在 flag 可见之前完成
        slot.flag.store(READY, std::memory_order_release);
        return true;
    }

    // ----------------------------------------------------------
    // pop (单消费者，无需 CAS)
    //   1. acquire 读取 tail 位置 flag。
    //   2. 若 READY 则取出描述符，清 flag，推进 tail。
    // 返回 false 表示队列为空。
    // ----------------------------------------------------------
    bool pop(IovecDescriptor*& desc) noexcept {
        std::size_t pos = tail_.load(std::memory_order_relaxed);
        Slot& slot = slots_[pos & mask_];

        // acquire：与生产者的 release store 配对，确保看到完整的 desc
        if (slot.flag.load(std::memory_order_acquire) != READY)
            return false;

        desc = slot.desc;

        // release：确保读取完成后再清 flag，让生产者可安全复用此槽位
        slot.flag.store(EMPTY, std::memory_order_release);
        tail_.store(pos + 1, std::memory_order_release);
        return true;
    }

    // ----------------------------------------------------------
    // 辅助查询（仅供监控，不保证实时精确）
    // ----------------------------------------------------------
    std::size_t size_approx() const noexcept {
        return head_.load(std::memory_order_relaxed)
             - tail_.load(std::memory_order_relaxed);
    }
    std::size_t capacity() const noexcept { return capacity_; }

private:
    // ---------- 槽位状态 ----------
    static constexpr std::uint32_t EMPTY = 0;
    static constexpr std::uint32_t READY = 1;

    // ---------- 槽位结构（缓存行对齐，消除伪共享） ----------
    struct alignas(kCacheLineSize) Slot {
        IovecDescriptor*       desc{nullptr};
        std::atomic<std::uint32_t> flag{EMPTY};
    };

    // ---------- 不变量 ----------
    const std::size_t capacity_;
    const std::size_t mask_;

    // ---------- 生产者端 / 消费者端各占独立缓存行 ----------
    alignas(kCacheLineSize) std::atomic<std::size_t> head_;
    alignas(kCacheLineSize) std::atomic<std::size_t> tail_;

    Slot* slots_;
};
