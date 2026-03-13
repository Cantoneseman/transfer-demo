#pragma once
// ============================================================
// ctrl_mem_pool.h — 控制面内存池
//
// QUIC 头部 / 控制帧从此池分配; 数据净荷仍指向 IovecDescriptor。
// 简化实现: 固定大小块的 freelist, 无锁单线程版本
// (协议栈处理在 UringWorker 单消费者线程内)。
// ============================================================

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <new>

class CtrlMemPool {
public:
    // block_size: 每块字节数 (应 >= QUIC 最大头部 ~62 字节)
    // pool_count: 预分配块数
    explicit CtrlMemPool(std::size_t block_size, std::size_t pool_count)
        : block_size_(block_size)
        , total_(pool_count)
    {
        assert(block_size >= 64 && "block too small for QUIC headers");
        // 一次性分配连续内存
        arena_ = static_cast<uint8_t*>(std::aligned_alloc(64, block_size * pool_count));
        if (!arena_) std::abort();

        // 构建 freelist
        for (std::size_t i = 0; i < pool_count; ++i) {
            auto* node = reinterpret_cast<FreeNode*>(arena_ + i * block_size);
            node->next = free_head_;
            free_head_  = node;
        }
    }

    ~CtrlMemPool() { std::free(arena_); }

    CtrlMemPool(const CtrlMemPool&)            = delete;
    CtrlMemPool& operator=(const CtrlMemPool&) = delete;

    // 分配一块控制面内存; 返回 nullptr 表示池耗尽
    void* alloc() noexcept {
        if (!free_head_) return nullptr;
        auto* node = free_head_;
        free_head_  = node->next;
        return static_cast<void*>(node);
    }

    // 归还一块控制面内存
    void dealloc(void* ptr) noexcept {
        if (!ptr) return;
        auto* node = static_cast<FreeNode*>(ptr);
        node->next = free_head_;
        free_head_  = node;
    }

    std::size_t block_size() const noexcept { return block_size_; }

private:
    struct FreeNode { FreeNode* next; };

    uint8_t*    arena_      = nullptr;
    FreeNode*   free_head_  = nullptr;
    std::size_t block_size_;
    std::size_t total_;
};
