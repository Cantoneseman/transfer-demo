#pragma once
// ============================================================
// IovecDescriptor — 指向应用层原始 iovec 的零拷贝轻量级描述符
// 严禁对数据载荷进行内存拷贝；仅传递指针与长度。
// ============================================================

#include <sys/uio.h>
#include <atomic>
#include <cstdint>

struct IovecDescriptor {
    struct iovec* iov;            // 指向调用方原始 iovec 数组，不拥有所有权
    int           iovcnt;         // iovec 数组元素个数
    std::atomic<int> ref_count;   // 引用计数 (初始化为 2: 应用层 + 传输层各持一份)

    IovecDescriptor() noexcept
        : iov(nullptr), iovcnt(0), ref_count(0) {}

    IovecDescriptor(struct iovec* v, int cnt) noexcept
        : iov(v), iovcnt(cnt), ref_count(2) {}

    // std::atomic 不可拷贝，禁用拷贝/移动
    IovecDescriptor(const IovecDescriptor&)            = delete;
    IovecDescriptor& operator=(const IovecDescriptor&) = delete;

    // 引用计数递减，返回递减后的值；调用方在值 == 0 时负责释放
    int release() noexcept {
        return ref_count.fetch_sub(1, std::memory_order_acq_rel) - 1;
    }
};
