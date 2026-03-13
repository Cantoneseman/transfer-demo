// ============================================================
// xio_prototype_test.cpp — 原型系统单元测试
//
// 覆盖:
//   [A] MpscRingBuffer 多生产者单消费者正确性
//   [B] DataProbeEngine 熵值探针 + FastCDC 分块
//   [D] IovecDescriptor 引用计数状态机
// ============================================================

#include "iovec_descriptor.h"
#include "mpsc_ring_buffer.h"
#include "data_probe_engine.h"

#include <sys/uio.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>
#include <algorithm>
#include <numeric>
#include <random>

// ==================== 测试框架 (极简) ========================

static int g_pass = 0, g_fail = 0;

#define TEST(name)                                                 \
    static void test_##name();                                     \
    struct Reg_##name {                                            \
        Reg_##name() { tests().push_back({#name, test_##name}); } \
    } reg_##name;                                                  \
    static void test_##name()

#define ASSERT_TRUE(expr)                                            \
    do { if (!(expr)) {                                              \
        std::fprintf(stderr, "  FAIL %s:%d: %s\n",                  \
                     __FILE__, __LINE__, #expr);                     \
        ++g_fail; return;                                            \
    }} while (0)

#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))

struct TestCase { const char* name; void (*fn)(); };
static std::vector<TestCase>& tests() {
    static std::vector<TestCase> v;
    return v;
}

// ==================== [A] MpscRingBuffer =====================

TEST(mpsc_single_thread) {
    MpscRingBuffer rb(16);
    // 基础 push/pop
    iovec v = {nullptr, 42};
    IovecDescriptor d(&v, 1);
    ASSERT_TRUE(rb.push(&d));

    IovecDescriptor* out = nullptr;
    ASSERT_TRUE(rb.pop(out));
    ASSERT_EQ(out, &d);
    ASSERT_EQ(out->iov[0].iov_len, size_t(42));

    // 空队列 pop 返回 false
    ASSERT_TRUE(!rb.pop(out));
    ++g_pass;
}

TEST(mpsc_fill_and_backpressure) {
    constexpr size_t cap = 8;
    MpscRingBuffer rb(cap);

    std::vector<IovecDescriptor*> descs;
    iovec v = {nullptr, 0};
    for (size_t i = 0; i < cap; ++i) {
        auto* d = new IovecDescriptor(&v, 1);
        descs.push_back(d);
    }

    // 填满
    for (size_t i = 0; i < cap - 1; ++i)
        ASSERT_TRUE(rb.push(descs[i]));

    // 第 cap 个应成功 (环形队列满判是 head - tail >= capacity)
    // 然后再 push 应失败
    // 实际满点取决于实现; 此处测试背压信号最终出现
    size_t pushed = cap - 1;
    while (pushed < cap && rb.push(descs[pushed]))
        ++pushed;

    // 此时应无法再 push 更多
    iovec v2 = {nullptr, 0};
    IovecDescriptor extra(&v2, 1);
    ASSERT_TRUE(!rb.push(&extra));

    // 清理
    for (auto* d : descs) delete d;
    ++g_pass;
}

TEST(mpsc_multi_producer) {
    constexpr size_t cap = 1024;
    constexpr int num_producers = 4;
    constexpr int items_per = 200;

    MpscRingBuffer rb(cap);
    std::atomic<int> total_pushed{0};

    iovec v = {nullptr, 0};
    // 每个生产者预分配自己的 descriptors
    std::vector<std::vector<IovecDescriptor*>> per_thread(num_producers);
    for (int t = 0; t < num_producers; ++t) {
        per_thread[t].resize(items_per);
        for (int i = 0; i < items_per; ++i)
            per_thread[t][i] = new IovecDescriptor(&v, 1);
    }

    // 生产者线程
    std::vector<std::thread> producers;
    for (int t = 0; t < num_producers; ++t) {
        producers.emplace_back([&, t]() {
            for (int i = 0; i < items_per; ++i) {
                while (!rb.push(per_thread[t][i])) {
                    // 自旋等待消费者腾出空间
                    std::this_thread::yield();
                }
                total_pushed.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    // 消费者 (主线程)
    int consumed = 0;
    const int expected = num_producers * items_per;
    while (consumed < expected) {
        IovecDescriptor* out = nullptr;
        if (rb.pop(out)) {
            ASSERT_TRUE(out != nullptr);
            ++consumed;
        } else {
            std::this_thread::yield();
        }
    }

    for (auto& t : producers) t.join();

    ASSERT_EQ(consumed, expected);
    ASSERT_EQ(total_pushed.load(), expected);

    // 清理
    for (auto& vec : per_thread)
        for (auto* d : vec) delete d;
    ++g_pass;
}

// ==================== [D] IovecDescriptor ref_count ==========

TEST(iovec_descriptor_refcount) {
    iovec v = {nullptr, 100};
    auto* desc = new IovecDescriptor(&v, 1);

    ASSERT_EQ(desc->ref_count.load(), 2);

    // 第一次 release → 1
    int r1 = desc->release();
    ASSERT_EQ(r1, 1);

    // 第二次 release → 0 → 可释放
    int r2 = desc->release();
    ASSERT_EQ(r2, 0);

    delete desc;
    ++g_pass;
}

// ==================== [B] DataProbeEngine ====================

TEST(probe_high_entropy_bypass) {
    // 构造随机数据 (高熵), 应触发旁路
    constexpr size_t len = 8192;
    auto* buf = static_cast<uint8_t*>(std::malloc(len));
    std::mt19937 rng(0xDEAD);
    for (size_t i = 0; i < len; ++i)
        buf[i] = static_cast<uint8_t>(rng() & 0xFF);

    iovec v{buf, len};
    IovecDescriptor desc(&v, 1);

    DataProbeEngine engine;
    ChunkResult res = engine.process_payload(desc);

    ASSERT_TRUE(res.bypassed);
    ASSERT_EQ(res.chunks.size(), size_t(1));
    ASSERT_EQ(res.chunks[0].iov_base, buf);   // 零拷贝: 指针不变
    ASSERT_EQ(res.chunks[0].iov_len, len);

    std::free(buf);
    ++g_pass;
}

TEST(probe_low_entropy_chunk) {
    // 构造重复数据 (低熵), 应触发 FastCDC 分块
    constexpr size_t len = 128 * 1024;   // 128 KB
    auto* buf = static_cast<uint8_t*>(std::malloc(len));
    // 填充重复模式 (极低熵)
    for (size_t i = 0; i < len; ++i)
        buf[i] = static_cast<uint8_t>(i % 4);

    iovec v{buf, len};
    IovecDescriptor desc(&v, 1);

    DataProbeEngine engine;
    ChunkResult res = engine.process_payload(desc);

    ASSERT_TRUE(!res.bypassed);
    ASSERT_TRUE(res.chunks.size() >= 1);

    // 验证 chunks 覆盖完整数据
    size_t total = 0;
    for (auto& c : res.chunks)
        total += c.iov_len;
    ASSERT_EQ(total, len);

    // chunks 已拷贝到新内存, 指针应不同于原始 buf
    // (除非恰好 malloc 返回相同地址, 概率极低)
    bool all_same = true;
    for (auto& c : res.chunks) {
        if (c.iov_base != buf) { all_same = false; break; }
    }
    ASSERT_TRUE(!all_same);   // 斩断了零拷贝链路

    // 释放 chunks 分配的内存
    for (auto& c : res.chunks)
        std::free(c.iov_base);
    std::free(buf);
    ++g_pass;
}

TEST(probe_empty_payload) {
    IovecDescriptor desc;
    DataProbeEngine engine;
    ChunkResult res = engine.process_payload(desc);
    ASSERT_TRUE(res.bypassed);
    ASSERT_TRUE(res.chunks.empty());
    ++g_pass;
}

// ==================== main ===================================

int main() {
    std::fprintf(stdout, "Running %zu tests...\n", tests().size());
    for (auto& tc : tests()) {
        std::fprintf(stdout, "  [RUN] %s\n", tc.name);
        tc.fn();
    }
    std::fprintf(stdout, "\nResult: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
