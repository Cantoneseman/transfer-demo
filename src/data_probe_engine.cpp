// ============================================================
// data_probe_engine.cpp — 模块 B 核心实现
//
// 两大核心路径:
//   1. entropy_probe()  — LZ4 dry-run 熵值探针
//   2. fastcdc_chunk()  — AVX-512 Gear Hash 内容分块
// ============================================================

#include "data_probe_engine.h"
#include "iovec_descriptor.h"

#include <lz4.h>
#include <immintrin.h>

#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <random>

// ==================== Gear 表初始化 ==========================
// 用确定性种子生成 256 项 64-bit 伪随机值, 供 rolling hash 查表。

void DataProbeEngine::init_gear_table() {
    std::mt19937_64 rng(0xFastCDC'2026ULL);
    for (auto& v : gear_table_)
        v = rng();
}

// ==================== 构造 / 析构 ============================

DataProbeEngine::DataProbeEngine(const CdcParams& params)
    : params_(params)
{
    init_gear_table();
}

DataProbeEngine::~DataProbeEngine() = default;

// ==================== 辅助: iovec → 连续视图 =================
// 将 scatter-gather iovec 线性化到一段连续缓冲区。
// 仅在需要 FastCDC 分块时调用 (旁路路径零拷贝, 不触及此函数)。
namespace {

struct LinearView {
    const uint8_t* data;
    size_t         len;
    uint8_t*       owned;   // 非空则需释放

    ~LinearView() { std::free(owned); }
};

LinearView linearize(const IovecDescriptor& desc) {
    // 快速路径: 单段 iovec, 直接返回其指针
    if (desc.iovcnt == 1) {
        return {
            static_cast<const uint8_t*>(desc.iov[0].iov_base),
            desc.iov[0].iov_len,
            nullptr
        };
    }
    // 多段: 合并 (仅探针 + 分块时触发, 非数据面热路径)
    size_t total = 0;
    for (int i = 0; i < desc.iovcnt; ++i)
        total += desc.iov[i].iov_len;

    auto* buf = static_cast<uint8_t*>(std::malloc(total));
    size_t off = 0;
    for (int i = 0; i < desc.iovcnt; ++i) {
        std::memcpy(buf + off, desc.iov[i].iov_base, desc.iov[i].iov_len);
        off += desc.iov[i].iov_len;
    }
    return {buf, total, buf};
}

} // anonymous namespace

// ==================== LZ4 熵值探针 ===========================
//
// Dry-run: 压缩前 4KB 样本, 通过压缩比推断数据熵。
// 压缩比 < 1.1 → 高熵 (已加密/已压缩), 旁路处理。
// ============================================================

static constexpr size_t kProbeSize = 4096;

double DataProbeEngine::entropy_probe(const uint8_t* data, size_t len) {
    size_t sample_len = std::min(len, kProbeSize);

    // LZ4_compressBound 返回最坏情况输出大小
    int bound = LZ4_compressBound(static_cast<int>(sample_len));
    // 栈上分配小缓冲区 (最大 ~4.1 KB), 避免堆分配
    auto* tmp = static_cast<char*>(__builtin_alloca(bound));

    int compressed = LZ4_compress_default(
        reinterpret_cast<const char*>(data),
        tmp,
        static_cast<int>(sample_len),
        bound);

    if (compressed <= 0)
        return 1.0;   // 压缩失败, 视为不可压缩

    return static_cast<double>(sample_len) / static_cast<double>(compressed);
}

// ==================== FastCDC — AVX-512 Gear Hash ============
//
// 核心循环: 64 字节/迭代 并行计算滚动哈希。
//
// 算法:
//   fp = 0
//   for each byte b:
//     fp = (fp << 1) + gear_table[b]
//     if (fp & mask) == 0 → 切分边界
//
// AVX-512 向量化策略:
//   1. _mm512_loadu_si512 加载 64 字节数据
//   2. vpgatherqq 按字节值从 gear_table 聚集查表
//   3. 逐 lane 累积 (fp <<1) + gear[b], 跨 lane 传播进位
//   4. 最终用标量 scan 在 64 个候选中检查掩码命中
//
// 说明: 因为 fp 存在跨字节的串行依赖 (左移+累加),
//       纯 SIMD 无法完全消除依赖链。采用 "向量查表 + 标量扫描"
//       混合策略: SIMD 负责 64 路并行查表, 标量负责 8 步 prefix-sum。
// ============================================================

// ---- FastCDC 掩码: 控制平均切分粒度 ----
// avg_chunk ~8KB → 需要约 13 bit 掩码
static constexpr uint64_t kMaskS = 0x0000D93003530000ULL;  // 窄掩码 (大粒度)
static constexpr uint64_t kMaskL = 0x0000D90003530000ULL;  // 宽掩码 (小粒度)

void DataProbeEngine::fastcdc_chunk(const uint8_t* data, size_t len,
                                    std::vector<iovec>& out)
{
    const size_t min_sz = params_.min_chunk;
    const size_t avg_sz = params_.avg_chunk;
    const size_t max_sz = params_.max_chunk;

    size_t offset = 0;   // 当前 chunk 起始位置

    while (offset < len) {
        size_t remaining = len - offset;
        size_t chunk_sz  = std::min(remaining, max_sz);
        if (chunk_sz <= min_sz) {
            // 不足最小块, 直接作为尾部 chunk
            goto emit_chunk;
        }

        {   // ---- Gear Hash 滚动扫描 ----
            uint64_t fp = 0;
            size_t   i  = min_sz;         // 跳过 min_chunk, 不会在此之前切分
            const uint8_t* p = data + offset;

            // ============================================
            // AVX-512 快速路径: 每次处理 64 字节
            // ============================================
#if defined(__AVX512F__) && defined(__AVX512BW__)
            // gear_table 基址广播
            const __m512i* gear_base =
                reinterpret_cast<const __m512i*>(gear_table_);
            (void)gear_base;   // 用于 gather (下方手动索引)

            while (i + 64 <= chunk_sz) {
                // (1) 加载 64 字节数据
                __m512i raw = _mm512_loadu_si512(p + i);

                // (2) 拆分为 8 个 8-byte lane, 对每字节查 gear_table
                //     因 vpgatherqq 一次取 8 个 64-bit, 需 8 轮
                alignas(64) uint8_t bytes[64];
                _mm512_storeu_si512(bytes, raw);

                // (3) 向量查表: 8 路一批, 共 8 批 = 64 字节
                alignas(64) uint64_t gear_vals[64];
                for (int batch = 0; batch < 8; ++batch) {
                    __m512i indices = _mm512_set_epi64(
                        bytes[batch * 8 + 7], bytes[batch * 8 + 6],
                        bytes[batch * 8 + 5], bytes[batch * 8 + 4],
                        bytes[batch * 8 + 3], bytes[batch * 8 + 2],
                        bytes[batch * 8 + 1], bytes[batch * 8 + 0]);

                    __m512i gathered = _mm512_i64gather_epi64(
                        indices,
                        reinterpret_cast<const long long*>(gear_table_),
                        8 /* scale: 8 bytes per entry */);

                    _mm512_store_si512(&gear_vals[batch * 8], gathered);
                }

                // (4) 标量扫描 64 个查表结果, 累积 fp 并检查边界
                bool found = false;
                for (int k = 0; k < 64; ++k) {
                    fp = (fp << 1) + gear_vals[k];
                    // 双级掩码: 前半用宽掩码(更易命中), 后半用窄掩码
                    uint64_t mask = (i + k < offset + avg_sz) ? kMaskL : kMaskS;
                    if ((fp & mask) == 0) {
                        chunk_sz = i + k + 1;
                        found = true;
                        break;
                    }
                }
                if (found) break;
                i += 64;
            }
#endif // __AVX512F__

            // ============================================
            // AVX2 回退路径: 每次处理 32 字节
            // ============================================
#if defined(__AVX2__) && !(defined(__AVX512F__) && defined(__AVX512BW__))
            while (i + 32 <= chunk_sz) {
                __m256i raw = _mm256_loadu_si256(
                    reinterpret_cast<const __m256i*>(p + i));

                alignas(32) uint8_t bytes[32];
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(bytes), raw);

                // 4 批 × 4 路 gather
                alignas(32) uint64_t gear_vals[32];
                for (int batch = 0; batch < 8; ++batch) {
                    __m256i indices = _mm256_set_epi64x(
                        bytes[batch * 4 + 3], bytes[batch * 4 + 2],
                        bytes[batch * 4 + 1], bytes[batch * 4 + 0]);

                    __m256i gathered = _mm256_i64gather_epi64(
                        reinterpret_cast<const long long*>(gear_table_),
                        indices,
                        8);

                    _mm256_store_si256(
                        reinterpret_cast<__m256i*>(&gear_vals[batch * 4]),
                        gathered);
                }

                bool found = false;
                for (int k = 0; k < 32; ++k) {
                    fp = (fp << 1) + gear_vals[k];
                    uint64_t mask = (i + k < offset + avg_sz) ? kMaskL : kMaskS;
                    if ((fp & mask) == 0) {
                        chunk_sz = i + k + 1;
                        found = true;
                        break;
                    }
                }
                if (found) break;
                i += 32;
            }
#endif // __AVX2__

            // ============================================
            // 标量扫尾: 处理 SIMD 循环未覆盖的余尾字节
            // ============================================
            while (i < chunk_sz) {
                fp = (fp << 1) + gear_table_[p[i]];
                uint64_t mask = (i < avg_sz) ? kMaskL : kMaskS;
                if ((fp & mask) == 0) {
                    chunk_sz = i + 1;
                    break;
                }
                ++i;
            }
        } // end gear hash scope

emit_chunk:
        // ---- 发射 chunk ----
        // 去重路径: 从控制面内存池拷贝 (模拟大页分配), 斩断零拷贝链路
        void* chunk_buf = std::malloc(chunk_sz);
        std::memcpy(chunk_buf, data + offset, chunk_sz);

        out.push_back(iovec{chunk_buf, chunk_sz});
        offset += chunk_sz;
    }
}

// ==================== 核心入口 ================================

ChunkResult DataProbeEngine::process_payload(const IovecDescriptor& desc) {
    ChunkResult result{};

    if (!desc.iov || desc.iovcnt <= 0) {
        result.bypassed = true;
        return result;
    }

    // ---- 计算总长 ----
    size_t total = 0;
    for (int i = 0; i < desc.iovcnt; ++i)
        total += desc.iov[i].iov_len;

    if (total == 0) {
        result.bypassed = true;
        return result;
    }

    // ---- 提取探针采样数据 ----
    // 需要连续内存来做 LZ4 探测; 若单段则零拷贝取前 4KB
    const uint8_t* probe_ptr;
    size_t          probe_len = std::min(total, kProbeSize);
    uint8_t         probe_stack[kProbeSize];
    bool            probe_from_stack = false;

    if (desc.iovcnt == 1 && desc.iov[0].iov_len >= probe_len) {
        // 单段 & 足够长: 直接引用, 零拷贝
        probe_ptr = static_cast<const uint8_t*>(desc.iov[0].iov_base);
    } else {
        // 多段: 拼接前 4KB 到栈缓冲区 (仅探针用, 不进数据面)
        size_t copied = 0;
        for (int i = 0; i < desc.iovcnt && copied < probe_len; ++i) {
            size_t take = std::min(desc.iov[i].iov_len, probe_len - copied);
            std::memcpy(probe_stack + copied, desc.iov[i].iov_base, take);
            copied += take;
        }
        probe_ptr = probe_stack;
        probe_from_stack = true;
    }

    // ---- 阶段 1: LZ4 熵值探针 ----
    double ratio = entropy_probe(probe_ptr, probe_len);

    // ---- 阶段 2: 旁路判定 ----
    if (ratio < 1.1) {
        // 高熵: 直接返回原始 iovec, 保持零拷贝 + MSG_ZEROCOPY 链路
        result.bypassed = true;
        result.chunks.reserve(desc.iovcnt);
        for (int i = 0; i < desc.iovcnt; ++i)
            result.chunks.push_back(desc.iov[i]);
        return result;
    }

    // ---- 阶段 3: 低熵 → FastCDC 分块 ----
    result.bypassed = false;

    // 需要连续缓冲区做 Gear Hash 滑动窗口
    LinearView view = linearize(desc);
    fastcdc_chunk(view.data, view.len, result.chunks);

    // 分块后的 chunks 已拷贝到新分配的内存, 原始 iovec 的
    // MSG_ZEROCOPY 链路被斩断; 上层可安全对原始缓冲区调用
    // IovecDescriptor::release()。
    return result;
}
