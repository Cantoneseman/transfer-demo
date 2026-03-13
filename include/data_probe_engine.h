#pragma once
// ============================================================
// DataProbeEngine — 模块 B: 探针驱动的源端减负层
//
// 流水线:
//   1. LZ4 dry-run 熵值探针 → 压缩比判定
//   2. 高熵(< 1.1): 旁路, 返回原始 iovec 零拷贝指针
//   3. 低熵(>= 1.1): FastCDC 内容分块 (AVX-512 Gear Hash)
//      → 拷贝到控制面内存池 → 斩断 MSG_ZEROCOPY 链路
// ============================================================

#include <sys/uio.h>
#include <cstddef>
#include <cstdint>
#include <vector>

struct IovecDescriptor;

// ---- 分块结果 ----
struct ChunkResult {
    bool                bypassed;   // true = 高熵旁路, chunks 指向原始缓冲区
    std::vector<iovec>  chunks;     // 切分后的 iovec 列表
};

class DataProbeEngine {
public:
    // FastCDC 参数
    struct CdcParams {
        size_t min_chunk  = 2  * 1024;   // 2 KB
        size_t avg_chunk  = 8  * 1024;   // 8 KB
        size_t max_chunk  = 64 * 1024;   // 64 KB
    };

    explicit DataProbeEngine(const CdcParams& params = {});
    ~DataProbeEngine();

    DataProbeEngine(const DataProbeEngine&)            = delete;
    DataProbeEngine& operator=(const DataProbeEngine&) = delete;

    // 核心入口: 对 desc 描述的 payload 执行探针 + 可选分块
    ChunkResult process_payload(const IovecDescriptor& desc);

private:
    // LZ4 dry-run 熵值探针, 返回压缩比 (>= 1.0)
    double entropy_probe(const uint8_t* data, size_t len);

    // FastCDC 分块 (AVX-512 Gear Hash), 对连续缓冲区操作
    void fastcdc_chunk(const uint8_t* data, size_t len,
                       std::vector<iovec>& out);

    CdcParams   params_;

    // ---- Gear Hash 查找表 (256 项, 64-bit) ----
    alignas(64) uint64_t gear_table_[256];

    void init_gear_table();
};
