#pragma once

#include "mpsc_ring_buffer.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <sys/uio.h>

struct ChunkResult {
    bool is_bypassed;
    std::vector<struct iovec> chunks;
};

class DataProbeEngine {
public:
    static constexpr size_t kProbeSize       = 4096;
    static constexpr double kEntropyThreshold = 1.1;

    static constexpr size_t kMinChunk = 2048;
    static constexpr size_t kAvgChunk = 8192;
    static constexpr size_t kMaxChunk = 65536;

    static constexpr uint64_t kCdcMask = (1ULL << 13) - 1; // ~8KB avg

    DataProbeEngine();

    ChunkResult process_payload(const IovecDescriptor& desc);

private:
    bool probe_entropy(const uint8_t* data, size_t len);

    void fastcdc_avx2(const uint8_t* data, size_t len,
                      std::vector<struct iovec>& out);

    alignas(32) uint64_t gear_table_[256];
};
