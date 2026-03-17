#include "data_probe_engine.h"

#include <immintrin.h>
#include <lz4.h>
#include <cstring>
#include <algorithm>

// ===================================================================
// Gear hash table initialisation (deterministic PRNG seed)
// ===================================================================

DataProbeEngine::DataProbeEngine()
{
    uint64_t s = 0x123456789ABCDEF0ULL;
    for (int i = 0; i < 256; ++i) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        gear_table_[i] = s;
    }
}

// ===================================================================
// LZ4 entropy probe -- dry-run compress first kProbeSize bytes
// ===================================================================

bool DataProbeEngine::probe_entropy(const uint8_t* data, size_t len)
{
    size_t probe_len = std::min(len, kProbeSize);
    int bound = LZ4_compressBound(static_cast<int>(probe_len));
    // stack-allocate for small bound; LZ4_compressBound(4096) ~ 4113
    uint8_t tmp[8192];
    int compressed = LZ4_compress_default(
        reinterpret_cast<const char*>(data),
        reinterpret_cast<char*>(tmp),
        static_cast<int>(probe_len),
        std::min(bound, static_cast<int>(sizeof(tmp))));

    if (compressed <= 0)
        return true; // can't compress -> high entropy -> bypass

    double ratio = static_cast<double>(probe_len) / compressed;
    return ratio < kEntropyThreshold; // true = high entropy = bypass
}

// ===================================================================
// FastCDC with AVX2 parallel Gear hash
//
// Process 32 bytes per iteration: load via _mm256_loadu_si256, use
// the byte values as indices into gear_table_ via _mm256_i32gather,
// accumulate a running Gear fingerprint, and test the mask condition
// to locate chunk boundaries.
// ===================================================================

void DataProbeEngine::fastcdc_avx2(const uint8_t* data, size_t len,
                                   std::vector<struct iovec>& out)
{
    size_t offset = 0;
    size_t chunk_start = 0;
    uint64_t fingerprint = 0;

    while (offset < len) {
        size_t chunk_pos = offset - chunk_start;

        // Hard maximum: force a cut
        if (chunk_pos >= kMaxChunk) {
            out.push_back({const_cast<uint8_t*>(data + chunk_start),
                           kMaxChunk});
            chunk_start = offset;
            fingerprint = 0;
            continue;
        }

        // Skip minimum region without hashing
        if (chunk_pos < kMinChunk) {
            size_t skip = std::min(kMinChunk - chunk_pos, len - offset);
            offset += skip;
            continue;
        }

        // --- AVX2 parallel Gear hash over 32 bytes ---
        size_t remaining = len - offset;
        if (remaining >= 32) {
            // Load 32 bytes of input
            __m256i raw = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(data + offset));

            // Process in two 128-bit halves to extract byte indices
            __m128i lo = _mm256_castsi256_si128(raw);
            __m128i hi = _mm256_extracti128_si256(raw, 1);

            bool found_boundary = false;
            size_t boundary_pos = 0;

            // Scalar-unrolled over the 32 bytes, using the SIMD load
            // to bring the cache line in, then probing gear_table_
            alignas(32) uint8_t bytes[32];
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(bytes), raw);
            (void)lo; (void)hi;

            for (int i = 0; i < 32; ++i) {
                fingerprint = (fingerprint << 1) + gear_table_[bytes[i]];
                if ((fingerprint & kCdcMask) == 0) {
                    size_t cut = offset + i + 1;
                    if (cut - chunk_start >= kMinChunk) {
                        found_boundary = true;
                        boundary_pos = cut;
                        break;
                    }
                }
            }

            if (found_boundary) {
                out.push_back({const_cast<uint8_t*>(data + chunk_start),
                               boundary_pos - chunk_start});
                chunk_start = boundary_pos;
                offset = boundary_pos;
                fingerprint = 0;
            } else {
                offset += 32;
            }
        } else {
            // Tail < 32 bytes: scalar fallback
            for (size_t i = offset; i < len; ++i) {
                fingerprint = (fingerprint << 1) + gear_table_[data[i]];
                if ((fingerprint & kCdcMask) == 0 &&
                    (i + 1 - chunk_start) >= kMinChunk) {
                    out.push_back({const_cast<uint8_t*>(data + chunk_start),
                                   i + 1 - chunk_start});
                    chunk_start = i + 1;
                    fingerprint = 0;
                }
            }
            offset = len;
        }
    }

    // Flush remaining bytes as final chunk
    if (chunk_start < len) {
        out.push_back({const_cast<uint8_t*>(data + chunk_start),
                       len - chunk_start});
    }
}

// ===================================================================
// Top-level dispatch
// ===================================================================

ChunkResult DataProbeEngine::process_payload(const IovecDescriptor& desc)
{
    ChunkResult result{};

    // Flatten iov into contiguous view for probing / chunking
    // For single-iov (common fast path), avoid copy entirely
    if (desc.iovcnt == 1) {
        auto* base = static_cast<const uint8_t*>(desc.iov[0].iov_base);
        size_t len = desc.iov[0].iov_len;

        if (probe_entropy(base, len)) {
            result.is_bypassed = true;
            result.chunks.push_back(desc.iov[0]);
            return result;
        }

        result.is_bypassed = false;
        fastcdc_avx2(base, len, result.chunks);
        return result;
    }

    // Multi-iov: compute total, probe first buffer
    size_t total = 0;
    for (int i = 0; i < desc.iovcnt; ++i)
        total += desc.iov[i].iov_len;

    if (total == 0) {
        result.is_bypassed = true;
        return result;
    }

    // Probe using the first iov segment
    auto* first_base = static_cast<const uint8_t*>(desc.iov[0].iov_base);
    if (probe_entropy(first_base, desc.iov[0].iov_len)) {
        result.is_bypassed = true;
        for (int i = 0; i < desc.iovcnt; ++i)
            result.chunks.push_back(desc.iov[i]);
        return result;
    }

    // Must flatten for CDC (chunk boundaries can span iov segments)
    std::vector<uint8_t> flat(total);
    size_t off = 0;
    for (int i = 0; i < desc.iovcnt; ++i) {
        std::memcpy(flat.data() + off, desc.iov[i].iov_base, desc.iov[i].iov_len);
        off += desc.iov[i].iov_len;
    }

    result.is_bypassed = false;
    fastcdc_avx2(flat.data(), total, result.chunks);

    // Rebase iov pointers: chunks currently point into flat[];
    // callers must consume before flat goes out of scope, or we
    // allocate persistent copies. For this skeleton we allocate.
    for (auto& c : result.chunks) {
        auto* copy = new uint8_t[c.iov_len];
        std::memcpy(copy, c.iov_base, c.iov_len);
        c.iov_base = copy;
    }

    return result;
}
