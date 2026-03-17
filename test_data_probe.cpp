#include "data_probe_engine.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>

int main()
{
    DataProbeEngine engine;

    // --- Test 1: High-entropy data -> bypass ---
    {
        constexpr size_t sz = 32768;
        auto* buf = new uint8_t[sz];
        // Fill with /dev/urandom for true high entropy
        FILE* f = fopen("/dev/urandom", "rb");
        assert(f);
        assert(fread(buf, 1, sz, f) == sz);
        fclose(f);

        struct iovec v{ .iov_base = buf, .iov_len = sz };
        IovecDescriptor desc(&v, 1);

        ChunkResult r = engine.process_payload(desc);
        std::printf("High-entropy: bypassed=%d  chunks=%zu\n",
                    r.is_bypassed, r.chunks.size());
        assert(r.is_bypassed);
        assert(r.chunks.size() == 1);
        assert(r.chunks[0].iov_base == buf);
        assert(r.chunks[0].iov_len == sz);
        delete[] buf;
        std::printf("PASS: high-entropy bypass\n");
    }

    // --- Test 2: Low-entropy (repetitive) data -> chunked ---
    {
        constexpr size_t sz = 262144;
        auto* buf = new uint8_t[sz];
        // Mix of patterns: compressible, with enough byte variation for CDC
        for (size_t i = 0; i < sz; ++i)
            buf[i] = static_cast<uint8_t>((i * 131 + (i >> 8) * 37) & 0xFF);

        struct iovec v{ .iov_base = buf, .iov_len = sz };
        IovecDescriptor desc(&v, 1);

        ChunkResult r = engine.process_payload(desc);
        std::printf("Low-entropy: bypassed=%d  chunks=%zu\n",
                    r.is_bypassed, r.chunks.size());
        assert(!r.is_bypassed);
        assert(r.chunks.size() >= 1);

        // Verify total chunk bytes == original
        size_t total = 0;
        for (auto& c : r.chunks) {
            assert(c.iov_len >= DataProbeEngine::kMinChunk ||
                   &c == &r.chunks.back()); // last chunk may be < min
            total += c.iov_len;
        }
        assert(total == sz);
        assert(r.chunks.size() > 1);
        std::printf("  total_chunk_bytes=%zu  num_chunks=%zu\n",
                    total, r.chunks.size());
        for (size_t i = 0; i < r.chunks.size(); ++i)
            std::printf("  chunk[%zu]: len=%zu\n", i, r.chunks[i].iov_len);

        delete[] buf;
        std::printf("PASS: low-entropy chunking\n");
    }

    // --- Test 3: Multi-iov low-entropy ---
    {
        constexpr size_t seg = 16384;
        auto* buf1 = new uint8_t[seg];
        auto* buf2 = new uint8_t[seg];
        std::memset(buf1, 'A', seg);
        std::memset(buf2, 'B', seg);

        struct iovec vs[2] = {
            { .iov_base = buf1, .iov_len = seg },
            { .iov_base = buf2, .iov_len = seg },
        };
        IovecDescriptor desc(vs, 2);

        ChunkResult r = engine.process_payload(desc);
        std::printf("Multi-iov: bypassed=%d  chunks=%zu\n",
                    r.is_bypassed, r.chunks.size());
        assert(!r.is_bypassed);

        size_t total = 0;
        for (auto& c : r.chunks) total += c.iov_len;
        assert(total == seg * 2);

        // Free allocated copies
        for (auto& c : r.chunks)
            delete[] static_cast<uint8_t*>(c.iov_base);

        delete[] buf1;
        delete[] buf2;
        std::printf("PASS: multi-iov chunking\n");
    }

    // --- Test 4: Natural CDC boundaries with /dev/urandom-seeded compressible data ---
    {
        constexpr size_t sz = 262144;
        auto* buf = new uint8_t[sz];
        // Repeating short pattern = highly compressible.
        // Add a slowly-varying offset so gear hash sees unique sequences.
        FILE* f = fopen("/dev/urandom", "rb");
        assert(f);
        uint8_t seed[64];
        assert(fread(seed, 1, 64, f) == 64);
        fclose(f);
        for (size_t i = 0; i < sz; ++i)
            buf[i] = seed[i % 64] ^ static_cast<uint8_t>(i >> 10);

        struct iovec v{ .iov_base = buf, .iov_len = sz };
        IovecDescriptor desc(&v, 1);

        ChunkResult r = engine.process_payload(desc);
        std::printf("Natural-CDC: bypassed=%d  chunks=%zu\n",
                    r.is_bypassed, r.chunks.size());

        size_t total = 0;
        for (size_t i = 0; i < r.chunks.size(); ++i) {
            std::printf("  chunk[%zu]: len=%zu\n", i, r.chunks[i].iov_len);
            total += r.chunks[i].iov_len;
        }
        assert(!r.is_bypassed);
        assert(total == sz);
        assert(r.chunks.size() >= 2);
        delete[] buf;
        std::printf("PASS: natural CDC boundaries\n");
    }

    std::printf("ALL TESTS PASSED\n");
    return 0;
}
