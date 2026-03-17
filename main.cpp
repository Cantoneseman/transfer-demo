#include "mpsc_ring_buffer.h"
#include "data_probe_engine.h"
#include "custom_quic_engine.h"
#include "uring_worker.h"

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static constexpr size_t kBlockSize = 4096;
static constexpr size_t kPageSize  = 4096;

int main()
{
    std::cout << "========================================\n"
              << "  XIO Prototype -- Polarity Pipeline Test\n"
              << "========================================\n\n";
    std::cout.flush();

    // ---------------------------------------------------------------
    // 1. Core engines
    // ---------------------------------------------------------------
    static UringWorker::Queue queue;
    DataProbeEngine probe;
    CustomQuicEngine quic_engine;
    quic_engine.inject_null_cipher();
    quic_engine.install_tcsack_cc();
    std::cout << "[Init] All engines instantiated. Null cipher injected, TC-SACK CC installed.\n\n";

    // ---------------------------------------------------------------
    // 2. UDP socket (SO_ZEROCOPY) + UringWorker background consumer
    // ---------------------------------------------------------------
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { std::perror("socket"); return 1; }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)) < 0)
        std::cerr << "[Main] SO_ZEROCOPY not supported, continuing without\n";

    struct sockaddr_in dest{};
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(9999);
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    UringWorker uring(fd, dest);
    uring.start_loop(&queue);
    std::cout << "[Uring] Background consumer thread started.\n\n";

    // ---------------------------------------------------------------
    // 3. Allocate two page-aligned 4KB blocks
    // ---------------------------------------------------------------
    void* ptr_a = nullptr;
    void* ptr_b = nullptr;
    if (posix_memalign(&ptr_a, kPageSize, kBlockSize) != 0 ||
        posix_memalign(&ptr_b, kPageSize, kBlockSize) != 0) {
        std::cerr << "[Main] posix_memalign failed\n";
        return 1;
    }

    std::memset(ptr_a, 0x00, kBlockSize);
    std::srand(42);
    auto* bytes_b = static_cast<uint8_t*>(ptr_b);
    for (size_t i = 0; i < kBlockSize; ++i)
        bytes_b[i] = static_cast<uint8_t>(std::rand() & 0xFF);

    // Stable iovec storage -- lives for the entire main() scope
    static struct iovec iovs[2];
    iovs[0] = { .iov_base = ptr_a, .iov_len = kBlockSize };
    iovs[1] = { .iov_base = ptr_b, .iov_len = kBlockSize };

    // Heap-allocate descriptors -- the SAME pointer goes into queue AND
    // is retained here for the ACK simulation. No copies anywhere.
    auto* desc_a = new IovecDescriptor(&iovs[0], 1);
    auto* desc_b = new IovecDescriptor(&iovs[1], 1);

    std::cout << "[Main] Chunk A (low-entropy 0x00): "
              << kBlockSize << " bytes @ " << static_cast<void*>(desc_a)
              << ", ref_count=" << desc_a->ref_count.load() << "\n";
    std::cout << "[Main] Chunk B (high-entropy rand): "
              << kBlockSize << " bytes @ " << static_cast<void*>(desc_b)
              << ", ref_count=" << desc_b->ref_count.load() << "\n\n";

    // ---------------------------------------------------------------
    // 4. Probe + QUIC encap: Chunk A (低熵)
    // ---------------------------------------------------------------
    std::cout << "--- Chunk A Pipeline (Low Entropy) ---\n";
    {
        // Probe uses a temporary wrapper for read-only inspection
        IovecDescriptor probe_view(&iovs[0], 1);
        ChunkResult cr = probe.process_payload(probe_view);
        if (cr.is_bypassed) {
            std::cout << "[Probe] Chunk A: BYPASS (high entropy)\n";
        } else {
            std::cout << "[Probe] Chunk A: FastCDC activated, "
                      << cr.chunks.size() << " chunk(s)\n";
            for (size_t i = 0; i < cr.chunks.size(); ++i)
                std::cout << "[Probe]   sub-chunk[" << i << "]: "
                          << cr.chunks[i].iov_len << " bytes\n";
        }

        uint8_t pkt_buf[8192]{};
        size_t pkt_len = 0;
        quic_engine.process_payload(desc_a, pkt_buf, sizeof(pkt_buf), pkt_len);
        std::cout << "[QUIC] Chunk A: null-cipher packet " << pkt_len
                  << " bytes (hdr=0x"
                  << std::hex << static_cast<int>(pkt_buf[0]) << std::dec
                  << "), ref_count=" << desc_a->ref_count.load() << "\n";
    }

    std::cout << "[MPSC] Pushing Chunk A @ " << static_cast<void*>(desc_a)
              << ", ref_count=" << desc_a->ref_count.load() << "\n\n";
    while (!queue.push(desc_a)) {}

    // ---------------------------------------------------------------
    // 5. Probe + QUIC encap: Chunk B (高熵)
    // ---------------------------------------------------------------
    std::cout << "--- Chunk B Pipeline (High Entropy) ---\n";
    {
        IovecDescriptor probe_view(&iovs[1], 1);
        ChunkResult cr = probe.process_payload(probe_view);
        if (cr.is_bypassed) {
            std::cout << "[Probe] Chunk B: BYPASS -- zero-copy path preserved\n";
        } else {
            std::cout << "[Probe] Chunk B: FastCDC activated, "
                      << cr.chunks.size() << " chunk(s)\n";
        }

        uint8_t pkt_buf[8192]{};
        size_t pkt_len = 0;
        quic_engine.process_payload(desc_b, pkt_buf, sizeof(pkt_buf), pkt_len);
        std::cout << "[QUIC] Chunk B: null-cipher packet " << pkt_len
                  << " bytes (hdr=0x"
                  << std::hex << static_cast<int>(pkt_buf[0]) << std::dec
                  << "), ref_count=" << desc_b->ref_count.load() << "\n";
    }

    std::cout << "[MPSC] Pushing Chunk B @ " << static_cast<void*>(desc_b)
              << ", ref_count=" << desc_b->ref_count.load() << "\n\n";
    while (!queue.push(desc_b)) {}

    // ---------------------------------------------------------------
    // 6. Wait for io_uring CQE reaping (DMA side)
    // ---------------------------------------------------------------
    std::cout << "[Main] All descriptors enqueued. Sleeping 2s for async I/O...\n";
    std::cout.flush();
    sleep(2);

    // ---------------------------------------------------------------
    // 7. Simulate remote ACK arrival (QUIC-ACK side)
    //    Same pointer as pushed into queue -- shared ref_count.
    // ---------------------------------------------------------------
    std::cout << "\n--- Remote ACK Simulation ---\n";
    {
        int prev = desc_a->ref_count.fetch_sub(1, std::memory_order_acq_rel);
        std::cout << "[QUIC-ACK] Chunk A @ " << static_cast<void*>(desc_a)
                  << ": remote ACK arrived, ref_count "
                  << prev << " -> " << prev - 1 << "\n";
        if (prev == 1) {
            std::cout << "[Memory] Chunk A ref_count=0, safe to release\n";
            delete desc_a;
            desc_a = nullptr;
        }
    }
    {
        int prev = desc_b->ref_count.fetch_sub(1, std::memory_order_acq_rel);
        std::cout << "[QUIC-ACK] Chunk B @ " << static_cast<void*>(desc_b)
                  << ": remote ACK arrived, ref_count "
                  << prev << " -> " << prev - 1 << "\n";
        if (prev == 1) {
            std::cout << "[Memory] Chunk B ref_count=0, safe to release\n";
            delete desc_b;
            desc_b = nullptr;
        }
    }
    std::cout << "\n";

    // ---------------------------------------------------------------
    // 8. Shutdown + final audit
    // ---------------------------------------------------------------
    std::cout << "[Main] Requesting UringWorker stop...\n";
    uring.request_stop();

    std::cout << "[Main] Final ref_count audit:\n";
    if (desc_a)
        std::cout << "[Main]   desc_a.ref_count = " << desc_a->ref_count.load() << "\n";
    else
        std::cout << "[Main]   desc_a: RELEASED (ref_count reached 0)\n";
    if (desc_b)
        std::cout << "[Main]   desc_b.ref_count = " << desc_b->ref_count.load() << "\n";
    else
        std::cout << "[Main]   desc_b: RELEASED (ref_count reached 0)\n";

    close(fd);
    free(ptr_a);
    free(ptr_b);

    std::cout << "\n[Main] Page-aligned memory freed. Pipeline shutdown complete.\n";
    std::cout << "========================================\n";
    return 0;
}
