#include "custom_quic_engine.h"
#include <cassert>
#include <cstdio>
#include <cstring>

int main()
{
    // --- Test 1: TcSackCC via C bridge ---
    tcsack_cc_init(nullptr, nullptr, nullptr, 0);

    picoquic_per_ack_state_t ack{};
    ack.nb_bytes_acknowledged = 1460;
    tcsack_cc_notify(nullptr, nullptr,
                     picoquic_congestion_notification_acknowledgement,
                     &ack, 100);

    uint64_t state = 0, param = 0;
    tcsack_cc_observe(nullptr, &state, &param);
    std::printf("CC state: cwin=%lu ssthresh=%lu\n", state, param);
    assert(state > 0);

    tcsack_cc_delete(nullptr);
    std::printf("PASS: TcSackCC C bridge\n");

    // --- Test 2: NullAead encrypt/decrypt round-trip ---
    uint8_t plain[] = "Hello QUIC zero-copy";
    uint8_t cipher[128]{};
    size_t enc_len = NullAead::encrypt(nullptr, plain, sizeof(plain),
                                       cipher, sizeof(cipher));
    assert(enc_len == sizeof(plain) + NullAead::kTagLen);

    uint8_t recovered[128]{};
    size_t dec_len = NullAead::decrypt(nullptr, cipher, enc_len,
                                       recovered, sizeof(recovered));
    assert(dec_len == sizeof(plain));
    assert(std::memcmp(plain, recovered, sizeof(plain)) == 0);
    std::printf("PASS: NullAead round-trip\n");

    // --- Test 3: process_payload packet construction ---
    char payload[] = "bulk-transfer-data";
    struct iovec v{ .iov_base = payload, .iov_len = sizeof(payload) };
    IovecDescriptor desc(&v, 1);

    uint8_t pkt[256]{};
    size_t pkt_len = 0;

    CustomQuicEngine engine;
    engine.inject_null_cipher();
    engine.install_tcsack_cc();
    engine.process_payload(&desc, pkt, sizeof(pkt), pkt_len);

    // header: 1 (flags) + 8 (DCID) + 2 (pktnum) = 11
    // payload: sizeof(payload) = 19
    // tag: 16
    size_t expected = 11 + sizeof(payload) + NullAead::kTagLen;
    std::printf("pkt_len=%zu expected=%zu\n", pkt_len, expected);
    assert(pkt_len == expected);
    assert(pkt[0] == 0x41);
    assert(pkt[1] == 0xDE);

    // payload starts at offset 11
    assert(std::memcmp(pkt + 11, payload, sizeof(payload)) == 0);
    std::printf("PASS: process_payload\n");

    std::printf("ALL TESTS PASSED\n");
    return 0;
}
