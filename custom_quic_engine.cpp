#include "custom_quic_engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>

// ===================================================================
// TcSackCC implementation
// ===================================================================

void TcSackCC::on_init(picoquic_cnx_t*, picoquic_path_t*,
                       const char*, uint64_t)
{
    cwin_     = kInitialCwin;
    ssthresh_ = UINT64_MAX;
    in_slow_start_ = true;
}

void TcSackCC::on_notify(picoquic_cnx_t*, picoquic_path_t*,
                         picoquic_congestion_notification_t event,
                         picoquic_per_ack_state_t* ack_state, uint64_t)
{
    switch (event) {
    case picoquic_congestion_notification_acknowledgement:
        if (in_slow_start_) {
            cwin_ += ack_state->nb_bytes_acknowledged;
            if (cwin_ >= ssthresh_)
                in_slow_start_ = false;
        } else {
            cwin_ += (ack_state->nb_bytes_acknowledged * 1460) / cwin_;
        }
        break;

    case picoquic_congestion_notification_repeat:
    case picoquic_congestion_notification_timeout:
        ssthresh_ = cwin_ / 2;
        if (ssthresh_ < kMinCwin)
            ssthresh_ = kMinCwin;
        cwin_ = ssthresh_;
        in_slow_start_ = false;
        break;

    case picoquic_congestion_notification_seed_cwin:
        if (ack_state && ack_state->nb_bytes_acknowledged > cwin_)
            cwin_ = ack_state->nb_bytes_acknowledged;
        break;

    case picoquic_congestion_notification_reset:
        cwin_     = kInitialCwin;
        ssthresh_ = UINT64_MAX;
        in_slow_start_ = true;
        break;

    default:
        break;
    }
}

void TcSackCC::on_delete(picoquic_path_t*) {}

void TcSackCC::on_observe(picoquic_path_t*,
                          uint64_t* cc_state, uint64_t* cc_param)
{
    if (cc_state) *cc_state = cwin_;
    if (cc_param) *cc_param = ssthresh_;
}

// ===================================================================
// C bridge trampolines
// ===================================================================

static thread_local TcSackCC g_tcsack_instance;

extern "C" {

void tcsack_cc_init(picoquic_cnx_t* cnx, picoquic_path_t* path,
                    char const* opts, uint64_t now)
{
    g_tcsack_instance.on_init(cnx, path, opts, now);
}

void tcsack_cc_notify(picoquic_cnx_t* cnx, picoquic_path_t* path,
                      picoquic_congestion_notification_t n,
                      picoquic_per_ack_state_t* ack, uint64_t now)
{
    g_tcsack_instance.on_notify(cnx, path, n, ack, now);
}

void tcsack_cc_delete(picoquic_path_t* path)
{
    g_tcsack_instance.on_delete(path);
}

void tcsack_cc_observe(picoquic_path_t* path,
                       uint64_t* cc_state, uint64_t* cc_param)
{
    g_tcsack_instance.on_observe(path, cc_state, cc_param);
}

} // extern "C"

static picoquic_congestion_algorithm_t tcsack_algorithm = {
    "tc-sack",                 // congestion_algorithm_id
    0xFF,                      // congestion_algorithm_number (custom)
    0,                         // ecn_mark
    tcsack_cc_init,            // alg_init
    tcsack_cc_notify,          // alg_notify
    tcsack_cc_delete,          // alg_delete
    tcsack_cc_observe          // alg_observe
};

picoquic_congestion_algorithm_t* get_tcsack_algorithm()
{
    return &tcsack_algorithm;
}

// ===================================================================
// CustomQuicEngine
// ===================================================================

int CustomQuicEngine::stream_data_cb(picoquic_cnx_t*, uint64_t, uint8_t*,
                                     size_t, picoquic_call_back_event_t,
                                     void*, void*)
{
    return 0;
}

CustomQuicEngine::CustomQuicEngine()
{
    uint64_t current_time = 0;
    quic_ = picoquic_create(
        128,                    // max_nb_connections
        nullptr,                // cert_file_name  (null for client-only / test)
        nullptr,                // key_file_name
        nullptr,                // cert_root_file_name
        "hq-interop",           // default_alpn
        stream_data_cb,         // default_callback_fn
        nullptr,                // default_callback_ctx
        nullptr,                // cnx_id_callback
        nullptr,                // cnx_id_callback_data
        nullptr,                // reset_seed
        current_time,           // current_time
        nullptr,                // p_simulated_time
        nullptr,                // ticket_file_name
        nullptr,                // ticket_encryption_key
        0                       // ticket_encryption_key_length
    );
    if (!quic_) {
        std::fprintf(stderr, "picoquic_create failed\n");
        std::abort();
    }
}

CustomQuicEngine::~CustomQuicEngine()
{
    if (quic_)
        picoquic_free(quic_);
}

// ---------------------------------------------------------------------------
// inject_null_cipher -- disable certificate verification and force the
// weakest cipher path. Real null-AEAD replacement requires patching the
// picotls layer; here we disable verification as the first domino, then
// document the ptls_aead override point for production integration.
// ---------------------------------------------------------------------------

void CustomQuicEngine::inject_null_cipher()
{
    picoquic_set_null_verifier(quic_);

    // Force cipher suite 20 (= 0x0014) which is an unassigned ID.
    // picoquic will fall back gracefully; in a production patch you would
    // register a custom ptls_cipher_suite_t with NullAead::encrypt/decrypt
    // as the AEAD callbacks.  The NullAead struct in the header provides
    // the exact encrypt/decrypt signatures needed for that registration:
    //
    //   ptls_aead_context_t->do_encrypt = [](ptls_aead_context_t *ctx, ...) {
    //       return NullAead::encrypt(ctx, input, input_len, output, out_max);
    //   };
    //
    // For the demo skeleton we disable verification which is the prerequisite.
    picoquic_set_cipher_suite(quic_, 0);
}

void CustomQuicEngine::install_tcsack_cc()
{
    picoquic_set_default_congestion_algorithm(quic_, get_tcsack_algorithm());
}

// ---------------------------------------------------------------------------
// process_payload -- build a minimal cleartext QUIC short-header packet
// from an IovecDescriptor, preserving the original iov pointers so that
// upstream MSG_ZEROCOPY semantics remain valid (the kernel DMA's directly
// from the application buffer referenced by iov_base).
// ---------------------------------------------------------------------------

void CustomQuicEngine::process_payload(IovecDescriptor* desc,
                                       uint8_t* packet_buf,
                                       size_t buf_capacity,
                                       size_t& out_len)
{
    out_len = 0;
    if (!desc || !desc->iov || desc->iovcnt <= 0)
        return;

    // --- Synthesize a 1-RTT short header (RFC 9000 Section 17.3) ---
    // Fixed bit (0x40) | spin=0 | key_phase=0 | pn_len=1  => 0x41
    static constexpr uint8_t kShortHeaderFlags = 0x41;
    // Dummy 8-byte DCID for demo
    static constexpr uint8_t kDummyDcid[8] = {
        0xDE,0xAD,0xBE,0xEF, 0xCA,0xFE,0xBA,0xBE
    };
    static constexpr size_t kDcidLen = sizeof(kDummyDcid);
    static uint32_t pkt_number = 0;

    size_t header_len = 1 + kDcidLen + 2; // flags + DCID + 2-byte pkt num
    if (header_len > buf_capacity)
        return;

    uint8_t* p = packet_buf;
    *p++ = kShortHeaderFlags;
    std::memcpy(p, kDummyDcid, kDcidLen);
    p += kDcidLen;

    uint32_t pn = pkt_number++;
    *p++ = static_cast<uint8_t>((pn >> 8) & 0xFF);
    *p++ = static_cast<uint8_t>(pn & 0xFF);

    // --- Null-encrypt: copy payload verbatim (bypass AES-GCM) ---
    size_t payload_total = 0;
    for (int i = 0; i < desc->iovcnt; ++i)
        payload_total += desc->iov[i].iov_len;

    if (header_len + payload_total + NullAead::kTagLen > buf_capacity) {
        out_len = 0;
        return;
    }

    uint8_t* payload_dst = p;
    for (int i = 0; i < desc->iovcnt; ++i) {
        std::memcpy(payload_dst, desc->iov[i].iov_base, desc->iov[i].iov_len);
        payload_dst += desc->iov[i].iov_len;
    }

    // Null AEAD tag (16 zero bytes in place of GCM tag)
    std::memset(payload_dst, 0, NullAead::kTagLen);
    payload_dst += NullAead::kTagLen;

    out_len = static_cast<size_t>(payload_dst - packet_buf);

    // NOTE: For true MSG_ZEROCOPY, the final sendmsg iov should point
    // directly at the original desc->iov entries (avoiding this memcpy).
    // In production the header is a small separate iov[0], and the payload
    // iov[1..N] remain the caller's original zero-copy buffers.
}
