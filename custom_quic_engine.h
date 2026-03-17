#pragma once

#include "mpsc_ring_buffer.h"
#include <picoquic.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <sys/uio.h>

// ===================================================================
// Null Cipher AEAD stubs -- bypass AES-GCM on the data path
// ===================================================================

struct NullAead {
    static constexpr size_t kTagLen = 16;

    static size_t encrypt(void*, const uint8_t* input, size_t input_len,
                          uint8_t* output, size_t /*output_max*/) {
        std::memcpy(output, input, input_len);
        std::memset(output + input_len, 0, kTagLen);
        return input_len + kTagLen;
    }

    static size_t decrypt(void*, const uint8_t* input, size_t input_len,
                          uint8_t* output, size_t /*output_max*/) {
        if (input_len < kTagLen) return 0;
        size_t plain_len = input_len - kTagLen;
        std::memcpy(output, input, plain_len);
        return plain_len;
    }
};

// ===================================================================
// Congestion Controller -- C++ VTable bridged to picoquic C callbacks
// ===================================================================

class CongestionControllerBase {
public:
    virtual ~CongestionControllerBase() = default;

    virtual void on_init(picoquic_cnx_t* cnx, picoquic_path_t* path,
                         const char* options, uint64_t now) = 0;

    virtual void on_notify(picoquic_cnx_t* cnx, picoquic_path_t* path,
                           picoquic_congestion_notification_t event,
                           picoquic_per_ack_state_t* ack_state,
                           uint64_t now) = 0;

    virtual void on_delete(picoquic_path_t* path) = 0;

    virtual void on_observe(picoquic_path_t* path,
                            uint64_t* cc_state, uint64_t* cc_param) = 0;
};

// --- TC-SACK inspired congestion controller ---

class TcSackCC final : public CongestionControllerBase {
public:
    static constexpr uint64_t kInitialCwin = 32 * 1460;
    static constexpr uint64_t kMinCwin     = 4 * 1460;

    void on_init(picoquic_cnx_t*, picoquic_path_t*,
                 const char*, uint64_t) override;

    void on_notify(picoquic_cnx_t*, picoquic_path_t*,
                   picoquic_congestion_notification_t,
                   picoquic_per_ack_state_t*, uint64_t) override;

    void on_delete(picoquic_path_t*) override;

    void on_observe(picoquic_path_t*,
                    uint64_t* cc_state, uint64_t* cc_param) override;

private:
    uint64_t cwin_     = kInitialCwin;
    uint64_t ssthresh_ = UINT64_MAX;
    bool     in_slow_start_ = true;
};

// --- C bridge: extern "C" trampolines ---

extern "C" {
void tcsack_cc_init(picoquic_cnx_t* cnx, picoquic_path_t* path,
                    char const* opts, uint64_t now);
void tcsack_cc_notify(picoquic_cnx_t* cnx, picoquic_path_t* path,
                      picoquic_congestion_notification_t n,
                      picoquic_per_ack_state_t* ack, uint64_t now);
void tcsack_cc_delete(picoquic_path_t* path);
void tcsack_cc_observe(picoquic_path_t* path,
                       uint64_t* cc_state, uint64_t* cc_param);
}

picoquic_congestion_algorithm_t* get_tcsack_algorithm();

// ===================================================================
// CustomQuicEngine -- top-level facade
// ===================================================================

class CustomQuicEngine {
public:
    static constexpr size_t kRingCapacity = 8192;
    using Queue = MpscRingBuffer<kRingCapacity>;

    CustomQuicEngine();
    ~CustomQuicEngine();

    CustomQuicEngine(const CustomQuicEngine&) = delete;
    CustomQuicEngine& operator=(const CustomQuicEngine&) = delete;

    void inject_null_cipher();
    void install_tcsack_cc();
    void process_payload(IovecDescriptor* desc, uint8_t* packet_buf,
                         size_t buf_capacity, size_t& out_len);

    picoquic_quic_t* quic_ctx() noexcept { return quic_; }

private:
    picoquic_quic_t* quic_ = nullptr;

    static int stream_data_cb(picoquic_cnx_t*, uint64_t, uint8_t*, size_t,
                              picoquic_call_back_event_t, void*, void*);
};
