#pragma once
// ============================================================
// congestion_control.h — 拥塞控制 VTable 挂载层
//
// 核心约束: 绝不修改 picoquic 拥塞控制 C 源码。
// 策略:
//   1. 定义 C++ 虚基类 CongestionControllerBase。
//   2. TcSackCC 继承实现 on_ack / on_loss / pacing_rate。
//   3. 静态适配器将 picoquic_congestion_algorithm_t 的
//      C 函数指针重定向到 C++ VTable 虚函数调用。
// ============================================================

#include <cstdint>
#include <cstddef>
#include <algorithm>

// picoquic C 头
extern "C" {
#include <picoquic.h>
#include <picoquic_internal.h>
}

// ============================================================
// CongestionControllerBase — C++ 拥塞控制虚基类
// ============================================================
class CongestionControllerBase {
public:
    virtual ~CongestionControllerBase() = default;

    // ACK 到达时回调
    //   nb_bytes_acked: 本次确认的字节数
    //   rtt_us:         本次 RTT 采样 (微秒)
    //   cwnd:           当前拥塞窗口 (字节)，可修改
    virtual void on_ack(uint64_t nb_bytes_acked,
                        uint64_t rtt_us,
                        uint64_t* cwnd) = 0;

    // 丢包检测时回调
    //   nb_bytes_lost:  本次丢失的字节数
    //   cwnd:           当前拥塞窗口，可修改
    virtual void on_loss(uint64_t nb_bytes_lost,
                         uint64_t* cwnd) = 0;

    // 返回当前发送 pacing rate (bytes/sec)
    virtual uint64_t pacing_rate() const = 0;
};

// ============================================================
// TcSackCC — TC-SACK 拥塞控制实现 (浅层挂载)
//
// 算法概要 (简化原型):
//   - 慢启动: cwnd 每 RTT 翻倍，直至 ssthresh。
//   - 拥塞避免: cwnd 每 RTT 线性 +1 MSS。
//   - SACK 感知丢包: cwnd 乘法减 (β=0.7)，比 Reno 更温和。
//   - pacing = cwnd / srtt。
// ============================================================
class TcSackCC final : public CongestionControllerBase {
public:
    static constexpr uint64_t kDefaultMSS     = 1200;   // QUIC 默认 MSS
    static constexpr uint64_t kInitCwnd        = 10 * kDefaultMSS;
    static constexpr uint64_t kMinCwnd         = 2 * kDefaultMSS;
    static constexpr double   kBeta            = 0.7;    // 乘法减因子

    TcSackCC() = default;

    void on_ack(uint64_t nb_bytes_acked,
                uint64_t rtt_us,
                uint64_t* cwnd) override
    {
        // 更新 SRTT (EWMA, α=1/8)
        if (srtt_us_ == 0)
            srtt_us_ = rtt_us;
        else
            srtt_us_ = srtt_us_ - (srtt_us_ >> 3) + (rtt_us >> 3);

        if (*cwnd < ssthresh_) {
            // 慢启动: cwnd += acked
            *cwnd += nb_bytes_acked;
        } else {
            // 拥塞避免: cwnd += MSS * acked / cwnd (线性增)
            *cwnd += kDefaultMSS * nb_bytes_acked / (*cwnd ? *cwnd : 1);
        }
    }

    void on_loss(uint64_t nb_bytes_lost, uint64_t* cwnd) override {
        // SACK 感知: 乘法减 β=0.7
        ssthresh_ = static_cast<uint64_t>(
            static_cast<double>(*cwnd) * kBeta);
        ssthresh_ = std::max(ssthresh_, kMinCwnd);
        *cwnd     = ssthresh_;
    }

    uint64_t pacing_rate() const override {
        // pacing = cwnd / srtt (bytes/sec)
        if (srtt_us_ == 0)
            return 0;   // SRTT 未初始化，由上层使用默认值
        return cwnd_snapshot_ * 1'000'000ULL / srtt_us_;
    }

    // 外部可通过此函数同步最新 cwnd 快照（用于 pacing 计算）
    void update_cwnd_snapshot(uint64_t cwnd) noexcept {
        cwnd_snapshot_ = cwnd;
    }

private:
    uint64_t ssthresh_      = UINT64_MAX;      // 初始无上限
    uint64_t srtt_us_       = 0;               // 平滑 RTT (微秒)
    uint64_t cwnd_snapshot_ = kInitCwnd;       // pacing 用 cwnd 快照
};

// ============================================================
// 静态适配器 — C 函数指针 → C++ VTable 桥接
//
// picoquic_congestion_algorithm_t 中的函数签名 (简化):
//   notify: void (*)(path_t*, notification, rtt_us, nb_bytes, lost, ...)
// 适配器从 path->congestion_alg_state 取回 TcSackCC*。
// ============================================================
namespace cc_adapter {

// ---- 从 picoquic 路径上下文取回 C++ 对象 ----
inline TcSackCC* get_cc(picoquic_path_t* path) {
    return static_cast<TcSackCC*>(path->congestion_alg_state);
}

// ---- init: 将 TcSackCC 实例挂载到 path ----
inline void cc_init(picoquic_path_t* path, uint64_t current_time) {
    auto* cc = new TcSackCC();
    path->congestion_alg_state = cc;
    path->cwin = TcSackCC::kInitCwnd;
}

// ---- release: 释放 TcSackCC 实例 ----
inline void cc_release(picoquic_path_t* path) {
    auto* cc = get_cc(path);
    delete cc;
    path->congestion_alg_state = nullptr;
}

// ---- notify: picoquic 事件分发入口 ----
// picoquic 在 ACK / 丢包 / 拥塞事件时调用此函数。
// 我们按 notification 类型分发到 C++ 虚函数。
inline void cc_notify(
    picoquic_cnx_t*                cnx,
    picoquic_path_t*               path,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t*      ack_state,
    uint64_t                       current_time)
{
    auto* cc = get_cc(path);
    if (!cc) return;

    switch (notification) {
    case picoquic_congestion_notification_acknowledgement:
    case picoquic_congestion_notification_repeat:
    case picoquic_congestion_notification_ecn_ec: {
        uint64_t acked = (ack_state) ? ack_state->nb_bytes_acknowledged : 0;
        uint64_t rtt   = path->rtt_sample;
        cc->on_ack(acked, rtt, &path->cwin);
        cc->update_cwnd_snapshot(path->cwin);
        break;
    }
    case picoquic_congestion_notification_timeout:
    case picoquic_congestion_notification_spurious_repeat:
    case picoquic_congestion_notification_cwin_blocked: {
        uint64_t lost = (ack_state) ? ack_state->nb_bytes_lost : 0;
        cc->on_loss(lost, &path->cwin);
        cc->update_cwnd_snapshot(path->cwin);
        break;
    }
    default:
        break;
    }
}

// ---- 静态 picoquic_congestion_algorithm_t 实例 ----
// 绝不修改 picoquic 核心源码; 仅填充外部算法结构体。
inline picoquic_congestion_algorithm_t* get_tcsack_algorithm() {
    static picoquic_congestion_algorithm_t algo{};
    algo.congestion_algorithm_id       = 0xFF01;  // 自定义 ID
    algo.congestion_algorithm_name     = "tc-sack";
    algo.alg_init                      = cc_init;
    algo.alg_delete                    = cc_release;
    algo.alg_notify                    = cc_notify;
    algo.alg_observe                   = nullptr;  // 可选
    return &algo;
}

} // namespace cc_adapter
