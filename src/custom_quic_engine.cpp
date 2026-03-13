// ============================================================
// custom_quic_engine.cpp — Module C 核心实现
//
// 两处魔改要害:
//   1. patch_crypto_callbacks() — Null Cipher 注入
//   2. patch_connection()       — TC-SACK CC VTable 挂载
// ============================================================

#include "custom_quic_engine.h"
#include "null_cipher.h"
#include "congestion_control.h"
#include "ctrl_mem_pool.h"
#include "iovec_descriptor.h"

extern "C" {
#include <picoquic.h>
#include <picoquic_internal.h>
}

#include <cstring>
#include <cstdio>

// ---- 控制面内存池参数 ----
static constexpr std::size_t kCtrlBlockSize  = 256;   // 足够容纳 QUIC 头部 + 控制帧
static constexpr std::size_t kCtrlPoolCount  = 4096;  // 预分配 4096 块

// ==================== 构造 / 析构 ============================

CustomQuicEngine::CustomQuicEngine()
    : ctrl_pool_(new CtrlMemPool(kCtrlBlockSize, kCtrlPoolCount))
{}

CustomQuicEngine::~CustomQuicEngine() {
    delete ctrl_pool_;
}

// ==================== init ===================================

int CustomQuicEngine::init(picoquic_quic_t* quic_ctx) {
    if (!quic_ctx) return -1;
    quic_ctx_ = quic_ctx;

    // ---- 魔改 1: 全局注册 TC-SACK 拥塞控制算法 ----
    // 不修改 picoquic C 源码; 仅通过 API 设置外部算法。
    picoquic_set_default_congestion_algorithm(
        quic_ctx_, cc_adapter::get_tcsack_algorithm());

    return 0;
}

// ==================== patch_connection =======================
// 在新 connection 建立后调用, 完成:
//   A) Null Cipher 注入 (加密降级)
//   B) TC-SACK CC 挂载 (已由 init 设置全局默认, 此处为 per-cnx 覆盖)

int CustomQuicEngine::patch_connection(picoquic_cnx_t* cnx) {
    if (!cnx) return -1;

    // ---- A: 密码学短接 ----
    patch_crypto_callbacks(cnx);

    // ---- B: 拥塞控制 per-cnx 覆盖 (可选, 全局已设置) ----
    // 若需要为某些连接使用不同 CC, 可在此处覆盖:
    // picoquic_set_congestion_algorithm(cnx, cc_adapter::get_tcsack_algorithm());
    // 当前方案已通过 init() 全局设置, 无需重复。

    return 0;
}

// ==================== 密码学短接 — 核心魔改 ===================
//
// picoquic 对每个 connection 维护 4 个 epoch 的 crypto_context:
//   epoch 0: Initial    (QUIC Initial 包)
//   epoch 1: 0-RTT      (0-RTT 数据)
//   epoch 2: Handshake  (握手)
//   epoch 3: 1-RTT      (应用数据)
//
// 每个 picoquic_crypto_context_t 包含:
//   - aead_encrypt / aead_decrypt  (void*, 实际是 AEAD 上下文指针)
//   - pn_enc / pn_dec              (void*, Header Protection 上下文)
//
// picoquic 内部通过 picoquic_aead_encrypt_generic() 等函数
// 间接调用 ptls 的 AEAD。我们的策略:
//
// 方案 A (首选 — ABI 级替换):
//   直接替换 ptls_aead_context_t 内部的 do_encrypt 函数指针。
//   这是最彻底的短接, 零函数调用开销。
//
// 方案 B (保守 — picotls shim):
//   构造 dummy ptls_aead_context_t, 其 do_encrypt/do_decrypt
//   指向 null_cipher::dummy_aead_encrypt/decrypt。
//
// 此处实现方案 B, 兼容性更强。
// ============================================================

// ---- dummy ptls cipher context (全局静态, 无状态可复用) ----
namespace {

// ptls AEAD 加密 shim: 透传明文 + 填零 tag
size_t shim_aead_do_encrypt(
    struct st_ptls_aead_context_t* ctx,
    void*       output,
    const void* input,
    size_t      inlen,
    uint64_t    seq,
    const void* aad,
    size_t      aadlen)
{
    return null_cipher::dummy_aead_encrypt(
        nullptr,
        static_cast<uint8_t*>(output), inlen + 16,
        static_cast<const uint8_t*>(input), inlen,
        static_cast<const uint8_t*>(aad), aadlen,
        nullptr, 0);
}

// ptls AEAD 解密 shim: 剥除 tag, 不校验
size_t shim_aead_do_decrypt(
    struct st_ptls_aead_context_t* ctx,
    void*       output,
    const void* input,
    size_t      inlen,
    uint64_t    seq,
    const void* aad,
    size_t      aadlen)
{
    return null_cipher::dummy_aead_decrypt(
        nullptr,
        static_cast<uint8_t*>(output), inlen,
        static_cast<const uint8_t*>(input), inlen,
        static_cast<const uint8_t*>(aad), aadlen,
        nullptr, 0);
}

} // anonymous namespace

void CustomQuicEngine::patch_crypto_callbacks(picoquic_cnx_t* cnx) {
    // 遍历 4 个 epoch, 替换加解密上下文的函数指针
    for (int epoch = 0; epoch < 4; ++epoch) {
        picoquic_crypto_context_t* ctx = &cnx->crypto_context[epoch];

        // ---- AEAD encrypt 方向 ----
        // picoquic 存储 ptls_aead_context_t* 在 aead_encrypt 字段。
        // 若尚未初始化 (握手未到该 epoch), 跳过; 后续由
        // TLS 回调触发时再 patch。
        auto* enc = static_cast<ptls_aead_context_t*>(ctx->aead_encrypt);
        if (enc) {
            // 替换函数指针 — ABI 级短接
            enc->do_encrypt = shim_aead_do_encrypt;
        }

        // ---- AEAD decrypt 方向 ----
        auto* dec = static_cast<ptls_aead_context_t*>(ctx->aead_decrypt);
        if (dec) {
            dec->do_decrypt = shim_aead_do_decrypt;
        }

        // ---- Header Protection ----
        // HP 掩码置零 = 不加扰包号
        // TODO: 类似替换 pn_enc->do_mask 函数指针
        // 目前 picoquic 的 HP 开销极低, 暂不短接。
    }
}

// ==================== prepare_packet =========================
// 将 IovecDescriptor 的净荷喂入协议栈, 组装 QUIC 包。
//
// 内存隔离:
//   - 头部 / 控制帧 → CtrlMemPool 分配 (控制面)
//   - 净荷数据      → desc->iov (数据面, 零拷贝)
//
// 在真实集成时, 此函数对接 picoquic_prepare_packet_ex(),
// 将 stream data 指向 desc->iov 而非从内部缓冲区拷贝。
// ============================================================

int CustomQuicEngine::prepare_packet(
    picoquic_cnx_t*  cnx,
    IovecDescriptor* desc,
    uint8_t*         send_buffer,
    size_t           send_buffer_max,
    size_t*          send_length)
{
    if (!cnx || !desc || !send_buffer) return -1;

    // ---- 从 CtrlMemPool 分配头部区域 ----
    void* hdr_block = ctrl_pool_->alloc();
    if (!hdr_block) return -1;   // 控制面内存耗尽

    // ---- 填充 QUIC 包头 (简化原型) ----
    // 实际应调用 picoquic_prepare_packet_ex(),
    // 此处仅演示内存隔离策略。
    uint8_t* hdr = static_cast<uint8_t*>(hdr_block);
    constexpr size_t kHdrLen = 22;   // Short Header 典型长度

    // 头部占位填充 (实际由 picoquic 生成)
    std::memset(hdr, 0, kHdrLen);
    hdr[0] = 0x40;   // Short Header 固定位

    // ---- 组装发送缓冲区: [header | payload(零拷贝)] ----
    size_t payload_total = 0;
    for (int i = 0; i < desc->iovcnt; ++i)
        payload_total += desc->iov[i].iov_len;

    if (kHdrLen + payload_total > send_buffer_max) {
        ctrl_pool_->dealloc(hdr_block);
        return -1;   // 超出 MTU
    }

    // 拷贝头部 (控制面, 仅 ~22 字节)
    std::memcpy(send_buffer, hdr, kHdrLen);

    // 净荷零拷贝: 直接将 iov 指针拼入发送缓冲区视图
    // 在真实 io_uring sendmsg 路径中, 使用 iovec scatter-gather,
    // 此处为 demo 演示拷贝语义 (线性化到 send_buffer)。
    size_t offset = kHdrLen;
    for (int i = 0; i < desc->iovcnt; ++i) {
        std::memcpy(send_buffer + offset,
                    desc->iov[i].iov_base,
                    desc->iov[i].iov_len);
        offset += desc->iov[i].iov_len;
    }

    *send_length = offset;

    // 归还头部内存块
    ctrl_pool_->dealloc(hdr_block);
    return 0;
}
