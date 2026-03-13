#pragma once
// ============================================================
// null_cipher.h — 密码学短接 (Null Cipher)
//
// 目标: 拔除 AES-GCM，释放 CPU 算力。
// 策略: 提供 dummy AEAD encrypt/decrypt，内部仅做指针透传，
//       零 crypto 运算。注册进 picoquic connection 上下文，
//       替换其默认密码学回调。
// ============================================================

#include <cstddef>
#include <cstdint>
#include <cstring>

// picoquic C 头 (extern "C" 包裹)
extern "C" {
#include <picoquic.h>
#include <picoquic_internal.h>
}

namespace null_cipher {

// ---- AEAD 占位上下文 (无实际密钥材料) ----
struct NullAeadCtx {
    uint8_t dummy;   // 非空，仅防 nullptr 判定为未初始化
};

// ============================================================
// dummy_aead_encrypt
//   净荷保持明文; 仅填充全零假 tag。
//   input  → output 零拷贝 (若 in-place) 或 memcpy。
//   返回 plaintext_len + tag_len。
// ============================================================
inline size_t dummy_aead_encrypt(
    void*          aead_ctx,          // NullAeadCtx*, 不使用
    uint8_t*       output,            // 密文输出缓冲区
    size_t         output_max,
    const uint8_t* plaintext,
    size_t         plaintext_len,
    const uint8_t* aad,               // 附加认证数据, 不使用
    size_t         aad_len,
    const uint8_t* nonce,             // 不使用
    size_t         nonce_len)
{
    constexpr size_t kTagLen = 16;    // AEAD tag 长度 (QUIC 标准)
    if (output_max < plaintext_len + kTagLen)
        return 0;   // 缓冲区不足

    // 净荷透传 (in-place 时 output == plaintext, memcpy UB → memmove)
    if (output != plaintext)
        std::memmove(output, plaintext, plaintext_len);

    // 全零假 tag，保持包格式合法
    std::memset(output + plaintext_len, 0, kTagLen);
    return plaintext_len + kTagLen;
}

// ============================================================
// dummy_aead_decrypt
//   跳过认证校验; 直接剥除 tag，返回明文长度。
// ============================================================
inline size_t dummy_aead_decrypt(
    void*          aead_ctx,
    uint8_t*       output,
    size_t         output_max,
    const uint8_t* ciphertext,
    size_t         ciphertext_len,
    const uint8_t* aad,
    size_t         aad_len,
    const uint8_t* nonce,
    size_t         nonce_len)
{
    constexpr size_t kTagLen = 16;
    if (ciphertext_len < kTagLen)
        return 0;

    size_t plaintext_len = ciphertext_len - kTagLen;
    if (output_max < plaintext_len)
        return 0;

    if (output != ciphertext)
        std::memmove(output, ciphertext, plaintext_len);

    // 不做 tag 校验 — 明文模式
    return plaintext_len;
}

// ============================================================
// dummy_hp_mask — Header Protection 掩码: 全零 (不加扰)
// ============================================================
inline void dummy_hp_mask(
    void*          hp_ctx,
    uint8_t*       mask,        // 输出 5 字节掩码
    const uint8_t* sample)      // 采样密文, 不使用
{
    std::memset(mask, 0, 5);
}

// ============================================================
// inject_null_cipher
//   将 dummy AEAD/HP 注册到指定 picoquic_cnx_t 的所有加密级别。
//   调用时机: connection 创建后、首包发出前。
//
//   picoquic 内部通过 picoquic_setup_1rtt_aead / picoquic_set_key
//   等函数设置加密回调。此处直接操作 cnx 内部的 crypto context，
//   用 Null Cipher 替换真实 AEAD。
//
//   注意: 这是论文原型专用的魔改路径，不得用于生产环境。
// ============================================================
inline void inject_null_cipher(picoquic_cnx_t* cnx) {
    if (!cnx) return;

    // 静态 NullAeadCtx 实例 (无状态，可全局复用)
    static NullAeadCtx null_ctx{0x01};

    // picoquic 每个 connection 维护多个 epoch 的加密上下文:
    //   0 = Initial, 1 = 0-RTT, 2 = Handshake, 3 = 1-RTT
    // 逐级短接:
    for (int epoch = 0; epoch < 4; ++epoch) {
        // ---- 发送方向 ----
        picoquic_crypto_context_t* send_ctx =
            &cnx->crypto_context[epoch];
        send_ctx->aead_encrypt     = reinterpret_cast<void*>(&null_ctx);
        send_ctx->aead_decrypt     = reinterpret_cast<void*>(&null_ctx);
        // 实际的函数指针挂载取决于 picoquic 版本的结构体布局。
        // 以下为适配层: 在 picoquic 调用加密时, 通过下方的
        // shim 函数转发到 dummy_aead_encrypt/decrypt。
        // 具体 hook 点见 custom_quic_engine.cpp 中的
        // patch_crypto_callbacks()。
    }
}

} // namespace null_cipher
