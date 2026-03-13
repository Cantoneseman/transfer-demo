#pragma once
// ============================================================
// custom_quic_engine.h — Module C 深水区协议魔改层 外壳
//
// 职责:
//   1. 封装 picoquic C API 为 C++ RAII 类。
//   2. init() 时注入 Null Cipher + TC-SACK 拥塞控制。
//   3. 协议栈头部/控制帧走 CtrlMemPool; 净荷走 IovecDescriptor。
// ============================================================

#include <cstdint>

// picoquic C 头
extern "C" {
#include <picoquic.h>
}

class CtrlMemPool;
struct IovecDescriptor;

class CustomQuicEngine {
public:
    CustomQuicEngine();
    ~CustomQuicEngine();

    CustomQuicEngine(const CustomQuicEngine&)            = delete;
    CustomQuicEngine& operator=(const CustomQuicEngine&) = delete;

    // 初始化: 注入 Null Cipher + TC-SACK CC
    // quic_ctx: 由外部 picoquic_create() 创建的上下文
    int init(picoquic_quic_t* quic_ctx);

    // 为指定 connection 短接加密 + 挂载 CC
    int patch_connection(picoquic_cnx_t* cnx);

    // 将 IovecDescriptor 喂入协议栈, 产出帧数据
    // header/frame 从 CtrlMemPool 分配; 净荷零拷贝指向 desc->iov
    int prepare_packet(picoquic_cnx_t* cnx,
                       IovecDescriptor* desc,
                       uint8_t* send_buffer,
                       size_t send_buffer_max,
                       size_t* send_length);

    CtrlMemPool* ctrl_pool() noexcept { return ctrl_pool_; }

private:
    // 低层: 将 dummy AEAD 函数注册到 connection 的 crypto context
    static void patch_crypto_callbacks(picoquic_cnx_t* cnx);

    picoquic_quic_t* quic_ctx_  = nullptr;
    CtrlMemPool*     ctrl_pool_ = nullptr;
};
