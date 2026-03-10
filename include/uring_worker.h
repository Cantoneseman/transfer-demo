#pragma once
// ============================================================
// UringWorker — 极限异步 I/O 底盘 (Module D)
//
// 设计要点:
//   1. 唯一 I/O 引擎: io_uring，禁止 sendmsg / epoll。
//   2. 零拷贝: MSG_ZEROCOPY + IORING_CQE_F_NOTIF 回收。
//   3. 内存生命周期铁律: ref_count 初始 2，
//      NOTIF → -1 (DMA 确认), mock_remote_ack → -1 (远端确认),
//      归零才允许释放。
//   4. NUMA 亲和: pthread_setaffinity_np 绑核。
// ============================================================

#include <liburing.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

class MpscRingBuffer;
struct IovecDescriptor;

class UringWorker {
public:
    // queue_depth: io_uring SQ/CQ 深度
    // cpu_id:      绑核目标 CPU 编号
    // fd:          已就绪的 UDP socket (外部创建, 已 setsockopt SO_ZEROCOPY)
    // ring_buf:    上游 MpscRingBuffer (Module A 的产出)
    UringWorker(unsigned queue_depth, int cpu_id, int fd, MpscRingBuffer& ring_buf);
    ~UringWorker();

    UringWorker(const UringWorker&)            = delete;
    UringWorker& operator=(const UringWorker&) = delete;

    // 启动后台绑核消费线程
    void start_loop();

    // 停止消费循环（线程安全）
    void stop() noexcept;

    // ---- Module B 尚未接入 QUIC ACK, 提供模拟远端确认 ----
    static void mock_remote_ack(IovecDescriptor* desc) noexcept;

private:
    // 从 MpscRingBuffer pop → 构建 SQE → submit
    void submit_tx(IovecDescriptor* desc);

    // 收割 CQE, 处理 NOTIF / 普通完成
    void reap_cqes();

    // 后台线程主函数
    void loop_fn();

    // 尝试释放描述符 (ref_count 归零则 delete)
    static void try_release(IovecDescriptor* desc) noexcept;

    // ---- 成员 ----
    struct io_uring          ring_{};
    int                      fd_;             // UDP socket
    int                      cpu_id_;         // 绑核目标
    unsigned                 queue_depth_;
    MpscRingBuffer&          ring_buf_;       // 上游无锁队列
    std::atomic<bool>        running_{false};
    std::thread              worker_;

    // 每次 submit_tx 需要一个 msghdr, 在栈上构造即可;
    // 目标地址由外部在 socket connect() 时绑定, 此处留占位.
    struct sockaddr_storage  dest_addr_{};
    socklen_t                dest_len_{0};
};
