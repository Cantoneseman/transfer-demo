// ============================================================
// xio_driver.cpp — Globus XIO 底层传输驱动替代方案 (Module A)
//
// 对外暴露 4 个 extern "C" 标准钩子：
//   open / close / read / write
//
// write 路径：零拷贝封装 IovecDescriptor → push 到无锁 MPSC 队列 → 立即返回。
// 消费者（Module B，后续实现）从队列 pop 后调度 QUIC 发送。
// ============================================================

#include "iovec_descriptor.h"
#include "mpsc_ring_buffer.h"

#include <sys/uio.h>
#include <cerrno>
#include <cstddef>
#include <new>

// ==================== 框架类型占位 ==========================
// 实际项目中由 <globus_xio.h> 提供；此处仅做最小声明以通过编译。
using globus_xio_handle_t    = void*;
using globus_xio_attr_t      = void*;
using globus_xio_contact_t   = void*;
using globus_xio_operation_t = void*;
using globus_result_t        = int;

static constexpr globus_result_t GLOBUS_SUCCESS = 0;
static constexpr globus_result_t GLOBUS_FAILURE = -1;

// ==================== 每连接驱动上下文 ======================
struct DriverContext {
    MpscRingBuffer queue;

    explicit DriverContext(std::size_t cap) : queue(cap) {}
};

// 默认队列容量 (2^14 = 16384 个描述符槽位)
static constexpr std::size_t kDefaultQueueCapacity = 1u << 14;

// ==================== extern "C" 钩子 =======================
extern "C" {

// ----------------------------------------------------------
// open: 建立连接时由框架调用，初始化驱动上下文与无锁队列。
// ----------------------------------------------------------
globus_result_t
globus_xio_driver_open(globus_xio_handle_t     handle,
                       globus_xio_attr_t       attr,
                       globus_xio_contact_t    contact_info)
{
    auto* ctx = new (std::nothrow) DriverContext(kDefaultQueueCapacity);
    if (!ctx)
        return GLOBUS_FAILURE;

    // TODO: 将 ctx 关联到 handle（具体 API 取决于 Globus XIO 框架）
    // globus_xio_driver_handle_set_context(handle, ctx);
    (void)handle;
    (void)attr;
    (void)contact_info;
    return GLOBUS_SUCCESS;
}

// ----------------------------------------------------------
// close: 连接关闭时释放驱动上下文。
// ----------------------------------------------------------
globus_result_t
globus_xio_driver_close(globus_xio_handle_t handle)
{
    // TODO: auto* ctx = static_cast<DriverContext*>(
    //           globus_xio_driver_handle_get_context(handle));
    // delete ctx;
    (void)handle;
    return GLOBUS_SUCCESS;
}

// ----------------------------------------------------------
// read: Module A 不处理读路径（由 Module B 反向投递），预留桩。
// ----------------------------------------------------------
globus_result_t
globus_xio_driver_read(globus_xio_handle_t     handle,
                       struct iovec*            iov,
                       int                      iovcnt,
                       globus_xio_operation_t   op)
{
    (void)handle;
    (void)iov;
    (void)iovcnt;
    (void)op;
    return GLOBUS_FAILURE;   // -ENOSYS 语义
}

// ----------------------------------------------------------
// write: 数据面快路径 —— 零拷贝入队，立即返回。
//
//   1. 将调用方传入的 iovec 封装为 IovecDescriptor（仅存指针，不拷贝）。
//   2. push 进 MPSC 无锁队列。
//   3. 立即向上层返回成功；网络 I/O 由消费者线程异步完成。
//   4. 若队列满，返回背压错误，上层应重试或降速。
// ----------------------------------------------------------
globus_result_t
globus_xio_driver_write(globus_xio_handle_t     handle,
                        struct iovec*            iov,
                        int                      iovcnt,
                        globus_xio_operation_t   op)
{
    (void)op;

    // TODO: auto* ctx = static_cast<DriverContext*>(
    //           globus_xio_driver_handle_get_context(handle));
    // 临时简化：使用 thread_local 静态上下文演示流程
    static thread_local DriverContext demo_ctx(kDefaultQueueCapacity);
    DriverContext* ctx = &demo_ctx;
    (void)handle;

    if (!iov || iovcnt <= 0)
        return GLOBUS_FAILURE;

    // ---- 封装零拷贝描述符 ----
    auto* desc = new (std::nothrow) IovecDescriptor(iov, iovcnt);
    if (!desc)
        return GLOBUS_FAILURE;

    // ---- 压入无锁队列 ----
    if (!ctx->queue.push(desc)) {
        // 队列满：释放描述符，向上层返回背压信号
        delete desc;
        return GLOBUS_FAILURE;
    }

    // 成功入队，不等待网络 I/O
    return GLOBUS_SUCCESS;
}

} // extern "C"
