# ============================================================
# CMakeLists.txt — Globus XIO QUIC 传输驱动原型系统
#
# 模块:
#   A — MpscRingBuffer 无锁队列 + XIO 钩子      (xio_driver.cpp)
#   B — FastCDC/AVX-512 探针 + LZ4 熵值探测     (data_probe_engine.cpp)
#   C — picoquic 魔改: Null Cipher + TC-SACK CC  (custom_quic_engine.cpp)
#   D — io_uring 零拷贝底盘                      (uring_worker.cpp)
#
# 产出:
#   libglobus_xio_prototype_quic.so  — 共享库
#   xio_prototype_test               — 单测可执行文件
# ============================================================

cmake_minimum_required(VERSION 3.16)
project(XioPrototypeQuic
    LANGUAGES  C CXX
    VERSION    1.0.0
    DESCRIPTION "Globus XIO QUIC transport driver prototype"
)

# ============================================================
# 1. 语言标准
# ============================================================
set(CMAKE_C_STANDARD            11)
set(CMAKE_C_STANDARD_REQUIRED   ON)
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ============================================================
# 2. 编译选项: 极限优化 + SIMD 指令集
# ============================================================
add_compile_options(
    # ---- 诊断 ----
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter

    # ---- 性能: -O3 + 本机微架构调优 ----
    -O3
    -march=native
    -mtune=native

    # ---- Module B SIMD: 显式启用 (保险, march=native 可能不含) ----
    -mavx2
    -mavx512f
    -mavx512bw
)

# Release 模式时追加 LTO
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR NOT CMAKE_BUILD_TYPE)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT _ipo_ok OUTPUT _ipo_err)
    if(_ipo_ok)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
    endif()
endif()

# ============================================================
# 3. 查找系统依赖
# ============================================================

# ---- liburing (apt install liburing-dev) ----
find_library(URING_LIB uring REQUIRED)
find_path(URING_INCLUDE_DIR liburing.h REQUIRED)

# ---- pthread ----
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ---- libnuma (apt install libnuma-dev) ----
find_library(NUMA_LIB numa REQUIRED)

# ---- LZ4 (apt install liblz4-dev) ----
find_library(LZ4_LIB lz4 REQUIRED)
find_path(LZ4_INCLUDE_DIR lz4.h REQUIRED)

# ---- picoquic + picotls (源码安装至系统路径) ----
find_path(PICOQUIC_INCLUDE_DIR picoquic.h
    HINTS /usr/local/include/picoquic /usr/include/picoquic
    REQUIRED)
find_path(PICOTLS_INCLUDE_DIR picotls.h
    HINTS /usr/local/include/picotls /usr/include/picotls
    REQUIRED)
find_library(PICOQUIC_CORE_LIB picoquic-core
    HINTS /usr/local/lib
    REQUIRED)
find_library(PICOTLS_CORE_LIB picotls-core
    HINTS /usr/local/lib
    REQUIRED)

# ============================================================
# 4. 共享库: libglobus_xio_prototype_quic.so
# ============================================================
set(LIB_SOURCES
    src/xio_driver.cpp              # Module A
    src/data_probe_engine.cpp       # Module B
    src/custom_quic_engine.cpp      # Module C
    src/uring_worker.cpp            # Module D
)

add_library(globus_xio_prototype_quic SHARED ${LIB_SOURCES})

target_include_directories(globus_xio_prototype_quic
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${URING_INCLUDE_DIR}
    PRIVATE ${LZ4_INCLUDE_DIR}
    PRIVATE ${PICOQUIC_INCLUDE_DIR}
    PRIVATE ${PICOTLS_INCLUDE_DIR}
)

target_link_libraries(globus_xio_prototype_quic
    PRIVATE ${URING_LIB}
    PRIVATE Threads::Threads
    PRIVATE ${NUMA_LIB}
    PRIVATE ${LZ4_LIB}
    PRIVATE ${PICOQUIC_CORE_LIB}
    PRIVATE ${PICOTLS_CORE_LIB}
)

set_target_properties(globus_xio_prototype_quic PROPERTIES
    # 导出 extern "C" 符号
    C_VISIBILITY_PRESET       default
    CXX_VISIBILITY_PRESET     default
    POSITION_INDEPENDENT_CODE ON
    # SO 版本
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# ============================================================
# 5. 测试可执行文件: xio_prototype_test
# ============================================================
enable_testing()

add_executable(xio_prototype_test
    tests/xio_prototype_test.cpp
)

target_include_directories(xio_prototype_test
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${URING_INCLUDE_DIR}
    PRIVATE ${LZ4_INCLUDE_DIR}
    PRIVATE ${PICOQUIC_INCLUDE_DIR}
    PRIVATE ${PICOTLS_INCLUDE_DIR}
)

target_link_libraries(xio_prototype_test
    PRIVATE globus_xio_prototype_quic
    PRIVATE ${URING_LIB}
    PRIVATE Threads::Threads
    PRIVATE ${NUMA_LIB}
    PRIVATE ${LZ4_LIB}
    PRIVATE ${PICOQUIC_CORE_LIB}
    PRIVATE ${PICOTLS_CORE_LIB}
)

add_test(NAME prototype_test COMMAND xio_prototype_test)

# ============================================================
# 6. 安装规则 (可选)
# ============================================================
include(GNUInstallDirs)

install(TARGETS globus_xio_prototype_quic
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/xio_prototype_quic
    FILES_MATCHING PATTERN "*.h"
)
