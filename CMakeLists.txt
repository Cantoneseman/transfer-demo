cmake_minimum_required(VERSION 3.16)
project(globus_xio_prototype_quic
    LANGUAGES CXX
    VERSION   0.2.0
    DESCRIPTION "Globus XIO QUIC transport driver prototype — Module A + D"
)

# ---- C++20 ----
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ---- 编译选项 ----
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
    -O2
)

# ---- 查找依赖 ----
# liburing: apt install liburing-dev
find_library(URING_LIB uring REQUIRED)
find_path(URING_INCLUDE_DIR liburing.h REQUIRED)

# pthread (CMake 内置)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# libnuma: apt install libnuma-dev
find_library(NUMA_LIB numa REQUIRED)

# ---- 目标: 动态链接库 ----
add_library(globus_xio_prototype_quic SHARED
    src/xio_driver.cpp
    src/uring_worker.cpp
)

target_include_directories(globus_xio_prototype_quic
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${URING_INCLUDE_DIR}
)

target_link_libraries(globus_xio_prototype_quic
    PRIVATE ${URING_LIB}
    PRIVATE Threads::Threads
    PRIVATE ${NUMA_LIB}
)

# 导出所有 extern "C" 符号
set_target_properties(globus_xio_prototype_quic PROPERTIES
    C_VISIBILITY_PRESET   default
    CXX_VISIBILITY_PRESET default
    POSITION_INDEPENDENT_CODE ON
)
