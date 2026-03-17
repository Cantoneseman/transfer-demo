cmake_minimum_required(VERSION 3.16)
project(XioPrototype CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Compiler flags ──────────────────────────────────────────────────
add_compile_options(-O3 -march=native -mtune=native -Wall -Wextra)

# ── Include / link search paths (hand-built protocol stacks) ───────
include_directories(
    ${CMAKE_SOURCE_DIR}
    /usr/local/include
    /home/sumu/projects/picotls/include
)

link_directories(
    /usr/local/lib
    /home/sumu/projects/picotls
)

# ── Main integration binary ────────────────────────────────────────
add_executable(xio_prototype_test
    main.cpp
    uring_worker.cpp
    custom_quic_engine.cpp
    data_probe_engine.cpp
)

target_link_libraries(xio_prototype_test
    picoquic-core
    picoquic-log
    picotls-openssl
    picotls-minicrypto
    picotls-core
    picotls-fusion
    uring
    numa
    lz4
    ssl
    crypto
    pthread
)

# ── Unit test targets ──────────────────────────────────────────────
add_executable(test_ring         test_ring.cpp)
target_link_libraries(test_ring  pthread)

add_executable(test_uring_worker test_uring_worker.cpp uring_worker.cpp)
target_link_libraries(test_uring_worker uring numa pthread)

add_executable(test_quic_engine  test_quic_engine.cpp custom_quic_engine.cpp)
target_link_libraries(test_quic_engine
    picoquic-core picoquic-log
    picotls-openssl picotls-minicrypto picotls-core picotls-fusion
    ssl crypto pthread
)

add_executable(test_data_probe   test_data_probe.cpp data_probe_engine.cpp)
target_link_libraries(test_data_probe lz4 pthread)
