cmake_minimum_required(VERSION 3.16)

project(pq_nas
        VERSION 0.1.0
        LANGUAGES C CXX
)

# -----------------------------------------------------------------------------
# Global standards / warnings
# -----------------------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Warnings (portable)
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# -----------------------------------------------------------------------------
# Dependencies (MUST come before targets that use them)
# -----------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(QRENCODE REQUIRED libqrencode)

# -----------------------------------------------------------------------------
# Core library
# -----------------------------------------------------------------------------
add_library(pqnas_core STATIC
        core/qrauth_v4.c
)

target_include_directories(pqnas_core PUBLIC
        ${CMAKE_SOURCE_DIR}/core
)

target_include_directories(pqnas_core PRIVATE
        ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(pqnas_core PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

target_link_libraries(pqnas_core PRIVATE
        ${SODIUM_LIBRARIES}
        OpenSSL::Crypto
)

# -----------------------------------------------------------------------------
# Server (C++ / httplib)
# -----------------------------------------------------------------------------
add_executable(pqnas_server
        server/src/main.cpp
        server/src/session_cookie.cc
        server/src/policy.cc
)

target_include_directories(pqnas_server PRIVATE
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/server/include
        ${CMAKE_SOURCE_DIR}/server/third_party
        ${SODIUM_INCLUDE_DIRS}
        ${QRENCODE_INCLUDE_DIRS}
)

target_compile_options(pqnas_server PRIVATE
        ${SODIUM_CFLAGS_OTHER}
        ${QRENCODE_CFLAGS_OTHER}
)

target_link_libraries(pqnas_server PRIVATE
        pqnas_core
        ${SODIUM_LIBRARIES}
        ${QRENCODE_LIBRARIES}
        OpenSSL::Crypto
        dl
)

set_target_properties(pqnas_server PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# -----------------------------------------------------------------------------
# Tool: verify_vectors
# -----------------------------------------------------------------------------
add_executable(verify_vectors
        tools/verify_vectors.c
)

target_include_directories(verify_vectors PRIVATE
        ${SODIUM_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/core
)

target_compile_options(verify_vectors PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

target_link_libraries(verify_vectors PRIVATE
        pqnas_core
        ${SODIUM_LIBRARIES}
        OpenSSL::Crypto
)

set_target_properties(verify_vectors PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_verify_vectors
        COMMAND "${CMAKE_BINARY_DIR}/bin/verify_vectors"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS verify_vectors
)

# -----------------------------------------------------------------------------
# Tool: pqnas_keygen
# -----------------------------------------------------------------------------
add_executable(pqnas_keygen
        tools/keygen.c
)

target_include_directories(pqnas_keygen PRIVATE
        ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(pqnas_keygen PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

target_link_libraries(pqnas_keygen PRIVATE
        ${SODIUM_LIBRARIES}
)

set_target_properties(pqnas_keygen PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
