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
find_package(Threads REQUIRED)

pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(QRENCODE REQUIRED libqrencode)

# -----------------------------------------------------------------------------
# Core library (default: used by tools/vectors; permissive / frozen-vector friendly)
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
# Core library (server strict mode: enables time enforcement in qrauth_v4.c)
# -----------------------------------------------------------------------------
add_library(pqnas_core_server STATIC
        core/qrauth_v4.c
)

target_include_directories(pqnas_core_server PUBLIC
        ${CMAKE_SOURCE_DIR}/core
)

target_include_directories(pqnas_core_server PRIVATE
        ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(pqnas_core_server PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

# Enforce req.exp and proof ts freshness in server builds only.
target_compile_definitions(pqnas_core_server PRIVATE
        QR_V4_ENFORCE_TIME=1
        QR_V4_MAX_SKEW_SEC=300
)

target_link_libraries(pqnas_core_server PRIVATE
        ${SODIUM_LIBRARIES}
        OpenSSL::Crypto
)

# -----------------------------------------------------------------------------
# Shared v4 verifier library (single source of truth for server + tools)
# -----------------------------------------------------------------------------
add_library(pqnas_verify_v4 STATIC
        server/src/v4_verify_shared.cc
        server/src/verify_v4_crypto.cc
        server/src/pqnas_util.cc
        server/src/authz.cc
        server/src/users_registry.cpp
        server/src/user_quota.cc
)

target_include_directories(pqnas_verify_v4 PUBLIC
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/server/src
        ${CMAKE_SOURCE_DIR}/server/include
        ${CMAKE_SOURCE_DIR}/server/third_party
        ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(pqnas_verify_v4 PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

# IMPORTANT:
# - Server must get strict time enforcement in core/qrauth_v4.c
# - Tools/vectors should remain permissive to avoid breaking frozen vectors.
# Therefore pqnas_verify_v4 links against pqnas_core_server.
target_link_libraries(pqnas_verify_v4 PUBLIC
        pqnas_core_server
        ${SODIUM_LIBRARIES}
        OpenSSL::Crypto
        dl
)

# -----------------------------------------------------------------------------
# Server (C++ / httplib)
# -----------------------------------------------------------------------------
add_executable(pqnas_server
        server/src/main.cpp
        server/src/routes_v5.cc
        server/src/session_cookie.cc
        server/src/policy.cc
        server/src/audit_log.cc
        server/src/allowlist.cc
        server/src/users_registry.cpp
        server/src/system_metrics.cc
        server/src/storage_info.cc
        server/src/share_links.cc
        server/src/static_serve.cc
        server/src/verify_login_common.cc
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
        pqnas_verify_v4
        ${QRENCODE_LIBRARIES}
        OpenSSL::Crypto
        Threads::Threads                   # <-- robust std::thread support (-pthread)
        dl
)

set_target_properties(pqnas_server PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

set(PQNAS_DNA_LIB_SRC "${CMAKE_SOURCE_DIR}/server/third_party/dna/lib/linux/x64/libdna_lib.so")

add_custom_command(TARGET pqnas_server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${PQNAS_DNA_LIB_SRC}"
        "$<TARGET_FILE_DIR:pqnas_server>/libdna_lib.so"
)

# -----------------------------------------------------------------------------
# Tool: verify_vectors
# -----------------------------------------------------------------------------
add_executable(verify_vectors
        tests/vectors/verify_vectors.c
)


target_include_directories(verify_vectors PRIVATE
        ${CMAKE_SOURCE_DIR}/core
        ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(verify_vectors PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

# IMPORTANT: verify_vectors stays linked to permissive core to keep frozen vectors working.
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
# Tool: verify_v4_vectors (JSON protocol freeze; uses shared verifier)
# -----------------------------------------------------------------------------
add_executable(verify_v4_vectors
        tests/v4_vectors/verify_v4_vectors.cpp
)


target_link_libraries(verify_v4_vectors PRIVATE
        pqnas_verify_v4
)

# Keep output next to other tools
set_target_properties(verify_v4_vectors PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

target_compile_options(verify_v4_vectors PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

target_include_directories(verify_v4_vectors PRIVATE
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/server/src
        ${CMAKE_SOURCE_DIR}/server/include
        ${CMAKE_SOURCE_DIR}/server/third_party
        ${SODIUM_INCLUDE_DIRS}
)

add_custom_command(TARGET verify_v4_vectors POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${PQNAS_DNA_LIB_SRC}"
        "$<TARGET_FILE_DIR:verify_v4_vectors>/libdna_lib.so"
)
# -----------------------------------------------------------------------------
# Tool: verify_v5_vectors (v5 glue checks; derives/compares k == st_hash_b64)
# -----------------------------------------------------------------------------
add_executable(verify_v5_vectors
        tests/v5_vectors/verify_v5_vectors.cpp
)

target_link_libraries(verify_v5_vectors PRIVATE
        pqnas_verify_v4
)

set_target_properties(verify_v5_vectors PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

target_compile_options(verify_v5_vectors PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

target_include_directories(verify_v5_vectors PRIVATE
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/server/src
        ${CMAKE_SOURCE_DIR}/server/include
        ${CMAKE_SOURCE_DIR}/server/third_party
        ${SODIUM_INCLUDE_DIRS}
)

add_custom_command(TARGET verify_v5_vectors POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${PQNAS_DNA_LIB_SRC}"
        "$<TARGET_FILE_DIR:verify_v5_vectors>/libdna_lib.so"
)

# -----------------------------------------------------------------------------
# Tool: test_admin_cookie (regression test for cookie+policy admin checks)
# -----------------------------------------------------------------------------
add_executable(test_admin_cookie
        tests/cookies/test_admin_cookie.cpp
        server/src/authz.cc
        server/src/allowlist.cc
        server/src/session_cookie.cc
        server/src/pqnas_util.cc
        server/src/users_registry.cpp
)


target_include_directories(test_admin_cookie PRIVATE
        ${CMAKE_SOURCE_DIR}/server/include
        ${CMAKE_SOURCE_DIR}/server/third_party
        ${CMAKE_SOURCE_DIR}/core
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(test_admin_cookie PRIVATE
        OpenSSL::Crypto
        ${SODIUM_LIBRARIES}
        Threads::Threads                  # (harmless; keeps things consistent)
)

set_target_properties(test_admin_cookie PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
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

# Run targets

add_custom_target(run_verify_v4_vectors
        COMMAND "${CMAKE_BINARY_DIR}/bin/verify_v4_vectors" "${CMAKE_SOURCE_DIR}/tests/v4_vectors/vectors.json"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS verify_v4_vectors
)

add_custom_target(run_verify_v5_vectors
        COMMAND "${CMAKE_BINARY_DIR}/bin/verify_v5_vectors" "${CMAKE_SOURCE_DIR}/tests/v5_vectors/v5_vectors.json"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS verify_v5_vectors
)

add_custom_target(run_test_admin_cookie
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_admin_cookie"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_admin_cookie
)
