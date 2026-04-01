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
find_package(SQLite3 REQUIRED)

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
# Vendored ML-KEM-768 backend (portable C, first integration)
# -----------------------------------------------------------------------------
add_library(pqnas_mlkem_native_obj OBJECT
        server/third_party/mlkem-native/mlkem/mlkem_native.c
)

target_include_directories(pqnas_mlkem_native_obj PRIVATE
        ${CMAKE_SOURCE_DIR}/server/third_party/mlkem-native
        ${CMAKE_SOURCE_DIR}/server/src
)

target_compile_definitions(pqnas_mlkem_native_obj PRIVATE
        MLK_CONFIG_FILE=\"pqnas_mlkem_native_config_768.h\"
)
# -----------------------------------------------------------------------------
# Vendored ML-KEM-768 backend for dna_pqcore (separate namespace prefix)
# -----------------------------------------------------------------------------
add_library(dnanexus_mlkem_native_obj OBJECT
        server/third_party/mlkem-native/mlkem/mlkem_native.c
)

target_include_directories(dnanexus_mlkem_native_obj PRIVATE
        ${CMAKE_SOURCE_DIR}/server/third_party/mlkem-native
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore
)

target_compile_definitions(dnanexus_mlkem_native_obj PRIVATE
        MLK_CONFIG_FILE=\"dna_mlkem_native_config_768.h\"
)
# -----------------------------------------------------------------------------
# Experimental DNA PQ core library (not wired into pqnas_server yet)
# -----------------------------------------------------------------------------
add_library(dna_pqcore_mlkem STATIC
        core/dna_pqcore/dna_mlkem768_backend.cpp
        core/dna_pqcore/dna_mlkem768_backend.h
        $<TARGET_OBJECTS:dnanexus_mlkem_native_obj>
)

target_include_directories(dna_pqcore_mlkem PUBLIC
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore
)

target_include_directories(dna_pqcore_mlkem PRIVATE
        ${CMAKE_SOURCE_DIR}/server/third_party/mlkem-native
)

target_link_libraries(dna_pqcore_mlkem PRIVATE
        OpenSSL::Crypto
)
# -----------------------------------------------------------------------------
# Server (C++ / httplib)
# -----------------------------------------------------------------------------
add_executable(pqnas_server
        server/src/main.cpp
        server/src/user_storage_migration.h
        server/src/user_storage_migration.cpp

        server/src/storage/snapshots/snapshot_provider_btrfs.cc
        server/src/storage/snapshots/snapshot_naming.cc
        server/src/storage/snapshots/snapshot_scheduler.cc

        server/src/routes_v5.cc
        server/src/session_cookie.cc
        server/src/policy.cc
        server/src/audit_log.cc
        server/src/allowlist.cc
        server/src/users_registry.cpp
        server/src/system_metrics.cc
        server/src/storage_info.cc
        server/src/drive_health.cc
        server/src/drive_health_monitor.cc
        server/src/share_links.cc
        server/src/static_serve.cc
        server/src/verify_login_common.cc
        server/src/storage_resolver.cpp
        server/src/file_favorites.cc
        server/src/file_location_index.cpp
        server/src/path_lock_manager.cpp
        server/src/storage_pools.cc
        server/src/app_tokens.cpp
        server/src/app_pairing.cpp
        server/src/share_pq_v1.cpp
        server/src/share_pq_crypto_v1.cpp
        server/src/share_pq_mlkem_v1.cpp
        server/src/share_pq_mlkem_v1.h
        $<TARGET_OBJECTS:pqnas_mlkem_native_obj>
)

# Treat warnings as errors for the server (security-sensitive)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pqnas_server PRIVATE -Werror)
endif()

target_include_directories(pqnas_server PRIVATE
        ${CMAKE_SOURCE_DIR}/core
        ${CMAKE_SOURCE_DIR}/server/include
        ${CMAKE_SOURCE_DIR}/server/third_party
        ${CMAKE_SOURCE_DIR}/server/third_party/mlkem-native
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
        SQLite::SQLite3
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
# Tool: test_mlkem_params_768 (learning implementation, params only)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_params_768
        tests/dna_pqcore_learn/test_mlkem_params_768.cpp
)

target_include_directories(test_mlkem_params_768 PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_params_768 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_params_768
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_params_768"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_params_768
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_bytes (learning implementation, poly byte encoding)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_bytes
        tests/dna_pqcore_learn/test_mlkem_poly_bytes.cpp
        core/dna_pqcore_learn/dna_mlkem_poly.cpp
        core/dna_pqcore_learn/dna_mlkem_poly_bytes.cpp
)

target_include_directories(test_mlkem_poly_bytes PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_bytes PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_bytes
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_bytes"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_bytes
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_compress_dv4 (learning implementation, dv=4 compression)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_compress_dv4
        tests/dna_pqcore_learn/test_mlkem_poly_compress_dv4.cpp
        core/dna_pqcore_learn/dna_mlkem_poly.cpp
        core/dna_pqcore_learn/dna_mlkem_compress.cpp
)

target_include_directories(test_mlkem_poly_compress_dv4 PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_compress_dv4 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_compress_dv4
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_compress_dv4"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_compress_dv4
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_polyvec_compress_du10 (learning implementation, du=10 polyvec compression)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_polyvec_compress_du10
        tests/dna_pqcore_learn/test_mlkem_polyvec_compress_du10.cpp
        core/dna_pqcore_learn/dna_mlkem_poly.cpp
        core/dna_pqcore_learn/dna_mlkem_polyvec.cpp
        core/dna_pqcore_learn/dna_mlkem_compress_du10.cpp
        core/dna_pqcore_learn/dna_mlkem_polyvec_compress_du10.cpp
)

target_include_directories(test_mlkem_polyvec_compress_du10 PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_polyvec_compress_du10 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_polyvec_compress_du10
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_polyvec_compress_du10"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_polyvec_compress_du10
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_ntt_constants (learning implementation, NTT constants/schedule)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_ntt_constants
        tests/dna_pqcore_learn/test_mlkem_ntt_constants.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt_constants.cpp
)

target_include_directories(test_mlkem_ntt_constants PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_ntt_constants PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_ntt_constants
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_ntt_constants"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_ntt_constants
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_ntt_butterfly (learning implementation, first real NTT unit)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_ntt_butterfly
        tests/dna_pqcore_learn/test_mlkem_ntt_butterfly.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt.cpp
)

target_include_directories(test_mlkem_ntt_butterfly PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_ntt_butterfly PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_ntt_butterfly
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_ntt_butterfly"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_ntt_butterfly
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_ntt_forward (learning implementation, full forward NTT)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_ntt_forward
        tests/dna_pqcore_learn/test_mlkem_poly_ntt_forward.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt.cpp
)

target_include_directories(test_mlkem_poly_ntt_forward PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_ntt_forward PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_ntt_forward
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_ntt_forward"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_ntt_forward
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_invntt_tomont (learning implementation, inverse NTT)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_invntt_tomont
        tests/dna_pqcore_learn/test_mlkem_poly_invntt_tomont.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt.cpp
)

target_include_directories(test_mlkem_poly_invntt_tomont PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_invntt_tomont PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_invntt_tomont
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_invntt_tomont"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_invntt_tomont
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_basemul_pair (learning implementation, NTT base multiplication)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_basemul_pair
        tests/dna_pqcore_learn/test_mlkem_basemul_pair.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt.cpp
)

target_include_directories(test_mlkem_basemul_pair PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_basemul_pair PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_basemul_pair
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_basemul_pair"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_basemul_pair
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_basemul_montgomery (learning implementation, full NTT-domain polynomial multiply)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_basemul_montgomery
        tests/dna_pqcore_learn/test_mlkem_poly_basemul_montgomery.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt.cpp
)

target_include_directories(test_mlkem_poly_basemul_montgomery PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_basemul_montgomery PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_basemul_montgomery
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_basemul_montgomery"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_basemul_montgomery
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_mul_via_ntt (learning implementation, full polynomial multiplication pipeline)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_mul_via_ntt
        tests/dna_pqcore_learn/test_mlkem_poly_mul_via_ntt.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt.cpp
)

target_include_directories(test_mlkem_poly_mul_via_ntt PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_mul_via_ntt PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_mul_via_ntt
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_mul_via_ntt"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_mul_via_ntt
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_cbd (learning implementation, centered binomial sampling)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_cbd
        tests/dna_pqcore_learn/test_mlkem_cbd.cpp
        core/dna_pqcore_learn/dna_mlkem_cbd.cpp
)

target_include_directories(test_mlkem_cbd PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_cbd PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_cbd
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_cbd"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_cbd
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_prf (learning implementation, SHAKE-256 seed||nonce expansion)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_prf
        tests/dna_pqcore_learn/test_mlkem_prf.cpp
        core/dna_pqcore_learn/dna_mlkem_prf.cpp
)

target_include_directories(test_mlkem_prf PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

target_link_libraries(test_mlkem_prf PRIVATE
        OpenSSL::Crypto
)

set_target_properties(test_mlkem_prf PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_prf
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_prf"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_prf
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_getnoise (learning implementation, PRF + CBD composition)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_getnoise
        tests/dna_pqcore_learn/test_mlkem_getnoise.cpp
        core/dna_pqcore_learn/dna_mlkem_cbd.cpp
        core/dna_pqcore_learn/dna_mlkem_prf.cpp
        core/dna_pqcore_learn/dna_mlkem_getnoise.cpp
)

target_include_directories(test_mlkem_getnoise PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

target_link_libraries(test_mlkem_getnoise PRIVATE
        OpenSSL::Crypto
)

set_target_properties(test_mlkem_getnoise PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_getnoise
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_getnoise"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_getnoise
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_uniform_rej (learning implementation, uniform rejection sampler)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_uniform_rej
        tests/dna_pqcore_learn/test_mlkem_uniform_rej.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_uniform.cpp
)

target_include_directories(test_mlkem_uniform_rej PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_uniform_rej PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_uniform_rej
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_uniform_rej"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_uniform_rej
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_ntt_layer (learning implementation, one full forward NTT layer)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_ntt_layer
        tests/dna_pqcore_learn/test_mlkem_ntt_layer.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_ntt.cpp
)

target_include_directories(test_mlkem_ntt_layer PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_ntt_layer PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_ntt_layer
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_ntt_layer"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_ntt_layer
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_field (learning implementation, finite-field arithmetic)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_field
        tests/dna_pqcore_learn/test_mlkem_field.cpp
        core/dna_pqcore_learn/dna_mlkem_field.cpp
)

target_include_directories(test_mlkem_field PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_field PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_field
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_field"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_field
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_compress_du10 (learning implementation, du=10 compression)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_compress_du10
        tests/dna_pqcore_learn/test_mlkem_poly_compress_du10.cpp
        core/dna_pqcore_learn/dna_mlkem_poly.cpp
        core/dna_pqcore_learn/dna_mlkem_compress_du10.cpp
)

target_include_directories(test_mlkem_poly_compress_du10 PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_compress_du10 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_compress_du10
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_compress_du10"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_compress_du10
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_polyvec_bytes (learning implementation, polyvec byte encoding)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_polyvec_bytes
        tests/dna_pqcore_learn/test_mlkem_polyvec_bytes.cpp
        core/dna_pqcore_learn/dna_mlkem_poly.cpp
        core/dna_pqcore_learn/dna_mlkem_poly_bytes.cpp
        core/dna_pqcore_learn/dna_mlkem_polyvec.cpp
        core/dna_pqcore_learn/dna_mlkem_polyvec_bytes.cpp
)

target_include_directories(test_mlkem_polyvec_bytes PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_polyvec_bytes PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_polyvec_bytes
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_polyvec_bytes"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_polyvec_bytes
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_polyvec_basics (learning implementation, polyvec helpers)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_polyvec_basics
        tests/dna_pqcore_learn/test_mlkem_polyvec_basics.cpp
        core/dna_pqcore_learn/dna_mlkem_poly.cpp
        core/dna_pqcore_learn/dna_mlkem_polyvec.cpp
)

target_include_directories(test_mlkem_polyvec_basics PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_polyvec_basics PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_polyvec_basics
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_polyvec_basics"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_polyvec_basics
)
# -----------------------------------------------------------------------------
# Tool: test_mlkem_poly_basics (learning implementation, poly helpers)
# -----------------------------------------------------------------------------
add_executable(test_mlkem_poly_basics
        tests/dna_pqcore_learn/test_mlkem_poly_basics.cpp
        core/dna_pqcore_learn/dna_mlkem_poly.cpp
)

target_include_directories(test_mlkem_poly_basics PRIVATE
        ${CMAKE_SOURCE_DIR}/core/dna_pqcore_learn
)

set_target_properties(test_mlkem_poly_basics PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_mlkem_poly_basics
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_poly_basics"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_mlkem_poly_basics
)
# -----------------------------------------------------------------------------
# Tool: test_dna_mlkem768_backend (experimental dna_pqcore test only)
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_backend
        tests/dna_pqcore/test_dna_mlkem768_backend.cpp
)

target_link_libraries(test_dna_mlkem768_backend PRIVATE
        dna_pqcore_mlkem
)

set_target_properties(test_dna_mlkem768_backend PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_custom_target(run_test_dna_mlkem768_backend
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_backend"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS test_dna_mlkem768_backend
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
