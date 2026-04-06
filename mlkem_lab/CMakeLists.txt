cmake_minimum_required(VERSION 3.16)

project(mlkem_lab
        VERSION 0.1.0
        LANGUAGES C CXX
)

# -----------------------------------------------------------------------------
# Repo root
# -----------------------------------------------------------------------------
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

# -----------------------------------------------------------------------------
# Standards / warnings
# -----------------------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

# -----------------------------------------------------------------------------
# Helper: runtime output + run target
# -----------------------------------------------------------------------------
function(mlkem_lab_set_bin_output target_name)
    set_target_properties(${target_name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endfunction()

function(mlkem_lab_add_run_target target_name)
    add_custom_target(run_${target_name}
            COMMAND "${CMAKE_BINARY_DIR}/bin/${target_name}"
            WORKING_DIRECTORY "${REPO_ROOT}"
            DEPENDS ${target_name}
    )
endfunction()

function(mlkem_lab_add_test target_name)
    set(options OPENSSL ORACLE)
    set(oneValueArgs)
    set(multiValueArgs SRCS INCLUDES LIBS)
    cmake_parse_arguments(MLT "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_executable(${target_name}
            ${MLT_SRCS}
    )

    target_include_directories(${target_name} PRIVATE
            "${REPO_ROOT}/core/dna_pqcore_learn"
            ${MLT_INCLUDES}
    )

    if (MLT_OPENSSL)
        target_link_libraries(${target_name} PRIVATE OpenSSL::Crypto)
    endif()

    if (MLT_ORACLE)
        target_include_directories(${target_name} PRIVATE
                "${REPO_ROOT}/core/dna_pqcore"
        )
        target_link_libraries(${target_name} PRIVATE
                dna_pqcore_mlkem
        )
    endif()

    if (MLT_LIBS)
        target_link_libraries(${target_name} PRIVATE
                ${MLT_LIBS}
        )
    endif()

    mlkem_lab_set_bin_output(${target_name})
    mlkem_lab_add_run_target(${target_name})
endfunction()

# -----------------------------------------------------------------------------
# Vendored ML-KEM-768 backend for dna_pqcore (separate namespace prefix)
# -----------------------------------------------------------------------------
add_library(dnanexus_mlkem_native_obj OBJECT
        "${REPO_ROOT}/server/third_party/mlkem-native/mlkem/mlkem_native.c"
)

target_include_directories(dnanexus_mlkem_native_obj PRIVATE
        "${REPO_ROOT}/server/third_party/mlkem-native"
        "${REPO_ROOT}/core/dna_pqcore"
)

target_compile_definitions(dnanexus_mlkem_native_obj PRIVATE
        MLK_CONFIG_FILE=\"dna_mlkem_native_config_768.h\"
)

# -----------------------------------------------------------------------------
# Learn-track source bundles
# -----------------------------------------------------------------------------
set(MLK_LEARN_FIELD_SRCS
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_field.cpp"
)

set(MLK_LEARN_POLY_SRCS
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_poly.cpp"
)

set(MLK_LEARN_POLY_BYTES_SRCS
        ${MLK_LEARN_POLY_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_poly_bytes.cpp"
)

set(MLK_LEARN_POLYVEC_SRCS
        ${MLK_LEARN_POLY_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_polyvec.cpp"
)

set(MLK_LEARN_POLYVEC_BYTES_SRCS
        ${MLK_LEARN_POLY_BYTES_SRCS}
        ${MLK_LEARN_POLYVEC_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_polyvec_bytes.cpp"
)

set(MLK_LEARN_COMPRESS_DV4_SRCS
        ${MLK_LEARN_POLY_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_compress.cpp"
)

set(MLK_LEARN_COMPRESS_DU10_SRCS
        ${MLK_LEARN_POLY_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_compress_du10.cpp"
)

set(MLK_LEARN_POLYVEC_COMPRESS_DU10_SRCS
        ${MLK_LEARN_POLYVEC_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_compress_du10.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_polyvec_compress_du10.cpp"
)

set(MLK_LEARN_NTT_CONSTANTS_SRCS
        ${MLK_LEARN_FIELD_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_ntt_constants.cpp"
)

set(MLK_LEARN_NTT_ONLY_SRCS
        ${MLK_LEARN_FIELD_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_ntt.cpp"
)

set(MLK_LEARN_TOMONT_SRCS
        ${MLK_LEARN_NTT_ONLY_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_tomont.cpp"
)

set(MLK_LEARN_SAMPLING_SRCS
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_cbd.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_prf.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_getnoise.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_noisevec.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_uniform.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_sample_ntt.cpp"
)

set(MLK_LEARN_MATRIX_SRCS
        ${MLK_LEARN_SAMPLING_SRCS}
        ${MLK_LEARN_NTT_ONLY_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_matrix_gen.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_matvec.cpp"
)

set(MLK_LEARN_INDCPA_CORE_SRCS
        ${MLK_LEARN_MATRIX_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_tomont.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_indcpa_keygen_skeleton.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_indcpa_encrypt_skeleton.cpp"
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_indcpa_decrypt_skeleton.cpp"
)

set(MLK_LEARN_MESSAGE_SRCS
        ${MLK_LEARN_FIELD_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_message.cpp"
)

set(MLK_LEARN_PACKED_SRCS
        ${MLK_LEARN_INDCPA_CORE_SRCS}
        ${MLK_LEARN_MESSAGE_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_indcpa_packed.cpp"
)

set(MLK_LEARN_CPAPKE_SRCS
        ${MLK_LEARN_PACKED_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_cpapke.cpp"
)

set(MLK_LEARN_KEM_SRCS
        ${MLK_LEARN_CPAPKE_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_kem.cpp"
)

set(MLK_LEARN_KEM_RANDOM_SRCS
        ${MLK_LEARN_KEM_SRCS}
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_kem_random.cpp"
)

set(MLK_LEARN_BACKEND_PARITY_SRCS
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_backend_oracle.cpp"
        ${MLK_LEARN_KEM_SRCS}
)

# -----------------------------------------------------------------------------
# Frozen learn-track KEM library (shared internal use)
# -----------------------------------------------------------------------------
add_library(dna_pqcore_learn_kem STATIC
        ${MLK_LEARN_KEM_SRCS}
)

target_include_directories(dna_pqcore_learn_kem PUBLIC
        "${REPO_ROOT}/core/dna_pqcore_learn"
)

target_link_libraries(dna_pqcore_learn_kem PRIVATE
        OpenSSL::Crypto
)

# -----------------------------------------------------------------------------
# Frozen learn-track backend-oracle adapter library
# -----------------------------------------------------------------------------
add_library(dna_pqcore_learn_backend_oracle STATIC
        "${REPO_ROOT}/core/dna_pqcore_learn/dna_mlkem_backend_oracle.cpp"
)

target_include_directories(dna_pqcore_learn_backend_oracle PUBLIC
        "${REPO_ROOT}/core/dna_pqcore_learn"
        "${REPO_ROOT}/core/dna_pqcore"
)

target_link_libraries(dna_pqcore_learn_backend_oracle PUBLIC
        dna_pqcore_learn_kem
        dna_pqcore_mlkem
)

# -----------------------------------------------------------------------------
# DNA provider encaps interop test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_dna_encaps_interop
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_dna_encaps_interop.cpp"
)

target_link_libraries(test_dna_mlkem768_dna_encaps_interop PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_dna_encaps_interop)
mlkem_lab_add_run_target(test_dna_mlkem768_dna_encaps_interop)

# -----------------------------------------------------------------------------
# DNA provider decaps interop test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_dna_decaps_interop
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_dna_decaps_interop.cpp"
)

target_link_libraries(test_dna_mlkem768_dna_decaps_interop PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_dna_decaps_interop)
mlkem_lab_add_run_target(test_dna_mlkem768_dna_decaps_interop)

# -----------------------------------------------------------------------------
# Provider confidence matrix test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_provider_matrix
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_provider_matrix.cpp"
)

target_link_libraries(test_dna_mlkem768_provider_matrix PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_provider_matrix)
mlkem_lab_add_run_target(test_dna_mlkem768_provider_matrix)

# -----------------------------------------------------------------------------
# Selected-provider override test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_selected_provider_override
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_selected_provider_override.cpp"
)

target_link_libraries(test_dna_mlkem768_selected_provider_override PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_selected_provider_override)
mlkem_lab_add_run_target(test_dna_mlkem768_selected_provider_override)

# -----------------------------------------------------------------------------
# DNA-selected freeze sanity test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_freeze_prefer_dna
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_freeze_prefer_dna.cpp"
)

target_link_libraries(test_dna_mlkem768_freeze_prefer_dna PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_freeze_prefer_dna)

# -----------------------------------------------------------------------------
# Convenience target: public-path freeze lane with selected provider forced to dna
# -----------------------------------------------------------------------------
add_custom_target(run_mlkem_lab_freeze_tests_dna_selected
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=dna "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_freeze_prefer_dna"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=dna "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_backend"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=dna "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_boundary"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=dna "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_secret_lifecycle"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=dna "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_compat"
        WORKING_DIRECTORY "${REPO_ROOT}"
        DEPENDS
        test_dna_mlkem768_freeze_prefer_dna
        test_dna_mlkem768_backend
        test_dna_mlkem768_boundary
        test_dna_mlkem768_secret_lifecycle
        test_dna_mlkem768_compat
)

# -----------------------------------------------------------------------------
# Native-selected freeze sanity test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_freeze_prefer_native
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_freeze_prefer_native.cpp"
)

target_link_libraries(test_dna_mlkem768_freeze_prefer_native PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_freeze_prefer_native)

# -----------------------------------------------------------------------------
# Convenience target: public-path freeze lane with selected provider forced to native
# -----------------------------------------------------------------------------
add_custom_target(run_mlkem_lab_freeze_tests_native_selected
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=native "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_freeze_prefer_native"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=native "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_backend"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=native "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_boundary"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=native "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_secret_lifecycle"
        COMMAND "${CMAKE_COMMAND}" -E env DNA_MLKEM_SELECTED_PROVIDER=native "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_compat"
        WORKING_DIRECTORY "${REPO_ROOT}"
        DEPENDS
        test_dna_mlkem768_freeze_prefer_native
        test_dna_mlkem768_backend
        test_dna_mlkem768_boundary
        test_dna_mlkem768_secret_lifecycle
        test_dna_mlkem768_compat
)

# -----------------------------------------------------------------------------
# DNA PQ core backend wrapper (default lab/dev provider = dna)
# -----------------------------------------------------------------------------
add_library(dna_pqcore_mlkem STATIC
        "${REPO_ROOT}/core/dna_pqcore/dna_mlkem768_backend.cpp"
        "${REPO_ROOT}/core/dna_pqcore/internal/dna_mlkem768_provider_native.cpp"
        "${REPO_ROOT}/core/dna_pqcore/internal/dna_mlkem768_provider_stub.cpp"
        "${REPO_ROOT}/core/dna_pqcore/internal/dna_mlkem768_provider_dna.cpp"
        "${REPO_ROOT}/core/dna_pqcore/internal/dna_mlkem768_provider_select.cpp"
        "${REPO_ROOT}/core/dna_pqcore/dna_mlkem768_backend.h"
        $<TARGET_OBJECTS:dnanexus_mlkem_native_obj>
)

target_include_directories(dna_pqcore_mlkem PUBLIC
        "${REPO_ROOT}/core/dna_pqcore"
)

target_include_directories(dna_pqcore_mlkem PRIVATE
        "${REPO_ROOT}/server/third_party/mlkem-native"
        "${REPO_ROOT}/core/dna_pqcore_learn"
)

target_link_libraries(dna_pqcore_mlkem PRIVATE
        OpenSSL::Crypto
        dna_pqcore_learn_kem
)

# -----------------------------------------------------------------------------
# Backend wrapper smoke test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_backend
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_backend.cpp"
)

target_link_libraries(test_dna_mlkem768_backend PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_backend)
mlkem_lab_add_run_target(test_dna_mlkem768_backend)

# -----------------------------------------------------------------------------
# Backend wrapper boundary test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_boundary
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_boundary.cpp"
)

target_link_libraries(test_dna_mlkem768_boundary PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_boundary)
mlkem_lab_add_run_target(test_dna_mlkem768_boundary)

# -----------------------------------------------------------------------------
# Backend wrapper secret lifecycle test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_secret_lifecycle
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_secret_lifecycle.cpp"
)

target_link_libraries(test_dna_mlkem768_secret_lifecycle PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_secret_lifecycle)
mlkem_lab_add_run_target(test_dna_mlkem768_secret_lifecycle)

# -----------------------------------------------------------------------------
# Backend wrapper compatibility-surface test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_compat
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_compat.cpp"
)

target_link_libraries(test_dna_mlkem768_compat PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_compat)
mlkem_lab_add_run_target(test_dna_mlkem768_compat)

# -----------------------------------------------------------------------------
# Backend wrapper provider-identity test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_provider_identity
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_provider_identity.cpp"
)

target_link_libraries(test_dna_mlkem768_provider_identity PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_provider_identity)
mlkem_lab_add_run_target(test_dna_mlkem768_provider_identity)

# -----------------------------------------------------------------------------
# Backend wrapper provider-by-id test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_provider_by_id
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_provider_by_id.cpp"
)

target_link_libraries(test_dna_mlkem768_provider_by_id PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_provider_by_id)
mlkem_lab_add_run_target(test_dna_mlkem768_provider_by_id)

# -----------------------------------------------------------------------------
# DNA provider keygen interop test
# -----------------------------------------------------------------------------
add_executable(test_dna_mlkem768_dna_keygen_interop
        "${REPO_ROOT}/tests/dna_pqcore/test_dna_mlkem768_dna_keygen_interop.cpp"
)

target_link_libraries(test_dna_mlkem768_dna_keygen_interop PRIVATE
        dna_pqcore_mlkem
)

mlkem_lab_set_bin_output(test_dna_mlkem768_dna_keygen_interop)
mlkem_lab_add_run_target(test_dna_mlkem768_dna_keygen_interop)

# -----------------------------------------------------------------------------
# High-value learn-track tests
# -----------------------------------------------------------------------------
mlkem_lab_add_test(test_mlkem_message
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_message.cpp"
        ${MLK_LEARN_MESSAGE_SRCS}
)

mlkem_lab_add_test(test_mlkem_indcpa_packed
        OPENSSL
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_indcpa_packed.cpp"
        ${MLK_LEARN_PACKED_SRCS}
)

mlkem_lab_add_test(test_mlkem_cpapke
        OPENSSL
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_cpapke.cpp"
        ${MLK_LEARN_CPAPKE_SRCS}
)

mlkem_lab_add_test(test_mlkem_kem
        OPENSSL
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_kem.cpp"
        ${MLK_LEARN_KEM_SRCS}
)

mlkem_lab_add_test(test_mlkem_kem_random
        OPENSSL
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_kem_random.cpp"
        ${MLK_LEARN_KEM_RANDOM_SRCS}
)

mlkem_lab_add_test(test_mlkem_kem_vs_backend
        OPENSSL
        ORACLE
        LIBS dna_pqcore_learn_backend_oracle
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_kem_vs_backend.cpp"
)

mlkem_lab_add_test(test_mlkem_kem_diff_many
        OPENSSL
        ORACLE
        LIBS dna_pqcore_learn_backend_oracle
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_kem_diff_many.cpp"
)

mlkem_lab_add_test(test_mlkem_kem_diff_fuzz
        OPENSSL
        ORACLE
        LIBS dna_pqcore_learn_backend_oracle
        SRCS
        "${REPO_ROOT}/tests/dna_pqcore_learn/test_mlkem_kem_diff_fuzz.cpp"
)

# -----------------------------------------------------------------------------
# Convenience target: default lab/dev ML-KEM freeze lane (default selected provider = dna)
# -----------------------------------------------------------------------------

add_custom_target(run_mlkem_lab_freeze_tests
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_backend"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_boundary"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_secret_lifecycle"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_compat"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_provider_identity"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_provider_by_id"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_dna_keygen_interop"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_dna_encaps_interop"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_dna_decaps_interop"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_provider_matrix"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_dna_mlkem768_selected_provider_override"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_message"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_indcpa_packed"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_cpapke"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_kem"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_kem_random"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_kem_vs_backend"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_kem_diff_many"
        COMMAND "${CMAKE_BINARY_DIR}/bin/test_mlkem_kem_diff_fuzz"
        WORKING_DIRECTORY "${REPO_ROOT}"
        DEPENDS
        test_dna_mlkem768_backend
        test_dna_mlkem768_boundary
        test_dna_mlkem768_secret_lifecycle
        test_dna_mlkem768_compat
        test_dna_mlkem768_provider_identity
        test_dna_mlkem768_provider_by_id
        test_dna_mlkem768_dna_keygen_interop
        test_dna_mlkem768_dna_encaps_interop
        test_dna_mlkem768_dna_decaps_interop
        test_dna_mlkem768_provider_matrix
        test_dna_mlkem768_selected_provider_override
        test_mlkem_message
        test_mlkem_indcpa_packed
        test_mlkem_cpapke
        test_mlkem_kem
        test_mlkem_kem_random
        test_mlkem_kem_vs_backend
        test_mlkem_kem_diff_many
        test_mlkem_kem_diff_fuzz
)