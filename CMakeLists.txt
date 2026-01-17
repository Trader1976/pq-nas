cmake_minimum_required(VERSION 3.16)

project(pq_nas
        VERSION 0.1.0
        LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Warnings (portable)
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ---- Tool: verify_vectors (C reference verifier) ----
add_executable(verify_vectors
        tools/verify_vectors.c
)

target_include_directories(verify_vectors PRIVATE
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(verify_vectors PRIVATE
        ${SODIUM_LIBRARIES}
        OpenSSL::Crypto
)

# Some distros need this for pkg-config-provided flags
target_compile_options(verify_vectors PRIVATE
        ${SODIUM_CFLAGS_OTHER}
)

# Convenience: run from CLion with repo root as working dir
# (so it finds the .md vector files)
set_target_properties(verify_vectors PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ---- Optional: a custom target to run the verifier from build tree ----
add_custom_target(run_verify_vectors
        COMMAND "${CMAKE_BINARY_DIR}/bin/verify_vectors"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS verify_vectors
)
