# ML-KEM-768 learn track module inventory

## Purpose

This document lists the learn-track ML-KEM-768 files and their roles.

It is meant as a quick map for future review work.

Main learn-track roots:

- `core/dna_pqcore_learn/`
- `tests/dna_pqcore_learn/`

This inventory is descriptive only.
It does not change the freeze rule for the learn track.

---

## Overall structure

The learn track was built in layers:

1. parameter and representation basics
2. field arithmetic
3. byte packing and compression
4. NTT and polynomial multiplication
5. sampling and matrix generation
6. IND-CPA algebra skeletons
7. packed IND-CPA flow
8. CPA-PKE wrapper
9. KEM wrapper
10. randomized convenience API
11. backend parity and regression harnesses

---

## Core modules

## `dna_mlkem_params_768.h`

Role:

- fixed ML-KEM-768 parameter constants

Key concepts:

- `n = 256`
- `q = 3329`
- `k = 3`
- packed size constants

Used by:

- almost every learn-track module

---

## `dna_mlkem_poly.h/.cpp`

Role:

- basic polynomial container-style operations

Responsibilities:

- coefficient handling
- canonical mod-q helpers
- polynomial add/sub basics

Used by:

- early structural tests
- representation and arithmetic foundation

---

## `dna_mlkem_poly_bytes.h/.cpp`

Role:

- exact 12-bit polynomial byte packing and unpacking

Responsibilities:

- serialize one polynomial
- parse one polynomial

Used by:

- packing tests
- later packed IND-CPA flow logic

---

## `dna_mlkem_polyvec.h/.cpp`

Role:

- basic `k=3` polyvec structure logic

Responsibilities:

- polyvec layout
- simple helper operations

Used by:

- polyvec representation tests
- later vector-oriented learning steps

---

## `dna_mlkem_polyvec_bytes.h/.cpp`

Role:

- exact byte packing/unpacking for one `k=3` polyvec

Responsibilities:

- serialize `k` polynomials in sequence
- parse `k` polynomials in sequence

Used by:

- packed secret/public-key logic

---

## `dna_mlkem_compress.h/.cpp`

Role:

- single-polynomial `dv = 4` compression/decompression

Responsibilities:

- lossy polynomial compression for the ciphertext `v` part

Used by:

- packed ciphertext flow

---

## `dna_mlkem_compress_du10.h/.cpp`

Role:

- single-polynomial `du = 10` compression/decompression

Responsibilities:

- lossy polynomial compression at `du=10`

Used by:

- poly-level learning and reference behavior

---

## `dna_mlkem_polyvec_compress_du10.h/.cpp`

Role:

- polyvec `du = 10` compression/decompression

Responsibilities:

- lossy compression for ciphertext `u`

Used by:

- packed ciphertext flow

---

## `dna_mlkem_field.h/.cpp`

Role:

- finite-field arithmetic helpers for `q = 3329`

Responsibilities:

- canonicalization mod `q`
- Barrett reduction
- Montgomery reduction
- Montgomery constants
- field multiply helpers

Used by:

- NTT
- compression rounding logic
- packing/canonical comparison logic
- message decode threshold logic

---

## `dna_mlkem_ntt_constants.h/.cpp`

Role:

- forward/inverse NTT constants and ordering data

Responsibilities:

- zeta table exposure
- NTT schedule support

Used by:

- `dna_mlkem_ntt.cpp`

---

## `dna_mlkem_ntt.h/.cpp`

Role:

- core transform and NTT-domain multiplication layer

Responsibilities:

- forward NTT
- inverse NTT with tomont behavior
- base multiplication
- polynomial multiplication via NTT-domain path
- Montgomery-domain transitions at the transform boundary

Used by:

- matrix-vector multiplication
- IND-CPA algebra skeletons
- message recovery path
- packed IND-CPA and KEM flow

---

## `dna_mlkem_cbd.h/.cpp`

Role:

- centered binomial distribution sampling

Responsibilities:

- `eta=2`
- `eta=3`

Used by:

- noise generation

---

## `dna_mlkem_prf.h/.cpp`

Role:

- deterministic PRF expansion for noise sampling

Responsibilities:

- seed + nonce expansion into bytes for CBD input

Used by:

- `dna_mlkem_getnoise.cpp`

---

## `dna_mlkem_getnoise.h/.cpp`

Role:

- single-polynomial noise generation

Responsibilities:

- `getnoise_eta2`
- `getnoise_eta3`

Used by:

- noise vectors
- keygen/encrypt algebra

---

## `dna_mlkem_uniform.h/.cpp`

Role:

- rejection sampling for uniform coefficients mod `q`

Responsibilities:

- parse 12-bit candidates
- accept only values `< q`

Used by:

- `SampleNTT`

---

## `dna_mlkem_sample_ntt.h/.cpp`

Role:

- direct `SampleNTT(rho || j || i)` implementation

Responsibilities:

- SHAKE-128 stream generation
- rejection sampling into 256 canonical coefficients

Used by:

- matrix entry generation

---

## `dna_mlkem_matrix_gen.h/.cpp`

Role:

- matrix generation in NTT representation

Responsibilities:

- single matrix entry
- transposed matrix entry
- full `3 x 3` matrix
- full transposed `3 x 3` matrix

Used by:

- keygen algebra
- encrypt algebra

---

## `dna_mlkem_matvec.h/.cpp`

Role:

- matrix-vector multiplication in NTT representation

Responsibilities:

- one row × vector multiply
- full matrix × vector multiply

Used by:

- keygen algebra
- encrypt algebra
- decrypt inner-product path

---

## `dna_mlkem_noisevec.h/.cpp`

Role:

- `k=3` vector wrapper over single-poly noise generation

Responsibilities:

- `eta=2` noise vector
- `eta=3` noise vector
- nonce scheduling across 3 polynomials

Used by:

- keygen algebra
- encrypt algebra

---

## `dna_mlkem_tomont.h/.cpp`

Role:

- coefficient-wise conversion into Montgomery domain

Responsibilities:

- one polynomial `tomont`
- one `k=3` vector `tomont`

Used by:

- keygen algebra when combining `A_hat * s_hat` with `e_hat`

---

## `dna_mlkem_indcpa_keygen_skeleton.h/.cpp`

Role:

- deterministic IND-CPA keygen algebra core

Responsibilities:

- generate `A_hat`
- sample `s` and `e`
- NTT both
- compute `t_hat = tomont(A_hat * s_hat) + e_hat`

Used by:

- packed IND-CPA keypair
- later CPA-PKE wrapper

---

## `dna_mlkem_indcpa_encrypt_skeleton.h/.cpp`

Role:

- deterministic IND-CPA encrypt algebra core

Responsibilities:

- generate `A_hat^T`
- sample `r`, `e1`, `e2`
- compute `u`
- compute `v`

Used by:

- packed IND-CPA encryption

---

## `dna_mlkem_indcpa_decrypt_skeleton.h/.cpp`

Role:

- deterministic IND-CPA decrypt algebra core

Responsibilities:

- NTT of `u`
- inner product with `s_hat`
- recover pre-decode message polynomial

Used by:

- packed IND-CPA decryption

---

## `dna_mlkem_indcpa_roundtrip_skeleton.h/.cpp`

Role:

- one combined deterministic IND-CPA algebra roundtrip

Responsibilities:

- keygen algebra
- encrypt algebra
- decrypt algebra
- recovered pre-decode message polynomial

Used by:

- end-to-end algebra validation

---

## `dna_mlkem_message.h/.cpp`

Role:

- message bytes ↔ message polynomial bridge

Responsibilities:

- `poly_frommsg`
- `poly_tomsg`

Used by:

- packed IND-CPA encryption/decryption
- CPA-PKE wrapper

---

## `dna_mlkem_indcpa_packed.h/.cpp`

Role:

- packed deterministic IND-CPA flow

Responsibilities:

- packed keypair
- packed encryption
- packed decryption
- exact packed size handling for:
    - secret key
    - public key
    - ciphertext

Used by:

- CPA-PKE wrapper

---

## `dna_mlkem_cpapke.h/.cpp`

Role:

- learn-track CPA-PKE wrapper

Responsibilities:

- derive `rho || sigma` from key seed
- deterministic keypair API
- deterministic encrypt API
- decrypt API

Used by:

- KEM wrapper

---

## `dna_mlkem_kem.h/.cpp`

Role:

- deterministic ML-KEM-768 wrapper

Responsibilities:

- full KEM secret-key layout
- deterministic keypair from `(d, z)`
- deterministic encaps from explicit `m`
- decapsulation
- backend-compatible shared-secret behavior

Used by:

- randomized convenience API
- backend parity tests

---

## `dna_mlkem_kem_random.h/.cpp`

Role:

- randomized top-level convenience API

Responsibilities:

- random keypair
- random encaps
- decaps wrapper
- randomness sourced from OpenSSL

Used by:

- smoke testing of the practical top layer

---

## `dna_mlkem_backend_oracle.h/.cpp`

Role:

- adapter between learn-track tests and the backend/oracle implementation

Responsibilities:

- isolate backend naming/linkage details
- expose backend keypair/encaps/decaps to learn-track parity tests

Used by:

- oracle comparison tests
- many-case regression harness

---

## Test modules

## Early representation and arithmetic tests

These verify the small foundational pieces:

- `test_mlkem_params_768.cpp`
- `test_mlkem_poly_basics.cpp`
- `test_mlkem_poly_bytes.cpp`
- `test_mlkem_polyvec_basics.cpp`
- `test_mlkem_polyvec_bytes.cpp`
- `test_mlkem_poly_compress_dv4.cpp`
- `test_mlkem_poly_compress_du10.cpp`
- `test_mlkem_polyvec_compress_du10.cpp`
- `test_mlkem_field.cpp`
- `test_mlkem_ntt_constants.cpp`

---

## Transform and multiplication tests

These verify the math layer:

- `test_mlkem_basemul_pair.cpp`
- `test_mlkem_poly_ntt_forward.cpp`
- `test_mlkem_poly_invntt_tomont.cpp`
- `test_mlkem_poly_basemul_montgomery.cpp`
- `test_mlkem_poly_mul_via_ntt.cpp`
- `test_mlkem_tomont.cpp`

---

## Sampling tests

These verify noise and uniform sampling:

- `test_mlkem_cbd.cpp`
- `test_mlkem_prf.cpp`
- `test_mlkem_getnoise.cpp`
- `test_mlkem_uniform_rej.cpp`
- `test_mlkem_sample_ntt.cpp`
- `test_mlkem_noisevec.cpp`

---

## Matrix and matvec tests

These verify structured algebra building blocks:

- `test_mlkem_matrix_entry_ntt.cpp`
- `test_mlkem_matrix_full_ntt.cpp`
- `test_mlkem_matvec_row_ntt.cpp`
- `test_mlkem_matvec_full_ntt.cpp`

---

## IND-CPA algebra tests

These verify the core encryption algebra before representation/packing:

- `test_mlkem_indcpa_keygen_skeleton.cpp`
- `test_mlkem_indcpa_encrypt_skeleton.cpp`
- `test_mlkem_indcpa_decrypt_skeleton.cpp`
- `test_mlkem_indcpa_roundtrip_skeleton.cpp`

---

## Representation and packed flow tests

These verify the bridge to practical byte-level behavior:

- `test_mlkem_message.cpp`
- `test_mlkem_indcpa_packed.cpp`
- `test_mlkem_cpapke.cpp`

---

## KEM and parity tests

These verify the final learn-track top layer and oracle comparison:

- `test_mlkem_kem.cpp`
- `test_mlkem_kem_random.cpp`
- `test_mlkem_kem_vs_backend.cpp`
- `test_mlkem_kem_diff_many.cpp`

---

## Review priority map

For future hardening review, the most important modules are:

### Highest priority

- `dna_mlkem_kem.cpp`
- `dna_mlkem_cpapke.cpp`
- `dna_mlkem_indcpa_packed.cpp`

Reason:

- top-level secret handling
- packed behavior
- decapsulation path
- final shared-secret behavior

### High priority

- `dna_mlkem_indcpa_keygen_skeleton.cpp`
- `dna_mlkem_indcpa_encrypt_skeleton.cpp`
- `dna_mlkem_indcpa_decrypt_skeleton.cpp`
- `dna_mlkem_message.cpp`

Reason:

- direct algebra flow
- message representation boundary

### Medium priority

- `dna_mlkem_matvec.cpp`
- `dna_mlkem_matrix_gen.cpp`
- `dna_mlkem_sample_ntt.cpp`
- `dna_mlkem_getnoise.cpp`
- `dna_mlkem_prf.cpp`
- `dna_mlkem_cbd.cpp`

Reason:

- secret-derived arithmetic and sampling behavior

### Lower priority for first pass

- parameter and shape modules
- basic byte helpers already covered by tests
- test harness files themselves

Reason:

- mostly structural
- lower complexity
- easier to re-check later

---

## Freeze note

The learn-track crypto logic should now be treated as frozen except for:

- parity-fixing changes
- correctness fixes found by tests
- documentation or review notes
- additional regression coverage

New feature work should not continue in this directory until review decisions are made.

---

## Summary

This inventory marks the learn track as:

- functionally complete
- organized in layers
- regression-tested
- backend-oracle verified

It is now ready for review-oriented work rather than feature growth.