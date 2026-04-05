# DNA ML-KEM architecture checkpoint

## Purpose

This document describes the current DNA ML-KEM architecture after the first production-readiness hardening phase.

It is intentionally focused on:

- the stable DNA-owned API boundary
- the internal provider layering
- the frozen learn-track role
- the permanent regression gates
- the path toward future provider replacement and eventual de-vendoring

It does **not** re-explain ML-KEM itself.

---

## Current architectural position

DNA ML-KEM is now organized into four clear layers:

1. **Public DNA API**
2. **Diagnostic surface**
3. **Internal provider selection**
4. **Concrete provider implementations**

The current active provider is:

- `mlkem-native-c`

The learn-track remains present, but frozen and non-production.

---

## Public DNA API

### File

- `core/dna_pqcore/dna_mlkem768_backend.h`

### Role

This is the stable DNA-owned ML-KEM-768 API boundary.

Callers should depend on this layer, not on vendored headers or provider details.

### Public production surface

The public production surface currently includes:

- `MlKem768Status`
- `MlKem768Keypair`
- `MlKem768EncapResult`
- `kMlKem768PublicKeyBytes`
- `kMlKem768SecretKeyBytes`
- `kMlKem768CiphertextBytes`
- `kMlKem768SharedSecretBytes`
- `mlkem768_wipe_keypair(...)`
- `mlkem768_wipe_encap_result(...)`
- `mlkem768_wipe_shared_secret(...)`
- `mlkem768_keygen_status(...)`
- `mlkem768_encapsulate_status(...)`
- `mlkem768_decapsulate_status(...)`

Compatibility helpers are also still exposed:

- `mlkem768_keygen(...)`
- `mlkem768_encapsulate(...)`
- `mlkem768_decapsulate(...)`

### Public contract

The status-returning API is the preferred production API.

The bool + error-string wrappers are compatibility helpers for existing call sites.

### Decapsulation contract

This is the most important API rule:

- wrong input lengths are API failures
- structurally invalid/corrupted secret keys are API failures
- correctly sized but invalid ciphertext is **not** an API failure
- implicit rejection happens inside the provider
- decapsulation still returns `ok` and produces a shared secret for correctly sized invalid ciphertext

This contract is now enforced by dedicated boundary tests.

---

## Diagnostic surface

### File

- `core/dna_pqcore/internal/dna_mlkem768_backend_diag.h`

### Role

This contains helpers that are useful for:

- tests
- startup checks
- diagnostics

but are intentionally separated from the public production API.

### Current diagnostic helpers

- `mlkem768_available()`
- `mlkem768_backend_name()`
- `mlkem768_selftest(...)`

These remain useful, but they are not part of the intended long-term production crypto surface.

---

## Internal provider interface

### File

- `core/dna_pqcore/internal/dna_mlkem768_provider.h`

### Role

This defines the internal provider contract behind the stable DNA API.

It is not public.

### Current internal provider types

- `MlKem768ProviderId::native`
- `MlKem768ProviderId::stub`

### Provider responsibilities

A provider implementation must satisfy:

- stable DNA size expectations
- stable DNA status contract
- output wipe discipline
- implicit-rejection decapsulation behavior
- provider identity reporting

The provider layer is where backend-specific integration belongs.

---

## Internal provider selector

### Files

- `core/dna_pqcore/internal/dna_mlkem768_provider_select.h`
- `core/dna_pqcore/internal/dna_mlkem768_provider_select.cpp`

### Role

This layer selects the currently active internal provider and dispatches calls to it.

Today this is intentionally simple.

### Current selected provider

- `MlKem768ProviderId::native`

### Why this exists now

Even with only one real provider, the selector seam is valuable because it prepares for:

- additional providers later
- controlled provider comparison
- future replacement of vendored code
- eventual DNA-native provider work

---

## Concrete providers

### Native provider

#### File

- `core/dna_pqcore/internal/dna_mlkem768_provider_native.cpp`

#### Role

This is the current real provider implementation.

It is backed by the vendored `mlkem-native` code and is responsible for:

- wrapper-owned randomness for keygen/encapsulate
- native provider calls
- mapping provider failures into stable DNA statuses

The concrete native provider reports:

- name: `mlkem-native-c`

### Stub provider

#### File

- `core/dna_pqcore/internal/dna_mlkem768_provider_stub.cpp`

#### Role

This is a non-crypto placeholder provider.

It exists to prove that the selector and provider layering are real and multi-provider capable.

It intentionally:

- reports unavailable
- returns `provider_failed`
- preserves output wipe discipline

The concrete stub provider reports:

- name: `stub-unavailable`

---

## Public adapter implementation

### File

- `core/dna_pqcore/dna_mlkem768_backend.cpp`

### Role

This file is now the stable DNA adapter layer.

It should contain:

- public API adapters
- compatibility wrappers
- stable status-to-string mapping
- public wipe helpers
- selftest that exercises the public DNA boundary

It should **not** directly own provider-specific logic anymore.

That provider-specific logic has been moved behind the internal provider seam.

---

## Learn-track role

### Directory

- `core/dna_pqcore_learn/`

### Role

The learn-track is frozen.

It is retained only as:

- reference implementation
- regression oracle
- understanding/spec aid

It is **not** the production path.

### Rule

Do not evolve learn-track crypto logic unless parity tests reveal a real bug.

---

## Current provider/backend status

### Active provider

- `mlkem-native-c`

### Current relationship to vendored code

The vendored backend is still present and active, but it is now isolated behind:

- internal provider interface
- internal provider selector
- stable DNA public API

That means caller-facing code no longer depends directly on vendored naming or layout.

This is the desired intermediate state before future de-vendoring work.

---

## Secret lifecycle discipline

The current boundary now includes explicit wipe helpers:

- `mlkem768_wipe_keypair(...)`
- `mlkem768_wipe_encap_result(...)`
- `mlkem768_wipe_shared_secret(...)`

These are safe on null and safe on repeated calls.

Wrapper internals also wipe temporary secret material on failure paths and selftest cleanup paths.

This does **not** yet mean the final secret-container design is complete, but it does establish explicit DNA-owned lifecycle handling at the API boundary.

---

## Stable sizes

The public header now exposes stable DNA-owned constants:

- `kMlKem768PublicKeyBytes = 1184`
- `kMlKem768SecretKeyBytes = 2400`
- `kMlKem768CiphertextBytes = 1088`
- `kMlKem768SharedSecretBytes = 32`

Callers and tests should use these constants rather than hardcoded literals.

---

## Stable status surface

The public status surface currently includes:

- `ok`
- `output_null`
- `bad_public_key_len`
- `bad_secret_key_len`
- `bad_ciphertext_len`
- `invalid_public_key`
- `invalid_secret_key`
- `random_failed`
- `provider_failed`

This is the preferred production-facing result model.

The bool + error-string wrappers map these statuses into stable coarse strings for compatibility.

---

## Permanent regression gates

The following are now treated as permanent gates for production safety:

### Core wrapper / boundary tests

- `test_dna_mlkem768_backend`
- `test_dna_mlkem768_boundary`
- `test_dna_mlkem768_secret_lifecycle`
- `test_dna_mlkem768_compat`
- `test_dna_mlkem768_provider_identity`

### Learn-track / oracle safety gates

- `test_mlkem_kem_vs_backend`
- `test_mlkem_kem_diff_many`
- `test_mlkem_kem_diff_fuzz`

### Freeze target

- `run_mlkem_lab_freeze_tests`

These tests currently verify:

- wrapper smoke path
- boundary contract
- secret lifecycle
- compatibility behavior
- provider identity
- parity with learn-track
- many-case differential behavior
- fuzz differential behavior

---

## What is intentionally not done yet

The following are intentionally deferred:

- removal of vendored `mlkem-native`
- addition of a real second provider
- runtime-configurable provider selection
- secure custom secret-container type replacing `std::vector<uint8_t>`
- removal of compatibility wrappers
- public deprecation policy for compatibility wrappers
- DNA-native ML-KEM provider implementation

Those are future steps, not current checkpoint claims.

---

## Current architectural summary

At this checkpoint, DNA ML-KEM should be understood as:

- a stable DNA-owned public boundary
- backed by an internal provider seam
- currently routed to a native vendored provider
- protected by frozen learn-track parity/differential regression gates

This is now a production-shaped integration boundary, even though the active provider is still vendored.

---

## Next recommended direction

The next meaningful phase should focus on one of:

1. defining the exact contract a future DNA-native provider must satisfy
2. adding by-id internal selector dispatch for direct provider-path testing
3. beginning an experimental DNA-native provider implementation behind the same internal provider contract

The public API should remain stable while those steps happen underneath it.