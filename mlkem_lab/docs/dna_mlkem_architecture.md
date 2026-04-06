# DNA ML-KEM architecture checkpoint

## Purpose

This document describes the current DNA ML-KEM architecture after the provider-layer completion and selector-confidence phase.

It is intentionally focused on:

- the stable DNA-owned API boundary
- the internal provider layering
- the frozen learn-track role
- the permanent regression gates
- the path toward future de-vendoring and native-provider hardening

It does **not** re-explain ML-KEM itself.

---

## Current architectural position

DNA ML-KEM is now organized into four clear layers:

1. **Public DNA API**
2. **Diagnostic surface**
3. **Internal provider selection**
4. **Concrete provider implementations**

The current default selected provider in the lab/dev path is:

- `dna-internal-wip`

The vendored native provider remains present and tested as an explicit fallback.

The learn-track also remains present, but frozen and non-production.

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

### Encapsulation contract

For encapsulation:

- wrong public-key length is an API failure
- structurally invalid public keys are API failures
- valid public keys return `ok` and produce ciphertext + shared secret

This contract is now enforced across both native and DNA provider paths.

### Decapsulation contract

This remains the most important API rule:

- wrong input lengths are API failures
- structurally invalid/corrupted secret keys are API failures
- correctly sized but invalid ciphertext is **not** an API failure
- implicit rejection happens inside the provider
- decapsulation still returns `ok` and produces a shared secret for correctly sized invalid ciphertext

This contract is now enforced by dedicated boundary tests and provider-comparison tests.

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
- `MlKem768ProviderId::dna`

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

### Current default selected provider

In the current lab/dev path, the default selected provider is:

- `MlKem768ProviderId::dna`

### Override support

The selector now also supports internal-only test/dev override mechanisms:

- in-process override for tests/dev
- environment-variable override for process-level test lanes

Supported selections are:

- `native`
- `dna`

Unsupported:

- `stub`

The stub provider remains intentionally non-selectable.

### Why this exists now

The selector seam now supports:

- direct provider-path testing
- cross-provider comparison
- explicit fallback to native
- test/dev forcing of provider choice
- gradual transition away from vendored code

---

## Concrete providers

### Native provider

#### File

- `core/dna_pqcore/internal/dna_mlkem768_provider_native.cpp`

#### Role

This is the vendored-backed provider implementation.

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

### DNA provider

#### File

- `core/dna_pqcore/internal/dna_mlkem768_provider_dna.cpp`

#### Role

This is the current DNA-native provider implementation behind the stable provider seam.

It now implements:

- keygen
- encapsulate
- decapsulate

It is built on the frozen high-level learn-track KEM entry points for the core cryptographic flow, while enforcing the stable DNA boundary contract at the provider boundary.

For boundary compatibility, the DNA provider currently also uses native-backed validation bridging for:

- public-key structural/modulus validation
- secret-key structural/hash validation

This is an intentional compatibility bridge, not the final long-term design.

The concrete DNA provider reports:

- name: `dna-internal-wip`

---

## Public adapter implementation

### File

- `core/dna_pqcore/dna_mlkem768_backend.cpp`

### Role

This file is the stable DNA adapter layer.

It contains:

- public API adapters
- compatibility wrappers
- stable status-to-string mapping
- public wipe helpers
- selftest that exercises the public DNA boundary

It does **not** directly own provider-specific logic.

That provider-specific logic is behind the internal provider seam.

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

### Current use in provider integration

The DNA provider currently reuses the frozen high-level learn-track KEM entry points for:

- deterministic keypair generation
- deterministic encapsulation core
- decapsulation core

This is part of the staged path away from vendored dependency dominance.

---

## Current provider/backend status

### Default selected provider in lab/dev

- `dna-internal-wip`

### Tested fallback provider

- `mlkem-native-c`

### Current relationship to vendored code

The vendored backend is no longer the only meaningful provider path.

It is now:

- isolated behind the internal provider interface
- selectable through the internal selector seam
- retained as an explicit tested fallback
- still used for some provider-local validation bridging in the DNA provider

Caller-facing code no longer depends directly on vendored naming or layout.

This is a strong intermediate state for future de-vendoring.

---

## Secret lifecycle discipline

The boundary includes explicit wipe helpers:

- `mlkem768_wipe_keypair(...)`
- `mlkem768_wipe_encap_result(...)`
- `mlkem768_wipe_shared_secret(...)`

These are safe on null and safe on repeated calls.

Wrapper and provider internals also wipe temporary secret material on failure paths and selftest cleanup paths.

This does **not** yet mean the final secret-container design is complete, but it does establish explicit DNA-owned lifecycle handling at the API boundary.

---

## Stable sizes

The public header exposes stable DNA-owned constants:

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

## Provider confidence and selection lanes

There are now three meaningful confidence lanes in the lab/dev path:

### Default lane

- selected provider defaults to DNA
- exercised by `run_mlkem_lab_freeze_tests`

### Forced-DNA lane

- selected provider forced to DNA through environment override
- exercised by `run_mlkem_lab_freeze_tests_dna_selected`

### Forced-native lane

- selected provider forced to native through environment override
- exercised by `run_mlkem_lab_freeze_tests_native_selected`

This provides both forward confidence and rollback confidence.

---

## Permanent regression gates

The following are now treated as permanent gates for production safety.

### Core wrapper / boundary tests

- `test_dna_mlkem768_backend`
- `test_dna_mlkem768_boundary`
- `test_dna_mlkem768_secret_lifecycle`
- `test_dna_mlkem768_compat`
- `test_dna_mlkem768_provider_identity`

### Provider-path / interop / confidence tests

- `test_dna_mlkem768_provider_by_id`
- `test_dna_mlkem768_dna_keygen_interop`
- `test_dna_mlkem768_dna_encaps_interop`
- `test_dna_mlkem768_dna_decaps_interop`
- `test_dna_mlkem768_provider_matrix`
- `test_dna_mlkem768_selected_provider_override`
- `test_dna_mlkem768_freeze_prefer_dna`
- `test_dna_mlkem768_freeze_prefer_native`

### Learn-track / oracle safety gates

- `test_mlkem_kem_vs_backend`
- `test_mlkem_kem_diff_many`
- `test_mlkem_kem_diff_fuzz`

### Freeze targets

- `run_mlkem_lab_freeze_tests`
- `run_mlkem_lab_freeze_tests_dna_selected`
- `run_mlkem_lab_freeze_tests_native_selected`

These tests currently verify:

- wrapper smoke path
- boundary contract
- secret lifecycle
- compatibility behavior
- provider identity
- direct by-id provider routing
- DNA/native interoperability
- provider matrix behavior across valid and tampered cases
- selected-provider override behavior
- default DNA freeze lane
- forced DNA freeze lane
- forced native freeze lane
- parity with learn-track
- many-case differential behavior
- fuzz differential behavior

---

## What is intentionally not done yet

The following are intentionally deferred:

- removal of vendored `mlkem-native`
- removal of the native-backed validation bridge inside the DNA provider
- runtime-configurable user-facing provider selection
- secure custom secret-container type replacing `std::vector<uint8_t>`
- removal of compatibility wrappers
- public deprecation policy for compatibility wrappers
- final provider hardening review for constant-time / side-channel confidence
- final long-term policy decision on whether native fallback should remain

Those are future steps, not current checkpoint claims.

---

## Current architectural summary

At this checkpoint, DNA ML-KEM should be understood as:

- a stable DNA-owned public boundary
- backed by an internal provider seam
- with a structurally complete DNA provider
- with the DNA provider now serving as the default selected provider in lab/dev
- with the vendored native provider still available as an explicitly tested fallback
- protected by frozen learn-track parity/differential regression gates and multi-lane provider confidence tests

This is now a production-shaped integration boundary with a practical DNA-default lab path.

---

## Next recommended direction

The next meaningful phase should focus on hardening and cleanup rather than adding new architecture.

Recommended next areas are:

1. hardening review of the DNA provider path
2. removal or reduction of native-backed validation bridging
3. longer soak/testing period with DNA as default in lab/dev
4. eventual decision on whether the native fallback should remain long-term
5. future de-vendoring cleanup once confidence is high enough

The public API should remain stable while those steps happen underneath it.