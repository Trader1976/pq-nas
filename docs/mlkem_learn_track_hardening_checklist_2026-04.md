# ML-KEM-768 learn track hardening checklist

## Purpose

This document is the follow-up freeze checklist for the ML-KEM-768 learn track.

The learn track is functionally complete and matches the vendored backend oracle.
From this point onward, new work should focus on review and hardening, not feature growth.

This checklist is intentionally practical.

---

## Scope

This checklist applies to:

- `core/dna_pqcore_learn/`
- `tests/dna_pqcore_learn/`

It does **not** by itself approve production use.

Its purpose is to identify what would still need review before any production-facing use or integration planning.

---

## Current state

Already achieved:

- functional ML-KEM-768 learn-track implementation
- deterministic and randomized APIs
- packed CPA-PKE flow
- deterministic KEM wrapper
- backend oracle parity
- many-case differential regression

Not yet claimed:

- constant-time safety
- side-channel resistance
- memory-zeroization completeness
- hardened API behavior under misuse
- production integration readiness

---

## Freeze rule

From this checkpoint onward:

- do not add new crypto features in the learn track
- only change crypto logic if:
    - a test fails
    - backend parity fails
    - a spec mismatch is confirmed

Allowed changes:

- comments
- docs
- review notes
- additional regression tests
- narrowly-scoped fixes required by parity or correctness

---

## Hardening checklist

## 1. Constant-time review

Goal:

- identify every branch, lookup, or memory-access pattern that may depend on secret data

Review items:

- [ ] inspect all secret-dependent branches in:
    - keygen path
    - encaps path
    - decaps path
- [ ] inspect all comparisons involving:
    - shared secrets
    - decrypted message bytes
    - recomputed ciphertext vs input ciphertext
- [ ] inspect all uses of:
    - `if`
    - early returns
    - loops with secret-dependent stopping conditions
- [ ] inspect array indexing for secret-dependent access patterns
- [ ] inspect message decode logic for branch behavior
- [ ] inspect compression/decompression helpers for secret-dependent branching
- [ ] inspect rejection/failure paths in decapsulation
- [ ] inspect any use of standard library code that may not be constant-time

Specific learn-track concern:

- the learn track prioritizes clarity, so some logic may be intentionally not constant-time even if it is functionally correct

Decision output:

- classify each function as:
    - clearly not constant-time
    - probably constant-time
    - needs deeper review

---

## 2. Secret data lifetime review

Goal:

- identify where secrets remain in memory longer than needed

Review items:

- [ ] list all buffers that may hold secrets:
    - `d`
    - `z`
    - `rho`
    - `sigma`
    - `m`
    - `m_prime`
    - `kr`
    - `hpk`
    - `kbar`
    - `coins`
    - `s_hat`
    - `e_hat`
    - `r_hat`
    - shared secret buffers
- [ ] inspect stack arrays holding secrets in:
    - CPA-PKE wrapper
    - KEM wrapper
    - backend parity harness
- [ ] decide which buffers should be explicitly zeroized
- [ ] note where `std::array` or local raw arrays currently remain uncleared
- [ ] decide whether a dedicated zeroization helper is needed
- [ ] ensure zeroization cannot be optimized away if later added

Important note:

- learn-track tests may intentionally keep intermediate values for verification
- that is acceptable for tests, but not for production-facing code

---

## 3. API misuse review

Goal:

- identify ways the current API could be used incorrectly

Review items:

- [ ] check all public learn-track entry points for null handling
- [ ] check all size assumptions are encoded clearly in type signatures or constants
- [ ] check whether function names clearly signal:
    - deterministic vs randomized
    - packed vs unpacked
    - learn-track only vs production-intended
- [ ] check whether any function makes unsafe assumptions about caller-owned buffers
- [ ] check whether decapsulation APIs expose too much detail in error behavior
- [ ] check whether helper names might be confused with production-safe implementations

Questions to answer:

- should some helpers remain internal-only?
- should some helpers be renamed to make “learn only” more obvious?
- should some headers carry stronger warning comments?

---

## 4. Error-handling review

Goal:

- ensure error behavior is understandable, consistent, and does not create accidental leakage patterns

Review items:

- [ ] inspect all `bool` + `std::string* err` paths
- [ ] ensure internal failures are described consistently
- [ ] identify places where errors distinguish too much detail
- [ ] inspect decapsulation failure path handling
- [ ] check whether any OpenSSL error path leaves partial outputs in user buffers
- [ ] decide whether outputs should be zeroed on failure in future hardened code

Specific concern:

- a learn-track implementation may be fine with descriptive errors
- production-facing code often needs a stricter failure surface

---

## 5. Packing and canonicalization review

Goal:

- confirm all packing/unpacking and modular representations are stable and explicit

Review items:

- [ ] verify all pack/unpack helpers treat coefficients consistently
- [ ] verify all comparisons use the intended representation:
    - raw representation
    - canonical mod-q representation
- [ ] inspect all places where signed-centered and canonical forms meet
- [ ] inspect message encode/decode threshold behavior
- [ ] inspect ciphertext compression rounding behavior
- [ ] inspect `tomont` and `from_montgomery` boundaries
- [ ] inspect all places where parity tests compare decoded vs raw byte forms

This matters because:

- several earlier mismatches were representation mismatches, not algebra failures

---

## 6. Differential regression coverage review

Goal:

- confirm the current regression harnesses are broad enough to freeze the learn track

Review items:

- [ ] verify `kem vs backend` covers:
    - deterministic keypair
    - deterministic encaps
    - decaps
    - tampered ciphertext path
- [ ] verify `kem diff many` covers many distinct seeds/messages
- [ ] consider increasing case counts later if needed
- [ ] consider adding edge-pattern inputs:
    - all-zero seed
    - all-FF seed
    - alternating bytes
    - repeated small patterns
- [ ] consider adding fixed seed corpus for long-term regression reproducibility

Decision output:

- decide whether current coverage is enough for freeze
- or whether a second larger regression tier is needed

---

## 7. Dependency and crypto primitive review

Goal:

- make sure assumptions about OpenSSL usage are explicit

Review items:

- [ ] list all OpenSSL primitives currently used
- [ ] confirm SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 usage matches intent
- [ ] confirm `RAND_bytes` is only used in randomized convenience APIs
- [ ] confirm deterministic APIs do not accidentally pull randomness
- [ ] decide whether backend-oracle tests should remain tied to current vendored backend behavior
- [ ] note any behavioral dependence on backend-specific conventions

Important distinction:

- the learn track currently matches the vendored backend oracle
- that is the reference for this repo checkpoint
- spec wording and backend behavior should both be documented if they differ in presentation details

---

## 8. Documentation review

Goal:

- make the current frozen state easy to understand later

Review items:

- [ ] each top-level learn-track API should say whether it is:
    - deterministic
    - randomized
    - packed
    - unpacked
    - learn-track only
- [ ] KEM secret-key layout should be documented in one place
- [ ] backend parity assumptions should be documented
- [ ] “not production-hardened” warning should remain visible
- [ ] explain that oracle parity is a strong functional check, not a side-channel proof

---

## 9. Integration readiness review

Goal:

- decide what must happen before any PQ-NAS integration discussion

Required before integration planning:

- [ ] constant-time review completed
- [ ] secret zeroization plan documented
- [ ] API misuse review completed
- [ ] learn-track freeze accepted
- [ ] clear boundary decided between:
    - educational code
    - reusable hardened code
    - backend/oracle code

Important rule:

- do not wire the learn track into PQ-NAS runtime just because functional tests pass

---

## 10. Review outcome template

Use this for each reviewed file or module:

### Module:
`<name>`

### Status:
- [ ] reviewed
- [ ] needs follow-up

### Findings:
- constant-time:
- secret lifetime:
- misuse risk:
- representation risk:
- documentation gaps:

### Action:
- [ ] no change
- [ ] docs only
- [ ] tests only
- [ ] targeted code fix required

---

## Suggested review order

Recommended sequence:

1. `dna_mlkem_kem.cpp`
2. `dna_mlkem_cpapke.cpp`
3. `dna_mlkem_indcpa_packed.cpp`
4. `dna_mlkem_message.cpp`
5. `dna_mlkem_indcpa_*_skeleton.cpp`
6. `dna_mlkem_matvec.cpp`
7. `dna_mlkem_matrix_gen.cpp`
8. `dna_mlkem_sample_ntt.cpp`
9. `dna_mlkem_getnoise.cpp` / `dna_mlkem_prf.cpp` / `dna_mlkem_cbd.cpp`
10. `dna_mlkem_ntt.cpp` / `dna_mlkem_tomont.cpp` / field helpers
11. backend parity harnesses and randomized convenience API

This order reviews the highest-level secret-handling code first.

---

## Minimal acceptance bar for freezing the learn track

The learn track can be considered frozen when:

- [ ] all current tests pass
- [ ] backend parity passes
- [ ] many-case differential harness passes
- [ ] no unresolved functional mismatches remain
- [ ] this hardening checklist has been reviewed and triaged

That does **not** mean production-ready.
It means functionally frozen and review-ready.

---

## Summary

The learn track is now in the correct phase transition:

- from building
- to reviewing

That is the right time to stop expanding crypto logic and start documenting the risks and boundaries clearly.