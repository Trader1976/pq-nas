# ML-KEM-768 learn track checkpoint

## Purpose

This learn track was built to understand ML-KEM-768 step by step in a clean and testable way.

It is intentionally separate from PQ-NAS runtime integration.

Main separation:

- `core/dna_pqcore/` + `tests/dna_pqcore/`
    - backend/oracle track
    - reusable wrapper around vendored `mlkem-native`
    - used as the reference/oracle path

- `core/dna_pqcore_learn/` + `tests/dna_pqcore_learn/`
    - learning implementation track
    - piece-by-piece build of ML-KEM-768
    - focused on understanding, structure, and verification
    - not production-integrated

---

## Final status of the learn track

The learn-track ML-KEM-768 implementation is now complete at the functional level.

It includes:

- finite-field helpers
- polynomial and polyvec basics
- polynomial and polyvec byte encoding
- compression/decompression (`du=10`, `dv=4`)
- NTT constants
- NTT / inverse NTT
- base multiplication in NTT domain
- PRF / CBD / noise sampling
- `SampleNTT`
- matrix entry and full matrix generation
- row and full matrix-vector multiply
- `tomont`
- IND-CPA keygen / encrypt / decrypt algebra skeletons
- IND-CPA roundtrip skeleton
- message polynomial encode/decode
- packed IND-CPA flow
- CPA-PKE wrapper
- deterministic ML-KEM-768 KEM wrapper
- randomized convenience API

Most importantly:

- the learn-track implementation matches the vendored backend oracle end-to-end
- many-case differential regression passes against the backend oracle

---

## What was verified

The following high-level properties are now covered by tests:

### Backend/oracle path

- backend availability
- backend self-test
- backend keygen / encapsulate / decapsulate roundtrip

### Learn-track construction path

- parameter layer
- polynomial arithmetic layer
- polynomial byte layout
- polyvec byte layout
- compression layers
- field math
- NTT constants and scheduling
- forward NTT
- inverse NTT
- base multiplication
- polynomial multiplication via NTT
- CBD
- PRF
- single-poly noise generation
- uniform rejection sampling
- `SampleNTT`
- matrix entry generation
- full matrix generation
- row matvec multiply
- full matvec multiply
- `tomont`
- IND-CPA keygen algebra skeleton
- IND-CPA encrypt algebra skeleton
- IND-CPA decrypt algebra skeleton
- IND-CPA roundtrip skeleton
- message encode/decode
- packed IND-CPA keygen / encrypt / decrypt
- CPA-PKE wrapper
- deterministic KEM wrapper
- randomized KEM convenience API
- direct backend parity harness
- many-case backend differential regression harness

---

## Current confidence level

Confidence is now strong at the functional/correctness level because:

- the implementation was built in very small steps
- each step has an isolated test
- the finished learn-track KEM matches the vendored backend oracle
- many deterministic cases and tamper cases were compared end-to-end

This is a strong stopping point for new crypto feature work in the learn track.

---

## Important caveats

This learn-track code is **not yet production-hardened**.

That means the following are still intentionally out of scope:

- constant-time audit
- side-channel review
- memory cleansing / zeroization review
- API hardening for production use
- misuse resistance review
- integration into PQ-NAS runtime
- operational deployment decisions

So the learn track should currently be treated as:

- educational
- structural
- differential-testable
- oracle-verified

but not yet as production-ready security code.

---

## Recommended next actions

The recommended order from here is:

1. freeze learn-track crypto logic
2. keep only regression fixes if a parity test finds a real bug
3. write a short hardening review checklist
4. only after that, consider any PQ-NAS integration design

In other words:

- no more feature growth in the learn track unless parity or correctness requires it
- next work should focus on review, documentation, and integration planning

---

## Suggested freeze rule

For the learn track, prefer this rule going forward:

- no logic changes unless:
    - a test fails
    - backend parity fails
    - a documented spec mismatch is found

Everything else should be:

- docs
- comments
- review notes
- harness improvements

---

## Summary

The ML-KEM-768 learn track is now functionally complete.

The main learning goal has been achieved:

- build the scheme from the inside out
- verify each layer
- reach full deterministic KEM behavior
- prove parity against the vendored backend oracle

This is now a stable checkpoint.