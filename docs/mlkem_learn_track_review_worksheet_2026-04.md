# ML-KEM-768 learn track review worksheet

## Purpose

This worksheet is for reviewing the frozen ML-KEM-768 learn track module by module.

Use it after:

- `mlkem_learn_track_checkpoint_2026-04.md`
- `mlkem_learn_track_hardening_checklist_2026-04.md`
- `mlkem_learn_track_module_inventory_2026-04.md`

This file is intentionally operational.

It is meant to be updated during review work.

---

## Review status scale

Use one of these values for each module:

- `not started`
- `in review`
- `reviewed`
- `reviewed with follow-up`
- `frozen`

Recommended meaning:

- `not started`
    - no serious review yet
- `in review`
    - currently being inspected
- `reviewed`
    - reviewed, no action needed
- `reviewed with follow-up`
    - findings exist, but not necessarily logic bugs
- `frozen`
    - reviewed and accepted for learn-track freeze

---

## Review rule

The learn track is frozen unless one of these is true:

- a test fails
- backend parity fails
- a real correctness bug is found
- a spec mismatch is confirmed

Otherwise, changes should prefer:

- docs
- comments
- review notes
- more regression coverage

---

## High-level review board

| Module | Status | Constant-time note | Secret lifetime note | Representation note | Action |
|---|---|---|---|---|---|
| `dna_mlkem_kem.cpp` | not started |  |  |  |  |
| `dna_mlkem_cpapke.cpp` | not started |  |  |  |  |
| `dna_mlkem_indcpa_packed.cpp` | not started |  |  |  |  |
| `dna_mlkem_message.cpp` | not started |  |  |  |  |
| `dna_mlkem_indcpa_keygen_skeleton.cpp` | not started |  |  |  |  |
| `dna_mlkem_indcpa_encrypt_skeleton.cpp` | not started |  |  |  |  |
| `dna_mlkem_indcpa_decrypt_skeleton.cpp` | not started |  |  |  |  |
| `dna_mlkem_matvec.cpp` | not started |  |  |  |  |
| `dna_mlkem_matrix_gen.cpp` | not started |  |  |  |  |
| `dna_mlkem_sample_ntt.cpp` | not started |  |  |  |  |
| `dna_mlkem_getnoise.cpp` | not started |  |  |  |  |
| `dna_mlkem_prf.cpp` | not started |  |  |  |  |
| `dna_mlkem_cbd.cpp` | not started |  |  |  |  |
| `dna_mlkem_ntt.cpp` | not started |  |  |  |  |
| `dna_mlkem_tomont.cpp` | not started |  |  |  |  |
| `dna_mlkem_field.cpp` | not started |  |  |  |  |
| `dna_mlkem_backend_oracle.cpp` | not started |  |  |  |  |
| `test_mlkem_kem_vs_backend.cpp` | not started | n/a | n/a |  |  |
| `test_mlkem_kem_diff_many.cpp` | not started | n/a | n/a |  |  |

---

## Review worksheet template

Copy this section once per module during actual review.

### Module
`<module path>`

### Status
`not started`

### Purpose
Short description of what this module does.

### Inputs that may be secret
- [ ] none
- [ ] seed material
- [ ] secret key material
- [ ] intermediate shared-secret material
- [ ] decrypted message material
- [ ] noise / coins / randomness
- [ ] other:

### Review notes

#### 1. Constant-time concerns
- branches depending on secret data:
- comparisons depending on secret data:
- data-dependent memory access:
- early-return behavior:
- conclusion:

#### 2. Secret lifetime concerns
- local secret buffers:
- buffers copied but not cleared:
- outputs left populated on failure:
- conclusion:

#### 3. Representation / packing concerns
- canonical vs signed-centered:
- montgomery-domain transitions:
- packing / unpacking assumptions:
- decode thresholds / rounding:
- conclusion:

#### 4. API / misuse concerns
- null handling:
- caller assumptions:
- confusing naming:
- internal helper exposure:
- conclusion:

#### 5. Test coverage
- directly covered by:
- indirectly covered by:
- additional coverage desired:

### Action
Choose one:

- [ ] no change
- [ ] docs only
- [ ] comments only
- [ ] more regression tests
- [ ] targeted correctness fix required
- [ ] hardening note only

### Final status
`reviewed`

---

## Suggested review order tracker

Mark these in order.

- [ ] `core/dna_pqcore_learn/dna_mlkem_kem.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_cpapke.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_indcpa_packed.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_message.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_indcpa_keygen_skeleton.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_indcpa_encrypt_skeleton.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_indcpa_decrypt_skeleton.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_matvec.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_matrix_gen.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_sample_ntt.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_getnoise.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_prf.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_cbd.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_ntt.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_tomont.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_field.cpp`
- [ ] `core/dna_pqcore_learn/dna_mlkem_backend_oracle.cpp`
- [ ] `tests/dna_pqcore_learn/test_mlkem_kem_vs_backend.cpp`
- [ ] `tests/dna_pqcore_learn/test_mlkem_kem_diff_many.cpp`

---

## Regression sign-off

Before calling the learn track frozen, confirm all of these:

- [ ] backend/oracle test passes
- [ ] many-case differential test passes
- [ ] deterministic KEM test passes
- [ ] randomized API smoke test passes
- [ ] packed IND-CPA flow test passes
- [ ] CPA-PKE wrapper test passes
- [ ] message encode/decode test passes
- [ ] no unresolved correctness mismatches remain

Optional stronger sign-off:

- [ ] rerun all `tests/dna_pqcore_learn/`
- [ ] rerun backend self-test
- [ ] rerun parity harness after clean rebuild

---

## Freeze decision

Use this only when review is done.

### Functional state
- [ ] accepted
- [ ] not accepted yet

### Hardening state
- [ ] reviewed enough for frozen learn-track status
- [ ] more review still needed

### Production readiness
- [ ] not claimed
- [ ] explicitly out of scope

### Notes
Write final review summary here.

---

## Final summary template

Use this when the review pass is complete.

```text
ML-KEM-768 learn track review summary

Functional state:
- frozen
- backend parity passing
- many-case differential regression passing

Hardening state:
- reviewed for learn-track freeze
- not claimed production-hardened

Allowed future changes:
- regression fixes
- parity fixes
- spec mismatch fixes
- docs/comments/tests only unless correctness requires more