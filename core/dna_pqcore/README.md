# dna_pqcore

Experimental reusable PQ crypto area for the DNA / PQ-NAS ecosystem.

Current scope:
- isolated ML-KEM-768 backend wrapper
- test-only
- not wired into PQ-NAS production flow yet

Rules for this folder:
- keep it independent from current PQ share route code
- build confidence with small tests first
- extract stable APIs before reusing anywhere else
- no app-specific wire format assumptions here unless intentionally added later

Planned growth:
- ML-KEM backend wrapper
- CEK wrap/unwrap helpers
- stream-v2 chunk helpers
- selftests / known-answer tests
- optional browser/WASM-facing compatibility layer later