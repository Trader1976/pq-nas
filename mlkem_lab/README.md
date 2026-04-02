# ML-KEM lab

This directory contains the isolated ML-KEM learning and validation workspace.

Purpose:

- keep ML-KEM learning work out of the main PQ-NAS build
- preserve the learn-track implementation and tests
- keep backend parity and fuzz validation easy to run
- keep review and hardening notes in one place

Main pieces:

- `CMakeLists.txt`
    - standalone build entry for the ML-KEM lab
- `docs/`
    - checkpoint, hardening, inventory, and review notes
- source code remains in:
    - `core/dna_pqcore/`
    - `core/dna_pqcore_learn/`
    - `tests/dna_pqcore/`
    - `tests/dna_pqcore_learn/`

Build:

```bash
cd ~/CLionProjects/pq-nas
cmake -S mlkem_lab -B build-mlkem
cmake --build build-mlkem -j

Run the freeze set:

cmake --build build-mlkem --target run_mlkem_lab_freeze_tests

Run the fuzz harness directly:

./build-mlkem/bin/test_mlkem_kem_diff_fuzz
./build-mlkem/bin/test_mlkem_kem_diff_fuzz 10000
./build-mlkem/bin/test_mlkem_kem_diff_fuzz 10000 0x12345678 8

Status:

learn-track is functionally complete
backend parity passes
differential fuzz passes
production hardening is still a separate step

Then commit it:

```bash
cd ~/CLionProjects/pq-nas
git add mlkem_lab/CMakeLists.txt mlkem_lab/README.md mlkem_lab/docs
git commit -m "mlkem_lab: move ML-KEM docs into standalone lab"