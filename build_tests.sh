#!/bin/bash
cmake --build build -j --target verify_v4_vectors test_admin_cookie && \
./build/bin/verify_v4_vectors tests/v4_vectors/vectors.json && \
./build/bin/test_admin_cookie
