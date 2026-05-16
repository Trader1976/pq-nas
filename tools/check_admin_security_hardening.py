#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "server/src/main.cpp"
TOK_H = ROOT / "server/include/app_tokens.h"
TOK_CPP = ROOT / "server/src/app_tokens.cpp"

def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)

def ok(msg):
    print("OK:", msg)

for p in [MAIN, TOK_H, TOK_CPP]:
    if not p.exists():
        fail(f"missing file: {p}")

main = MAIN.read_text()
tok_h = TOK_H.read_text()
tok_cpp = TOK_CPP.read_text()

for needle in [
    "admin_would_remove_last_enabled_admin",
    "self_disable",
    "last_admin",
]:
    if needle not in main:
        fail(f"missing admin lockout guard marker: {needle}")
ok("admin self-disable / last-admin guard markers exist")

if "revoke_devices_for_fingerprint" not in tok_h or "AppTokenStore::revoke_devices_for_fingerprint" not in tok_cpp:
    fail("missing AppTokenStore revoke_devices_for_fingerprint")
if "g_app_tokens.revoke_devices_for_fingerprint(fp" not in main:
    fail("main.cpp does not revoke app tokens on admin status changes")
ok("app token revocation on disabled/revoked users is wired")

for forbidden in [
    '{"user_dir"',
    '{"data_root"',
    '{"pool_mount"',
]:
    if forbidden in main:
        fail(f"absolute path response key still present: {forbidden}")
ok("absolute filesystem path response keys are absent")

# Optional hardening item not enforced here:
# GET /api/v4/admin/users read-audit should be wired with the real audit helper
# once the local main.cpp audit API shape is inspected.
print("SKIP: admin user-list read audit marker is optional in this source check")

# Check that admin/storage/raid/poolmgr POST routes with admin auth have same-origin guard.
def route_blocks(src):
    out = []
    for m in re.finditer(r'srv\.Post\("([^"]+)"', src):
        route = m.group(1)
        start = m.start()
        # Lightweight route-body window; enough for source regression, not a C++ parser.
        next_route = src.find('srv.', start + 1)
        end = next_route if next_route >= 0 else len(src)
        out.append((route, src[start:end]))
    return out

target_prefixes = (
    "/api/v4/admin/",
    "/api/v4/storage/",
    "/api/v4/raid/",
    "/api/v4/poolmgr/",
)

missing_csrf = []
for route, block in route_blocks(main):
    if not route.startswith(target_prefixes):
        continue
    if "require_admin_" not in block:
        continue
    if "require_same_origin_for_cookie_mutation" not in block:
        missing_csrf.append(route)

if missing_csrf:
    fail("admin POST route(s) missing same-origin guard: " + ", ".join(missing_csrf))

ok("admin/storage/raid/poolmgr admin POST routes have same-origin guard")
print("All admin security hardening source checks passed.")
