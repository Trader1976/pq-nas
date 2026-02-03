#!/usr/bin/env bash
set -euo pipefail

# PQ-NAS release tarball builder
# Usage:
#   ./tools/release/make_tarball.sh 0.9.0
# Output:
#   /tmp/pqnas-release/pqnas-<ver>-linux-x86_64.tar.gz

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <version>   (example: $0 0.9.0)"
  exit 1
fi

VER="$1"
ARCH="x86_64"
OUTDIR="/tmp/pqnas-release"
STAGE="$OUTDIR/pqnas"
TARBALL="$OUTDIR/pqnas-${VER}-linux-${ARCH}.tar.gz"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RELEASE_CFG_DIR="$REPO_ROOT/tools/release/config"

echo "[*] Repo root: $REPO_ROOT"
echo "[*] Version:   $VER"
echo "[*] Stage:     $STAGE"
echo "[*] Output:    $TARBALL"

# ---- Safety: refuse to ship dev state from repo config/ ----
# If you REALLY want to ship repo config, you'd explicitly disable this check.
if grep -R --line-number --binary-files=without-match \
  -E '"fingerprint"\s*:|"token"\s*:|"owner_fp"\s*:|"storage_set_by"\s*:|nas\.example\.com' \
  "$REPO_ROOT/config" >/dev/null 2>&1; then
  echo "ERROR: $REPO_ROOT/config appears to contain dev/state data (fingerprints/tokens/etc)." >&2
  echo "Release tarballs must use clean templates from: $RELEASE_CFG_DIR" >&2
  echo "Fix by putting sanitized defaults into tools/release/config/." >&2
  exit 1
fi

# ---- Require release templates to exist ----
for f in admin_settings.json policy.json users.json shares.json; do
  if [[ ! -f "$RELEASE_CFG_DIR/$f" ]]; then
    echo "ERROR: Missing release template: $RELEASE_CFG_DIR/$f" >&2
    echo "Create it (sanitized) so release tarballs never ship your local settings." >&2
    exit 1
  fi
done

rm -rf "$OUTDIR"
mkdir -p "$STAGE"

# ---- 1) Build binaries (adjust generator if you prefer Ninja/Make) ----
echo "[*] Building pqnas_server + pqnas_keygen..."
cmake --build "$REPO_ROOT/build" --target pqnas_server pqnas_keygen

# Verify binaries exist
test -x "$REPO_ROOT/build/bin/pqnas_server"
test -x "$REPO_ROOT/build/bin/pqnas_keygen"

# ---- 2) Stage package layout expected by installer ----
# Package layout root (extracted dir) contains:
#   pqnas_server
#   pqnas_keygen
#   static/        (copied from server/src/static)
#   bundled/       (copied from apps/bundled)
#   config/        (defaults)   <-- IMPORTANT: comes from tools/release/config/
#   installer/     (pqnas_install.py etc)
#   docs/          (optional)
#   README.md

echo "[*] Staging files..."

# Top-level installer entrypoint (for end users)
if [[ -f "$REPO_ROOT/install.sh" ]]; then
  install -m 0755 "$REPO_ROOT/install.sh" "$STAGE/install.sh"
else
  echo "[!] Missing $REPO_ROOT/install.sh (top-level installer launcher)."
fi

# Binaries at package root
install -m 0755 "$REPO_ROOT/build/bin/pqnas_server" "$STAGE/pqnas_server"
install -m 0755 "$REPO_ROOT/build/bin/pqnas_keygen" "$STAGE/pqnas_keygen"

# Static web assets (package-mode)
rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  "$REPO_ROOT/server/src/static/" "$STAGE/static/"

# Bundled apps (zips + any bundled folders)
if [[ -d "$REPO_ROOT/apps/bundled" ]]; then
  rsync -a --delete \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    "$REPO_ROOT/apps/bundled/" "$STAGE/bundled/"
else
  mkdir -p "$STAGE/bundled"
fi

# Default config (IMPORTANT: always from tools/release/config, never repo config/)
mkdir -p "$STAGE/config"
rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  "$RELEASE_CFG_DIR/" "$STAGE/config/"

# Extra safety: ensure staged config is clean too
if grep -R --line-number --binary-files=without-match \
  -E '"fingerprint"\s*:|"token"\s*:|"owner_fp"\s*:|"storage_set_by"\s*:|nas\.example\.com' \
  "$STAGE/config" >/dev/null 2>&1; then
  echo "ERROR: Staged config contains dev/state markers. Check tools/release/config/*." >&2
  exit 1
fi

# Installer (your textual wizard)
# (If your installer folder is tools/installer, copy that.)
if [[ -d "$REPO_ROOT/tools/installer" ]]; then
  rsync -a --delete \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    "$REPO_ROOT/tools/installer/" "$STAGE/installer/"
else
  echo "[!] Missing tools/installer (expected installer script)."
  mkdir -p "$STAGE/installer"
fi

# Docs (optional)
if [[ -d "$REPO_ROOT/docs" ]]; then
  rsync -a --delete \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    "$REPO_ROOT/docs/" "$STAGE/docs/"
fi

# README
if [[ -f "$REPO_ROOT/README.md" ]]; then
  install -m 0644 "$REPO_ROOT/README.md" "$STAGE/README.md"
fi

if [[ -f "$REPO_ROOT/LICENSE" ]]; then
  install -m 0644 "$REPO_ROOT/LICENSE" "$STAGE/LICENSE"
fi

# ---- 3) Clean junk that should never ship ----
echo "[*] Cleaning __pycache__ and *.pyc..."
find "$STAGE" -type d -name '__pycache__' -prune -exec rm -rf {} + || true
find "$STAGE" -type f -name '*.pyc' -delete || true

# ---- 4) Create tarball ----
echo "[*] Creating tarball..."
(
  cd "$OUTDIR"
  tar -czf "$(basename "$TARBALL")" pqnas
)

echo "[*] Done."
ls -lh "$TARBALL"

echo
echo "Test extract:"
echo "  rm -rf /tmp/pqnas-test && mkdir -p /tmp/pqnas-test"
echo "  tar -xzf '$TARBALL' -C /tmp/pqnas-test"
echo "  ls -la /tmp/pqnas-test/pqnas"
echo
echo "============================================================"
echo " PQ-NAS INSTALL QUICK START"
echo "============================================================"
echo
echo "1) Copy tarball to target server"
echo "2) Extract:"
echo "     tar -xzf $(basename "$TARBALL")"
echo "     cd pqnas"
echo
echo "3) Run installer:"
echo "     sudo ./install.sh"
echo
echo "The installer will:"
echo "  - partition disks"
echo "  - mount storage"
echo "  - install server binaries"
echo "  - copy static UI"
echo "  - install bundled apps"
echo "  - generate crypto keys"
echo "  - register systemd service"
echo
echo "============================================================"
