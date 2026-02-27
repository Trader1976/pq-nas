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
REL_ROOT="$REPO_ROOT/tools/release"
CLEAN_CONFIG_DIR="$REL_ROOT/config"
SYSTEMD_DIR="$REL_ROOT/systemd"
RESTORE_JOB_SRC="$REPO_ROOT/server/src/storage/snapshots/pqnas_restore_job.sh"

echo "[*] Repo root: $REPO_ROOT"
echo "[*] Version:   $VER"
echo "[*] Stage:     $STAGE"
echo "[*] Output:    $TARBALL"

rm -rf "$OUTDIR"
mkdir -p "$STAGE"

# ---- 1) Build binaries ----
echo "[*] Building pqnas_server + pqnas_keygen..."
cmake --build "$REPO_ROOT/build" --target pqnas_server pqnas_keygen

test -x "$REPO_ROOT/build/bin/pqnas_server"
test -x "$REPO_ROOT/build/bin/pqnas_keygen"

# ---- 2) NOTE: repo config may be "dirty" during development ----
# We do NOT ship $REPO_ROOT/config anymore. We always ship tools/release/config.
# So: warn only (useful reminder), but do not fail the release build.
if [[ -d "$REPO_ROOT/config" ]]; then
  if rg -n --hidden --no-messages \
      '"fingerprint"\s*:\s*"|pqnas_session|cookie|token|secret|sk_b64|private|owner_fp|expires_at|downloads' \
      "$REPO_ROOT/config" >/dev/null 2>&1; then
    echo "[!] WARNING: $REPO_ROOT/config contains dev/state data (fingerprints/tokens/etc)."
    echo "[!] This is OK during development because release tarballs use: $CLEAN_CONFIG_DIR"
  fi
fi


# ---- 3) Ensure release template config exists + contains required files ----
if [[ ! -d "$CLEAN_CONFIG_DIR" ]]; then
  echo "ERROR: Missing clean config templates: $CLEAN_CONFIG_DIR"
  echo "Create it and add sanitized defaults (admin_settings.json, policy.json, users.json, shares.json)."
  exit 2
fi

required=(admin_settings.json policy.json users.json shares.json pools.json)
for f in "${required[@]}"; do
  if [[ ! -f "$CLEAN_CONFIG_DIR/$f" ]]; then
    echo "ERROR: Missing required config template: $CLEAN_CONFIG_DIR/$f"
    exit 2
  fi
done

# Extra guard: templates must not contain fingerprints/tokens either.
if rg -n --hidden --no-messages \
    '"fingerprint"\s*:\s*"[0-9a-f]{32,}"|pqnas_session|cookie|token|secret|sk_b64|private' \
    "$CLEAN_CONFIG_DIR" >/dev/null 2>&1; then
  echo "ERROR: $CLEAN_CONFIG_DIR contains secrets/dev data. Templates must be sanitized."
  echo "Remove fingerprints/tokens/keys and ship safe defaults only."
  exit 2
fi

# ---- 4) Stage package layout expected by installer ----
echo "[*] Staging files..."

# Top-level installer entrypoint (for end users)
if [[ -f "$REPO_ROOT/install.sh" ]]; then
  install -m 0755 "$REPO_ROOT/install.sh" "$STAGE/install.sh"
else
  echo "[!] Missing $REPO_ROOT/install.sh (top-level installer launcher)."
fi

# Top-level SAFE uninstaller entrypoint (keeps /srv/pqnas data + /etc/pqnas config)
if [[ -f "$REPO_ROOT/uninstall.sh" ]]; then
  install -m 0755 "$REPO_ROOT/uninstall.sh" "$STAGE/uninstall.sh"
else
  echo "[!] Missing $REPO_ROOT/uninstall.sh (safe uninstaller)."
fi


# Binaries at package root
install -m 0755 "$REPO_ROOT/build/bin/pqnas_server" "$STAGE/pqnas_server"
install -m 0755 "$REPO_ROOT/build/bin/pqnas_keygen" "$STAGE/pqnas_keygen"

# DNA engine shared library (needed by /api/v4/verify)
DNA_SRC="$REPO_ROOT/server/third_party/dna/lib/linux/x64/libdna_lib.so"
if [[ -f "$DNA_SRC" ]]; then
  install -d "$STAGE/lib/dna"
  install -m 0755 "$DNA_SRC" "$STAGE/lib/dna/libdna_lib.so"
else
  echo "ERROR: Missing DNA lib: $DNA_SRC"
  echo "Build or fetch libdna_lib.so before making a release."
  exit 3
fi

# systemd units (restore jobs + helpers)
if [[ -d "$SYSTEMD_DIR" ]]; then
  install -d "$STAGE/systemd"
  rsync -a --delete \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    "$SYSTEMD_DIR/" "$STAGE/systemd/"
else
  echo "ERROR: Missing systemd dir: $SYSTEMD_DIR"
  echo "Create tools/release/systemd and add pqnas-restore@.service + pqnas-ok.service + pqnas-fail.service"
  exit 5
fi

# Snapshot restore job script (installed to /usr/local/lib/pqnas/)
if [[ -f "$RESTORE_JOB_SRC" ]]; then
  install -d "$STAGE/lib/pqnas"
  install -m 0755 "$RESTORE_JOB_SRC" "$STAGE/lib/pqnas/pqnas_restore_job.sh"
else
  echo "[!] Snapshot restore job not found: $RESTORE_JOB_SRC"
  echo "[!] This is OK only if you intentionally ship without snapshot-restore support."
fi

# Static web assets (package-mode)
# Copies: server/src/static/*  ->  <tarball>/pqnas/static/*
rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  "$REPO_ROOT/server/src/static/" "$STAGE/static/"

# HARD GUARD: fail release if static didn't stage
test -f "$STAGE/static/app.js" || {
  echo "ERROR: static assets did not stage to $STAGE/static (missing app.js)"
  echo "REPO_ROOT=$REPO_ROOT"
  echo "STAGE=$STAGE"
  ls -la "$REPO_ROOT/server/src/static" | head -n 80 || true
  ls -la "$STAGE" | head -n 120 || true
  exit 90
}

# Inject version into static HTML to bust CDN/browser caches.
# app.html should contain: __PQNAS_VERSION__
if [[ -f "$STAGE/static/app.html" ]]; then
  # Use a temp file to be portable across sed variants.
  tmp="$(mktemp)"
  sed "s/__PQNAS_VERSION__/${VER}/g" "$STAGE/static/app.html" > "$tmp"
  install -m 0644 "$tmp" "$STAGE/static/app.html"
  rm -f "$tmp"
else
  echo "[!] Missing staged static HTML: $STAGE/static/app.html"
fi
# Inject version into static JS too (desktop status line)
if [[ -f "$STAGE/static/app.js" ]]; then
  tmp="$(mktemp)"
  sed "s/__PQNAS_VERSION__/${VER}/g" "$STAGE/static/app.js" > "$tmp"
  install -m 0644 "$tmp" "$STAGE/static/app.js"
  rm -f "$tmp"
else
  echo "[!] Missing staged static JS: $STAGE/static/app.js"
fi

# ---- 4.x) Build bundled app zips from src (source of truth) ----
# Ensures release tarball ships fresh <id>-<version>.zip artifacts.
if [[ -x "$REPO_ROOT/tools/build_all_bundled_zips.sh" ]]; then
  echo "[*] Building bundled app zips..."
  "$REPO_ROOT/tools/build_all_bundled_zips.sh"
else
  echo "ERROR: Missing zip builder: $REPO_ROOT/tools/build_all_bundled_zips.sh"
  echo "Add it, or run your app zip build step before making a tarball."
  exit 11
fi

# HARD GUARD: fail if any app directory has src/ but no zip
missing_zips=0
for appdir in "$REPO_ROOT/apps/bundled"/*; do
  [[ -d "$appdir" ]] || continue
  if [[ -d "$appdir/src" ]]; then
    if ! ls "$appdir"/*.zip >/dev/null 2>&1; then
      echo "ERROR: App has src/ but no zip: $appdir"
      missing_zips=1
    fi
  fi
done
[[ "$missing_zips" -eq 0 ]] || exit 12


# Bundled apps (zips + any bundled folders)
if [[ -d "$REPO_ROOT/apps/bundled" ]]; then
  rsync -a --delete \
    --include '*/' \
    --include '*.zip' \
    --exclude '*' \
    "$REPO_ROOT/apps/bundled/" "$STAGE/bundled/"
else
  mkdir -p "$STAGE/bundled"
fi


# Clean default config (IMPORTANT: from tools/release/config, not repo config/)
rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  "$CLEAN_CONFIG_DIR/" "$STAGE/config/"

# Installer (textual wizard)
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

# README / LICENSE
[[ -f "$REPO_ROOT/README.md" ]] && install -m 0644 "$REPO_ROOT/README.md" "$STAGE/README.md"
[[ -f "$REPO_ROOT/LICENSE" ]] && install -m 0644 "$REPO_ROOT/LICENSE" "$STAGE/LICENSE"

# ---- 5) Clean junk that should never ship ----
echo "[*] Cleaning __pycache__ and *.pyc..."
find "$STAGE" -type d -name '__pycache__' -prune -exec rm -rf {} + || true
find "$STAGE" -type f -name '*.pyc' -delete || true

# ---- 6) Create tarball ----
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
