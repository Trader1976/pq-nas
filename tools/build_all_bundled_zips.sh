#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

BUNDLED_DIR="apps/bundled"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need jq
need zip
need unzip

build_one() {
  local appdir="$1"
  local appname
  appname="$(basename "$appdir")"

  local src="$appdir/src"
  local man="$src/manifest.json"
  local www="$src/www"

  if [[ ! -f "$man" || ! -d "$www" ]]; then
    echo "[SKIP] $appname: missing src/manifest.json or src/www/"
    return 0
  fi

  local id ver
  id="$(jq -r '.id // empty' "$man")"
  ver="$(jq -r '.version // empty' "$man")"

  if [[ -z "$id" || -z "$ver" ]]; then
    echo "[ERROR] $appname: manifest.json missing .id or .version" >&2
    return 2
  fi

  if [[ "$id" != "$appname" ]]; then
    echo "[WARN] $appname: manifest id='$id' differs from directory name '$appname'"
  fi

  local out_abs="${REPO_ROOT}/${appdir}/${id}-${ver}.zip"

  # Optional cleanup: remove stale zips for this app (uncomment if you want)
  # find "$appdir" -maxdepth 1 -type f -name "${id}-*.zip" ! -name "${id}-${ver}.zip" -delete

  local stage
  stage="$(mktemp -d)"
  cp -a "$man" "$stage/manifest.json"
  cp -a "$www" "$stage/www"

  rm -f "$out_abs"
  ( cd "$stage" && zip -qr "$out_abs" manifest.json www )
  rm -rf "$stage"

  # verification: ensure zip is valid and contains required files
  unzip -tq "$out_abs" >/dev/null 2>&1 || {
    echo "[ERROR] $appname: zip is corrupt: $out_abs" >&2
    return 3
  }

   # list ONLY file names, one per line (no table columns)
   names="$(unzip -Z -1 "$out_abs" | tr -d '\r')"

   printf '%s\n' "$names" | grep -qx 'manifest.json' || {
     echo "[ERROR] $appname: zip missing manifest.json: $out_abs" >&2
     return 3
   }

   printf '%s\n' "$names" | grep -q '^www/' || {
     echo "[ERROR] $appname: zip missing www/: $out_abs" >&2
     return 3
   }



  printf "[OK] %-14s -> %s (%s bytes)\n" \
    "$appname" "$(basename "$out_abs")" "$(stat -c %s "$out_abs")"
}
for appdir in "$BUNDLED_DIR"/*; do
  [[ -d "$appdir" ]] || continue
  build_one "$appdir"
done
