#!/usr/bin/env bash
set -euo pipefail

# PQ-NAS bundled app zip builder
# Rebuilds zips from canonical versioned folders:
#   apps/bundled/<app>/<version>/manifest.json
#   apps/bundled/<app>/<version>/www/*
#
# Output:
#   apps/bundled/<app>/<app>-<version>.zip

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLED_DIR="$REPO_ROOT/apps/bundled"

echo "[*] Repo root: $REPO_ROOT"
echo "[*] Bundled dir: $BUNDLED_DIR"
echo

build_one() {
    local app="$1"
    local ver="$2"

    local src="$BUNDLED_DIR/$app/$ver"
    local outdir="$BUNDLED_DIR/$app"
    local out_abs
    out_abs="$(cd "$outdir" && pwd)/${app}-${ver}.zip"

    echo "[*] Building: $app $ver"

    if [[ ! -d "$src" ]]; then
        echo "    [SKIP] missing dir: $src"
        return
    fi

    if [[ ! -f "$src/manifest.json" ]]; then
        echo "    [ERROR] missing manifest.json: $src/manifest.json"
        exit 2
    fi

    if [[ ! -d "$src/www" ]]; then
        echo "    [ERROR] missing www/: $src/www"
        exit 2
    fi

    mkdir -p "$outdir"

    local stage
    stage="$(mktemp -d)"

    cp -a "$src/manifest.json" "$stage/"
    cp -a "$src/www" "$stage/"

    rm -f "$out_abs"

    (
        cd "$stage"
        zip -qr "$out_abs" manifest.json www
    )

    rm -rf "$stage"

    echo "    [OK] $out_abs"

    # verification
    unzip -l "$out_abs" | egrep "manifest\.json|www/.*\.(png|svg)$" || true
    echo
}

# ------------------------------------------------------------
# Auto-discover apps + versions
# ------------------------------------------------------------

found_any=false

for appdir in "$BUNDLED_DIR"/*; do
    [[ -d "$appdir" ]] || continue

    app="$(basename "$appdir")"

    for verdir in "$appdir"/*; do
        [[ -d "$verdir" ]] || continue

        ver="$(basename "$verdir")"

        # must look like version folder and contain manifest.json
        if [[ -f "$verdir/manifest.json" && -d "$verdir/www" ]]; then
            build_one "$app" "$ver"
            found_any=true
        fi
    done
done

if [[ "$found_any" == false ]]; then
    echo "[!] No versioned bundled apps found."
    exit 1
fi

echo "[*] All bundled app zips rebuilt successfully."
