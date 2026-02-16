#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pkg_root="$here"
installer_dir="$pkg_root/installer"

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Run as root: sudo $0" >&2
    exit 1
  fi
}

ensure_python3() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found. Install Python 3 first." >&2
    exit 1
  fi
}

ensure_os_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "[*] Installing OS dependencies (apt)..."
    export DEBIAN_FRONTEND=noninteractive

    # If previous installs were interrupted, finish configuring packages first
    dpkg --configure -a || true

    apt-get update -y

    # Tooling deps required by pqnas_install.py when using disk mode:
    # - lsblk/wipefs/blkid/partprobe: util-linux
    # - sgdisk: gdisk
    # - partitioning: parted
    # - mkfs.ext4: e2fsprogs
    # - mkfs.btrfs + btrfs subvolume: btrfs-progs
    #
    # Runtime deps required by pqnas_server:
    # - libqrencode4 (fixes libqrencode.so.4 not found)
    #
    # Common on minimal VPS images:
    # - ca-certificates
    apt-get install -y \
      python3-venv \
      python3-pip \
      util-linux \
      gdisk \
      parted \
      e2fsprogs \
      btrfs-progs \
      libqrencode4 \
      libsodium23 \
      libssl3 \
      libstdc++6 \
      libgcc-s1 \
      ca-certificates

    return 0
  fi

  echo "ERROR: Unsupported distro (apt-get not found)." >&2
  echo "Install these manually:" >&2
  echo "  - python3-venv python3-pip" >&2
  echo "  - util-linux gdisk parted e2fsprogs btrfs-progs" >&2
  echo "  - libqrencode (libqrencode.so.4) + runtime libs (openssl3/libsodium/libstdc++)" >&2
  exit 1
}


ensure_venv() {
  local venv="/opt/pqnas-installer/venv"
  local py="$venv/bin/python"

  # Always make sure parent exists
  mkdir -p /opt/pqnas-installer

  # (Re)create venv if missing OR if python is not executable
  if [[ ! -x "$py" ]]; then
    echo "[*] Creating venv at $venv" >&2
    rm -rf "$venv"
    python3 -m venv "$venv"
  fi

  # Ensure pip works inside venv (avoid relying on venv/bin/pip symlink health)
  "$py" -m pip --version >/dev/null 2>&1 || {
    echo "[*] Bootstrapping pip in venv..." >&2
    "$py" -m ensurepip --upgrade >/dev/null 2>&1 || true
  }

  # Upgrade core packaging tools (quiet but reliable)
  echo "[*] Ensuring installer Python deps..." >&2
  "$py" -m pip install --upgrade pip setuptools wheel >/dev/null

  # Install textual if missing (quiet)
  "$py" -c "import textual" >/dev/null 2>&1 || {
    echo "[*] Installing Textual into venv..." >&2
    "$py" -m pip install textual
  }

  echo "$py"
}


main() {
  need_root
  ensure_python3

  echo "[*] Package root: $pkg_root"
  echo "[*] Installer dir: $installer_dir"

  # NEW: ensure runtime OS deps exist before starting installer
  ensure_os_deps

  export PQNAS_ASSET_ROOT="$pkg_root"

  py="$(ensure_venv)"
  exec "$py" "$installer_dir/pqnas_install.py"
}

main "$@"
