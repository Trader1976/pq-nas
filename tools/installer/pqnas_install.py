#!/usr/bin/env python3
"""
PQ-NAS CLI Installer (Textual) — Wizard v1

Flow:
  1) Disk selection (safe: system disks marked + blocked)
  2) Backend selection: ext4 / btrfs / zfs
  3) Plan preview (exact commands shown)
  4) Optional reverse proxy (nginx, HTTP-only)
  5) Typed confirm: "WIPE <diskname>" or "INSTALL <mountpoint>"
  6) Execute with live log

Notes:
- Run as root (sudo). Disk operations + systemd need it.
- We generate a command plan first; execution only occurs after typed confirmation.
- Upgrade support:
  - If /usr/local/bin/pqnas_server exists, we treat it as an upgrade.
  - Existing binaries are saved as *.bak before replacing.
  - If service fails to start, a Rollback screen lets you restore *.bak binaries.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Header,
    Footer,
    Static,
    ListView,
    ListItem,
    Label,
    RadioSet,
    RadioButton,
    Button,
    Input,
    Log,
)

# -----------------------------------------------------------------------------
# Small UI/log helpers
# -----------------------------------------------------------------------------

def log_line(logw: Log, msg: str) -> None:
    # Force each message to be a separate line in Textual Log widget
    logw.write(msg.rstrip("\n") + "\n")



def looks_like_ip(host: str) -> bool:
    host = (host or "").strip()
    if not host:
        return False
    # IPv4
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        parts = host.split(".")
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except Exception:
            return False
    # Very loose IPv6 detection (good enough for our note logic)
    if ":" in host and re.fullmatch(r"[0-9a-fA-F:]+", host):
        return True
    return False


def run_cmd_capture(argv: List[str]) -> str:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return (p.stdout or "").strip()

# -----------------------------------------------------------------------------
# Upgrade/rollback helpers
# -----------------------------------------------------------------------------


def detect_existing_install(dest_dir: str = "/usr/local/bin") -> bool:
    return os.path.exists(os.path.join(dest_dir, "pqnas_server"))


def have_bak_binaries(dest_dir: str = "/usr/local/bin") -> bool:
    return os.path.exists(os.path.join(dest_dir, "pqnas_server.bak"))


def rollback_binaries(dest_dir: str = "/usr/local/bin") -> None:
    """
    Restore /usr/local/bin/pqnas_server(.bak) and pqnas_keygen(.bak) if present.
    Keeps the .bak files intact (copy -> replace).
    """
    for name in ("pqnas_server", "pqnas_keygen"):
        cur = os.path.join(dest_dir, name)
        bak = cur + ".bak"
        if os.path.exists(bak):
            tmp = cur + ".rollback"
            shutil.copy2(bak, tmp)
            os.chmod(tmp, 0o755)
            os.replace(tmp, cur)


# -----------------------------------------------------------------------------
# Runtime dependency checks (ldd + apt)
# -----------------------------------------------------------------------------


def have_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def ldd_missing_libs(bin_path: str) -> List[str]:
    """
    Returns missing SONAMEs from `ldd <bin>`,
    e.g. ["libqrencode.so.4"].
    """
    p = subprocess.run(
        ["ldd", bin_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out = p.stdout or ""
    missing: List[str] = []
    for line in out.splitlines():
        line = line.strip()
        if "=>" in line and "not found" in line:
            missing.append(line.split("=>", 1)[0].strip())
    return missing


def apt_install(pkgs: List[str], log: Optional[Log] = None) -> None:
    if not have_cmd("apt-get"):
        raise RuntimeError("apt-get not found (unsupported distro).")

    def w(msg: str) -> None:
        if log:
            log.write(msg)
        else:
            print(msg)

    w("[*] apt-get update …")
    p1 = subprocess.run(
        ["apt-get", "update", "-y"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if p1.returncode != 0:
        raise RuntimeError(f"apt-get update failed:\n{(p1.stdout or '').strip()}")

    w(f"[*] apt-get install: {' '.join(pkgs)} …")
    p2 = subprocess.run(
        ["apt-get", "install", "-y", *pkgs],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if p2.returncode != 0:
        raise RuntimeError(f"apt-get install failed:\n{(p2.stdout or '').strip()}")


def ensure_runtime_deps_for_server(server_exec: str, log: Optional[Log] = None, extra_ldd_paths: Optional[List[str]] = None) -> None:
    """
    Ensure pqnas_server (and optionally extra .so paths) have all shared libraries.
    Debian/Ubuntu only; other distros fail with clear error.
    """
    paths = [server_exec] + (extra_ldd_paths or [])

    # Explicit SONAME -> package mapping (extend only when proven missing)
    soname_to_pkg = {
        "libqrencode.so.4": "libqrencode4",

        # Needed by libdna_lib.so on your VPS (Ubuntu noble)
        "libfmt.so.9": "libfmt9",
        "libjsoncpp.so.25": "libjsoncpp25",
    }

    # Collect missing libs across all checked binaries/DSOs
    missing_all: List[str] = []
    missing_by_path: dict[str, List[str]] = {}

    for p in paths:
        missing = ldd_missing_libs(p)
        if missing:
            missing_by_path[p] = missing
            missing_all.extend(missing)

    if not missing_all:
        if log:
            log.write("[*] Runtime deps: OK (ldd clean) for server + extras.")
        return

    # Map missing sonames -> packages
    pkgs: List[str] = []
    unknown: List[str] = []

    # De-duplicate missing list but keep stable order
    seen = set()
    missing_unique: List[str] = []
    for lib in missing_all:
        if lib not in seen:
            seen.add(lib)
            missing_unique.append(lib)

    for lib in missing_unique:
        pkg = soname_to_pkg.get(lib)
        if pkg:
            pkgs.append(pkg)
        else:
            unknown.append(lib)

    if log:
        log.write("[*] Missing runtime libs (combined): " + ", ".join(missing_unique))
        for p, miss in missing_by_path.items():
            log.write(f"    - {p}: " + ", ".join(miss))

    if unknown:
        raise RuntimeError(
            "Missing shared libraries with no package mapping:\n"
            + "\n".join(f"  - {x}" for x in unknown)
            + "\nInstall them manually or extend soname_to_pkg."
        )

    if log:
        log.write("[*] Installing via apt: " + ", ".join(sorted(set(pkgs))))

    apt_install(sorted(set(pkgs)), log=log)

    # Re-check all paths
    still_missing: List[str] = []
    for p in paths:
        miss2 = ldd_missing_libs(p)
        if miss2:
            still_missing.extend([f"{p}: {x}" for x in miss2])

    if still_missing:
        raise RuntimeError(
            "Runtime deps still missing after apt install:\n"
            + "\n".join(f"  - {x}" for x in still_missing)
        )

    if log:
        log.write("[*] Runtime deps resolved (ldd now OK) for server + extras.")

# -----------------------------------------------------------------------------
# Repo / package asset discovery
# -----------------------------------------------------------------------------


def find_repo_root() -> str:
    # 1) explicit override
    rr = os.environ.get("PQNAS_REPO_ROOT", "").strip()
    if rr and os.path.isdir(rr):
        return rr

    # 2) walk up from this script
    p = Path(__file__).resolve()
    for parent in [p] + list(p.parents):
        if (parent / "server" / "src" / "main.cpp").exists() and (parent / "config").is_dir():
            return str(parent)

    raise RuntimeError("Could not find PQ-NAS repo root. Set PQNAS_REPO_ROOT=/path/to/pq-nas")


def find_asset_root() -> Tuple[str, str]:
    """
    Returns (mode, root_path)

    mode:
      - "package": extracted release folder (contains pqnas_server + static/ + bundled/ + config/)
      - "repo": git repo root (contains server/src/main.cpp + config/)

    You can override with:
      PQNAS_ASSET_ROOT=/path   (forces package-like root)
      PQNAS_REPO_ROOT=/path    (repo root discovery still works)
    """
    # 0) explicit override: asset root (package)
    ar = os.environ.get("PQNAS_ASSET_ROOT", "").strip()
    if ar and os.path.isdir(ar):
        return ("package", ar)

    # 1) detect "package" by walking up from this script
    p = Path(__file__).resolve()
    for parent in [p] + list(p.parents):
        if (parent / "pqnas_server").is_file() and (parent / "static").is_dir() and (parent / "config").is_dir():
            return ("package", str(parent))

    # 2) fallback to repo root (dev)
    return ("repo", find_repo_root())


MODE, ASSET_ROOT = find_asset_root()
# Keep the old variable name used throughout the file: it's really "asset root"
REPO_ROOT = ASSET_ROOT


# -----------------------------------------------------------------------------
# Models + state
# -----------------------------------------------------------------------------


@dataclass
class Disk:
    name: str  # e.g. "nvme0n1"
    path: str  # e.g. "/dev/nvme0n1"
    size: str  # e.g. "931.5G"
    model: str
    serial: str
    mountpoints: str
    is_system: bool  # heuristic: contains "/" mountpoint


@dataclass
class InstallState:
    disk: Optional[Disk] = None
    backend: str = "btrfs"
    mountpoint: str = "/srv/pqnas"
    install_mode: str = "disk"  # "disk" (wipe) or "existing" (no partitioning)
    plan: List[List[str]] = None
    plan_notes: List[str] = None

    # Login authentication mode (installer forces v5-only)
    auth_mode: str = "v5"   # v5-only

    # Optional nginx reverse proxy (HTTP-only for now)
    nginx_enabled: bool = False
    nginx_hostname: str = ""  # server_name (e.g. nas.example.com or 192.168.1.50)
    nginx_listen_port: int = 80

    # Optional Let's Encrypt HTTPS (only used if nginx_enabled)
    https_enabled: bool = False
    https_email: str = ""
    https_redirect: bool = True


# -----------------------------------------------------------------------------
# System helpers
# -----------------------------------------------------------------------------


def run_cmd(argv: List[str]) -> str:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(argv)}\n{(p.stderr or '').strip()}")
    return p.stdout or ""


def lsblk_json() -> dict:
    out = run_cmd(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINTS,MODEL,SERIAL"])
    return json.loads(out)


def flatten_mountpoints(node: dict) -> List[str]:
    mps: List[str] = []
    for mp in (node.get("mountpoints") or []):
        if mp:
            mps.append(mp)
    for ch in (node.get("children") or []):
        mps.extend(flatten_mountpoints(ch))
    return mps


def detect_disks() -> List[Disk]:
    j = lsblk_json()
    disks: List[Disk] = []
    for dev in j.get("blockdevices", []):
        if dev.get("type") != "disk":
            continue

        name = dev.get("name") or ""
        path = f"/dev/{name}"
        size = dev.get("size") or "?"
        model = (dev.get("model") or "").strip() or "—"
        serial = (dev.get("serial") or "").strip() or "—"

        mps = flatten_mountpoints(dev)
        mp_join = ", ".join(mps) if mps else "—"
        is_system = ("/" in mps)

        disks.append(
            Disk(
                name=name,
                path=path,
                size=size,
                model=model,
                serial=serial,
                mountpoints=mp_join,
                is_system=is_system,
            )
        )

    disks.sort(key=lambda d: (not d.is_system, d.name))
    return disks


def fmt_cmd(argv: List[str]) -> str:
    return " ".join(shlex.quote(x) for x in argv)


def dev_part_path(disk: Disk) -> str:
    # nvme uses p1, sata uses 1
    return f"{disk.path}p1" if "nvme" in disk.name else f"{disk.path}1"


def get_uuid_for_device(dev: str) -> str:
    out = run_cmd(["blkid", "-s", "UUID", "-o", "value", dev]).strip()
    if not out:
        raise RuntimeError(f"Could not read UUID for {dev}")
    return out


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def fstab_has_mountpoint(mountpoint: str) -> bool:
    try:
        with open("/etc/fstab", "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if len(parts) >= 2 and parts[1] == mountpoint:
                    return True
    except FileNotFoundError:
        return False
    return False


def append_fstab_entry(entry: str) -> None:
    with open("/etc/fstab", "a", encoding="utf-8") as f:
        if not entry.endswith("\n"):
            entry += "\n"
        f.write(entry)


def write_fstab_uuid(mountpoint: str, fstype: str, uuid: str, options: str) -> None:
    if fstab_has_mountpoint(mountpoint):
        raise RuntimeError(f"/etc/fstab already contains an entry for {mountpoint}")
    entry = f"UUID={uuid}\t{mountpoint}\t{fstype}\t{options}\t0\t2"
    append_fstab_entry(entry)


def create_pqnas_layout(root: str) -> None:
    for p in ("data", "logs", "apps/bundled", "apps/installed", "apps/users", "audit", "tmp"):
        ensure_dir(os.path.join(root, p))
    ensure_dir("/opt/pqnas/static")


def find_dna_lib_source(asset_root: str) -> str:
    """
    Locate libdna_lib.so inside assets (package or repo layout).
    Returns absolute path to source .so.
    """
    candidates = [
        # package mode candidates (you decide your release layout)
        os.path.join(asset_root, "lib", "dna", "libdna_lib.so"),
        os.path.join(asset_root, "dna", "libdna_lib.so"),
        os.path.join(asset_root, "third_party", "dna", "lib", "linux", "x64", "libdna_lib.so"),

        # repo mode candidate
        os.path.join(asset_root, "server", "third_party", "dna", "lib", "linux", "x64", "libdna_lib.so"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    raise RuntimeError(
        "libdna_lib.so not found in assets. Tried:\n"
        + "\n".join(f"  - {p}" for p in candidates)
        + "\nFix your release packaging to include libdna_lib.so, or set PQNAS_ASSET_ROOT correctly."
    )

def install_static_assets(asset_root: str, dest_root: str = "/opt/pqnas/static") -> None:
    """
    Copy static web assets into /opt/pqnas/static.

    repo mode:    <repo>/server/src/static/*
    package mode: <pkg>/static/*
    """
    pkg = os.path.join(asset_root, "static")
    repo = os.path.join(asset_root, "server", "src", "static")

    src = pkg if os.path.isdir(pkg) else repo
    if not os.path.isdir(src):
        raise RuntimeError(f"Missing static dir (tried): {pkg} and {repo}")

    os.makedirs(dest_root, exist_ok=True)

    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(dest_root, name)

        if os.path.isdir(s):
            if os.path.exists(d):
                shutil.rmtree(d)
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)


def install_bundled_apps(asset_root: str, apps_bundled_dest: str) -> None:
    """
    Install bundled app ZIPs into the storage root.

    Expected source layouts:

    Package mode (release tarball):
      - <asset_root>/bundled/<app>/<id>-<version>.zip

    Repo mode (dev):
      - <asset_root>/apps/bundled/<app>/<id>-<version>.zip
        (source lives in src/, but we only install zips)

    Destination layout:
      - <apps_bundled_dest>/<app>/<id>-<version>.zip
    """
    pkg = os.path.join(asset_root, "bundled")
    repo = os.path.join(asset_root, "apps", "bundled")

    src_root = pkg if os.path.isdir(pkg) else repo
    if not os.path.isdir(src_root):
        return

    os.makedirs(apps_bundled_dest, exist_ok=True)

    for app in sorted(os.listdir(src_root)):
        app_src = os.path.join(src_root, app)
        if not os.path.isdir(app_src):
            continue

        # pick all zips in the app folder
        zips = sorted([f for f in os.listdir(app_src) if f.endswith(".zip")])

        if not zips:
            raise RuntimeError(f"No bundled zip found for app '{app}' under: {app_src}\n"
                       f"Run: tools/build_all_bundled_zips.sh")

        app_dst = os.path.join(apps_bundled_dest, app)
        os.makedirs(app_dst, exist_ok=True)

        # Optional: clear old zips in dest app dir to avoid stale versions hanging around
        for old in os.listdir(app_dst):
            if old.endswith(".zip"):
                try:
                    os.remove(os.path.join(app_dst, old))
                except Exception:
                    pass

        # Copy current zips
        for z in zips:
            s = os.path.join(app_src, z)
            d = os.path.join(app_dst, z)
            shutil.copy2(s, d)


def ensure_config_files(root: str, asset_root: str) -> None:
    """
    Ensure PQ-NAS config files exist.

    Production layout:
      - /etc/pqnas/*.json
      - /srv/pqnas/* (storage root)

    Default source:
      - <asset_root>/config
    """
    src = os.path.join(asset_root, "config")
    if not os.path.isdir(src):
        raise RuntimeError(f"Missing config dir: {src}")

    etc_dir = "/etc/pqnas"
    os.makedirs(etc_dir, exist_ok=True)

    force = os.environ.get("PQNAS_FORCE_CONFIG", "").strip().lower() in ("1", "true", "yes", "y", "on")

    for name in ("admin_settings.json", "policy.json", "users.json", "shares.json"):
        s = os.path.join(src, name)
        d = os.path.join(etc_dir, name)

        if not os.path.exists(s):
            raise RuntimeError(f"Missing default config: {s}")

        if os.path.exists(d) and not force:
            continue

        shutil.copy2(s, d)

    # Optional breadcrumb under storage root
    try:
        marker_dir = os.path.join(root, "config")
        os.makedirs(marker_dir, exist_ok=True)
        marker_path = os.path.join(marker_dir, "README.txt")
        if not os.path.exists(marker_path):
            with open(marker_path, "w", encoding="utf-8") as f:
                f.write(
                    "PQ-NAS config lives in /etc/pqnas.\n"
                    "This directory is intentionally not used for runtime config.\n"
                )
    except Exception:
        pass


def write_env_file(
    root: str,
    *,
    origin: Optional[str] = None,
    rp_id: Optional[str] = None,
    dna_lib_path: Optional[str] = None,
    auth_mode: Optional[str] = None,
) -> None:

    etc_dir = "/etc/pqnas"
    os.makedirs(etc_dir, exist_ok=True)

    env_path = os.path.join(etc_dir, "pqnas.env")

    lines = [
        f"PQNAS_ROOT={root}",
        "PQNAS_CONFIG=/etc/pqnas",
        "",
        "PQNAS_ADMIN_SETTINGS_PATH=/etc/pqnas/admin_settings.json",
        "PQNAS_POLICY_PATH=/etc/pqnas/policy.json",
        "PQNAS_USERS_PATH=/etc/pqnas/users.json",
        "PQNAS_SHARES_PATH=/etc/pqnas/shares.json",
        "",
        f"PQNAS_AUDIT_DIR={root}/audit",
        f"PQNAS_LOG_DIR={root}/logs",
        f"PQNAS_TMP_DIR={root}/tmp",
        "",
        f"PQNAS_DATA_ROOT={root}/data",
        "PQNAS_STATIC_ROOT=/opt/pqnas/static",
        f"PQNAS_APPS_ROOT={root}/apps",
    ]

    # URL / relying party settings (used by v4 QR auth)
    if origin:
        lines += ["", f"PQNAS_ORIGIN={origin}"]
    if rp_id:
        lines += [f"PQNAS_RP_ID={rp_id}"]

    # Login authentication mode (v4 | v5 | auto)
    if auth_mode:
        lines += [f"PQNAS_AUTH_MODE={auth_mode}"]


    # DNA engine .so path for /api/v4/verify
    if dna_lib_path:
        lines += ["", f"PQNAS_DNA_LIB={dna_lib_path}"]

    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

def write_keys_env(asset_root: str, path: str = "/etc/pqnas/keys.env") -> None:
    """
    Generate Ed25519 + cookie keys and write systemd-friendly EnvironmentFile.
    Searches for pqnas_keygen in:
      1) /usr/local/bin/pqnas_keygen
      2) <asset_root>/pqnas_keygen              (package)
      3) <asset_root>/build/bin/pqnas_keygen    (repo)
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    candidates = [
        "/usr/local/bin/pqnas_keygen",
        os.path.join(asset_root, "pqnas_keygen"),
        os.path.join(asset_root, "build", "bin", "pqnas_keygen"),
    ]

    keygen = next((p for p in candidates if os.path.isfile(p)), None)
    if not keygen:
        raise RuntimeError("pqnas_keygen not found (build it or install it first)")

    out = run_cmd([keygen]).strip().splitlines()

    kv: List[str] = []
    for line in out:
        line = line.strip()
        if not line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" in line:
            k, v = line.split("=", 1)
            v = v.strip().strip("'").strip('"')
            kv.append(f"{k.strip()}={v}")

    needed = {"PQNAS_SERVER_PK_B64URL", "PQNAS_SERVER_SK_B64URL", "PQNAS_COOKIE_KEY_B64URL"}
    got = {x.split("=", 1)[0] for x in kv}
    if not needed.issubset(got):
        raise RuntimeError(f"pqnas_keygen output missing keys: {sorted(needed - got)}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(kv) + "\n")

    os.chmod(path, 0o600)


# -----------------------------------------------------------------------------
# Install binaries
# -----------------------------------------------------------------------------


def install_binaries(asset_root: str, dest_dir: str = "/usr/local/bin") -> Tuple[str, Optional[str], bool]:
    """
    Install pqnas_server + pqnas_keygen into /usr/local/bin.
    Returns: (server_exec, keygen_exec_or_none, was_upgrade)
    """
    was_upgrade = detect_existing_install(dest_dir)

    # package sources
    pkg_server = os.path.join(asset_root, "pqnas_server")
    pkg_keygen = os.path.join(asset_root, "pqnas_keygen")

    # repo sources
    repo_dir = os.path.join(asset_root, "build", "bin")
    repo_server = os.path.join(repo_dir, "pqnas_server")
    repo_keygen = os.path.join(repo_dir, "pqnas_keygen")

    package_mode = os.path.isfile(pkg_server)

    if package_mode:
        src_server = pkg_server
        src_keygen = pkg_keygen if os.path.isfile(pkg_keygen) else None
        if src_keygen is None:
            raise RuntimeError(f"Missing keygen binary in package: {pkg_keygen}")
    else:
        src_server = repo_server
        src_keygen = repo_keygen if os.path.isfile(repo_keygen) else None

    if not os.path.isfile(src_server):
        raise RuntimeError(f"Missing server binary (tried): {pkg_server} and {repo_server}")

    os.makedirs(dest_dir, exist_ok=True)

    dst_server = os.path.join(dest_dir, "pqnas_server")
    dst_keygen = os.path.join(dest_dir, "pqnas_keygen")

    # Backup current binaries (if present)
    if os.path.exists(dst_server):
        shutil.copy2(dst_server, dst_server + ".bak")
    if src_keygen and os.path.exists(dst_keygen):
        shutil.copy2(dst_keygen, dst_keygen + ".bak")

    # Atomic replace
    tmp_server = dst_server + ".new"
    shutil.copy2(src_server, tmp_server)
    os.chmod(tmp_server, 0o755)
    os.replace(tmp_server, dst_server)

    out_keygen: Optional[str] = None
    if src_keygen and os.path.isfile(src_keygen):
        tmp_keygen = dst_keygen + ".new"
        shutil.copy2(src_keygen, tmp_keygen)
        os.chmod(tmp_keygen, 0o755)
        os.replace(tmp_keygen, dst_keygen)
        out_keygen = dst_keygen

    return dst_server, out_keygen, was_upgrade


# -----------------------------------------------------------------------------
# systemd helpers
# -----------------------------------------------------------------------------


def write_systemd_unit(
        exec_path: str,
        env_file: str = "/etc/pqnas/pqnas.env",
        keys_file: str = "/etc/pqnas/keys.env",
) -> str:
    unit_path = "/etc/systemd/system/pqnas.service"

    unit = f"""[Unit]
Description=PQ-NAS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={env_file}
EnvironmentFile={keys_file}
ExecStart={exec_path}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
"""
    with open(unit_path, "w", encoding="utf-8") as f:
        f.write(unit)
    return unit_path
def install_snapshot_restore_assets(asset_root: str, backend: str, log: Optional[Log] = None) -> None:
    """
    Install snapshot restore helper script + systemd units.

    Package layout (release tarball):
      - <asset_root>/lib/pqnas/pqnas_restore_job.sh
      - <asset_root>/systemd/pqnas-restore@.service
      - <asset_root>/systemd/pqnas-ok.service
      - <asset_root>/systemd/pqnas-fail.service

    Repo layout (dev):
      - <asset_root>/server/src/storage/snapshots/pqnas_restore_job.sh
      - <asset_root>/tools/release/systemd/<units>
    """
    if backend not in ("btrfs", "zfs"):
        if log:
            log.write("[*] Snapshot restore assets: skipped (backend is not snapshot-capable).")
        return

    # --- restore job script ---
    script_candidates = [
        os.path.join(asset_root, "lib", "pqnas", "pqnas_restore_job.sh"),  # package mode
        os.path.join(asset_root, "server", "src", "storage", "snapshots", "pqnas_restore_job.sh"),  # repo mode
    ]
    script_src = next((p for p in script_candidates if os.path.isfile(p)), None)
    if not script_src:
        raise RuntimeError(
            "pqnas_restore_job.sh not found. Tried:\n" +
            "\n".join(f"  - {p}" for p in script_candidates)
        )

    os.makedirs("/usr/local/lib/pqnas", exist_ok=True)
    script_dst = "/usr/local/lib/pqnas/pqnas_restore_job.sh"
    tmp = script_dst + ".new"
    shutil.copy2(script_src, tmp)
    os.chmod(tmp, 0o755)
    os.replace(tmp, script_dst)

    if log:
        log.write(f"[*] Installed restore job: {script_dst} (from {script_src})")

    # --- systemd units ---
    unit_dir_candidates = [
        os.path.join(asset_root, "systemd"),                 # package mode
        os.path.join(asset_root, "tools", "release", "systemd"),  # repo mode
    ]
    unit_dir = next((p for p in unit_dir_candidates if os.path.isdir(p)), None)
    if not unit_dir:
        raise RuntimeError(
            "systemd unit dir not found. Tried:\n" +
            "\n".join(f"  - {p}" for p in unit_dir_candidates)
        )

    units = ["pqnas-restore@.service", "pqnas-ok.service", "pqnas-fail.service"]
    for u in units:
        src = os.path.join(unit_dir, u)
        if not os.path.isfile(src):
            raise RuntimeError(f"Missing unit asset: {src}")
        dst = os.path.join("/etc/systemd/system", u)
        tmpu = dst + ".new"
        shutil.copy2(src, tmpu)
        os.chmod(tmpu, 0o644)
        os.replace(tmpu, dst)
        if log:
            log.write(f"[*] Installed unit: {dst}")

    # Make sure systemd sees new units
    run_systemctl(["daemon-reload"])

    # Optionally enable template (not necessary; templates can be started without enabling)
    if log:
        log.write("[*] Snapshot restore assets installed (script + units).")


def enable_letsencrypt_nginx(domain: str, email: str, redirect: bool, logw=None) -> bool:
    """
    Returns True on success, False on failure (installer should continue with HTTP if False).
    """
    try:
        apt_install(["certbot", "python3-certbot-nginx"], log=logw)

        cmd = [
            "certbot", "--nginx",
            "-d", domain,
            "--non-interactive",
            "--agree-tos",
            "--email", email,
        ]
        if redirect:
            cmd.append("--redirect")
        else:
            cmd.append("--no-redirect")

        if logw: logw.write("Running: " + " ".join(cmd))
        subprocess.run(cmd, check=True)

        # nginx should already be reloaded by certbot, but this is harmless
        subprocess.run(["systemctl", "reload", "nginx"], check=False)
        return True
    except Exception as e:
        if logw: logw.write(f"[WARN] HTTPS setup failed: {e}")
        return False


def run_systemctl(args: List[str]) -> str:
    p = subprocess.run(["systemctl", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = (p.stdout or "").strip()
    if p.returncode != 0:
        raise RuntimeError(f"systemctl {' '.join(args)} failed:\n{out}")
    return out

def systemd_unit_exists(unit: str) -> bool:
    """
    True if systemd knows about the unit file (fresh install => False).
    We use list-unit-files because it answers 'does a unit file exist' rather than 'is it running'.
    """
    try:
        r = subprocess.run(
            ["systemctl", "list-unit-files", unit, "--no-pager", "--no-legend"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        # Output line usually begins with: "pqnas.service enabled" etc.
        return (r.returncode == 0) and (unit in (r.stdout or ""))
    except Exception:
        return False


# -----------------------------------------------------------------------------
# nginx reverse-proxy helpers (optional)
# -----------------------------------------------------------------------------


def ensure_nginx_installed(log: Optional[Log] = None) -> None:
    """
    Debian/Ubuntu: installs nginx via apt if missing.
    """
    if have_cmd("nginx"):
        if log:
            log.write("[*] nginx: already installed.")
        return
    if log:
        log.write("[*] Installing nginx (apt) …")
    apt_install(["nginx"], log=log)


def nginx_sites_layout() -> str:
    """
    Returns:
      - "sites"  for /etc/nginx/sites-available + sites-enabled
      - "confd"  for /etc/nginx/conf.d
    """
    if os.path.isdir("/etc/nginx/sites-available") and os.path.isdir("/etc/nginx/sites-enabled"):
        return "sites"
    if os.path.isdir("/etc/nginx/conf.d"):
        return "confd"
    return "sites"

def letsencrypt_cert_paths(hostname: str) -> tuple[str, str]:
    """
    Return (fullchain, privkey) paths for a hostname under /etc/letsencrypt/live/<host>/.
    """
    h = (hostname or "").strip()
    base = f"/etc/letsencrypt/live/{h}"
    return (os.path.join(base, "fullchain.pem"), os.path.join(base, "privkey.pem"))


def have_letsencrypt_cert(hostname: str) -> bool:
    """
    True if certbot/letsencrypt cert files exist for hostname.
    """
    fullchain, privkey = letsencrypt_cert_paths(hostname)
    return os.path.isfile(fullchain) and os.path.isfile(privkey)


def write_nginx_site_http_only(
        server_name: str,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 8081,
        listen_port: int = 80,
) -> str:
    """
    Writes an HTTP-only reverse proxy config for PQ-NAS.
    Returns the config path written.
    """
    server_name = (server_name or "").strip()
    if not server_name:
        raise RuntimeError("nginx server_name is empty.")

    layout = nginx_sites_layout()

    conf_text = f"""# PQ-NAS nginx reverse proxy (HTTP-only)
# Generated by pqnas_install.py
#
# Upstream: http://{upstream_host}:{upstream_port}
# Server:   http://{server_name}:{listen_port}

server {{
    listen {listen_port};
    server_name {server_name};

    # Uploads: adjust if needed
    client_max_body_size 2g;

    location / {{
        proxy_pass http://{upstream_host}:{upstream_port};

        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Safe defaults (helpful for future websockets/SSE)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}
}}
"""

    if layout == "sites":
        avail = "/etc/nginx/sites-available/pqnas"
        enabled = "/etc/nginx/sites-enabled/pqnas"
        with open(avail, "w", encoding="utf-8") as f:
            f.write(conf_text)

        # enable symlink
        if os.path.islink(enabled) or os.path.exists(enabled):
            try:
                os.remove(enabled)
            except Exception:
                pass
        os.symlink(avail, enabled)

        # Disable default site if present (common on Debian/Ubuntu)
        default_enabled = "/etc/nginx/sites-enabled/default"
        if os.path.exists(default_enabled):
            try:
                os.remove(default_enabled)
            except Exception:
                pass

        return avail

    # conf.d fallback
    confd = "/etc/nginx/conf.d/pqnas.conf"
    with open(confd, "w", encoding="utf-8") as f:
        f.write(conf_text)
    return confd

def write_nginx_site_https_if_available(
        server_name: str,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 8081,
        client_max_body_size: str = "2g",
) -> str:
    """
    Writes nginx site config:
      - If letsencrypt cert exists: 80->308 redirect, 443 proxy_pass upstream
      - Else: HTTP-only proxy on 80 (no redirect)
    Returns the config path written.
    """
    server_name = (server_name or "").strip()
    if not server_name:
        raise RuntimeError("nginx server_name is empty.")

    layout = nginx_sites_layout()
    use_https = have_letsencrypt_cert(server_name)
    fullchain, privkey = letsencrypt_cert_paths(server_name)

    if use_https:
        conf_text = f"""# PQ-NAS nginx reverse proxy (HTTPS)
# Generated by pqnas_install.py
#
# Upstream: http://{upstream_host}:{upstream_port}
# Server:   https://{server_name}:443  (http://{server_name}:80 redirects with 308)

server {{
    listen 80;
    server_name {server_name};
    return 308 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {server_name};

    client_max_body_size {client_max_body_size};

    ssl_certificate {fullchain};
    ssl_certificate_key {privkey};

    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    location / {{
        proxy_pass http://{upstream_host}:{upstream_port};

        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}
}}
"""
    else:
        conf_text = f"""# PQ-NAS nginx reverse proxy (HTTP-only)
# Generated by pqnas_install.py
#
# Upstream: http://{upstream_host}:{upstream_port}
# Server:   http://{server_name}:80

server {{
    listen 80;
    server_name {server_name};

    client_max_body_size {client_max_body_size};

    location / {{
        proxy_pass http://{upstream_host}:{upstream_port};

        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}
}}
"""

    if layout == "sites":
        avail = "/etc/nginx/sites-available/pqnas"
        enabled = "/etc/nginx/sites-enabled/pqnas"

        with open(avail, "w", encoding="utf-8") as f:
            f.write(conf_text)

        # enable symlink
        if os.path.islink(enabled) or os.path.exists(enabled):
            try:
                os.remove(enabled)
            except Exception:
                pass
        os.symlink(avail, enabled)

        # Disable default site if present (common on Debian/Ubuntu)
        default_enabled = "/etc/nginx/sites-enabled/default"
        if os.path.exists(default_enabled):
            try:
                os.remove(default_enabled)
            except Exception:
                pass

        return avail

    # conf.d fallback
    confd = "/etc/nginx/conf.d/pqnas.conf"
    with open(confd, "w", encoding="utf-8") as f:
        f.write(conf_text)
    return confd


def nginx_test_reload(log: Optional[Log] = None) -> None:
    """
    Validate config and reload nginx.
    """
    p = subprocess.run(["nginx", "-t"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = (p.stdout or "").strip()
    if p.returncode != 0:
        raise RuntimeError(f"nginx -t failed:\n{out}")
    if log:
        log.write("[*] nginx -t OK")
    run_systemctl(["enable", "--now", "nginx"])
    run_systemctl(["reload", "nginx"])
    if log:
        log.write("[*] nginx reloaded.")

# -----------------------------------------------------------------
# Plan generation (ext4 / btrfs / zfs)
# -----------------------------------------------------------------------------


def plan_for(state: InstallState) -> Tuple[List[List[str]], List[str]]:
    """
    Returns: (plan_argvs, notes)
    Plan uses a single-disk model for now.
    """
    assert state.disk, "disk not selected"
    d = state.disk
    mp = state.mountpoint.rstrip("/") or "/srv/pqnas"

    notes: List[str] = []
    plan: List[List[str]] = []

    if state.install_mode == "existing":
        notes.append("Mode: existing filesystem (NO wipe, NO partitioning).")
        notes.append(f"PQ-NAS will be installed under: {mp}")
        notes.append("WARNING: This uses your current root filesystem capacity.")
        return plan, notes

    if d.is_system:
        raise RuntimeError("Refusing to operate on system disk (contains / mount).")

    # Always clean slate first
    plan += [
        ["wipefs", "-a", d.path],
        ["sgdisk", "--zap-all", d.path],
        ["dd", "if=/dev/zero", f"of={d.path}", "bs=1M", "count=32", "status=none"],
        ["sync"],
        ["sgdisk", "--zap-all", d.path],
        ["partprobe", d.path],
    ]
    notes.append("Disk will be destroyed (wipefs + zap GPT + zero first 32MiB).")

    if state.backend == "ext4":
        part = dev_part_path(d)
        plan += [
            ["parted", d.path, "--script", "mklabel", "gpt", "mkpart", "primary", "ext4", "1MiB", "100%"],
            ["partprobe", d.path],
            ["mkfs.ext4", "-F", "-L", "PQNAS_DATA", part],
            ["mkdir", "-p", mp],
            ["mount", part, mp],
        ]
        notes.append("Backend: ext4 (no snapshots).")

    elif state.backend == "btrfs":
        part = dev_part_path(d)
        plan += [
            ["parted", d.path, "--script", "mklabel", "gpt", "mkpart", "primary", "btrfs", "1MiB", "100%"],
            ["partprobe", d.path],
            ["mkfs.btrfs", "-f", "-L", "PQNAS_DATA", part],
            ["mkdir", "-p", mp],
            ["mount", part, mp],
            ["btrfs", "subvolume", "create", f"{mp}/data"],
            ["btrfs", "subvolume", "create", f"{mp}/snaps"],
            ["umount", mp],
            ["mount", "-o", "subvol=data", part, mp],
        ]
        notes.append("Backend: btrfs (snapshots supported via subvolumes).")

    elif state.backend == "zfs":
        pool = "pqnas"
        plan += [
            ["zpool", "create", "-f", pool, d.path],
            ["zfs", "set", f"mountpoint={mp}", f"{pool}"],
            ["zfs", "create", f"{pool}/data"],
            ["zfs", "create", f"{pool}/snaps"],
        ]
        notes.append("Backend: zfs (snapshots/replication/scrub supported).")
        notes.append("Note: pool name is 'pqnas' (single-disk).")
    else:
        raise RuntimeError(f"Unknown backend: {state.backend}")

    notes.append("TODO: fstab (ext4/btrfs) or ZFS import-on-boot; permissions.")
    return plan, notes


# -----------------------------------------------------------------------------
# UI components
# -----------------------------------------------------------------------------


class DiskListItem(ListItem):
    def __init__(self, disk: Disk) -> None:
        self.disk = disk
        title = f"{disk.name}  •  {disk.size}"
        if disk.is_system:
            title += "   [SYSTEM]"
        super().__init__(Label(title))


class DiskSelectScreen(Screen):
    BINDINGS = [("r", "refresh", "Refresh"), ("n", "next", "Next"), ("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="left"):
                yield Static(
                    "[b]Step 1/6[/b] Select target disk\n\n"
                    "[r]R[/r] refresh  •  [r]N[/r] next  •  [r]Q[/r] quit\n",
                    classes="muted",
                )
                self.lv = ListView()
                yield self.lv

                yield Static("\n[b]Install mode[/b]", classes="muted")
                self.mode = RadioSet(
                    RadioButton("Use a dedicated disk (WIPE + format)", id="disk"),
                    RadioButton("Use existing filesystem (NO wipe) — demo/small install", id="existing"),
                )
                yield self.mode

                self.mode_hint = Static("", classes="warn")
                yield self.mode_hint

            with Vertical(id="right"):
                yield Static("[b]Disk details[/b]\n", classes="muted")
                self.details = Static("", classes="muted")
                yield self.details
                self.warn = Static("", classes="warn")
                yield self.warn
        yield Footer()

    def on_mount(self) -> None:
        for btn in self.mode.query(RadioButton):
            if btn.id == "disk":
                btn.value = True
        self.mode_hint.update("")
        self.action_refresh()

    def action_refresh(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        app.disks = detect_disks()
        self.lv.clear()
        for d in app.disks:
            self.lv.append(DiskListItem(d))

        if app.disks:
            self.lv.index = 0
            app.state.disk = app.disks[0]
            self.render_details(app.state.disk)
        else:
            app.state.disk = None
            self.details.update("No disks found.")
            self.warn.update("")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, DiskListItem):
            d = event.item.disk
            app: InstallerApp = self.app  # type: ignore
            app.state.disk = d
            self.render_details(d)

    def render_details(self, d: Disk) -> None:
        sysflag = "[SYSTEM]" if d.is_system else ""
        self.details.update(
            f"[b]{d.name}[/b] {sysflag}\n\n"
            f"[b]Path:[/b] {d.path}\n"
            f"[b]Size:[/b] {d.size}\n"
            f"[b]Model:[/b] {d.model}\n"
            f"[b]Serial:[/b] {d.serial}\n"
            f"[b]Mounts:[/b] {d.mountpoints}\n"
        )
        if d.is_system:
            self.warn.update("This disk contains '/' (system disk). Wipe mode will be blocked.")
        else:
            self.warn.update("")
        self.mode_hint.update("")

    def action_next(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        if not app.state.disk:
            self.warn.update("No disk selected.")
            return

        chosen_mode = "disk"
        for btn in self.mode.query(RadioButton):
            if btn.value:
                chosen_mode = btn.id
                break

        app.state.install_mode = chosen_mode

        if chosen_mode == "disk" and app.state.disk.is_system:
            self.warn.update("Refusing: selected disk is a SYSTEM disk (contains '/').")
            return

        if chosen_mode == "existing":
            self.mode_hint.update(
                "WARNING: Existing filesystem mode uses your current root disk capacity. "
                "Use /srv/pqnas and monitor free space."
            )

        app.push_screen(BackendSelectScreen())


class BackendSelectScreen(Screen):
    BINDINGS = [("b", "back", "Back"), ("n", "next", "Next"), ("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 2/6[/b] Select storage backend\n", classes="muted")

            self.radio = RadioSet(
                RadioButton("ext4 (simple, no snapshots)", id="ext4"),
                RadioButton("btrfs (snapshots; recommended)", id="btrfs"),
                RadioButton("zfs (advanced NAS features)", id="zfs"),
            )
            yield self.radio

            yield Static("\n[b]Mountpoint[/b] (where PQ-NAS data will live):", classes="muted")
            self.mp_in = Input(value="/srv/pqnas", placeholder="/srv/pqnas")
            yield self.mp_in

            with Horizontal():
                yield Button("Back", id="back", variant="default")
                yield Button("Next", id="next", variant="primary")

            self.hint = Static("\nTip: ext4 = simplest, btrfs = best default, zfs = hardcore NAS.", classes="muted")
            yield self.hint

        yield Footer()

    def on_mount(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        backend = app.state.backend
        for btn in self.radio.query(RadioButton):
            if btn.id == backend:
                btn.value = True
        self.mp_in.value = app.state.mountpoint

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.action_back()
        elif event.button.id == "next":
            self.action_next()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_next(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        chosen = None
        for btn in self.radio.query(RadioButton):
            if btn.value:
                chosen = btn.id
                break
        if chosen not in ("ext4", "btrfs", "zfs"):
            return

        mp = (self.mp_in.value or "").strip()
        if not mp.startswith("/"):
            self.hint.update("[warn]Mountpoint must be an absolute path like /srv/pqnas[/warn]")
            return

        app.state.backend = chosen
        app.state.mountpoint = mp
        app.push_screen(PlanScreen())


class PlanScreen(Screen):
    BINDINGS = [("b", "back", "Back"), ("n", "next", "Next"), ("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 3/6[/b] Plan preview (exact commands)\n", classes="muted")
            self.plan_box = Static("", classes="muted")
            yield self.plan_box
            with Horizontal():
                yield Button("Back", id="back", variant="default")
                yield Button("Next", id="next", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        if not app.state.disk:
            self.plan_box.update("[b]Error[/b]\nNo disk selected.")
            return

        try:
            plan, notes = plan_for(app.state)
            app.state.plan = plan
            app.state.plan_notes = notes
        except Exception as e:
            self.plan_box.update(f"[b]Error generating plan[/b]\n{e}")
            return

        d = app.state.disk
        text: List[str] = []
        text.append(f"[b]Disk:[/b] {d.name} ({d.size})  {d.model}  serial={d.serial}")
        text.append(f"[b]Mode:[/b] {app.state.install_mode}")
        text.append(f"[b]Backend:[/b] {app.state.backend}")
        text.append(f"[b]Mountpoint:[/b] {app.state.mountpoint}\n")
        text.append("[b]Notes:[/b]")
        for n in (app.state.plan_notes or []):
            text.append(f"  • {n}")

        text.append("\n[b]Commands:[/b]")
        if app.state.plan:
            for i, argv in enumerate(app.state.plan, start=1):
                text.append(f"{i:02d}. {fmt_cmd(argv)}")
        else:
            text.append("  (no destructive commands; existing filesystem mode)")

        self.plan_box.update("\n".join(text))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.action_back()
        elif event.button.id == "next":
            self.action_next()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_next(self) -> None:
        self.app.push_screen(ReverseProxyScreen())

class ReverseProxyScreen(Screen):
    BINDINGS = [("b", "back", "Back"), ("n", "next", "Next"), ("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 4/6[/b] Optional reverse proxy (nginx)\n", classes="muted")

            yield Static(
                "If enabled, PQ-NAS will be reachable via:\n"
                "  http://<hostname>/   (no :8081)\n\n"
                "Hostname can be a domain or an IP.\n"
                "For real-world use, the hostname must resolve to this server (DNS / router DNS / hosts).\n",
                classes="muted",
            )

            self.enable = RadioSet(
                RadioButton("No reverse proxy (keep :8081)", id="off"),
                RadioButton("Enable nginx reverse proxy", id="on"),
            )
            yield self.enable

            yield Static("\n[b]Login authentication mode:[/b] v5 (stateless) — forced by installer", classes="muted")

            yield Static("\n[b]Hostname or IP[/b] (nginx server_name):", classes="muted")
            self.host_in = Input(value="", placeholder="nas.example.com  (or 192.168.1.50)")
            yield self.host_in

            yield Static("\n[b]HTTPS (optional)[/b]", classes="muted")
            self.https_enable = RadioSet(
                RadioButton("HTTP only", id="https_off"),
                RadioButton("Enable HTTPS (Let’s Encrypt)", id="https_on"),
            )
            yield self.https_enable

            yield Static("\n[b]Email[/b] (required for Let’s Encrypt):", classes="muted")
            self.email_in = Input(value="", placeholder="you@example.com")
            yield self.email_in

            self.redirect_btn = RadioSet(
                RadioButton("No redirect (keep HTTP)", id="redir_off"),
                RadioButton("Redirect HTTP → HTTPS", id="redir_on"),
            )
            yield self.redirect_btn

            with Horizontal():
                yield Button("Back", id="back", variant="default")
                yield Button("Next", id="next", variant="primary")

            self.err = Static("", classes="warn")
            yield self.err

        yield Footer()

    def on_mount(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        st = app.state

        # nginx on/off
        for btn in self.enable.query(RadioButton):
            btn.value = (btn.id == ("on" if st.nginx_enabled else "off"))

        self.host_in.value = st.nginx_hostname or ""

        # https on/off
        for btn in self.https_enable.query(RadioButton):
            btn.value = (btn.id == ("https_on" if st.https_enabled else "https_off"))

        self.email_in.value = st.https_email or ""

        # redirect
        for btn in self.redirect_btn.query(RadioButton):
            btn.value = (btn.id == ("redir_on" if st.https_redirect else "redir_off"))

        self._sync()

    def _sync(self) -> None:
        enabled = any(btn.value and btn.id == "on" for btn in self.enable.query(RadioButton))
        self.host_in.disabled = not enabled

        https_on = enabled and any(btn.value and btn.id == "https_on" for btn in self.https_enable.query(RadioButton))
        self.email_in.disabled = not https_on

        for btn in self.redirect_btn.query(RadioButton):
            btn.disabled = not https_on

        if not enabled:
            self.err.update("")
        else:
            # Clear errors on toggles; validation happens on Next
            self.err.update("")

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        # Any radio toggle updates enabled/disabled widgets
        self._sync()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.action_back()
        elif event.button.id == "next":
            self.action_next()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_next(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        st = app.state

        enabled = any(btn.value and btn.id == "on" for btn in self.enable.query(RadioButton))
        host = (self.host_in.value or "").strip()

        if enabled:
            if not host or " " in host or "/" in host:
                self.err.update("Enter a hostname or IP (no spaces, no slashes).")
                return

            st.nginx_enabled = True
            st.nginx_hostname = host
            st.nginx_listen_port = 80

            st.https_enabled = any(btn.value and btn.id == "https_on" for btn in self.https_enable.query(RadioButton))
            st.https_email = (self.email_in.value or "").strip()
            st.https_redirect = any(btn.value and btn.id == "redir_on" for btn in self.redirect_btn.query(RadioButton))

            if st.https_enabled:
                if not st.https_email or "@" not in st.https_email:
                    self.err.update("HTTPS enabled: please enter a valid email for Let’s Encrypt.")
                    return
        else:
            st.nginx_enabled = False
            st.nginx_hostname = ""
            st.nginx_listen_port = 80
            st.https_enabled = False
            st.https_email = ""
            st.https_redirect = True

        st.auth_mode = "v5"
        app.push_screen(ConfirmScreen())

class ConfirmScreen(Screen):
    BINDINGS = [("b", "back", "Back"), ("enter", "try_start", "Start"), ("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 5/6[/b] Destructive confirmation\n", classes="warn")
            self.msg = Static("", classes="muted")
            yield self.msg

            self.confirm_in = Input(placeholder="Type the confirmation exactly…")
            yield self.confirm_in

            self.hint = Static("Tip: type the text, then press Enter • Tab moves focus", classes="muted")
            yield self.hint

            with Horizontal():
                yield Button("Back", id="back", variant="default")
                self.start_btn = Button("Start", id="start", variant="error", disabled=True)
                yield self.start_btn

            self.err = Static("", classes="warn")
            yield self.err
        yield Footer()

    def on_mount(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        d = app.state.disk
        # Give instant feedback (Textual can look "stuck" before first log lines)
        self.logw.write("Starting installer… please wait.")
        self.logw.write("Tip: disk operations + apt installs can take a while on VPS.")
        self.logw.write("")

        mode = app.state.install_mode

        if mode == "existing":
            self.required = f"INSTALL {app.state.mountpoint.rstrip('/') or '/srv/pqnas'}"
            self.msg.update(
                "This will install PQ-NAS into the existing filesystem.\n\n"
                "No partitioning or formatting will be done.\n\n"
                "Target path:\n\n"
                f"[b]{app.state.mountpoint}[/b]\n\n"
                "To proceed, type exactly:\n\n"
                f"[b]{self.required}[/b]\n"
            )
        else:
            assert d is not None
            self.required = f"WIPE {d.name}"
            self.msg.update(
                f"This will DESTROY ALL DATA on [b]{d.path}[/b].\n\n"
                "To proceed, type exactly:\n\n"
                f"[b]{self.required}[/b]\n"
            )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input is self.confirm_in:
            self._sync_ui()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.action_back()
        elif event.button.id == "start":
            self._start()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_try_start(self) -> None:
        self._start()

    def _sync_ui(self) -> None:
        val = (self.confirm_in.value or "").strip()
        ok = (val == self.required)
        self.start_btn.disabled = not ok
        if ok:
            self.err.update("")

    def _start(self) -> None:
        val = (self.confirm_in.value or "").strip()
        if val != self.required:
            self.err.update("Confirmation does not match. Nothing has been done.")
            return
        self.app.push_screen(ExecuteScreen())


class RollbackScreen(Screen):
    BINDINGS = [("q", "quit", "Quit"), ("b", "back", "Back")]

    def __init__(self, error_text: str, *, was_upgrade: bool) -> None:
        super().__init__()
        self.error_text = error_text
        self.was_upgrade = was_upgrade

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Service failed to start[/b]\n", classes="warn")

            expl = (
                "What happened:\n"
                "  • PQ-NAS was installed, but systemd could not start pqnas.service.\n\n"
                "Rollback option:\n"
                "  • If this was an upgrade, the installer saved previous binaries as:\n"
                "      /usr/local/bin/pqnas_server.bak\n"
                "      /usr/local/bin/pqnas_keygen.bak\n"
                "  • Rollback will restore those .bak files and restart pqnas.service.\n\n"
                "Notes:\n"
                "  • Rollback changes ONLY binaries, not your data/config.\n"
            )
            yield Static(expl, classes="muted")

            yield Static("[b]Error details[/b]", classes="muted")
            self.err_box = Static(self.error_text.strip() or "(no error text)", classes="muted")
            yield self.err_box

            with Horizontal():
                self.btn_status = Button("Show systemd status", id="status", variant="default")
                yield self.btn_status
                self.btn_keep = Button("Keep new binaries (no rollback)", id="keep", variant="default")
                yield self.btn_keep
                self.btn_rollback = Button("Rollback binaries + restart service", id="rollback", variant="error")
                yield self.btn_rollback

            self.out = Log()
            yield self.out
        yield Footer()

    def on_mount(self) -> None:
        if not self.was_upgrade or not have_bak_binaries("/usr/local/bin"):
            self.btn_rollback.disabled = True
            self.out.write("[!] Rollback not available (no upgrade detected or no .bak binaries).")

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "status":
            self._show_status()
        elif event.button.id == "keep":
            self.app.pop_screen()
        elif event.button.id == "rollback":
            self._do_rollback()

    def _show_status(self) -> None:
        p = subprocess.run(
            ["systemctl", "status", "pqnas.service", "--no-pager", "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.out.write((p.stdout or "").strip() or "(no output)")

    def _do_rollback(self) -> None:
        self.out.write("[*] Stopping pqnas.service …")
        if systemd_unit_exists("pqnas.service"):
            subprocess.run(
                ["systemctl", "stop", "pqnas.service"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            self.out.write("[*] pqnas.service not installed; skip stop.")


        self.out.write("[*] Restoring /usr/local/bin/*.bak → active binaries …")
        rollback_binaries("/usr/local/bin")

        self.out.write("[*] systemd daemon-reload …")
        subprocess.run(["systemctl", "daemon-reload"], check=False)

        self.out.write("[*] Restarting pqnas.service …")
        p = subprocess.run(
            ["systemctl", "restart", "pqnas.service"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        if p.returncode == 0:
            self.out.write("✅ Rollback done. Service restarted successfully.")
        else:
            self.out.write("❌ Rollback attempted but service still failed to start:")
            self.out.write((p.stdout or "").strip() or "(no output)")

class HealthScreen(Screen):
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("b", "back", "Back"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(
        self,
        *,
        mp: str,
        mode: str,
        backend: str,
        nginx_enabled: bool,
        nginx_hostname: str,
        nginx_port: int,
        auth_mode: str,
    ) -> None:
        super().__init__()
        self.mp = mp
        self.mode = mode
        self.backend = backend
        self.nginx_enabled = nginx_enabled
        self.nginx_hostname = nginx_hostname
        self.nginx_port = nginx_port
        self.auth_mode = auth_mode

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Install health[/b]\n", classes="muted")

            self.summary = Static("", classes="muted")
            yield self.summary

            with Horizontal():
                yield Button("Refresh checks", id="refresh", variant="primary")
                yield Button("systemctl status pqnas", id="status_pqnas", variant="default")
                yield Button("journalctl pqnas", id="logs_pqnas", variant="default")
                yield Button("nginx -t", id="nginx_test", variant="default")
                yield Button("ip addr", id="ip_addr", variant="default")

            self.out = Log()
            yield self.out

        yield Footer()

    def on_mount(self) -> None:
        self._render_summary()
        self.action_refresh()

    def _render_summary(self) -> None:
        if self.nginx_enabled and self.nginx_hostname:
            url = f"http://{self.nginx_hostname}/"
        else:
            url = "http://<server-ip>:8081/"

        lines = [
            f"[b]Storage:[/b] {self.mp}",
            f"[b]Mode:[/b] {self.mode}",
            f"[b]Backend:[/b] {self.backend}",
            f"[b]Auth mode:[/b] v5 (forced by installer)",
            "",
            f"[b]Access URL:[/b] {url}",
        ]


        if self.nginx_enabled and self.nginx_hostname:
            if looks_like_ip(self.nginx_hostname):
                lines.append("[b]DNS:[/b] not needed (you used an IP).")
            else:
                lines.append("[b]DNS:[/b] make sure this hostname resolves to this server (DNS/router/hosts).")

        self.summary.update("\n".join(lines))

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self.out.write("== checks ==")

        # pqnas.service status
        self.out.write("$ systemctl is-active pqnas.service")
        self.out.write(run_cmd_capture(["systemctl", "is-active", "pqnas.service"]) or "(no output)")

        self.out.write("$ systemctl status pqnas.service --no-pager -l")
        self.out.write(run_cmd_capture(["systemctl", "status", "pqnas.service", "--no-pager", "-l"]) or "(no output)")

        if self.nginx_enabled:
            self.out.write("")
            self.out.write("$ systemctl is-active nginx")
            self.out.write(run_cmd_capture(["systemctl", "is-active", "nginx"]) or "(no output)")

            self.out.write("$ nginx -t")
            self.out.write(run_cmd_capture(["nginx", "-t"]) or "(no output)")

        self.out.write("")
        self.out.write("$ ss -lntp | rg ':80|:8081'  (best effort)")
        # Don't fail if ss/rg missing; just show what we can.
        try:
            ss = run_cmd_capture(["ss", "-lntp"])
            filt = "\n".join([ln for ln in ss.splitlines() if (":80" in ln or ":8081" in ln)])
            self.out.write(filt or "(no listeners found for :80/:8081 in ss output)")
        except Exception as e:
            self.out.write(f"(could not run ss: {e})")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "refresh":
            self.action_refresh()
            return

        if bid == "status_pqnas":
            self.out.write("$ systemctl status pqnas.service --no-pager -l")
            self.out.write(run_cmd_capture(["systemctl", "status", "pqnas.service", "--no-pager", "-l"]) or "(no output)")
            return

        if bid == "logs_pqnas":
            self.out.write("$ journalctl -u pqnas.service -n 200 --no-pager")
            self.out.write(run_cmd_capture(["journalctl", "-u", "pqnas.service", "-n", "200", "--no-pager"]) or "(no output)")
            return

        if bid == "nginx_test":
            self.out.write("$ nginx -t")
            self.out.write(run_cmd_capture(["nginx", "-t"]) or "(no output)")
            return

        if bid == "ip_addr":
            self.out.write("$ ip -br addr")
            self.out.write(run_cmd_capture(["ip", "-br", "addr"]) or "(no output)")
            return

class ExecuteScreen(Screen):
    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 6/6[/b] Executing… (live log)\n", classes="muted")
            self.logw = Log()
            yield self.logw
            self.done = Static("", classes="muted")
            yield self.done
        yield Footer()

    def on_mount(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        st = app.state

        if not st.disk:
            self.done.update("No disk selected.")
            return

        mode = st.install_mode
        plan = st.plan or []

        self.logw.write(f"Mode: {mode}")
        self.logw.write(f"Mountpoint: {st.mountpoint}")
        self.logw.write("")

        self.logw.write(
            "NOTE: If this is an upgrade and the new version fails to start,\n"
            "you can use the Rollback screen to restore previous binaries\n"
            "from /usr/local/bin/*.bak and restart the service.\n"
        )

        # 1) Execute destructive plan only in disk mode
        if mode == "disk":
            if not plan:
                self.done.update("No plan to execute.")
                return

            ok = True
            for argv in plan:
                self.logw.write(f"$ {fmt_cmd(argv)}")
                try:
                    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    assert p.stdout is not None
                    for line in p.stdout:
                        log_line(self.logw, line.rstrip("\n"))
                    rc = p.wait()
                    if rc != 0:
                        ok = False
                        self.logw.write(f"[ERROR] exit code {rc}")
                        break
                except Exception as e:
                    ok = False
                    self.logw.write(f"[ERROR] {e}")
                    break

            if not ok:
                self.done.update(
                    "\n❌ Failed.\n\n"
                    "Nothing else will be executed. Check the log above.\n"
                    "You can safely rerun after wiping again.\n"
                )
                return
        else:
            self.logw.write("Existing filesystem mode: skipping wipe/partition/format steps.")
            self.logw.write("")

        # 2) Finalize (common for both modes)
        try:
            mp = st.mountpoint.rstrip("/") or "/srv/pqnas"
            backend = st.backend
            disk = st.disk
            assert disk is not None

            asset_root = REPO_ROOT  # REPO_ROOT == ASSET_ROOT in this file

            log_line(self.logw, "== Finalize ==")
            subprocess.run(["mkdir", "-p", mp], check=False)

            if mode == "disk":
                if backend in ("ext4", "btrfs"):
                    part = dev_part_path(disk)
                    uuid = get_uuid_for_device(part)
                    fstype = "ext4" if backend == "ext4" else "btrfs"
                    opts = "defaults,noatime,errors=remount-ro" if backend == "ext4" else "defaults,noatime,compress=zstd"

                    self.logw.write(f"Partition: {part}")
                    self.logw.write(f"UUID: {uuid}")
                    self.logw.write(f"Writing /etc/fstab entry for {mp}…")
                    write_fstab_uuid(mp, fstype, uuid, opts)

                    self.logw.write("Testing mount persistence: umount + mount -a …")
                    subprocess.run(["umount", mp], check=False)
                    subprocess.run(["mount", "-a"], check=True)
                    self.logw.write("mount -a OK")
                elif backend == "zfs":
                    self.logw.write("ZFS backend: mounts managed by ZFS.")
                    subprocess.run(["zfs", "mount", "-a"], check=False)
            else:
                self.logw.write("Existing filesystem mode: NOT writing /etc/fstab and NOT changing mounts.")

            self.logw.write(f"Creating PQ-NAS directory layout under {mp} …")
            create_pqnas_layout(mp)

            self.logw.write("Installing static assets to /opt/pqnas/static …")
            install_static_assets(asset_root, "/opt/pqnas/static")
            subprocess.run(["chown", "-R", "root:root", "/opt/pqnas/static"], check=False)

            self.logw.write("Installing DNA engine library to /opt/pqnas/lib/dna …")
            os.makedirs("/opt/pqnas/lib/dna", exist_ok=True)

            src_dna = find_dna_lib_source(asset_root)
            dst_dna = "/opt/pqnas/lib/dna/libdna_lib.so"

            tmp_dna = dst_dna + ".new"
            shutil.copy2(src_dna, tmp_dna)
            os.chmod(tmp_dna, 0o755)
            os.replace(tmp_dna, dst_dna)

            subprocess.run(["chown", "root:root", dst_dna], check=False)
            subprocess.run(["chmod", "755", dst_dna], check=False)

            self.logw.write(f"DNA lib installed: {dst_dna}  (from {src_dna})")


            self.logw.write(f"Installing bundled apps to {mp}/apps/bundled …")
            install_bundled_apps(asset_root, os.path.join(mp, "apps", "bundled"))

            self.logw.write("Ensuring /etc/pqnas config files …")
            ensure_config_files(mp, asset_root)

            self.logw.write("Writing /etc/pqnas/pqnas.env …")

            dna_path = "/opt/pqnas/lib/dna/libdna_lib.so"

            # Decide origin/rp_id from your nginx hostname if enabled
            origin = None
            rp_id = None

            if st.nginx_enabled and st.nginx_hostname:
                # If certbot/letsencrypt cert exists, prefer https; otherwise http
                if have_letsencrypt_cert(st.nginx_hostname):
                    origin = f"https://{st.nginx_hostname}"
                else:
                    origin = f"http://{st.nginx_hostname}"
                rp_id = st.nginx_hostname


            write_env_file(
                mp,
                origin=origin,
                rp_id=rp_id,
                dna_lib_path=dna_path,
                auth_mode=st.auth_mode,
            )


            # Make canonical URL handling impossible to miss
            if origin and rp_id:
                self.logw.write("")
                self.logw.write("🔒 Public URL locked to: " + origin)
                self.logw.write(
                    "[!] If you change domain or enable TLS later, update:\n"
                    "    /etc/pqnas/pqnas.env (PQNAS_ORIGIN + PQNAS_RP_ID)"
                )
            else:
                self.logw.write("")
                self.logw.write(
                    "[!] No public URL configured yet.\n"
                    "    If you later add nginx or HTTPS, update:\n"
                    "    /etc/pqnas/pqnas.env (PQNAS_ORIGIN + PQNAS_RP_ID)"
                )

            self.logw.write("")
            self.logw.write("== systemd ==")

            # Snapshot restore service + helper script (btrfs/zfs only)
            install_snapshot_restore_assets(asset_root, backend, log=self.logw)


            self.logw.write("Stopping pqnas.service (if running) …")
            if systemd_unit_exists("pqnas.service"):
                subprocess.run(
                    ["systemctl", "stop", "pqnas.service"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                subprocess.run(
                    ["systemctl", "disable", "--now", "pqnas.service"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                self.logw.write("pqnas.service not installed yet; skipping stop/disable.")

            subprocess.run(["pkill", "-f", r"^/usr/local/bin/pqnas_server$"], check=False)
            subprocess.run(["pkill", "-f", "pqnas_server"], check=False)

            server_exec, keygen_exec, was_upgrade = install_binaries(asset_root, "/usr/local/bin")

            if was_upgrade:
                self.logw.write("Upgrade detected: previous binaries saved as /usr/local/bin/*.bak")
            else:
                self.logw.write("First install detected.")

            self.logw.write(f"Installed server binary: {server_exec}")
            if keygen_exec:
                self.logw.write(f"Installed keygen binary: {keygen_exec}")

            self.logw.write("Checking runtime dependencies (ldd) …")
            self.logw.write("This may take a while (apt-get update/install).")
            ensure_runtime_deps_for_server(
                server_exec,
                log=self.logw,
                extra_ldd_paths=["/opt/pqnas/lib/dna/libdna_lib.so"],
            )


            self.logw.write("Generating /etc/pqnas/keys.env …")
            write_keys_env(asset_root, "/etc/pqnas/keys.env")
            self.logw.write("keys.env written (mode 600).")

            unit_path = write_systemd_unit(server_exec, "/etc/pqnas/pqnas.env")
            self.logw.write(f"Wrote unit: {unit_path}")

            self.logw.write("Reloading systemd…")
            run_systemctl(["daemon-reload"])

            self.logw.write("Enabling + starting pqnas.service …")
            try:
                run_systemctl(["enable", "--now", "pqnas.service"])
            except Exception as e:
                err_text = str(e)
                self.logw.write("[ERROR] pqnas.service failed to start.")
                self.logw.write(err_text)
                self.app.push_screen(RollbackScreen(err_text, was_upgrade=was_upgrade))
                self.done.update(
                    "\n⚠️ Service failed to start.\n\n"
                    "Use the rollback screen to restore previous binaries or keep the new ones.\n"
                )
                return

            self.logw.write("Service status:")
            status = subprocess.run(
                ["systemctl", "status", "pqnas.service", "--no-pager", "-l"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.logw.write((status.stdout or "").strip())

            # Optional: nginx reverse proxy (HTTP-only)
            if st.nginx_enabled:
                self.logw.write("")
                self.logw.write("== nginx reverse proxy ==")
                self.logw.write(f"Host: {st.nginx_hostname}")
                self.logw.write(f"Listen: {st.nginx_listen_port}")
                self.logw.write("Installing nginx if needed …")
                ensure_nginx_installed(log=self.logw)

                self.logw.write("Writing nginx site config …")
                conf_path = write_nginx_site_https_if_available(
                    server_name=st.nginx_hostname,
                    upstream_host="127.0.0.1",
                    upstream_port=8081,
                    client_max_body_size="2g",
                )
                if have_letsencrypt_cert(st.nginx_hostname):
                    self.logw.write(f"✅ nginx enabled: https://{st.nginx_hostname}/ (http redirects with 308)")
                else:
                    self.logw.write(f"✅ nginx enabled: http://{st.nginx_hostname}/ (no TLS cert detected)")

                self.logw.write(f"Wrote: {conf_path}")

                self.logw.write("Testing + reloading nginx …")
                nginx_test_reload(log=self.logw)
                # Optional: Let's Encrypt HTTPS (only if user enabled it)
                if st.https_enabled:
                    self.logw.write("")
                    self.logw.write("== Let's Encrypt HTTPS ==")
                    ok = enable_letsencrypt_nginx(
                        domain=st.nginx_hostname,
                        email=st.https_email,
                        redirect=st.https_redirect,
                        logw=self.logw,
                    )
                    # Update PQNAS_ORIGIN/PQNAS_RP_ID to https now that TLS exists
                    self.logw.write("Updating /etc/pqnas/pqnas.env to use https origin …")
                    write_env_file(
                        mp,
                        origin=f"https://{st.nginx_hostname}",
                        rp_id=st.nginx_hostname,
                        dna_lib_path=dna_path,
                        auth_mode=st.auth_mode,
                    )
                    run_systemctl(["restart", "pqnas.service"])

                if ok:
                    self.logw.write("[OK] HTTPS enabled via certbot.")
                    # Re-write nginx config so it switches to 443 + redirect (now cert exists)
                    self.logw.write("Rewriting nginx site config for HTTPS …")
                    conf_path = write_nginx_site_https_if_available(
                        server_name=st.nginx_hostname,
                        upstream_host="127.0.0.1",
                        upstream_port=8081,
                        client_max_body_size="2g",
                    )
                    self.logw.write(f"Wrote: {conf_path}")
                    self.logw.write("Testing + reloading nginx …")
                    nginx_test_reload(log=self.logw)
                else:
                    self.logw.write("[WARN] HTTPS setup failed; continuing with HTTP.")

                if have_letsencrypt_cert(st.nginx_hostname):
                    self.logw.write(f"✅ nginx ready: https://{st.nginx_hostname}/  (http redirects with 308)")
                    self.logw.write("PQNAS_ORIGIN will be set to https automatically on next install/run (or edit /etc/pqnas/pqnas.env).")
                else:
                    self.logw.write(f"✅ nginx ready: http://{st.nginx_hostname}/  (no TLS cert detected)")
                    self.logw.write("Tip: after you add TLS (certbot), PQNAS_ORIGIN should be https://… and HTTP should redirect with 308.")


                # DNS note (only meaningful for hostnames, not IPs)
                if not looks_like_ip(st.nginx_hostname):
                    self.logw.write("Note: if you used a hostname, ensure it resolves to this server (DNS/router/hosts).")
                else:
                    self.logw.write("Note: you used an IP, so DNS is not needed.")
            else:
                self.logw.write("")
                self.logw.write("nginx reverse proxy: (disabled)")

            self.logw.write("")
            self.logw.write("Layout created: data/ logs/ apps/ audit/ tmp/")

            self.done.update(
                "\n✅ Done.\n\n"
                f"Storage path: {mp}\n"
                f"Mode: {mode}\n"
                f"Backend: {backend}\n\n"
                "Created folders:\n"
                "  data/ logs/ apps/ audit/ tmp/\n"
            )
            self.app.push_screen(
                HealthScreen(
                    mp=mp,
                    mode=mode,
                    backend=backend,
                    nginx_enabled=st.nginx_enabled,
                    nginx_hostname=st.nginx_hostname,
                    nginx_port=st.nginx_listen_port,
                    auth_mode=st.auth_mode,
                )
            )

            return

        except Exception as e:
            self.logw.write(f"[FINALIZE ERROR] {e}")
            self.done.update(
                "\n⚠️ Finalize failed.\n\n"
                "Check log above.\n"
            )
            return


# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------


class InstallerApp(App):
    TITLE = "PQ-NAS Installer (TUI)"
    CSS = """
    Screen { background: #0b1020; color: #e9fbff; }
    #left { width: 46%; border: round #00f0f8; padding: 1; }
    #right { width: 54%; border: round #00f0f8; padding: 1; }
    .muted { color: #9ccbd6; }
    .warn { color: #ffd166; }
    """

    def __init__(self) -> None:
        super().__init__()
        self.disks: List[Disk] = []
        self.state = InstallState(plan=[], plan_notes=[])

    def on_mount(self) -> None:
        if os.geteuid() != 0:
            self.exit(message="Run as root: sudo ./installer/install.sh")
        self.push_screen(DiskSelectScreen())


if __name__ == "__main__":
    InstallerApp().run()
