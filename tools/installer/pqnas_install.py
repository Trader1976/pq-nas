#!/usr/bin/env python3
"""
PQ-NAS CLI Installer (Textual) — Wizard v1

Flow:
  1) Disk selection (safe: system disks marked + blocked)
  2) Backend selection: ext4 / btrfs / zfs
  3) Plan preview (exact commands shown)
  4) Typed confirm: "WIPE <diskname>"
  5) Execute with live log

Notes:
- This is designed to be run as root (sudo), since it needs disk ops later.
- We generate a command plan first; execution only occurs after typed confirmation.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Static, ListView, ListItem, Label,
    RadioSet, RadioButton, Button, Input, Log
)
from textual.screen import Screen

import shutil
from pathlib import Path

def log_line(logw: Log, msg: str) -> None:
    # Force each message to be a separate line in Textual Log widget
    logw.write(msg.rstrip("\n") + "\n")

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
        raise RuntimeError(f"apt-get update failed:\n{p1.stdout.strip()}")

    w(f"[*] apt-get install: {' '.join(pkgs)} …")
    p2 = subprocess.run(
        ["apt-get", "install", "-y", *pkgs],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if p2.returncode != 0:
        raise RuntimeError(f"apt-get install failed:\n{p2.stdout.strip()}")


def ensure_runtime_deps_for_server(server_exec: str, log: Optional[Log] = None) -> None:
    """
    Ensure pqnas_server has all shared libraries.
    Debian/Ubuntu only; other distros fail with clear error.
    """
    missing = ldd_missing_libs(server_exec)
    if not missing:
        if log:
            log.write("[*] Runtime deps: OK (ldd clean).")
        return

    # Explicit SONAME -> package mapping (extend only when proven missing)
    soname_to_pkg = {
        "libqrencode.so.4": "libqrencode4",
    }

    pkgs: List[str] = []
    unknown: List[str] = []

    for lib in missing:
        pkg = soname_to_pkg.get(lib)
        if pkg:
            pkgs.append(pkg)
        else:
            unknown.append(lib)

    if unknown:
        raise RuntimeError(
            "Missing shared libraries with no package mapping:\n"
            + "\n".join(f"  - {x}" for x in unknown)
            + "\nInstall them manually or extend soname_to_pkg."
        )

    if log:
        log.write("[*] Missing runtime libs: " + ", ".join(missing))
        log.write("[*] Installing via apt: " + ", ".join(pkgs))

    apt_install(sorted(set(pkgs)), log=log)

    # Re-check
    missing2 = ldd_missing_libs(server_exec)
    if missing2:
        raise RuntimeError(
            "Runtime deps still missing after apt install:\n"
            + "\n".join(f"  - {x}" for x in missing2)
        )

    if log:
        log.write("[*] Runtime deps resolved (ldd now OK).")


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
REPO_ROOT = ASSET_ROOT  # keep variable name to minimize edits; it's "asset root" now

#REPO_ROOT = find_repo_root()

# -----------------------------------------------------------------------------
# Models + state
# -----------------------------------------------------------------------------

@dataclass
class Disk:
    name: str          # e.g. "nvme0n1"
    path: str          # e.g. "/dev/nvme0n1"
    size: str          # e.g. "931.5G"
    model: str
    serial: str
    mountpoints: str
    is_system: bool    # heuristic: contains "/" mountpoint


@dataclass
class InstallState:
    disk: Optional[Disk] = None
    backend: str = "btrfs"
    mountpoint: str = "/srv/pqnas"
    install_mode: str = "disk"   # "disk" (wipe) or "existing" (no partitioning)
    plan: List[List[str]] = None
    plan_notes: List[str] = None


# -----------------------------------------------------------------------------
# System helpers (read-only + execution)
# -----------------------------------------------------------------------------

def run_cmd(argv: List[str]) -> str:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(argv)}\n{p.stderr.strip()}")
    return p.stdout


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

        disks.append(Disk(
            name=name, path=path, size=size,
            model=model, serial=serial,
            mountpoints=mp_join, is_system=is_system
        ))

    disks.sort(key=lambda d: (not d.is_system, d.name))
    return disks


def fmt_cmd(argv: List[str]) -> str:
    # shell-escaped display only
    return " ".join(shlex.quote(x) for x in argv)

def must_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("This installer must run as root (sudo).")


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
                # crude parse: fields separated by whitespace
                parts = s.split()
                if len(parts) >= 2 and parts[1] == mountpoint:
                    return True
    except FileNotFoundError:
        return False
    return False


def append_fstab_entry(entry: str) -> None:
    # Ensure file exists
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

    # overwrite program assets (idempotent)
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
    Copy bundled apps into the storage root.

    repo mode:    <repo>/apps/bundled/*
    package mode: <pkg>/bundled/*
    """

    pkg = os.path.join(asset_root, "bundled")
    repo = os.path.join(asset_root, "apps", "bundled")

    src = pkg if os.path.isdir(pkg) else repo
    if not os.path.isdir(src):
        return  # OK if none exist yet

    os.makedirs(apps_bundled_dest, exist_ok=True)

    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(apps_bundled_dest, name)

        if os.path.isdir(s):
            if os.path.exists(d):
                shutil.rmtree(d)
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)

def ensure_config_files(root: str, asset_root: str) -> None:
    """
    Ensure PQ-NAS config files exist.

    Production layout:
      - /etc/pqnas/*.json   (config)
      - /srv/pqnas/*        (storage root)

    Source of defaults:
      - package mode: <asset_root>/config
      - repo mode:    <asset_root>/config  (repo root also has config/)
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

def write_env_file(root: str):
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

    kv = []
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

    # Write file (simple version). If you want extra safety, write to temp then rename.
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(kv) + "\n")

    os.chmod(path, 0o600)

# -----------------------------------------------------------------------------
# Install binaries
# -----------------------------------------------------------------------------
def install_binaries(asset_root: str, dest_dir: str = "/usr/local/bin") -> Tuple[str, Optional[str]]:
    """
    Install pqnas_server + pqnas_keygen into /usr/local/bin.

    repo mode:    <repo>/build/bin/*
    package mode: <pkg>/pqnas_server and <pkg>/pqnas_keygen
    """
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
    tmp_server = dst_server + ".new"
    shutil.copy2(src_server, tmp_server)
    os.chmod(tmp_server, 0o755)
    os.replace(tmp_server, dst_server)  # atomic replace on same filesystem


    dst_keygen = None
    if src_keygen and os.path.isfile(src_keygen):
        dst_keygen = os.path.join(dest_dir, "pqnas_keygen")
        tmp_keygen = dst_keygen + ".new"
        shutil.copy2(src_keygen, tmp_keygen)
        os.chmod(tmp_keygen, 0o755)
        os.replace(tmp_keygen, dst_keygen)

    return dst_server, dst_keygen


def write_systemd_unit(exec_path: str,
                       env_file: str = "/etc/pqnas/pqnas.env",
                       keys_file: str = "/etc/pqnas/keys.env") -> str:
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



def run_systemctl(args: List[str]) -> str:
    p = subprocess.run(["systemctl", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"systemctl {' '.join(args)} failed:\n{p.stdout.strip()}")
    return p.stdout

# -----------------------------------------------------------------------------
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

    # Safety: refuse system disk (even at plan time)
    if d.is_system:
        raise RuntimeError("Refusing to operate on system disk (contains / mount).")

    # Always clean slate first (avoid interactive prompts)
    # For ZFS ghosts, we do a hard wipe of first 32MiB as you discovered.
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
        # GPT + single partition + ext4 + mountpoint (fstab step later)
        part = f"{d.path}p1" if "nvme" in d.name else f"{d.path}1"
        plan += [
            ["parted", d.path, "--script", "mklabel", "gpt", "mkpart", "primary", "ext4", "1MiB", "100%"],
            ["partprobe", d.path],
            ["mkfs.ext4", "-F", "-L", "PQNAS_DATA", part],
            ["mkdir", "-p", mp],
            ["mount", part, mp],
        ]
        notes.append("Backend: ext4 (no snapshots).")

    elif state.backend == "btrfs":
        part = f"{d.path}p1" if "nvme" in d.name else f"{d.path}1"
        plan += [
            ["parted", d.path, "--script", "mklabel", "gpt", "mkpart", "primary", "btrfs", "1MiB", "100%"],
            ["partprobe", d.path],
            ["mkfs.btrfs", "-f", "-L", "PQNAS_DATA", part],
            ["mkdir", "-p", mp],
            # mount root, create subvols, remount data subvol
            ["mount", part, mp],
            ["btrfs", "subvolume", "create", f"{mp}/data"],
            ["btrfs", "subvolume", "create", f"{mp}/snaps"],
            ["umount", mp],
            ["mount", "-o", "subvol=data", part, mp],
        ]
        notes.append("Backend: btrfs (snapshots supported via subvolumes).")

    elif state.backend == "zfs":
        pool = "pqnas"
        # Use whole disk vdev (no partitions) for simplicity.
        # Note: mountpoint default is /<pool>; we set a custom root mountpoint under mp.
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

    notes.append("TODO next: write /etc/fstab (ext4/btrfs) or import-on-boot for ZFS; also permissions.")
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
                    "[b]Step 1/5[/b] Select target disk\n\n"
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
        # default mode: disk wipe
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

        # Read selected mode
        chosen_mode = "disk"
        for btn in self.mode.query(RadioButton):
            if btn.value:
                chosen_mode = btn.id
                break

        app.state.install_mode = chosen_mode

        # In wipe-mode, block system disk
        if chosen_mode == "disk" and app.state.disk.is_system:
            self.warn.update("Refusing: selected disk is a SYSTEM disk (contains '/').")
            return

        # In existing-mode, allow system disk but warn
        if chosen_mode == "existing":
            self.mode_hint.update(
                "WARNING: Existing filesystem mode uses your current root disk capacity. "
                "Use /srv/pqnas and monitor free space."
            )

        app.push_screen(BackendSelectScreen())


def action_next(self) -> None:
    app: InstallerApp = self.app  # type: ignore
    if not app.state.disk:
        return

    chosen_mode = "disk"
    for btn in self.mode.query(RadioButton):
        if btn.value:
            chosen_mode = btn.id
            break

    app.state.install_mode = chosen_mode

    # If wipe-mode, block system disk
    if chosen_mode == "disk" and app.state.disk.is_system:
        self.warn.update("Refusing: selected disk is a SYSTEM disk.")
        return

    # If existing-mode, warn loudly but allow
    if chosen_mode == "existing" and app.state.disk.is_system:
        self.warn.update("Using existing filesystem on '/'. No partitioning will be done.")
        self.mode_hint.update("WARNING: This can fill your root filesystem. Use /srv/pqnas and monitor free space.")

    app.push_screen(BackendSelectScreen())



class BackendSelectScreen(Screen):
    BINDINGS = [("b", "back", "Back"), ("n", "next", "Next"), ("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 2/5[/b] Select storage backend\n", classes="muted")

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
        # set defaults based on state
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
            yield Static("[b]Step 3/5[/b] Plan preview (exact commands)\n", classes="muted")
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
        text = []
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
        self.app.push_screen(ConfirmScreen())


class ConfirmScreen(Screen):
    BINDINGS = [
        ("b", "back", "Back"),
        ("enter", "try_start", "Start"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 4/5[/b] Destructive confirmation\n", classes="warn")
            self.msg = Static("", classes="muted")
            yield self.msg

            self.confirm_in = Input(placeholder="Type the confirmation exactly…")
            yield self.confirm_in

            self.hint = Static(
                "Tip: type the text, then press Enter • Tab moves focus to buttons",
                classes="muted",
            )
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
        mode = app.state.install_mode

        if mode == "existing":
            self.required = f"INSTALL {app.state.mountpoint.rstrip('/') or '/srv/pqnas'}"
            self.msg.update(
                f"This will install PQ-NAS into the existing filesystem.\n\n"
                f"No partitioning or formatting will be done.\n\n"
                f"Target path:\n\n"
                f"[b]{app.state.mountpoint}[/b]\n\n"
                f"To proceed, type exactly:\n\n"
                f"[b]{self.required}[/b]\n"
            )
        else:
            self.required = f"WIPE {d.name}"
            self.msg.update(
                f"This will DESTROY ALL DATA on [b]{d.path}[/b].\n\n"
                f"To proceed, type exactly:\n\n"
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
        # Enter key binding
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



class ExecuteScreen(Screen):
    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("[b]Step 5/5[/b] Executing… (live log)\n", classes="muted")
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

        # -----------------------------------------------------------------
        # 1) Execute destructive plan only in disk mode
        # -----------------------------------------------------------------
        if mode == "disk":
            if not plan:
                self.done.update("No plan to execute.")
                return

            ok = True
            for i, argv in enumerate(plan, start=1):
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

        # -----------------------------------------------------------------
        # 2) Finalize (common for both modes)
        # -----------------------------------------------------------------
        try:
            mp = st.mountpoint.rstrip("/") or "/srv/pqnas"
            backend = st.backend
            disk = st.disk
            assert disk is not None

            asset_root = REPO_ROOT  # in your file REPO_ROOT == ASSET_ROOT

            log_line(self.logw, "== Finalize ==")
            subprocess.run(["mkdir", "-p", mp], check=False)

            if mode == "disk":
                # Persist mounts only if we actually created filesystems
                if backend in ("ext4", "btrfs"):
                    part = dev_part_path(disk)
                    uuid = get_uuid_for_device(part)
                    fstype = "ext4" if backend == "ext4" else "btrfs"

                    if backend == "ext4":
                        opts = "defaults,noatime,errors=remount-ro"
                    else:
                        opts = "defaults,noatime,compress=zstd"

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

            self.logw.write(f"Installing bundled apps to {mp}/apps/bundled …")
            install_bundled_apps(asset_root, os.path.join(mp, "apps", "bundled"))

            self.logw.write("Ensuring /etc/pqnas config files …")
            ensure_config_files(mp, asset_root)

            self.logw.write("Writing /etc/pqnas/pqnas.env …")
            write_env_file(mp)

            self.logw.write("")
            self.logw.write("== systemd ==")

            # If we're re-installing/upgrading, stop the service first so the binary isn't "text file busy".
            self.logw.write("Stopping pqnas.service (if running) …")
            subprocess.run(["systemctl", "stop", "pqnas.service"], check=False)

            # Prevent auto-restart loops during upgrade (safe if not enabled yet)
            subprocess.run(["systemctl", "disable", "--now", "pqnas.service"], check=False)

            # Best-effort kill if something still has it open
            subprocess.run(["pkill", "-f", r"^/usr/local/bin/pqnas_server$"], check=False)
            subprocess.run(["pkill", "-f", "pqnas_server"], check=False)

            server_exec, keygen_exec = install_binaries(asset_root, "/usr/local/bin")
            self.logw.write(f"Installed server binary: {server_exec}")
            if keygen_exec:
                self.logw.write(f"Installed keygen binary: {keygen_exec}")

                # --- NEW: sanity-check runtime deps before systemd ---
            self.logw.write("Checking runtime dependencies (ldd) …")
            ensure_runtime_deps_for_server(server_exec, log=self.logw)


            self.logw.write("Generating /etc/pqnas/keys.env …")
            write_keys_env(asset_root, "/etc/pqnas/keys.env")
            self.logw.write("keys.env written (mode 600).")

            unit_path = write_systemd_unit(server_exec, "/etc/pqnas/pqnas.env")
            self.logw.write(f"Wrote unit: {unit_path}")

            self.logw.write("Reloading systemd…")
            run_systemctl(["daemon-reload"])

            self.logw.write("Enabling + starting pqnas.service …")
            run_systemctl(["enable", "--now", "pqnas.service"])

            self.logw.write("Service status:")
            status = subprocess.run(
                ["systemctl", "status", "pqnas.service", "--no-pager", "-l"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.logw.write(status.stdout.strip())

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

        except Exception as e:
            self.logw.write(f"[FINALIZE ERROR] {e}")
            self.done.update(
                "\n⚠️ Finalize failed.\n\n"
                "Check log above.\n"
            )



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
        # Require root to avoid sudo prompts mid-flight.
        if os.geteuid() != 0:
            # Show a simple message and exit.
            # (Textual full-screen still works, but we keep it minimal.)
            self.exit(message="Run as root: sudo ./installer/install.sh")


        self.push_screen(DiskSelectScreen())


if __name__ == "__main__":
    InstallerApp().run()
