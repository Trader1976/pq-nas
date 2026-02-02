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

REPO_ROOT = str(Path(__file__).resolve().parents[2])

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
    backend: str = "btrfs"  # default advanced
    mountpoint: str = "/srv/pqnas"
    # generated at plan step:
    plan: List[List[str]] = None  # argv lists
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
    # Keep it simple; you can rename later.
    for p in ("data", "logs", "apps", "audit", "tmp"):
        ensure_dir(os.path.join(root, p))

def ensure_config_files(root: str, repo_root: str) -> None:
    """
    Ensure PQ-NAS config files exist.

    Production layout:
      - /etc/pqnas/*.json   (config)
      - /srv/pqnas/*        (storage root)

    We copy defaults from repo_root/config into /etc/pqnas on first install.
    We do NOT overwrite existing config (idempotent), unless PQNAS_FORCE_CONFIG=1.
    """
    src = os.path.join(repo_root, "config")

    etc_dir = "/etc/pqnas"
    os.makedirs(etc_dir, exist_ok=True)

    force = os.environ.get("PQNAS_FORCE_CONFIG", "").strip() in ("1", "true", "yes", "y", "on")

    for name in ("admin_settings.json", "policy.json", "users.json", "shares.json"):
        s = os.path.join(src, name)
        d = os.path.join(etc_dir, name)

        if not os.path.exists(s):
            raise RuntimeError(f"Missing default config: {s}")

        if os.path.exists(d) and not force:
            continue

        shutil.copy2(s, d)

    # Optional: keep a pointer under the storage root (nice for humans)
    # This is NOT used by the server, just a breadcrumb.
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
        # Do not fail install on a non-critical breadcrumb write.
        pass

def write_env_file(root: str):
    """
    Write runtime environment file for PQ-NAS.

    This is sourced by systemd / launch scripts and tells the server
    where storage and config live.

    Production layout:
      PQNAS_ROOT=/srv/pqnas
      PQNAS_CONFIG=/etc/pqnas
    """

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
    ]

    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
# -----------------------------------------------------------------------------
# Install binaries
# -----------------------------------------------------------------------------
def install_binaries(repo_root: str, dest_dir: str = "/usr/local/bin") -> Tuple[str, Optional[str]]:
    """
    Copy pqnas_server + pqnas_keygen from repo build/bin into dest_dir.

    Returns: (server_exec_path, keygen_exec_path_or_None)
    """
    src_dir = os.path.join(repo_root, "build", "bin")
    src_server = os.path.join(src_dir, "pqnas_server")
    src_keygen = os.path.join(src_dir, "pqnas_keygen")

    if not os.path.exists(src_server):
        raise RuntimeError(f"Missing server binary: {src_server} (build first?)")

    os.makedirs(dest_dir, exist_ok=True)

    dst_server = os.path.join(dest_dir, "pqnas_server")
    shutil.copy2(src_server, dst_server)
    os.chmod(dst_server, 0o755)

    dst_keygen = None
    if os.path.exists(src_keygen):
        dst_keygen = os.path.join(dest_dir, "pqnas_keygen")
        shutil.copy2(src_keygen, dst_keygen)
        os.chmod(dst_keygen, 0o755)

    return dst_server, dst_keygen


def write_systemd_unit(exec_path: str, env_file: str = "/etc/pqnas/pqnas.env") -> str:
    """
    Write /etc/systemd/system/pqnas.service and return its path.
    """
    unit_path = "/etc/systemd/system/pqnas.service"

    unit = f"""[Unit]
Description=PQ-NAS Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={env_file}
ExecStart={exec_path}
Restart=on-failure
RestartSec=2

# For now we run as root (simple). Later we can add:
# User=pqnas
# Group=pqnas
# and hardening options.

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
                yield Static("[b]Step 1/5[/b] Select target disk\n\n"
                             "[r]R[/r] refresh  •  [r]N[/r] next  •  [r]Q[/r] quit\n",
                             classes="muted")
                self.lv = ListView()
                yield self.lv
            with Vertical(id="right"):
                yield Static("[b]Disk details[/b]\n", classes="muted")
                self.details = Static("", classes="muted")
                yield self.details
                self.warn = Static("", classes="warn")
                yield self.warn
        yield Footer()

    def on_mount(self) -> None:
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
            self.warn.update("This disk contains '/' and will be blocked from wiping.")
        else:
            self.warn.update("")

    def action_next(self) -> None:
        app: InstallerApp = self.app  # type: ignore
        if not app.state.disk:
            return
        if app.state.disk.is_system:
            self.warn.update("Refusing: selected disk is a SYSTEM disk.")
            return
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
        text.append(f"[b]Backend:[/b] {app.state.backend}")
        text.append(f"[b]Mountpoint:[/b] {app.state.mountpoint}\n")
        text.append("[b]Notes:[/b]")
        for n in (app.state.plan_notes or []):
            text.append(f"  • {n}")
        text.append("\n[b]Commands:[/b]")
        for i, argv in enumerate(app.state.plan or [], start=1):
            text.append(f"{i:02d}. {fmt_cmd(argv)}")

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
        self.required = f"WIPE {d.name}"
        self.msg.update(
            f"This will DESTROY ALL DATA on [b]{d.path}[/b].\n\n"
            f"To proceed, type exactly:\n\n"
            f"[b]{self.required}[/b]\n"
        )
        self.confirm_in.value = ""
        self.err.update("")
        self._sync_ui()

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
        plan = app.state.plan or []
        if not plan:
            self.done.update("No plan to execute.")
            return

        # Execute sequentially. This is intentionally simple for v1.
        # IMPORTANT: run the installer as root so commands don't prompt for password mid-flight.
        ok = True
        for i, argv in enumerate(plan, start=1):
            self.logw.write(f"$ {fmt_cmd(argv)}")
            try:
                p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                assert p.stdout is not None
                for line in p.stdout:
                    self.logw.write(line.rstrip("\n"))
                rc = p.wait()
                if rc != 0:
                    ok = False
                    self.logw.write(f"[ERROR] exit code {rc}")
                    break
            except Exception as e:
                ok = False
                self.logw.write(f"[ERROR] {e}")
                break

        if ok:
            # Post-install finalize: persist mount + create layout
            try:
                app: InstallerApp = self.app  # type: ignore
                st = app.state
                mp = st.mountpoint.rstrip("/") or "/srv/pqnas"
                backend = st.backend
                disk = st.disk
                assert disk is not None

                self.logw.write("")
                self.logw.write("== Finalize ==")

                subprocess.run(["mkdir", "-p", mp], check=False)

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

                self.logw.write(f"Creating PQ-NAS directory layout under {mp} …")
                create_pqnas_layout(mp)
                ensure_config_files(mp, REPO_ROOT)
                write_env_file(mp)
                self.logw.write("Config files copied and environment file written.")
                self.logw.write("Layout created: data/ logs/ apps/ audit/ tmp/")

                self.done.update(
                    "\n✅ Done.\n\n"
                    f"Storage mounted at: {mp}\n"
                    f"Backend: {backend}\n\n"
                    "Created folders:\n"
                    "  data/ logs/ apps/ audit/ tmp/\n"
                )

            except Exception as e:
                self.logw.write(f"[FINALIZE ERROR] {e}")
                self.done.update(
                    "\n⚠️ Storage created, but finalize failed.\n\n"
                    "Check log above. You may need to fix /etc/fstab or mounts manually.\n"
                )

        else:
            self.done.update(
                "\n❌ Failed.\n\n"
                "Nothing else will be executed. Check the log above.\n"
                "You can safely rerun after wiping again.\n"
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
            self.exit(message="Run as root: sudo /opt/pqnas-installer/venv/bin/python tools/installer/pqnas_install.py")

        self.push_screen(DiskSelectScreen())


if __name__ == "__main__":
    InstallerApp().run()
