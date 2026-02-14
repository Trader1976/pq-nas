# INSTALLING PROCEDURE

Download `pqnas-1.2.0-linux-x86_64.tar.gz` (or whatever version is available) and run:

tar -xzf pqnas-1.2.0-linux-x86_64.tar.gz

This will extract all required files into the `pqnas` folder.

Now do:

cd pqnas  
sudo ./install.sh

After install, open your NAS URL in a browser.  
You should now see a QR code.

---

## Common Errors

### DNA-Messenger says: Authentication Failed — Server returned 301

That means there is a mismatch between what the server presents for login and what is configured in:

/etc/pqnas/pqnas.env

If you already have an HTTPS certificate, you most likely still have HTTP configured.

Open:

sudo nano /etc/pqnas/pqnas.env

Find:

PQNAS_ORIGIN=http://...

Change it to:

PQNAS_ORIGIN=https://...

Restart the server:

sudo systemctl restart pqnas.service

---

# PQ-NAS User Manual — Admin Settings

This section explains the **Admin → Settings** page in PQ-NAS.

These controls allow administrators to:

- Control how much is written into the audit log
- Rotate audit logs manually or automatically
- Decide how long old audit logs are kept
- Preview and run safe cleanup operations

All actions here require administrator privileges.

---

# Audit Logging

PQ-NAS records security-relevant activity in an audit log.

The log is tamper-evident and designed for forensic review and compliance use.  
Once written, entries are never changed.

Instead of editing old logs, PQ-NAS:

- Rotates logs into archives
- Keeps or deletes old archives according to retention rules

---

# Audit Verbosity

This controls how much information is written into the audit log going forward.

## What the levels mean

- DEBUG — everything, including internal operations
- INFO — normal system activity
- ADMIN — configuration and administrative actions
- SECURITY — only security-relevant events

## What you see

- Persisted — the level that will survive restarts
- Runtime — what is currently active inside the server

## Buttons

Save  
Stores the selected level and activates it immediately.

Reload  
Reloads the values currently in use.

---

# Audit Rotation (Manual)

The Rotate now button immediately closes the current audit log and starts a new one.

Use this when:

- Performing maintenance
- Preparing for backups
- Segmenting logs for investigation
- Testing rotation policies

Rotation does not delete anything — it only archives the current file.

---

# Automatic Audit Rotation

This section controls when PQ-NAS should rotate logs by itself.

## Rotation modes

- Off — logs grow until rotated manually
- Daily — rotate once per day
- When size exceeds N MB — rotate when the active log becomes large
- Size OR daily — whichever happens first

## Fields

- Rotate MB — size limit for automatic rotation

Save policy stores the automatic rotation rules and activates them immediately.

---

# Audit Retention

Retention decides how long rotated audit logs are kept.

The active audit log is never removed by retention rules.  
Only archived logs are affected.

## Retention modes

- Never delete automatically — archives are kept forever
- Keep last N days — deletes older archives
- Keep last N files — keeps only the newest archives
- Keep up to N MB total — limits total disk usage of archives

## Buttons

Save policy  
Stores the retention rules.

Preview prune  
Shows what would be deleted without removing anything.

Use this before running prune in production.

Run prune now  
Deletes archived audit logs according to the saved rules.

A confirmation prompt is always shown first.

---

# Preview Table

When previewing retention, the table lists:

- File name
- Size
- Modification time
- Reason it would be deleted

A summary pill shows how much disk space would be freed.

---

# Active Log Status

The Settings page also displays:

- The current audit log size

This is useful for:

- Testing size-based rotation
- Capacity planning
- Verifying automatic rotation works

---

# Safe Operation Principles

PQ-NAS is designed so that administrators can operate these controls safely:

- Active audit logs are never deleted automatically
- Preview always runs before deletion
- All changes are audited
- Admin confirmation required for destructive actions
- Rotation never alters existing records
- Retention only affects archived logs

---

# When to Use What

Rotate now  
Use when you want to start a fresh audit log immediately.

Automatic rotation  
Enable to avoid oversized logs and to keep investigations cleanly separated.

Preview prune  
Always run before pruning in production.

Run prune now  
Use only after verifying the preview.

---

# Snapshots (Btrfs)

PQ-NAS supports automatic filesystem snapshots using Btrfs read-only subvolume snapshots.

Snapshots provide point-in-time copies of your data that can be used for:

- Recovering accidentally deleted files
- Rolling back after ransomware or corruption
- Inspecting historical states
- Creating backups or replication targets

Snapshots are created using:

btrfs subvolume snapshot -r <source> <destination>

They are read-only, lightweight, and space-efficient because Btrfs stores only changed blocks.

---

# How Snapshot Scheduling Works

Snapshots run periodically according to a schedule.

## Times per day

Controls how many snapshots are taken in 24 hours.

Examples:

1 = once per day  
2 = every 12 hours  
6 = every 4 hours  
24 = every hour

---

## Jitter (seconds)

Jitter adds a random delay before each scheduled run.

Why this matters:

- Prevents multiple systems from snapshotting at exactly the same second
- Avoids disk I/O spikes at fixed times
- Reduces contention when many services run on the same host

Example:

Times/day = 6  
Jitter = 120 seconds

Each snapshot will run roughly every 4 hours, plus a random delay of up to 2 minutes.

---

# Snapshot Retention Policy

Retention controls how many old snapshots are kept:

- keep_days — minimum age to keep
- keep_min — minimum number always preserved
- keep_max — maximum allowed snapshots

After every successful snapshot, PQ-NAS automatically prunes old ones while respecting these limits.

---

# Snapshot Volumes

Each snapshot entry contains:

- Volume name
- Source subvolume
- Snapshot root

Example:

{
"name": "data",
"source_subvolume": "/srv/pqnas/data",
"snap_root": "/srv/pqnas/.snapshots/data"
}

Snapshots are created inside the snapshot root as timestamped directories.

---

# Admin UI — Snapshot Controls

The Admin → Settings → Snapshots (Btrfs) panel allows runtime configuration.

Enabled  
Turns snapshotting on or off globally.

When disabled:
- No snapshots run
- Settings remain visible
- Inputs are greyed out

When enabled:
- Scheduler is active
- Snapshots run automatically

Per-volume schedule  
When enabled, each volume can override the global schedule.

Each volume row gets its own:
- Times/day
- Jitter

When disabled:
- All volumes use the global schedule.

Global Times / Day  
The default snapshot frequency applied to all volumes unless per-volume scheduling is enabled.

Global Jitter  
Default jitter applied to all volumes unless per-volume scheduling is enabled.

Snapshot Root Path  
Shows where snapshots are written for the primary volume.

This must:
- Be an absolute path
- Be empty or non-existent before creation
- Reside on the same Btrfs filesystem as the source subvolume

PQ-NAS will automatically create the directory if missing.

Save snapshots  
Writes the current snapshot configuration to disk and activates it.

This:
- Updates /etc/pqnas/admin_settings.json
- Reloads the scheduler
- Applies new timing immediately

Reload  
Reloads snapshot settings from the server.

Useful if:
- Another admin changed settings
- You edited configuration files manually
- You want to discard unsaved UI changes

---

# Locking and Safety

Only one snapshot runner executes at a time.

PQ-NAS uses a lock file:

/run/pqnas_snapshot.lock

(or /tmp as fallback)

This prevents overlapping snapshot jobs.

---

# Notes and Best Practices

Recommended Defaults for home / small office:

Times/day: 6  
Jitter: 120

Retention:
keep_days: 7  
keep_min: 12  
keep_max: 500

Snapshot Storage

Snapshot directories can grow large.  
Make sure:

- The snapshot root has enough free space
- Your backup strategy includes snapshot replication or cleanup

Snapshots Are Not Backups

Snapshots protect against:

- Accidental deletion
- Local corruption

They do not protect against:

- Disk failure
- Filesystem destruction
- Fire or theft

For full protection, replicate snapshots to another machine or off-site backup target.

---

# Advanced Usage

Administrators may:

- Add multiple volumes
- Use different schedules per volume
- Disable snapshotting temporarily during maintenance

---

# Snapshot Manager — Restore and Manual Snapshots

The Snapshot Manager allows administrators to:

- View all snapshots for each volume
- Inspect snapshot details
- Restore any snapshot safely
- Create a new snapshot manually ("Snapshot now")

Automatic snapshot scheduling is configured separately in:

Admin → Settings → Snapshots (Btrfs)

Snapshot Manager is used for manual operations and recovery.

---

# Opening Snapshot Manager

Open:

Admin → Snapshot Manager

The page contains two main columns:

Left column — Volumes  
Right column — Snapshots for the selected volume

Top bar contains:

Refresh — reload volumes and snapshots  
Details — show detailed snapshot information  
Restore — restore the selected snapshot  
Snapshot now — create a new snapshot immediately

---

# Volume List (Left Side)

Each row represents a configured snapshot volume.

Example row:

data    enabled  
/srv/pqnas/data  |  /srv/pqnas/.snapshots/data

Fields:

Volume name  
Logical volume identifier.

enabled / disabled  
Whether automatic snapshots are enabled for that volume.

source_subvolume  
The live data location.

snap_root  
Directory where snapshots are stored.

Selecting a volume loads its snapshots.

---

# Snapshot List (Right Side)

Each row represents one snapshot.

Example:

2026-02-14T11-21-40.805Z    ro

Fields:

Snapshot ID  
Timestamp-based identifier.

Status label (right side)

Possible values:

latest  
Newest snapshot available.

ro  
Read-only snapshot (normal and expected).

rw  
Read-write snapshot (unusual; typically indicates a manual or non-standard snapshot).

⚠  
Snapshot could not be verified due to missing sudo permissions.

junk  
Directory exists but is not a valid Btrfs snapshot subvolume.

Creation time  
Displayed below the snapshot ID.

Snapshots are sorted newest first.

---

# What ro and rw Mean

ro — Read-only snapshot  
This is the normal and safe snapshot type.

Properties:

Cannot be modified  
Fully safe for restore  
Created using:

btrfs subvolume snapshot -r <source> <destination>

rw — Read-write snapshot  
This is not normally created by PQ-NAS.

May indicate:

Manual test snapshot  
External tool snapshot  
Improper snapshot

PQ-NAS restore still works, but read-only snapshots are recommended.

---

# Snapshot now Button

Snapshot now creates a new snapshot immediately.

This is useful when:

Before software upgrades  
Before risky changes  
Before deleting or moving large files  
Before maintenance

When clicked, PQ-NAS runs:

btrfs subvolume snapshot -r <source_subvolume> <snap_root>/<timestamp>

The new snapshot appears in the list within seconds.

This does not affect automatic scheduling.

---

# Restore Button

Restore replaces the live volume with the selected snapshot.

Steps:

1. Select a snapshot
2. Click Restore
3. Confirm the action
4. Type the confirmation phrase exactly
5. Confirm restore plan

PQ-NAS will:

Stop pqnas.service briefly  
Preserve current data as backup  
Replace live data with snapshot  
Restart pqnas.service

Downtime is typically less than a few seconds.

---

# Backup Safety During Restore

Before restore, PQ-NAS automatically creates a backup of the current live volume.

Example:

/srv/pqnas/data.pre_restore.2026-02-14T11-28-08.838Z

This allows recovery if needed.

Backups can be removed manually after verification.

---

# Details Button

Shows technical information about the selected snapshot.

Includes:

Full filesystem path  
Verification result  
Internal metadata  
Btrfs subvolume information

This is useful for troubleshooting.

---

# Refresh Button

Reloads volumes and snapshots from the server.

Use this when:

A new snapshot was created  
Another admin performed changes  
You want the latest status

---

# Status Labels and Meaning

latest  
Newest snapshot available.

ro  
Safe read-only snapshot.

rw  
Writable snapshot (not standard).

⚠  
Verification failed due to missing sudo permission.

junk  
Directory is not a valid snapshot.

Only valid Btrfs snapshots can be restored.

---

# Restore Safety Model

Restore uses atomic subvolume swap.

This means:

No partial restores  
No inconsistent state  
Instant rollback capability

PQ-NAS guarantees either:

Restore fully succeeds  
or  
System remains unchanged

---

# Recommended Usage

Create snapshot now before:

System upgrades  
Configuration changes  
File deletions  
Testing

Restore snapshot when:

Files were deleted accidentally  
Data became corrupted  
Ransomware or unwanted changes occurred

---

# Relationship with Automatic Snapshots

Snapshot Manager does not control automatic snapshot schedules.

Scheduling is configured in:

Admin → Settings → Snapshots

Snapshot Manager is used for:

Manual snapshots  
Restore operations  
Inspection

---

# Safety and Permissions

All Snapshot Manager operations require administrator privileges.

All actions are audited.

Restore operations require explicit confirmation.

Snapshots are always created inside configured snap_root directories.

---

# Summary

Snapshot Manager provides safe and reliable recovery.

Key capabilities:

View snapshots  
Create snapshots manually  
Restore any snapshot  
Inspect snapshot details

Snapshots are fast, space-efficient, and safe.

---

© CPUNK 2026 — PQ-NAS Security Platform

