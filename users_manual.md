# PQ-NAS Users Manual

**PQ-NAS** is a modular, quantum-resistant Network Attached Storage (NAS) orchestration layer designed for Linux systems. It provides multi-user support, multi-storage-pool management, application-based extensibility, and a straightforward installation process.

Unlike many traditional NAS solutions, PQ-NAS does not replace or take over the host operating system. Instead, it runs on top of Linux, allowing the same host to continue running other applications and containers in parallel.

PQ-NAS is designed to work together with the **CPUNK DNA-Messenger** application, where user identity (fingerprint) is derived from post-quantum cryptographic keys.

PQ-NAS currently has two important security contexts:

1. **Authentication and session access**
2. **Post-quantum file sharing**

Authentication remains device-mediated through DNA-Messenger.  
PQ file sharing uses local browser-side decryption for protected share opening.

---

## 1. System requirements

For the best user experience, it is recommended to install PQ-NAS on a **Btrfs** filesystem. This enables full use of advanced features such as:

- snapshots
- RAID pool management
- volume restore workflows

PQ-NAS can also be installed on an **Ext4** filesystem and even operated with a single SSD or HDD. However, this configuration comes with limitations, especially regarding snapshots and advanced storage features.

### Recommended storage configuration

- One dedicated **system drive** where the operating system and PQ-NAS are installed (Ext4 or Btrfs)
- One or more **separate SSDs/HDDs** dedicated to user data storage
- For RAID data mirroring, at least **two data SSDs/HDDs**

Separating the system drive from the data drives improves:

- reliability
- maintainability
- upgrade flexibility

### Memory requirements

- **Minimum:** 8 GB RAM
- **Recommended:** 16 GB RAM for smoother operation, especially in multi-user or multi-pool environments

---

## 2. Installation

Download the Linux tarball package to your NAS server. Extracting the package will create a `pqnas` directory containing all required files.

Navigate to the extracted directory and run:

```bash
sudo ./install.sh
```

This command starts the installation procedure.

After installation is complete and PQ-NAS is accessible in your web browser, a QR code will be displayed.

Using the QR scanner in the DNA-Messenger application, scan the QR code and approve the authentication request. After successful verification, you will be redirected to the main page of PQ-NAS.

Your cryptographic fingerprint will automatically be registered in the PQ-NAS user registry.

If you are the first user to authenticate, you will automatically be granted administrator privileges. Administrators have full permission to configure system settings and manage users.

---

## 2.1 Initial configuration

PQ-NAS is designed as a modular NAS orchestration framework. By default, a fresh installation does not include functional apps for everyday use. To begin using the system, you should install at least one application.

At minimum, it is recommended to install:

- **File Manager**

For a more complete user experience, the following applications are recommended:

- **File Manager**
- **Share Manager**
- **Storage Manager**
- **Snapshot Manager** (when using Btrfs snapshots)

These applications provide essential file access, sharing, storage administration, and recovery features.

### File system requirements

To fully utilize advanced features such as **snapshots** and **RAID**, your data drives should use **Btrfs**.

PQ-NAS can also operate on systems using **Ext4**, but certain features will be limited.

A common and supported configuration is:

- The system drive (where the operating system and PQ-NAS are installed) uses Ext4
- Separate data drives use Btrfs to enable RAID and snapshot functionality

---

## 2.2 Storage allocation

After installing the File Manager application, you may see the message:

> “Storage not allocated yet”

This is expected behavior. Every user — including administrators — must have storage space explicitly allocated before accessing file services.

To allocate storage:

1. Navigate to **Admin → User Profiles**
2. Open your user account entry
3. Click **Allocate**
4. Select the **storage pool** and specify the **quota** in gigabytes

After confirming the allocation, PQ-NAS will create the user’s personal data directory inside the selected storage pool and reserve the requested quota.

### Important notes

- For administrator accounts, the options **Enable**, **Disable**, **Revoke**, and **Delete** are disabled for the currently logged-in administrator
- An administrator cannot demote, disable, or delete their own account
- Storage allocation must be performed before the user can access file services

---

## 2.3 Storage pools and migration

PQ-NAS may contain multiple storage pools. Each user’s data resides in exactly one active pool at a time.

If storage hardware is added or reorganized, user data can be moved safely between pools.

To migrate a user’s storage:

1. Navigate to **Admin → User Profiles**
2. Open the desired user entry
3. Click **Migrate**
4. Select the destination storage pool

The migration runs as an asynchronous background job. PQ-NAS will:

- copy the user’s data to the destination pool
- verify the copied data
- switch the user’s storage mapping to the new pool

During migration the system remains operational, and the process can be monitored through status messages displayed in the interface.

---

## 2.4 Cleaning up old storage copies

After a successful migration, the original storage location may still contain a copy of the user’s data.

This copy is preserved temporarily as a safety measure.

Once the administrator has confirmed that the migration completed successfully, the obsolete copy can be removed.

To remove the old storage copy:

1. Navigate to **Admin → User Profiles**
2. Open the user entry
3. Click **Cleanup old copy**
4. Confirm the storage pool containing the obsolete data

PQ-NAS will verify that the user is actively mapped to the current storage pool before removing the old directory. This prevents accidental deletion of active data.

---

## 2.5 Profile settings

From the same user profile screen, you may also:

- change your avatar image
- update optional profile information such as name, notes, and email
- review storage usage and quota information

---

## 2.6 User approvals

When configuring PQ-NAS for a multi-user environment, additional users may access the system by opening PQ-NAS in their web browser and scanning the displayed QR code using DNA-Messenger.

After successful authentication, each user’s cryptographic fingerprint will appear in the **Admin → Approvals** page.

From this page, an administrator can review pending authentication requests and decide which users are granted access.

### Granting access

1. Open **Admin → Approvals**
2. Approve the desired user
3. Navigate to **Admin → User Profiles**
4. Allocate storage space for the approved user

Once storage has been allocated, the user can begin using PQ-NAS normally.

---

## 2.7 Applications

PQ-NAS is a modular NAS system that supports extensible functionality through installable applications. Administrators can install and manage applications to customize the user experience.

To install an application:

1. Navigate to **Admin → Apps**
2. Select **Install App from ZIP**
3. Choose the application ZIP package from your local computer
4. Click **Install**

After successful installation, the application will appear in the list of installed apps.

### Application validation

PQ-NAS enforces strict application validation. Only application packages that meet the required structural and security criteria can be installed.

If the ZIP package is missing mandatory files or does not conform to the required format, installation will be rejected.

This validation mechanism helps preserve system integrity and security.

### Accessing installed applications

Once successfully installed, the application will appear in the main screen’s left navigation panel and can be accessed by authorized users.

---

## 2.8 File sharing

PQ-NAS supports both standard file sharing and post-quantum protected sharing, depending on the application flow and share type.

### Standard shares

Standard shares are suitable for simple browser-based download scenarios. The server generates and validates the share according to the configured rules.

### Post-quantum shares

PQ shares are intended for stronger recipient-bound protection.

In the current PQ share model:

- the file content encryption key is wrapped for the intended recipient
- unwrap and payload decryption happen locally in the browser
- the downloaded file is verified before final save

This means PQ share opening has a different trust model from login authentication:

- the browser is **not** trusted for authentication
- the browser **is** the local decryption endpoint for PQ share opening

### Practical implications

For PQ share opening:

- the server delivers encrypted payloads and share metadata
- the browser unwraps the file key and decrypts the content locally
- the plaintext file is then downloaded by the browser

Because of this, browser compromise can affect **share confidentiality**, even though authentication still remains device-mediated and server-verified.

### User guidance for PQ shares

When opening a PQ share:

- use a browser session you trust
- prefer an up-to-date browser
- avoid unnecessary browser extensions during sensitive share opening
- if opening a highly sensitive share, use a clean browser session or private/incognito session

---

## 3. Advanced settings

## 3.1 Audit logging

PQ-NAS records security-relevant activity in an audit log. The log is tamper-evident (hash chained) and designed for forensic review and compliance use.

Once written, entries are never changed.

Instead of editing old logs, PQ-NAS:

- rotates logs into archives
- keeps or deletes old archives according to retention rules

---

## 3.2 Audit verbosity

This controls how much information is written into the audit log going forward.

### What the levels mean

- **DEBUG** — everything, including internal operations
- **INFO** — normal system activity
- **ADMIN** — configuration and administrative actions
- **SECURITY** — only security-relevant events

### What you see

- **Persisted** — the level that will survive restarts
- **Runtime** — what is currently active inside the server

### Buttons

**Save**  
Stores the selected level and activates it immediately.

**Reload**  
Reloads the values currently in use.

---

## 3.3 Audit rotation (manual)

The **Rotate now** button immediately closes the current audit log and starts a new one.

Use this when:

- performing maintenance
- preparing for backups
- segmenting logs for investigation
- testing rotation policies

Rotation does not delete anything — it only archives the current file.

---

## 3.4 Automatic audit rotation

This section controls when PQ-NAS should rotate logs automatically.

### Rotation modes

- **Off** — logs grow until rotated manually
- **Daily** — rotate once per day
- **When size exceeds N MB** — rotate when the active log becomes large
- **Size OR daily** — whichever happens first

### Fields

- **Rotate MB** — size limit for automatic rotation

**Save policy** stores the automatic rotation rules and activates them immediately.

---

## 3.5 Audit retention

Retention decides how long rotated audit logs are kept. The active audit log is never removed by retention rules. Only archived logs are affected.

### Retention modes

- **Never delete automatically** — archives are kept forever
- **Keep last N days** — deletes older archives
- **Keep last N files** — keeps only the newest archives
- **Keep up to N MB total** — limits total disk usage of archives

### Buttons

**Save policy**  
Stores the retention rules.

**Preview prune**  
Shows what would be deleted without removing anything.

Use this before running prune in production.

**Run prune now**  
Deletes archived audit logs according to the saved rules.

A confirmation prompt is always shown first.

### Preview table

When previewing retention, the table lists:

- file name
- size
- modification time
- reason it would be deleted

A summary pill shows how much disk space would be freed.

### Active log status

The Settings page also displays:

- the current audit log size

This is useful for:

- testing size-based rotation
- capacity planning
- verifying automatic rotation works

### Safe operation principles

PQ-NAS is designed so that administrators can operate these controls safely:

- active audit logs are never deleted automatically
- preview always runs before deletion
- all changes are audited
- admin confirmation is required for destructive actions
- rotation never alters existing records
- retention only affects archived logs

### When to use what

**Rotate now**  
Use when you want to start a fresh audit log immediately.

**Automatic rotation**  
Enable to avoid oversized logs and to keep investigations cleanly separated.

**Preview prune**  
Always run before pruning in production.

**Run prune now**  
Use only after verifying the preview.

---

## 3.6 Snapshots

DNA-Nexus Server supports automatic filesystem snapshots using **Btrfs read-only subvolume snapshots**. Snapshots provide point-in-time copies of your data that can be used for:

- recovering accidentally deleted files
- rolling back after corruption, unwanted changes, or ransomware
- inspecting historical states
- creating backup or replication source data

Snapshots are **read-only, lightweight, and space-efficient** because Btrfs stores only changed blocks between snapshots.

### How snapshot scheduling works

Snapshots run periodically according to a schedule.

### Times per day

Controls how many snapshots are taken in a 24-hour period.

Examples:

- `1` = once per day
- `2` = every 12 hours
- `6` = every 4 hours
- `24` = every hour

### Jitter (seconds)

Jitter adds a random delay before each scheduled run.

Why this matters:

- prevents multiple systems from snapshotting at exactly the same second
- avoids disk I/O spikes at fixed times
- reduces contention when many services run on the same host

Example:

- `Times/day = 6`
- `Jitter = 120 seconds`

Each snapshot will run roughly every 4 hours, plus a random delay of up to 2 minutes.

### Snapshot retention policy

Retention controls how many old snapshots are kept:

- `keep_days` — minimum age window to preserve
- `keep_min` — minimum number of snapshots always kept
- `keep_max` — maximum allowed snapshot count

After every successful snapshot, DNA-Nexus Server automatically prunes old snapshots while respecting these limits.

### Snapshot volumes

Each snapshot volume entry contains:

- volume name
- source subvolume
- snapshot root

Example:

```json
{ "name": "data", "source_subvolume": "/srv/pqnas/data", "snap_root": "/srv/pqnas/.snapshots/data" }
```

Snapshots are created inside the configured snapshot root using timestamp-based names.

### Admin UI — snapshot controls

The **Admin → Settings → Snapshots (Btrfs)** panel allows runtime configuration.

#### Enabled

Turns automatic snapshotting on or off globally.

When disabled:

- no automatic snapshots run
- settings remain visible, but scheduling is inactive

When enabled:

- the scheduler is active
- snapshots run automatically according to the configured schedule

#### Per-volume schedule

When enabled, each configured volume can override the global schedule.

Each volume row gets its own:

- Times/day
- Jitter

When disabled:

- all volumes use the global schedule

#### Global Times / Day

The default snapshot frequency applied to all volumes unless per-volume scheduling is enabled.

#### Global Jitter

The default jitter applied to all volumes unless per-volume scheduling is enabled.

#### Snapshot root path

Each configured volume has its own snapshot root path.

This path must:

- be an absolute path
- exist on the same Btrfs filesystem as the source subvolume
- be intended only for snapshot storage for that volume

DNA-Nexus Server will create the path if needed when the configuration is valid.

#### Save snapshots

Writes the current snapshot configuration to disk and activates it.

This:

- updates `/etc/pqnas/admin_settings.json`
- reloads snapshot scheduling
- applies the new timing configuration immediately

#### Reload

Reloads snapshot settings from the server.

Useful if:

- another administrator changed settings
- configuration files were edited manually
- you want to discard unsaved UI changes

### Locking and safety

Only one snapshot runner executes at a time.

DNA-Nexus Server uses a lock file:

- `/run/pqnas_snapshot.lock`

(or `/tmp` as fallback)

This prevents overlapping snapshot jobs.

### Notes and best practices

Recommended defaults for home or small office use:

- `Times/day: 6`
- `Jitter: 120`

Retention example:

- `keep_days: 7`
- `keep_min: 12`
- `keep_max: 500`

### Snapshot storage

Snapshot trees can grow large over time. Make sure:

- the Btrfs filesystem has enough free space
- retention settings are appropriate for your storage size
- your backup strategy includes snapshot replication or additional backup copies

### Snapshots are not backups

Snapshots protect against:

- accidental deletion
- unwanted local changes
- local corruption

They do **not** protect against:

- disk failure
- total filesystem loss
- fire or theft
- host compromise that destroys both live data and snapshots

For full protection, replicate snapshots to another machine or maintain an off-site backup.

### Advanced usage

Administrators may:

- add multiple snapshot volumes
- use different schedules per volume
- disable automatic snapshotting temporarily during maintenance

---

## 3.7 Snapshot Manager — restore and manual snapshots

The Snapshot Manager allows administrators to:

- view all snapshots for each configured volume
- inspect snapshot details
- restore a selected snapshot safely
- create a new snapshot manually using **Snapshot now**

Automatic snapshot scheduling is configured separately in:

- **Admin → Settings → Snapshots (Btrfs)**

Snapshot Manager is used for manual operations and recovery.

### Opening Snapshot Manager

Open:

- **Admin → Snapshot Manager**

The page contains two main columns:

- **Left column** — Volumes
- **Right column** — Snapshots for the selected volume

The top bar contains:

- **Refresh** — reload volumes and snapshots
- **Details** — show detailed snapshot information
- **Restore** — restore the selected snapshot
- **Snapshot now** — create a new snapshot immediately

### Volume list (left side)

Each row represents a configured snapshot volume.

Example row:

- `data enabled`
- `/srv/pqnas/data | /srv/pqnas/.snapshots/data`

Fields:

- **Volume name** — logical volume identifier
- **enabled / disabled** — whether automatic snapshots are enabled for that volume
- **source_subvolume** — the live data location
- **snap_root** — directory where snapshots are stored

Selecting a volume loads its snapshots.

### Snapshot list (right side)

Each row represents one snapshot.

Example:

- `2026-02-14T11-21-40.805Z ro`

Fields:

- **Snapshot ID** — timestamp-based identifier
- **Status label**
- **Creation time**

Snapshots are sorted newest first.

### Status labels

- **latest** — newest snapshot available
- **ro** — read-only snapshot, which is the normal and expected type
- **rw** — read-write snapshot, which is unusual and typically indicates a manual or non-standard snapshot
- **⚠** — snapshot could not be fully verified, often due to missing sudo permissions
- **junk** — directory exists but is not a valid Btrfs snapshot subvolume

### What ro and rw mean

**ro — Read-only snapshot**

This is the normal and safe snapshot type.

Properties:

- cannot be modified
- safe for restore
- created using read-only snapshot semantics

**rw — Read-write snapshot**

This is not normally created by DNA-Nexus Server.

It may indicate:

- a manual test snapshot
- an external tool snapshot
- an improperly created snapshot

Restore may still work, but read-only snapshots are the recommended and expected format.

### Snapshot now button

**Snapshot now** creates a new snapshot immediately.

This is useful:

- before software upgrades
- before risky changes
- before deleting or moving large files
- before maintenance

The new snapshot appears in the list within seconds.

This does not affect automatic scheduling.

### Restore button

**Restore** replaces the live volume with the selected snapshot.

Typical steps:

1. Select a snapshot
2. Click **Restore**
3. Confirm the action
4. Type the confirmation phrase exactly
5. Confirm the restore plan

DNA-Nexus Server will:

- stop `pqnas.service` briefly
- preserve current data as a backup
- replace the live subvolume with the selected snapshot
- restart `pqnas.service`

Downtime is typically only a few seconds.

### Backup safety during restore

Before restore, DNA-Nexus Server automatically creates a backup of the current live volume.

Example:

- `/srv/pqnas/data.pre_restore.2026-02-14T11-28-08.838Z`

This allows recovery if needed.

These backup subvolumes can be removed manually after verification.

### Details button

Shows technical information about the selected snapshot.

This may include:

- full filesystem path
- verification result
- internal metadata
- Btrfs subvolume information

This is useful for troubleshooting and validation.

### Refresh button

Reloads volumes and snapshots from the server.

Use this when:

- a new snapshot was created
- another administrator performed changes
- you want the latest status

### Restore safety model

Restore uses an atomic subvolume swap model.

This means:

- no partial restores
- no inconsistent intermediate state
- quick rollback behavior at the filesystem level

DNA-Nexus Server is designed so that restore either:

- succeeds fully

or

- leaves the system unchanged

### Recommended usage

Create **Snapshot now** before:

- system upgrades
- configuration changes
- large file deletions
- testing or maintenance work

Restore a snapshot when:

- files were deleted accidentally
- data became corrupted
- ransomware or unwanted changes occurred

### Relationship with automatic snapshots

Snapshot Manager does not control automatic snapshot schedules.

Scheduling is configured in:

- **Admin → Settings → Snapshots (Btrfs)**

Snapshot Manager is used for:

- manual snapshot creation
- restore operations
- snapshot inspection

### Safety and permissions

- all Snapshot Manager operations require administrator privileges
- actions are auditable
- restore operations require explicit confirmation
- snapshots are created only inside configured `snap_root` directories

### Summary

Snapshot Manager provides safe and reliable recovery tools.

Key capabilities:

- view snapshots
- create snapshots manually
- restore a selected snapshot
- inspect snapshot details

Snapshots are fast, space-efficient, and useful for recovery, but they should still be combined with proper backups for full protection.
---

## 4. Troubleshooting

### DNA-Messenger shows: Authentication Failed — Server returned 301

This error usually indicates a mismatch between the login URL presented by the PQ-NAS server and the value configured in the server environment file.

In most cases, the server is running with an HTTPS certificate but the configuration still points to HTTP.

Check the PQ-NAS configuration file:

- `/etc/pqnas/pqnas.env`

Open the file:

```bash
sudo nano /etc/pqnas/pqnas.env
```

Locate the following line:

```bash
PQNAS_ORIGIN=http://...
```

If your server is using HTTPS, update it to:

```bash
PQNAS_ORIGIN=https://...
```

Save the file and restart the PQ-NAS service:

```bash
sudo systemctl restart pqnas.service
```

After restarting the service, refresh the PQ-NAS web interface and try scanning the login QR code again.

---

### PQ share opens but browser cannot decrypt the file

If a PQ share page opens but decryption fails:

- make sure JavaScript is enabled
- make sure the browser session still has the required local share-opening identity material
- try reopening the link in the same browser profile that previously enrolled or claimed the recipient device
- if testing in a private/incognito session, remember that browser-local share data may not persist after the session closes

If you are testing a newly updated PQ-NAS server:

- refresh the page fully
- retry with a freshly generated PQ share
- verify the server startup log shows ML-KEM available and selftest passing

A healthy startup log currently looks like:

```text
[pq/mlkem] backend=dna-internal-wip available=yes selftest=ok
[pq/mlkem-envelope] selftest=ok
```

---

### Storage not allocated yet

If a user successfully logs in but cannot access File Manager and sees:

> “Storage not allocated yet”

this means the account has been approved, but no storage allocation has been created yet.

Fix:

1. Open **Admin → User Profiles**
2. Select the user
3. Click **Allocate**
4. Choose a storage pool and quota
5. Save

After allocation, the user can access file services.

---

### Snapshot restore or snapshot verification problems

If Snapshot Manager shows warnings such as `⚠`, the most common cause is missing or incomplete sudo permission for required filesystem inspection commands.

Check:

- snapshot helper permissions
- configured sudo rules
- whether the snapshot root and source subvolume are on the same Btrfs filesystem

---

## 5. Notes for administrators

### Current ML-KEM provider path

In the current lab/dev path, PQ-NAS uses the DNA-owned ML-KEM wrapper boundary for PQ share server-side operations.

The default selected provider is currently the DNA provider, while the native implementation remains available as a tested fallback.

A healthy startup message may therefore show:

```text
[pq/mlkem] backend=dna-internal-wip available=yes selftest=ok
```

This is expected in the current development checkpoint.

### Security reminder

For login authentication:

- the browser is not the trust anchor
- authentication remains device-mediated through DNA-Messenger

For PQ share opening:

- the browser performs local unwrap and decryption
- browser compromise can affect share confidentiality

Administrators should explain this difference clearly to users handling sensitive shared files.

---

© CPUNK 2026 — PQ-NAS Security Platform