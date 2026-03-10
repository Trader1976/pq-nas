## ![](C:\Users\a200889\AppData\Roaming\marktext\images\2026-02-28-02-26-26-image.png)

## PQ-NAS Users Manual

**PQ-NAS** is a modular, quantum-resistant Network Attached Storage (NAS) orchestration layer designed for Linux systems. It provides multi-user support, multi-storage-pool management, and an easy-to-use installation process. PQ-NAS is designed to work seamlessly with Nginx and Cloudflare-based deployments.

Unlike many traditional NAS solutions, PQ-NAS does not replace or take over the host operating system. Instead, it runs independently on top of Linux, allowing users to continue running other applications and containers in parallel.

PQ-NAS is intended to be used together with the CPUNK DNA-Messenger application, where user identity (fingerprint) is derived from post-quantum cryptographic keys.

## 1. System requirements

    For the best user experience, it is recommended to install PQ-NAS on a **Btrfs** file     system. This enables full utilization of advanced features such as snapshots and RAID     functionality.

    PQ-NAS can also be installed on an **Ext4** file system and even operated with a single     SSD or HDD. However, this configuration comes with certain limitations, particularly     regarding snapshot support and advanced storage features.

###### Recommended Storage Configuration

- One dedicated **system drive** where the operating system and PQ-NAS are installed (Ext4 or Btrfs).

- One or more **separate SSDs/HDDs** dedicated to user data storage.

- For RAID data mirroring, at least **two data SSDs/HDDs** are required.

    Separating the system drive from the data drives improves reliability, maintainability,     and upgrade flexibility.

###### Memory Requirements

- **Minimum:** 8 GB RAM

- **Recommended:** 16 GB RAM for smoother operation, especially in multi-user or multi-pool environments.

## 2. Installation

    Download the Linux tarball package to your NAS server. Extracting the package will     create a `pqnas` directory containing all required files.

    Navigate to the extracted directory and run: sudo ./install.sh

    This command starts the installation procedure.

    After installation is complete and PQ-NAS is accessible in your web browser, a QR     code will be displayed on the screen.

    Using the QR scanner in the DNA-Messenger application, scan the QR code and     approve the authentication request. After successful verification, you will be     redirected to the main page of PQ-NAS.

    Your cryptographic fingerprint will automatically be registered in the PQ-NAS user     registry.

    If you are the first user to authenticate, you will automatically be granted     administrator privileges. Administrators have full permission to configure system     settings and manage users.

###### 2.1 Initial Configuration

    PQ-NAS is designed as a modular NAS orchestration framework. By default, a fresh     installation does not include any functional apps. To begin using the system, you     must install at least one application.

    At minimum, it is recommended to install the **File Manager** application. For a     complete user experience, the following applications are recommended:

- **File Manager**

- **Share Manager**

- **Storage Manager**

    These applications provide essential file access, sharing capabilities, and storage     administration features.

###### File System Requirements

    To fully utilize advanced features such as **snapshots** and **RAID**, your data drives     must use the **Btrfs** file system.

    PQ-NAS can also operate on systems using **Ext4**, but certain features will be limited.     A common and supported configuration is:

- The system drive (where the operating system and PQ-NAS are installed) using Ext4.

- Separate data drives formatted with Btrfs to enable RAID and snapshot functionality.

###### Storage Allocation

    After installing the File Manager application, you may see the message:

>     “Storage not allocated yet”

    This is expected behavior. Every user — including administrators — must have  
    storage space explicitly allocated before accessing file services.

    To allocate storage:

1. Navigate to **Admin → User Profiles**.

2. Open your user account entry.

3. Click **Allocate**.

4. Select the **storage pool** and specify the **quota** (in gigabytes).

    After confirming the allocation, PQ-NAS will create the user’s personal data  
    directory inside the selected storage pool and reserve the requested storage  
    quota.

    Please note:

- For administrator accounts, the options **Enable**, **Disable**, **Revoke**, and **Delete** are disabled for the currently logged-in administrator.

- An administrator cannot demote, disable, or delete their own account.

- Storage allocation must be performed before the user can access file services.

---

###### Storage Pools and Migration

    PQ-NAS may contain multiple storage pools. Each user’s data resides in exactly  
    one active pool at a time.

    If storage hardware is added or reorganized, user data can be moved safely  
    between pools.

    To migrate a user’s storage:

1. Navigate to **Admin → User Profiles**.

2. Open the desired user entry.

3. Click **Migrate**.

4. Select the destination storage pool.

    The migration runs as an asynchronous background job. PQ-NAS will:

- Copy the user’s data to the destination pool.

- Verify the copied data.

- Switch the user’s storage mapping to the new pool.

    During migration the system remains operational, and the process can be  
    monitored through the status messages displayed in the interface.

---

###### Cleaning Up Old Storage Copies

    After a successful migration, the original storage location may still contain  
    a copy of the user’s data.

    This copy is preserved temporarily as a safety measure.

    Once the administrator has confirmed that the migration completed successfully,  
    the obsolete copy can be removed.

    To remove the old storage copy:

1. Navigate to **Admin → User Profiles**.

2. Open the user entry.

3. Click **Cleanup old copy**.

4. Confirm the storage pool containing the obsolete data.

    PQ-NAS will verify that the user is actively mapped to the current storage pool  
    before removing the old directory. This prevents accidental deletion of active data.

---

###### Profile Settings

    From the same user profile screen, you may also:

- Change your avatar image.

- Update optional profile information (such as name, notes, and email).

- Review storage usage and quota information.

---

###### 2.2 User Approvals

    When configuring PQ-NAS for a multi-user environment, additional users may  
    access the system by opening PQ-NAS in their web browser and scanning the  
    displayed QR code using the DNA-Messenger application.

    After successful authentication, each user’s cryptographic fingerprint will  
    appear in the **Admin → Approvals** page.

    From this page, an administrator can review pending authentication requests  
    and decide which users are granted access to the system.

---

###### Granting Access

1. Open **Admin → Approvals**.

2. Approve the desired user.

3. Navigate to **Admin → User Profiles**.

4. Allocate storage space for the approved user.

    Once storage has been allocated, the user can begin using PQ-NAS normally.
###### 2.3. Applications

    PQ-NAS is a modular Network Attached Storage (NAS) system that supports     extensible functionality through installable applications. Administrators can install     and manage applications to customize the user experience.

    To install an application:

1. Navigate to **Admin → Apps**.

2. Select **Install App from ZIP**.

3. Choose the application ZIP package from your local computer.

4. Click **Install**.

After successful installation, the application will appear in the list of installed apps.

###### Application Validation

    PQ-NAS enforces strict application validation. Only application packages that meet     the required structural and security criteria can be installed. If the ZIP package is     missing any mandatory files or does not conform to the required format, the     installation will be rejected.

    This validation mechanism helps ensure system integrity and security.

###### Accessing Installed Applications

    Once successfully installed, the application will appear in the main screen’s left     navigation panel and can be accessed normally by authorized users.



## 3. Advanced settings

![](C:\Users\a200889\AppData\Roaming\marktext\images\2026-02-28-23-37-23-image.png)

###### 3.1 Audit logging

    PQ-NAS records security-relevant activity in an audit log. The log is tamper-evident     (hash chained) and designed for forensic review and compliance use.  Once written,     entries are never changed.

    Instead of editing old logs, PQ-NAS:

- Rotates logs into archives
- Keeps or deletes old archives according to retention rules

###### 3.2  Audit Verbosity

    This controls how much information is written into the audit log going forward.

###### What the levels mean

- DEBUG — everything, including internal operations
- INFO — normal system activity
- ADMIN — configuration and administrative actions
- SECURITY — only security-relevant events

###### What you see

- Persisted — the level that will survive restarts
- Runtime — what is currently active inside the server

###### Buttons

    Save  
    Stores the selected level and activates it immediately.

    Reload  
    Reloads the values currently in use.

###### 3.3  Audit Rotation (Manual)

    The Rotate now button immediately closes the current audit log and starts a new     one.

    Use this when:

- Performing maintenance
- Preparing for backups
- Segmenting logs for investigation
- Testing rotation policies

    Rotation does not delete anything — it only archives the current file.

###### 3.4 Automatic Audit Rotation

    This section controls when PQ-NAS should rotate logs by itself.

###### Rotation modes

- Off — logs grow until rotated manually
- Daily — rotate once per day
- When size exceeds N MB — rotate when the active log becomes large
- Size OR daily — whichever happens first

###### Fields

- Rotate MB — size limit for automatic rotation

    Save policy stores the automatic rotation rules and activates them immediately.

![](C:\Users\a200889\AppData\Roaming\marktext\images\2026-03-01-02-29-54-image.png)

###### 3.5 Audit Retention

    Retention decides how long rotated audit logs are kept. The active audit log is never     removed by retention rules.  Only archived logs are affected.

###### Retention modes

- Never delete automatically — archives are kept forever
- Keep last N days — deletes older archives
- Keep last N files — keeps only the newest archives
- Keep up to N MB total — limits total disk usage of archives

###### Buttons

    Save policy - Stores the retention rules.

    Preview prune - Shows what would be deleted without removing anything.

        Use this before running prune in production.

    Run prune now - Deletes archived audit logs according to the saved rules.

        A confirmation prompt is always shown first.

###### Preview Table

    When previewing retention, the table lists:

- File name
- Size
- Modification time
- Reason it would be deleted

    A summary pill shows how much disk space would be freed.

###### Active Log Status

    The Settings page also displays:

- The current audit log size

    This is useful for:

- Testing size-based rotation
- Capacity planning
- Verifying automatic rotation works

###### Safe Operation Principles

    PQ-NAS is designed so that administrators can operate these controls safely:

- Active audit logs are never deleted automatically
- Preview always runs before deletion
- All changes are audited
- Admin confirmation required for destructive actions
- Rotation never alters existing records
- Retention only affects archived logs

###### When to Use What

    Rotate now  
    Use when you want to start a fresh audit log immediately.

    Automatic rotation  
    Enable to avoid oversized logs and to keep investigations cleanly separated.

    Preview prune  
    Always run before pruning in production.

    Run prune now  
    Use only after verifying the preview.

###### 3.6 Snapshots

    PQ-NAS supports automatic filesystem snapshots using Btrfs read-only subvolume     snapshots. Snapshots provide point-in-time copies of your data that can be used for:

- Recovering accidentally deleted files
- Rolling back after ransomware or corruption
- Inspecting historical states
- Creating backups or replication targets



    Snapshots are read-only, lightweight, and space-efficient because Btrfs stores only     changed blocks.

###### How Snapshot Scheduling Works

    Snapshots run periodically according to a schedule.

###### Times per day

    Controls how many snapshots are taken in 24 hours.

    Examples:

    1 = once per day  
    2 = every 12 hours  
    6 = every 4 hours  
    24 = every hour

###### Jitter (seconds)

    Jitter adds a random delay before each scheduled run.

    Why this matters:

- Prevents multiple systems from snapshotting at exactly the same second
- Avoids disk I/O spikes at fixed times
- Reduces contention when many services run on the same host

    Example:

    Times/day = 6  
    Jitter = 120 seconds

    Each snapshot will run roughly every 4 hours, plus a random delay of up to 2     minutes.

###### Snapshot Retention Policy

    Retention controls how many old snapshots are kept:

- keep_days — minimum age to keep
- keep_min — minimum number always preserved
- keep_max — maximum allowed snapshots

    After every successful snapshot, PQ-NAS automatically prunes old ones while     respecting these limits.

###### Snapshot Volumes

    Each snapshot entry contains:

- Volume name
- Source subvolume
- Snapshot root

    Example:

    { "name": "data", "source_subvolume": "/srv/pqnas/data", "snap_root":     "/srv/pqnas/.snapshots/data" }

    Snapshots are created inside the snapshot root as timestamped directories.

###### Admin UI — Snapshot Controls

    The Admin → Settings → Snapshots (Btrfs) panel allows runtime configuration.

    Enabled  
    Turns snapshotting on or off globally.

    When disabled: No snapshots run, settings remain visible but Inputs are greyed out.

    When enabled: Scheduler is active and snapshots run automatically.

    Per-volume schedule  
    When enabled, each volume can override the global schedule.

    Each volume row gets its own:

- Times/day
- Jitter

    When disabled:

- All volumes use the global schedule.

    Global Times / Day  
    The default snapshot frequency applied to all volumes unless per-volume scheduling     is enabled.

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

###### Locking and Safety

    Only one snapshot runner executes at a time.

    PQ-NAS uses a lock file:

    /run/pqnas_snapshot.lock

    (or /tmp as fallback)

    This prevents overlapping snapshot jobs.

###### Notes and Best Practices

    Recommended Defaults for home / small office:

    Times/day: 6  
    Jitter: 120

    Retention: keep_days: 7  
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

###### Advanced Usage

    Administrators may:

- Add multiple volumes
- Use different schedules per volume
- Disable snapshotting temporarily during maintenance

###### Snapshot Manager — Restore and Manual Snapshots

    The Snapshot Manager allows administrators to:

- View all snapshots for each volume
- Inspect snapshot details
- Restore any snapshot safely
- Create a new snapshot manually ("Snapshot now")

    Automatic snapshot scheduling is configured separately in:

    Admin → Settings → Snapshots (Btrfs)

    Snapshot Manager is used for manual operations and recovery.

###### Opening Snapshot Manager

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

###### Volume List (Left Side)

    Each row represents a configured snapshot volume.

    Example row:

    data enabled  
    /srv/pqnas/data | /srv/pqnas/.snapshots/data

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



###### Snapshot List (Right Side)

    Each row represents one snapshot.

    Example:

    2026-02-14T11-21-40.805Z ro

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
    Read-write snapshot (unusual; typically indicates a manual or non-standard     snapshot).

    ⚠  
    Snapshot could not be verified due to missing sudo permissions.

    junk  
    Directory exists but is not a valid Btrfs snapshot subvolume.

    Creation time  
    Displayed below the snapshot ID.

    Snapshots are sorted newest first.



###### What ro and rw Mean

    ro — Read-only snapshot  
    This is the normal and safe snapshot type.

    Properties:

    Cannot be modified  
    Fully safe for restore  
    Created using:

    btrfs subvolume snapshot -r

    rw — Read-write snapshot  
    This is not normally created by PQ-NAS.

    May indicate:

    Manual test snapshot  
    External tool snapshot  
    Improper snapshot

    PQ-NAS restore still works, but read-only snapshots are recommended.



###### Snapshot now Button

    Snapshot now creates a new snapshot immediately.

    This is useful when:

    Before software upgrades  
    Before risky changes  
    Before deleting or moving large files  
    Before maintenance

    When clicked, PQ-NAS runs:

    btrfs subvolume snapshot -r <source_subvolume> <snap_root>/

    The new snapshot appears in the list within seconds.

    This does not affect automatic scheduling.



###### Restore Button

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



###### Backup Safety During Restore

    Before restore, PQ-NAS automatically creates a backup of the current live volume.

    Example:

    /srv/pqnas/data.pre_restore.2026-02-14T11-28-08.838Z

    This allows recovery if needed.

    Backups can be removed manually after verification.



###### Details Button

    Shows technical information about the selected snapshot.

    Includes:

    Full filesystem path  
    Verification result  
    Internal metadata  
    Btrfs subvolume information

    This is useful for troubleshooting.



###### Refresh Button

    Reloads volumes and snapshots from the server.

    Use this when:

    A new snapshot was created  
    Another admin performed changes  
    You want the latest status



###### Status Labels and Meaning

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



###### Restore Safety Model

    Restore uses atomic subvolume swap.

    This means:

    No partial restores  
    No inconsistent state  
    Instant rollback capability

    PQ-NAS guarantees either:

    Restore fully succeeds  
    or  
    System remains unchanged



###### Recommended Usage

    Create snapshot now before:

    System upgrades  
    Configuration changes  
    File deletions  
    Testing

    Restore snapshot when:

    Files were deleted accidentally  
    Data became corrupted  
    Ransomware or unwanted changes occurred



###### Relationship with Automatic Snapshots

    Snapshot Manager does not control automatic snapshot schedules.

    Scheduling is configured in:

    Admin → Settings → Snapshots

    Snapshot Manager is used for:

    Manual snapshots  
    Restore operations  
    Inspection



###### Safety and Permissions

    All Snapshot Manager operations require administrator privileges.

    All actions are audited.

    Restore operations require explicit confirmation.

    Snapshots are always created inside configured snap_root directories.



###### Summary

    Snapshot Manager provides safe and reliable recovery.

    Key capabilities:

    View snapshots  
    Create snapshots manually  
    Restore any snapshot  
    Inspect snapshot details

    Snapshots are fast, space-efficient, and safe.

## Troubleshooting

###### DNA-Messenger shows: Authentication Failed — Server returned 301

This error usually indicates a mismatch between the login URL presented by the PQ-NAS server and the value configured in the server environment file.

In most cases, the server is running with an HTTPS certificate but the configuration still points to HTTP.

Check the PQ-NAS configuration file:

    /etc/pqnas/pqnas.env

Open the file:

    sudo nano /etc/pqnas/pqnas.env

Locate the following line:

    PQNAS_ORIGIN=http://...

If your server is using HTTPS, update it to:

    PQNAS_ORIGIN=https://...

Save the file and restart the PQ-NAS service:

    sudo systemctl restart pqnas.service

After restarting the service, refresh the PQ-NAS web interface and try scanning the login QR code again.

© CPUNK 2026 — PQ-NAS Security Platform