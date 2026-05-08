# DNA-Nexus Garbage and Storage Hygiene Management

This document describes how DNA-Nexus handles deleted files, Trash, file versions, quota accounting, and long-term garbage prevention.

## Goals

DNA-Nexus must avoid silent long-term storage growth.

After years of use, especially with many users, the system should not accumulate hidden files, old versions, trash payloads, metadata, or orphaned blobs that users cannot see or clean.

Main rules:

- Deleted files first go to Trash.
- Trash is recoverable for a limited time.
- Active Trash counts toward user quota.
- Permanently purged Trash deletes the trash payload.
- Permanently purged Trash also deletes matching file version history.
- File versions are separate from Trash.
- Internal metadata should not reduce user quota.
- Internal metadata still needs its own retention policy over time.

## Trash lifecycle

When a user deletes a file or folder, DNA-Nexus does not immediately remove it from disk. Instead, the item is moved into the internal Trash area.

Typical Trash payload location:

    /srv/pqnas/data/.pqnas/trash/...

Trash metadata is stored in:

    /srv/pqnas/config/trash.db

The main table is:

    trash_items

Important fields include:

    trash_id
    scope_type
    scope_id
    item_type
    original_rel_path
    payload_physical_path
    size_bytes
    file_count
    deleted_epoch
    purge_after_epoch
    restore_status

Trash states:

    trashed   = active, restorable trash item
    restoring = temporary state while restore is in progress
    restored  = item was restored
    purging   = temporary state while permanent purge is in progress
    purged    = item was permanently deleted

Normal lifecycle:

    live file
      -> move to Trash
      -> restore OR permanently purge

## Trash retention

Trash entries have a purge deadline.

Default retention:

    30 days

The purge deadline is stored per trash row as:

    purge_after_epoch

This is decided when the item is moved to Trash.

The background Trash cleanup worker periodically scans for expired active Trash rows:

    restore_status = 'trashed'
    purge_after_epoch <= now

Expired rows are purged through the same service path as manual permanent deletion.

These permanent-delete paths share the same core behavior:

    Manual Delete permanently
    Empty Trash
    30-day automatic Trash cleanup

## Manual Trash UI

File Manager has a Trash UI.

Users can see:

    Trash item count
    Trash storage usage
    Next auto-delete date
    30-day retention note
    Version storage usage

Example UI information:

    Trash: 36 item(s)
    Trash uses: 372 MiB
    Versions use: 513 MiB
    Next auto-delete: ...
    Items in Trash are automatically deleted after 30 days.

Users can:

    Restore an item
    Delete an item permanently
    Empty Trash

## Quota policy

DNA-Nexus quota usage should include all recoverable user-owned data.

Current intended policy:

    Quota used = live user files + active Trash + file versions

This prevents users from bypassing quota by moving files to Trash and leaving them there.

Correct behavior:

    Upload file:
      live_bytes increases
      used_bytes increases

    Move file to Trash:
      live_bytes decreases
      trash_bytes increases
      used_bytes stays the same

    Permanently purge Trash:
      trash_bytes decreases
      used_bytes decreases

This means Trash is still recoverable, but it is not a free hidden storage bucket.

## Storage summary fields

The user storage endpoint should expose a clear breakdown:

    live_bytes
    trash_bytes
    used_bytes
    quota_bytes
    used_percent
    warn_level
    partial

Where:

    live_bytes  = user content under the user root, excluding internal metadata
    trash_bytes = active Trash bytes from trash.db
    used_bytes  = live_bytes + trash_bytes

File versions are currently stored under the user root, so they are included in live_bytes.

Example response:

    {
      "live_bytes": 9806773673,
      "trash_bytes": 390085199,
      "used_bytes": 10196858872,
      "quota_bytes": 11811160064,
      "used_percent": 86.33,
      "warn_level": "warn"
    }

## File versions

File versions are not Trash.

When a file is overwritten or restored over an existing file, DNA-Nexus may preserve the previous copy as a file version.

Version metadata is stored in:

    /srv/pqnas/config/file_versions.db

Version blobs are stored under the user or workspace root:

    .pqnas/versions/blobs/...

Examples of version events:

    overwrite_preserve
    restore_preserve
    delete_preserve

Versions are full preserved copies, not binary diffs.

This means large files can create large version history. For example, overwriting a 512 MiB file can preserve a 512 MiB version blob.

## Version summary

File Manager can show version storage usage.

User endpoint:

    GET /api/v4/files/versions/summary

Workspace endpoint:

    GET /api/v4/workspaces/files/versions/summary?workspace_id=...

Example response:

    {
      "ok": true,
      "scope_type": "user",
      "scope_id": "...",
      "versions_count": 13,
      "versions_bytes": 537743007
    }

## Trash purge and version cleanup

Important rule:

    Moving a file to Trash keeps its version history.
    Restoring a file from Trash keeps its version history.
    Permanently purging a file from Trash deletes matching version history.

This prevents hidden orphaned versions from accumulating after users believe files were permanently removed.

For a file purge:

    Delete versions where:
      scope_type = same scope
      scope_id = same owner/workspace
      logical_rel_path = original_rel_path

For a directory purge:

    Delete versions where:
      logical_rel_path = original_rel_path
      OR logical_rel_path starts with original_rel_path + '/'

Example:

    Permanently purge:
      Documents/Old Project

    Also delete versions for:
      Documents/Old Project
      Documents/Old Project/file1.txt
      Documents/Old Project/subdir/file2.jpg

The purge API reports version cleanup metrics:

    {
      "ok": true,
      "trash_id": "trash_...",
      "size_bytes": 4096,
      "file_count": 1,
      "versions_deleted": 1,
      "version_bytes_deleted": 4096,
      "version_blobs_missing": 0,
      "version_cleanup_error": ""
    }

This makes permanent purge transparent.

## Internal metadata

Some files under a user root are DNA-Nexus system metadata, not user content.

Example:

    .pqnas_activity/activity.sqlite

This activity database records user-visible events such as:

    file.uploaded
    file.trashed
    file.restored
    file.purged
    file.moved
    file.copied
    share.created
    security.device_paired

The activity database uses SQLite pages. A small increase such as 4096 bytes can simply mean SQLite added one page.

Example:

    page_size  = 4096
    page_count = 27
    file size  = 27 * 4096 = 110592 bytes

This is normal metadata growth, not leaked file content.

Internal metadata should generally not count against user quota.

Current intended exclusion:

    .pqnas_activity

Future exclusions may include:

    thumbnail caches
    temporary app caches
    internal indexes
    derived metadata

## Activity log retention

Activity metadata should not grow forever.

Current activity database is small, but a long-running system with many users needs retention.

Recommended future policy:

    Keep last 10,000 events per user
    OR keep last 365 days
    OR both

Possible cleanup behavior:

    Delete old activity_events rows
    Keep recent and important events
    Run VACUUM only occasionally if freelist grows large

VACUUM should not run too frequently because it rewrites the SQLite database.

## Snapshots and Trash

Btrfs snapshots may still retain old Trash data even after live Trash is purged.

Example live Trash path:

    /srv/pqnas/data/.pqnas/trash

Example snapshot Trash path:

    /srv/pqnas/.snapshots/data/.../.pqnas/trash

Permanent purge removes live Trash payloads, but old snapshots may continue to reference old data until snapshot retention removes those snapshots.

This is expected Btrfs behavior.

Therefore:

    Trash purge frees live filesystem data.
    Snapshot retention controls old snapshot-held data.

## Current verified behavior

The following behavior has been tested:

    Upload tiny file:
      live_bytes increases after landing-tier migration
      used_bytes increases

    Move tiny file to Trash:
      live_bytes decreases
      trash_bytes increases
      used_bytes stays the same

    Permanently purge tiny file:
      trash_bytes decreases
      used_bytes decreases
      trash row becomes purged
      no leftover file remains under user root

Version cleanup has also been tested:

    Upload file
    Overwrite file to create version
    Move file to Trash
    Permanently purge file

Result:

    matching version row is deleted
    matching version blob is deleted
    version_bytes decreases
    purge response reports versions_deleted and version_bytes_deleted

## Important design decisions

### Trash counts against quota

Reason:

    Trash is still recoverable user-owned data.
    If Trash did not count, users could bypass quota by moving files to Trash.

### Permanent purge removes matching versions

Reason:

    If a user permanently deletes a file, hidden version history for that file should not remain forever.
    Otherwise DNA-Nexus could accumulate invisible orphaned version blobs over years.

### Internal metadata does not count against quota

Reason:

    Users should not lose storage quota because DNA-Nexus records activity logs or internal metadata.

### Activity metadata still needs cleanup

Reason:

    Even if internal metadata does not count against quota, it still consumes real disk space.
    Long-running systems need retention policies.

## Future improvements

Recommended future work:

    1. Add explicit storage breakdown UI:
       - Live files
       - Trash
       - Versions
       - Internal metadata

    2. Add version management UI:
       - list largest versions
       - delete selected version
       - delete all versions for a file
       - delete orphaned versions if any are found

    3. Add version retention policy:
       - keep forever
       - keep last N versions per file
       - delete versions older than X days
       - optional max version storage per user

    4. Add activity retention:
       - keep last N events
       - keep last X days
       - occasional VACUUM if needed

    5. Add admin garbage report:
       - total Trash bytes
       - total version bytes
       - total internal metadata bytes
       - oldest Trash item
       - largest Trash entries
       - largest version blobs
       - orphaned metadata/blob check

    6. Add repair/check command:
       - verify trash.db rows match payload paths
       - verify file_versions.db rows match blob files
       - report missing blobs
       - report orphaned blobs
       - optionally repair safely

## Operational commands

Show active Trash summary:

    sudo sqlite3 /srv/pqnas/config/trash.db "
    SELECT
      restore_status,
      COUNT(*) AS items,
      COALESCE(SUM(size_bytes),0) AS bytes
    FROM trash_items
    GROUP BY restore_status;
    "

Show largest active Trash items:

    sudo sqlite3 /srv/pqnas/config/trash.db "
    SELECT
      size_bytes,
      original_rel_path,
      datetime(deleted_epoch,'unixepoch','localtime') AS deleted_at,
      datetime(purge_after_epoch,'unixepoch','localtime') AS purge_after
    FROM trash_items
    WHERE restore_status='trashed'
    ORDER BY size_bytes DESC
    LIMIT 20;
    "

Show version usage:

    sudo sqlite3 /srv/pqnas/config/file_versions.db "
    SELECT
      event_kind,
      COUNT(*) AS versions,
      COALESCE(SUM(bytes),0) AS bytes
    FROM file_versions
    GROUP BY event_kind;
    "

Show largest versions:

    sudo sqlite3 /srv/pqnas/config/file_versions.db "
    SELECT
      bytes,
      ROUND(bytes / 1024.0 / 1024.0, 2) AS mib,
      event_kind,
      datetime(created_epoch,'unixepoch','localtime') AS created_at,
      logical_rel_path,
      blob_rel_path
    FROM file_versions
    ORDER BY bytes DESC
    LIMIT 20;
    "

Show activity DB size:

    USER_ROOT="/srv/pqnas/data/users/<USER_FP>"
    ACT="$USER_ROOT/.pqnas_activity/activity.sqlite"

    sudo ls -lh "$ACT"

    sudo sqlite3 "$ACT" "
    PRAGMA page_size;
    PRAGMA page_count;
    PRAGMA freelist_count;
    "

Show activity event counts:

    sudo sqlite3 "$ACT" "
    SELECT COUNT(*) AS events FROM activity_events;

    SELECT event_type, COUNT(*)
    FROM activity_events
    GROUP BY event_type
    ORDER BY COUNT(*) DESC;
    "

## Summary

DNA-Nexus garbage management should follow this model:

    Recoverable data counts against quota.
    Permanent deletion frees quota and disk.
    Permanent deletion also removes matching version history.
    Internal system metadata is excluded from user quota.
    Internal system metadata still needs retention cleanup.

This prevents quota bypass, invisible version garbage, and long-term NAS storage rot.