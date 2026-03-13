# PQ-NAS Storage Tiering Architecture

## Overview

PQ-NAS implements a **tiered storage model** where new uploads are first written to a fast **landing tier** (typically SSD) and later migrated automatically to **capacity storage** (typically HDD pools). This design improves write performance while preserving large-scale storage efficiency.

The architecture consists of four main components:

1. Landing tier (write cache)
2. File location metadata index
3. Background migration worker
4. Capacity storage pools

Together these form the PQ-NAS **tiering pipeline**.

---

# Storage Write Path

When a user uploads a file, the server determines where the file should be written.

If tiering is disabled:

```
Upload → Capacity storage
```

If tiering is enabled:

```
Upload → Landing pool (SSD)
```

Landing storage acts as a **write accelerator** and temporary holding area.

---

# Tiering Pipeline

The lifecycle of a file in PQ-NAS tiered storage is:

```
Upload
  │
  ▼
Landing tier (SSD)
  │
  ▼
Background migration worker
  │
  ▼
Capacity storage (HDD)
```

Uploads are immediately acknowledged once written to the landing tier.
Migration to capacity storage happens **asynchronously in the background**.

---

# Directory Layout

Example filesystem layout:

```
/srv/pqnas/
    pools/
        raidtest/
            landing/
                <fingerprint>/
                    file.txt
            data/
                users/
                    <fingerprint>/
                        file.txt
```

Landing files are stored in:

```
/srv/pqnas/pools/<pool>/landing/<fingerprint>/<file>
```

Capacity files are stored in:

```
/srv/pqnas/pools/<pool>/data/users/<fingerprint>/<file>
```

---

# File Location Metadata Index

PQ-NAS maintains a SQLite metadata index tracking the physical location of every file.

Database:

```
/srv/pqnas/config/storage_meta.db
```

Table:

```
file_locations
```

Example schema:

```
fp
logical_rel_path
current_pool
physical_path
tier_state
size_bytes
mtime_epoch
created_epoch
updated_epoch
version
```

This table allows PQ-NAS to:

* locate files quickly
* migrate files safely
* support multi-tier storage
* avoid filesystem scanning
* enable future advanced storage features

---

# Tier States

Each file has a **tier_state** describing where it currently resides.

Possible states:

| State     | Meaning                                    |
| --------- | ------------------------------------------ |
| landing   | file is in SSD landing tier                |
| migrating | file is currently being copied to capacity |
| capacity  | file resides in final storage              |

State transitions:

```
landing → migrating → capacity
```

---

# Migration Worker

A background worker performs automatic migration.

Worker loop:

```
scan landing files
select eligible candidates
migrate files to capacity storage
update metadata index
delete source file
repeat
```

Worker configuration parameters:

```
interval_sec
min_age_sec
max_candidates_per_pass
```

Example configuration:

```
interval: 15 seconds
min age: 10 seconds
max migrations per pass: 4
```

---

# Migration Safety

Migration follows a **copy-verify-rename pattern** to ensure data integrity.

Steps:

1. Copy landing file to temporary destination
2. Verify file size matches
3. Rename temporary file to final path
4. Update metadata index
5. Delete source file

Order is critical:

```
copy → verify → metadata switch → delete source
```

This guarantees a file always exists in **at least one location**.

---

# Stuck Migration Recovery

If the server crashes during migration, files may remain in the **migrating** state.

PQ-NAS includes recovery logic:

```
startup → scan metadata
detect migrating entries
reset or retry migration
```

This prevents permanent inconsistent states.

---

# Admin API

PQ-NAS exposes tiering management APIs.

Manual migration:

```
POST /api/v4/admin/storage/tiering/migrate_one
```

Status endpoint:

```
GET /api/v4/admin/storage/tiering/status
```

The status API returns:

```
landing files
migrating files
capacity files
byte counts
worker status
```

---

# Storage Manager UI

The Storage Manager application visualizes tiering activity.

UI displays:

* Landing backlog
* Migrating files
* Capacity storage
* Total files
* Migration throughput
* Tiering flow bar

Example UI model:

```
Landing → Migrating → Capacity
```

Live metrics include:

```
MiB/s migration rate
landing backlog size
capacity growth
```

The interface refreshes automatically.

---

# Configuration

Tiering is controlled by environment variables.

Example configuration:

```
PQNAS_TIERING_ENABLE=1
PQNAS_TIERING_LANDING_POOL=raidtest
```

Behavior:

| Setting  | Effect                          |
| -------- | ------------------------------- |
| disabled | uploads go directly to capacity |
| enabled  | uploads land in landing tier    |

If the landing pool is invalid, PQ-NAS **fails closed** and refuses uploads.

---

# Benefits

Tiered storage provides several advantages:

Fast writes
SSD buffering
HDD cost efficiency
Background optimization
Improved user experience

Uploads complete quickly while large files are migrated later.

---

# Future Extensions

The current architecture enables several advanced features:

* SSD write-back caching
* hot/cold file promotion
* multi-tier storage
* archive tiers
* cross-pool migration
* per-user tiering policies
* bandwidth throttling
* deduplication
* snapshot-aware migration

The metadata index is the foundation for these capabilities.

---

# Summary

PQ-NAS tiering introduces a high-performance storage pipeline:

```
Upload
   ↓
SSD Landing Tier
   ↓
Migration Worker
   ↓
Capacity Storage
```

The system ensures:

* fast writes
* safe migration
* metadata consistency
* real-time monitoring

This architecture forms the basis for future enterprise-grade storage capabilities in PQ-NAS.
