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

- **rotates** logs into archives
- **keeps** or **deletes** old archives according to retention rules

---

# Audit Verbosity

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

# Audit Rotation (Manual)

The **Rotate now** button immediately closes the current audit log and starts a new one.

Use this when:

- performing maintenance
- preparing for backups
- segmenting logs for investigation
- testing rotation policies

Rotation does **not** delete anything — it only archives the current file.

---

# Automatic Audit Rotation

This section controls when PQ-NAS should rotate logs by itself.

### Rotation modes

- **Off** — logs grow until rotated manually
- **Daily** — rotate once per day
- **When size exceeds N MB** — rotate when the active log becomes large
- **Size OR daily** — whichever happens first

### Fields

- **Rotate MB** — size limit for automatic rotation

### Save policy

Stores the automatic rotation rules and activates them immediately.

---

# Audit Retention

Retention decides how long rotated audit logs are kept.

The active audit log is **never** removed by retention rules.

Only archived logs are affected.

---

## Retention modes

- **Never delete automatically** — archives are kept forever
- **Keep last N days** — deletes older archives
- **Keep last N files** — keeps only the newest archives
- **Keep up to N MB total** — limits total disk usage of archives

---

## Buttons

**Save policy**  
Stores the retention rules.

**Preview prune**  
Shows what *would* be deleted without removing anything.

Use this before running prune in production.

**Run prune now**  
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

- testing size-based rotation
- capacity planning
- verifying automatic rotation works

---

# Safe Operation Principles

PQ-NAS is designed so that administrators can operate these controls safely:

- ✔️ Active audit logs are never deleted automatically
- ✔️ Preview always runs before deletion
- ✔️ All changes are audited
- ✔️ Admin confirmation required for destructive actions
- ✔️ Rotation never alters existing records
- ✔️ Retention only affects archived logs

---

# When to Use What

### Rotate now
Use when you want to start a fresh audit log immediately.

### Automatic rotation
Enable to avoid oversized logs and to keep investigations cleanly separated.

### Preview prune
Always run before pruning in production.

### Run prune now
Use only after verifying the preview.

---

© CPUNK 2026 — PQ-NAS Security Platform
