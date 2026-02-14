#!/usr/bin/env bash
set -euo pipefail

command -v flock >/dev/null 2>&1 || { echo "ERROR: flock not installed" >&2; exit 3; }

JOBID="${1:-}"
if [[ -z "$JOBID" ]]; then
  echo "ERROR: missing job id argument" >&2
  exit 64
fi

BASE="/run/pqnas/restore"
JOBFILE="$BASE/$JOBID.json"
RESULTFILE="$BASE/$JOBID.result.json"

# Ensure runtime dir exists
mkdir -p "$BASE"
chmod 0750 "$BASE" || true

# Global lock so only ONE restore job can run at a time.
LOCKFILE="$BASE/.restore.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
  STEP="lock_busy"
  ERR="another restore job is already running (lock: $LOCKFILE)"
  exit 65
fi

ts_utc() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }

OK=false
ERR=""
STEP="init"
RESULT_WRITTEN=false

# Rollback state (armed after live->backup rename)
rollback_needed=false
BACKUP_PATH=""
LIVE_PATH=""

write_result() {
  # If we already wrote a final result file (e.g. rich success JSON), don't overwrite it.
  if [[ "${RESULT_WRITTEN:-false}" == "true" ]]; then
    return 0
  fi

  local now; now="$(ts_utc)"
  local msg="${ERR:-""}"
cat >"$RESULTFILE" <<JSON
{
  "ok": ${OK},
  "job_id": "$(printf '%s' "$JOBID" | sed 's/"/\\"/g')",
  "ts_utc": "$now",
  "step": "$(printf '%s' "$STEP" | sed 's/"/\\"/g')",
  "error": "$(printf '%s' "$msg" | sed 's/"/\\"/g')"
}
JSON
  chown pqnas:pqnas "$RESULTFILE" 2>/dev/null || true
  chmod 0640 "$RESULTFILE" || true
  RESULT_WRITTEN=true
}

rollback() {
  if [[ "${rollback_needed:-false}" == "true" ]]; then
    echo "[restore][$JOBID] ROLLBACK: starting"

    if [[ -n "${LIVE_PATH:-}" && -e "$LIVE_PATH" ]]; then
      echo "[restore][$JOBID] ROLLBACK: deleting partial live at $LIVE_PATH"
      /usr/bin/btrfs subvolume delete "$LIVE_PATH" >/dev/null 2>&1 || rm -rf "$LIVE_PATH" || true
    fi

    if [[ -n "${BACKUP_PATH:-}" && -e "$BACKUP_PATH" ]]; then
      echo "[restore][$JOBID] ROLLBACK: restoring backup $BACKUP_PATH -> $LIVE_PATH"
      mv "$BACKUP_PATH" "$LIVE_PATH" || true
    else
      echo "[restore][$JOBID] ROLLBACK: backup path missing: ${BACKUP_PATH:-"(unset)"}"
    fi

    echo "[restore][$JOBID] ROLLBACK: done; live exists? $(test -e "$LIVE_PATH" && echo YES || echo NO)"
  fi
}

on_exit() {
  rc=$?
  if [[ "$rc" -ne 0 ]]; then
    ERR="${ERR:-"failed"} (rc=$rc)"
    # If we already renamed live -> backup, always attempt rollback on any error.
    rollback || true
  fi
  write_result
  exit $rc
}

trap on_exit EXIT

STEP="read_job"
if [[ ! -f "$JOBFILE" ]]; then
  ERR="job file not found: $JOBFILE"
  exit 2
fi

command -v jq >/dev/null 2>&1 || { ERR="jq not installed"; exit 3; }

SERVICE_NAME="$(jq -r '.service_name // empty' "$JOBFILE")"
LIVE_PATH="$(jq -r '.volume.live_path // empty' "$JOBFILE")"
SNAP_PATH="$(jq -r '.volume.snap_path // empty' "$JOBFILE")"
SNAPSHOT_ID="$(jq -r '.snapshot_id // empty' "$JOBFILE")"
MODE="$(jq -r '.request.mode // "probe"' "$JOBFILE")"
CONFIRM_ID="$(jq -r '.request.confirm_id // empty' "$JOBFILE")"

if [[ -z "$SERVICE_NAME" || -z "$LIVE_PATH" || -z "$SNAP_PATH" || -z "$SNAPSHOT_ID" ]]; then
  ERR="missing required fields in job json (service_name, volume.live_path, volume.snap_path, snapshot_id)"
  exit 4
fi

STEP="validate_paths"
case "$LIVE_PATH" in /srv/pqnas/*) ;; *) ERR="live_path not allowed: $LIVE_PATH"; exit 6 ;; esac
case "$SNAP_PATH" in /srv/pqnas/.snapshots/*) ;; *) ERR="snap_path not allowed: $SNAP_PATH"; exit 6 ;; esac

STEP="ensure_live_exists"
if [[ ! -e "$LIVE_PATH" ]]; then
  echo "[restore][$JOBID] ensure_live_exists: live missing at $LIVE_PATH"

  NEWEST_BACKUP="$(/usr/bin/ls -1dt "${LIVE_PATH}".pre_restore.* 2>/dev/null | head -n 1 || true)"


  if [[ -z "$NEWEST_BACKUP" ]]; then
    ERR="live missing and no pre_restore backups found for $LIVE_PATH"
    exit 7
  fi

  echo "[restore][$JOBID] ensure_live_exists: recovering $NEWEST_BACKUP -> $LIVE_PATH"
  mv "$NEWEST_BACKUP" "$LIVE_PATH"
  /usr/bin/chown -R pqnas:pqnas "$LIVE_PATH" || true
  /usr/bin/chmod 0750 "$LIVE_PATH" || true

  echo "[restore][$JOBID] ensure_live_exists: after recovery live exists? $(test -e "$LIVE_PATH" && echo YES || echo NO)"
fi

if [[ ! -d "$SNAP_PATH" ]]; then ERR="snapshot path does not exist: $SNAP_PATH"; exit 7; fi
if [[ ! -d "$LIVE_PATH" ]]; then ERR="live path does not exist: $LIVE_PATH"; exit 7; fi

STEP="btrfs_probe"
if ! /usr/bin/btrfs subvolume show "$SNAP_PATH" >/dev/null 2>&1; then
  ERR="snapshot path is not a btrfs subvolume (or btrfs failed): $SNAP_PATH"
  exit 8
fi
if ! /usr/bin/btrfs subvolume show "$LIVE_PATH" >/dev/null 2>&1; then
  ERR="live path is not a btrfs subvolume (or btrfs failed): $LIVE_PATH"
  exit 8
fi

if [[ "$MODE" == "probe" ]]; then
  STEP="probe_ok"
  OK=true
  ERR=""
  write_result
  exit 0
fi

if [[ "$MODE" != "swap" ]]; then
  STEP="not_implemented"
  ERR="request.mode=$MODE not implemented (use probe or swap)"
  exit 9
fi

STEP="swap_init"
if [[ -z "$CONFIRM_ID" ]]; then
  ERR="missing request.confirm_id (refusing swap without explicit confirmation token)"
  exit 10
fi

STAMP="$(date -u +"%Y-%m-%dT%H-%M-%S.%3NZ")"
BACKUP_PATH="${LIVE_PATH}.pre_restore.${STAMP}"

if [[ -e "$BACKUP_PATH" ]]; then
  ERR="backup path already exists: $BACKUP_PATH"
  exit 11
fi

STEP="stop_service"
if ! /usr/bin/systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
  ERR="service not found: $SERVICE_NAME"
  exit 12
fi

echo "[restore][$JOBID] stop_service: BEFORE stop, live exists? $(test -e "$LIVE_PATH" && echo YES || echo NO) live=$LIVE_PATH service=$SERVICE_NAME"
ls -ld "$LIVE_PATH" 2>&1 | sed 's/^/[restore]['"$JOBID"'] /' || true
/usr/bin/btrfs subvolume show "$LIVE_PATH" 2>&1 | sed 's/^/[restore]['"$JOBID"'] /' || true

/usr/bin/systemctl stop "$SERVICE_NAME" || true

echo "[restore][$JOBID] stop_service: AFTER stop, live exists? $(test -e "$LIVE_PATH" && echo YES || echo NO) live=$LIVE_PATH"
ls -ld "$LIVE_PATH" 2>&1 | sed 's/^/[restore]['"$JOBID"'] /' || true
/usr/bin/btrfs subvolume show "$LIVE_PATH" 2>&1 | sed 's/^/[restore]['"$JOBID"'] /' || true

STEP="rename_live_to_backup"
echo "[restore][$JOBID] rename_live_to_backup: BEFORE: live exists? $(test -e "$LIVE_PATH" && echo YES || echo NO) live=$LIVE_PATH backup=$BACKUP_PATH"
if [[ ! -e "$LIVE_PATH" ]]; then
  ERR="live path missing before rename: $LIVE_PATH"
  exit 12
fi

mv "$LIVE_PATH" "$BACKUP_PATH"

# From this point forward we MUST rollback on error
rollback_needed=true

echo "[restore][$JOBID] rename_live_to_backup: AFTER: live exists? $(test -e "$LIVE_PATH" && echo YES || echo NO), backup exists? $(test -e "$BACKUP_PATH" && echo YES || echo NO)"
ls -ld "$BACKUP_PATH" 2>&1 | sed 's/^/[restore]['"$JOBID"'] /' || true

STEP="create_new_live_from_snapshot"
if ! /usr/bin/btrfs subvolume snapshot "$SNAP_PATH" "$LIVE_PATH"; then
  ERR="failed to create new live subvolume from snapshot"
  rollback
  exit 13
fi

# Make restored live writable even if source snapshot is ro=true
if /usr/bin/btrfs property get -ts "$LIVE_PATH" ro 2>/dev/null | /bin/grep -q 'ro=true'; then
  /usr/bin/btrfs property set -ts "$LIVE_PATH" ro false
fi

STEP="fix_ownership"
# New live subvolume inherits ownership from the snapshot. We must make it writable by pqnas.
# NOTE: this can be expensive for huge trees, but is correct for now.
if ! /usr/bin/chown -R pqnas:pqnas "$LIVE_PATH"; then
  ERR="failed to chown restored live path to pqnas"
  rollback
  exit 13
fi

# Ensure root is accessible only to pqnas (matches your desired hardening)
chmod 0750 "$LIVE_PATH" || true

STEP="start_service"
if ! /usr/bin/systemctl start "$SERVICE_NAME"; then
  ERR="failed to start service after restore; rolling back"
  rollback
  exit 14
fi

rollback_needed=false

STEP="swap_ok"
OK=true
ERR=""

now="$(ts_utc)"
cat >"$RESULTFILE" <<JSON
{
  "ok": true,
  "job_id": "$(printf '%s' "$JOBID" | sed 's/"/\\"/g')",
  "ts_utc": "$now",
  "step": "swap_ok",
  "service_name": "$(printf '%s' "$SERVICE_NAME" | sed 's/"/\\"/g')",
  "live_path": "$(printf '%s' "$LIVE_PATH" | sed 's/"/\\"/g')",
  "backup_path": "$(printf '%s' "$BACKUP_PATH" | sed 's/"/\\"/g')",
  "restored_from": "$(printf '%s' "$SNAP_PATH" | sed 's/"/\\"/g')",
  "snapshot_id": "$(printf '%s' "$SNAPSHOT_ID" | sed 's/"/\\"/g')"
}
JSON
chown pqnas:pqnas "$RESULTFILE" 2>/dev/null || true
chmod 0640 "$RESULTFILE" || true
RESULT_WRITTEN=true
exit 0
