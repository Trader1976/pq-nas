#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-pqnas.service}"
CONFIG_DIR="${CONFIG_DIR:-/srv/pqnas/config}"
DATA_DIR="${DATA_DIR:-/srv/pqnas/data}"
PQNAS_USER="${PQNAS_USER:-pqnas}"
PQNAS_GROUP="${PQNAS_GROUP:-pqnas}"

USERS_JSON="$CONFIG_DIR/users.json"
WORKSPACES_JSON="$CONFIG_DIR/workspaces.json"
SHARES_JSON="$CONFIG_DIR/shares.json"
APP_AUTH_JSON="$CONFIG_DIR/app_auth.json"

die() {
    echo "[reset] ERROR: $*" >&2
    exit 1
}

log() {
    echo "[reset] $*"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

[[ "${EUID}" -eq 0 ]] || die "run as root (sudo)"
require_cmd jq
require_cmd realpath
[[ -d "$CONFIG_DIR" ]] || die "missing config dir: $CONFIG_DIR"
[[ -d "$DATA_DIR" ]] || die "missing data dir: $DATA_DIR"
[[ -f "$USERS_JSON" ]] || die "missing users.json: $USERS_JSON"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

ADMIN_USERS_JSON="$tmpdir/users.admin.json"
ADMIN_ROOTS_TXT="$tmpdir/admin_roots.txt"

log "extracting admin users to keep"
jq '{users: [ .users[] | select(.role == "admin") ]}' "$USERS_JSON" > "$ADMIN_USERS_JSON"
jq -r '.users[] | select(.role == "admin") | .root_rel' "$USERS_JSON" > "$ADMIN_ROOTS_TXT"

admin_count="$(jq '.users | length' "$ADMIN_USERS_JSON")"
[[ "$admin_count" -ge 1 ]] || die "no admin users found in $USERS_JSON"

log "stopping $SERVICE_NAME"
systemctl stop "$SERVICE_NAME" || true

log "resetting config json files"
install -o "$PQNAS_USER" -g "$PQNAS_GROUP" -m 0640 "$ADMIN_USERS_JSON" "$USERS_JSON"

printf '%s\n' '{"version":1,"workspaces":[]}' | jq '.' > "$WORKSPACES_JSON"
chown "$PQNAS_USER:$PQNAS_GROUP" "$WORKSPACES_JSON"
chmod 0640 "$WORKSPACES_JSON"

printf '%s\n' '{"shares":[]}' | jq '.' > "$SHARES_JSON"
chown "$PQNAS_USER:$PQNAS_GROUP" "$SHARES_JSON"
chmod 0640 "$SHARES_JSON"

printf '%s\n' '{"devices":{},"refresh_tokens":{},"version":1}' | jq '.' > "$APP_AUTH_JSON"
chown "$PQNAS_USER:$PQNAS_GROUP" "$APP_AUTH_JSON"
chmod 0640 "$APP_AUTH_JSON"

log "removing old user registry backups"
rm -f "$CONFIG_DIR"/users.json.bak.*

log "resetting share-related state"
rm -rf \
  "$CONFIG_DIR/share_invites_v1" \
  "$CONFIG_DIR/share_manifests_v1" \
  "$CONFIG_DIR/share_recipient_sessions_v1" \
  "$CONFIG_DIR/share_recipients_v1"

mkdir -p \
  "$CONFIG_DIR/share_invites_v1" \
  "$CONFIG_DIR/share_manifests_v1" \
  "$CONFIG_DIR/share_recipient_sessions_v1" \
  "$CONFIG_DIR/share_recipients_v1"

chown -R "$PQNAS_USER:$PQNAS_GROUP" \
  "$CONFIG_DIR/share_invites_v1" \
  "$CONFIG_DIR/share_manifests_v1" \
  "$CONFIG_DIR/share_recipient_sessions_v1" \
  "$CONFIG_DIR/share_recipients_v1"

chmod 0750 \
  "$CONFIG_DIR/share_invites_v1" \
  "$CONFIG_DIR/share_manifests_v1" \
  "$CONFIG_DIR/share_recipient_sessions_v1" \
  "$CONFIG_DIR/share_recipients_v1"

log "removing metadata databases"
for base in file_versions.db gallery_meta.db storage_meta.db trash.db; do
    rm -f \
      "$CONFIG_DIR/$base" \
      "$CONFIG_DIR/$base-shm" \
      "$CONFIG_DIR/$base-wal"
done

log "removing user/workspace/trash/avatar data"
rm -rf \
  "$DATA_DIR/users" \
  "$DATA_DIR/workspaces" \
  "$DATA_DIR/.pqnas/trash"
  "/srv/pqnas/.snapshots"

log "recreating base data directories"
mkdir -p \
  "$DATA_DIR/users" \
  "$DATA_DIR/workspaces" \
  "$DATA_DIR/avatars" \
  "$DATA_DIR/.pqnas/trash/users" \
  "$DATA_DIR/.pqnas/trash/workspaces"
  "/srv/pqnas/.snapshots"
chown -R "$PQNAS_USER:$PQNAS_GROUP" \
  "$DATA_DIR/users" \
  "$DATA_DIR/workspaces" \
  "$DATA_DIR/avatars" \
  "$DATA_DIR/.pqnas"
  "/srv/pqnas/.snapshots"

log "recreating empty roots for kept admin users"
while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue

    abs="$(realpath -m "$DATA_DIR/$rel")"
    case "$abs" in
        "$DATA_DIR"/*) ;;
        *) die "admin root_rel escapes data dir: $rel" ;;
    esac

    mkdir -p "$abs/.pqnas"
    chown -R "$PQNAS_USER:$PQNAS_GROUP" "$abs"
done < "$ADMIN_ROOTS_TXT"

log "starting $SERVICE_NAME"
systemctl start "$SERVICE_NAME"

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    die "$SERVICE_NAME did not start cleanly"
fi

log "done"
log "kept admin users: $admin_count"
log "all user files, workspaces, trash, shares, auth tokens, and metadata DBs were reset"
