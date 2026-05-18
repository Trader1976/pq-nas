# Building DNA-Nexus Server from Source
## Recommended Installation

Most users should install DNA-Nexus Server from a prebuilt release tarball.

The release installer handles:

- OS runtime dependencies
- Python installer environment
- server binary installation
- static web assets
- bundled apps
- default configuration
- service user setup
- systemd service setup
- storage initialization
- optional reverse proxy setup

Building from source is intended for developers, contributors, and advanced users.

This document explains how to build and install **DNA-Nexus Server** from source on Linux.

The project is currently in a branding transition from **PQ-NAS** to **DNA-Nexus Server**. Some internal paths, service names, binaries, and environment variable names still use `pqnas`.

Current examples:

```text
Server binary:        pqnas_server
Key generator:        pqnas_keygen
Systemd service:      pqnas.service
Service user:         pqnas
System config:        /etc/pqnas
Runtime data root:    /srv/pqnas
Static web root:      /opt/pqnas/static
Installed apps root:  /srv/pqnas/apps
```

These names are expected in current builds.

---

# Repository

Clone the repository:

```bash
git clone git@github.com:DNA-Nexus/pq-nas.git
cd pq-nas
```

Or, if you already have it locally:

```bash
cd ~/CLionProjects/pq-nas
git pull
```

---

# Supported Build Environment

The current installer and development flow target Debian/Ubuntu-style systems with `apt-get`.

Other Linux distributions may work, but dependency names, systemd layout, runtime library packages, and installer behavior may need adjustment.

---

# Build Dependencies

Install compiler and development dependencies:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  pkg-config \
  libssl-dev \
  libsodium-dev \
  libqrencode-dev \
  libjsoncpp-dev \
  libsqlite3-dev
```

Optional but useful development tools:

```bash
sudo apt install -y \
  git \
  jq \
  rsync \
  curl \
  inotify-tools
```

---

# Runtime and Installer Dependencies

The release installer installs a broader set of OS dependencies because it needs to prepare disks, create filesystems, run the Textual installer, and support runtime features.

For a source-built development install, these packages are also useful:

```bash
sudo apt update
sudo apt install -y \
  python3-venv \
  python3-pip \
  util-linux \
  gdisk \
  parted \
  e2fsprogs \
  btrfs-progs \
  libqrencode4 \
  libsqlite3-0 \
  smartmontools \
  libsodium23 \
  libssl3 \
  openssl \
  libstdc++6 \
  libgcc-s1 \
  ca-certificates
```

What these are used for:

```text
python3-venv, python3-pip    Installer virtual environment
util-linux                   lsblk, wipefs, blkid, partprobe
gdisk                        sgdisk
parted                       Partitioning
e2fsprogs                    mkfs.ext4
btrfs-progs                  mkfs.btrfs and btrfs subvolumes
libqrencode4                 QR code runtime library
libsqlite3-0                 SQLite runtime library
smartmontools                smartctl drive health probing
libsodium23                  libsodium runtime
libssl3, openssl             OpenSSL runtime and tooling
libstdc++6, libgcc-s1        C/C++ runtime libraries
ca-certificates              TLS certificate trust store
```

---

# External Runtime Tools

Some DNA-Nexus Server features call external programs at runtime. These are not always visible from `ldd`.

Install them with:

```bash
sudo apt install -y \
  smartmontools \
  unzip \
  libimage-exiftool-perl \
  imagemagick
```

Used for:

```text
smartctl / smartmontools     Drive health probing
unzip                        ZIP handling
exiftool                     Embedded image metadata, EXIF, IPTC, XMP
convert / magick             Gallery thumbnail generation
```

---

# Optional Reverse Proxy / HTTPS Dependencies

If you use the installer’s nginx reverse proxy or Let’s Encrypt flow, these may also be installed:

```bash
sudo apt install -y \
  nginx \
  certbot \
  python3-certbot-nginx
```

For normal local development on `:8081`, nginx is not required.

---

# Build

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The main binaries are produced under:

```text
./build/bin/
```

Important outputs:

```text
./build/bin/pqnas_server
./build/bin/pqnas_keygen
```

---

# Install Service User

The normal runtime service user is `pqnas`.

Create it if it does not already exist:

```bash
if ! id -u pqnas >/dev/null 2>&1; then
  sudo useradd -r -s /usr/sbin/nologin -M pqnas
fi
```

---

# Runtime Directory Layout

Create the main runtime directories:

```bash
sudo install -d -o pqnas -g pqnas /srv/pqnas
sudo install -d -o pqnas -g pqnas /srv/pqnas/data
sudo install -d -o pqnas -g pqnas /srv/pqnas/logs
sudo install -d -o pqnas -g pqnas /srv/pqnas/apps
sudo install -d -o pqnas -g pqnas /srv/pqnas/apps/bundled
sudo install -d -o pqnas -g pqnas /srv/pqnas/apps/installed
sudo install -d -o pqnas -g pqnas /srv/pqnas/apps/users
sudo install -d -o pqnas -g pqnas /srv/pqnas/audit
sudo install -d -o pqnas -g pqnas /srv/pqnas/tmp

sudo install -d -o pqnas -g pqnas /etc/pqnas
sudo install -d -o pqnas -g pqnas /opt/pqnas/static
```

Common runtime paths:

```text
/usr/local/bin/pqnas_server        Main server binary
/usr/local/bin/pqnas_keygen        Key generator

/etc/pqnas/                        System configuration
/etc/pqnas/pqnas.env               Main environment file
/etc/pqnas/keys.env                Generated server/cookie keys
/etc/pqnas/admin_settings.json     Admin settings
/etc/pqnas/policy.json             Policy configuration
/etc/pqnas/users.json              User registry
/etc/pqnas/shares.json             Share metadata
/etc/pqnas/pools.json              Storage pool metadata
/etc/pqnas/app_auth.json           App/mobile auth state

/opt/pqnas/static/                 Main static web UI files

/srv/pqnas/                        Main runtime data root
/srv/pqnas/data/                   User/share data root
/srv/pqnas/logs/                   Logs
/srv/pqnas/apps/                   App root
/srv/pqnas/apps/bundled/           Bundled app ZIPs
/srv/pqnas/apps/installed/         Installed app versions
/srv/pqnas/apps/users/             User app data
/srv/pqnas/audit/                  Audit logs
/srv/pqnas/tmp/                    Temporary files
```

Some older development notes or older builds may also reference config files under:

```text
/srv/pqnas/config/
```

Current installer-style production config lives under:

```text
/etc/pqnas/
```

---

# Install Binaries

Install the freshly built server and key generator:

```bash
sudo install -m 0755 -o root -g root \
  ./build/bin/pqnas_server \
  /usr/local/bin/pqnas_server

sudo install -m 0755 -o root -g root \
  ./build/bin/pqnas_keygen \
  /usr/local/bin/pqnas_keygen
```

---

# Install DNA Runtime Library

The server expects the DNA runtime library to be available.

Current source-tree location:

```text
server/third_party/dna/lib/linux/x64/libdna_lib.so
```

Install it to:

```bash
sudo install -d -o pqnas -g pqnas /opt/pqnas/lib/dna

sudo install -m 0755 -o pqnas -g pqnas \
  server/third_party/dna/lib/linux/x64/libdna_lib.so \
  /opt/pqnas/lib/dna/libdna_lib.so
```

---

# Install Static Web Assets

Static UI assets live in:

```text
server/src/static/
```

Install them to:

```text
/opt/pqnas/static/
```

Recommended development command:

```bash
cd ~/CLionProjects/pq-nas

sudo install -d -o pqnas -g pqnas /opt/pqnas/static

sudo rsync -a --delete \
  --chown=pqnas:pqnas \
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
  server/src/static/ \
  /opt/pqnas/static/
```

This installs files such as:

```text
app.html
app.js
theme.css
login.html
admin.html
admin_users.html
admin_settings.html
admin_apps.html
admin_audit.html
system.html
external_workspace.html
external_workspace.css
external_workspace.js
share_pq_invite.js
share_pq_open.js
```

After updating static files, restart the service and hard-refresh the browser.

---

# Build Bundled App ZIPs

The installer expects bundled app ZIPs in the app folders.

From the installer logic, the expected development layout is:

```text
apps/bundled/<app>/<id>-<version>.zip
```

If the ZIPs are missing, build them first:

```bash
cd ~/CLionProjects/pq-nas
tools/build_all_bundled_zips.sh
```

Then install bundled ZIPs into:

```text
/srv/pqnas/apps/bundled/
```

```bash
cd ~/CLionProjects/pq-nas

sudo install -d -o pqnas -g pqnas /srv/pqnas/apps/bundled

for app_dir in apps/bundled/*; do
  [ -d "$app_dir" ] || continue

  app="$(basename "$app_dir")"
  sudo install -d -o pqnas -g pqnas "/srv/pqnas/apps/bundled/$app"

  sudo find "/srv/pqnas/apps/bundled/$app" -maxdepth 1 -type f -name '*.zip' -delete

  found_zip=0
  for zip in "$app_dir"/*.zip; do
    [ -f "$zip" ] || continue
    found_zip=1
    sudo install -m 0644 -o pqnas -g pqnas "$zip" "/srv/pqnas/apps/bundled/$app/$(basename "$zip")"
  done

  if [ "$found_zip" -eq 0 ]; then
    echo "WARNING: no bundled zip found for $app"
  fi
done
```

---

# Development Shortcut: Install App Source Directly

During active development, it is often faster to copy app source files directly into the installed app directory.

This bypasses ZIP packaging and is useful when changing JavaScript, CSS, or HTML.

Installed app source layout:

```text
/srv/pqnas/apps/installed/<app>/<version>/
├─ manifest.json
└─ www/
```

Install or refresh one app from source:

```bash
cd ~/CLionProjects/pq-nas

app_id="filemgr"
manifest="apps/bundled/$app_id/src/manifest.json"
app_version="$(jq -r '.version' "$manifest")"
install_dir="/srv/pqnas/apps/installed/$app_id/$app_version"

sudo install -d -o pqnas -g pqnas "$install_dir"
sudo install -m 0644 -o pqnas -g pqnas "$manifest" "$install_dir/manifest.json"

sudo install -d -o pqnas -g pqnas "$install_dir/www"

sudo rsync -a --delete \
  --chown=pqnas:pqnas \
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
  "apps/bundled/$app_id/src/www/" \
  "$install_dir/www/"

sudo systemctl restart pqnas.service
```

Replace `filemgr` with another bundled app id, for example:

```text
photogallery
sharesmgr
dropzone
echostack
reelstack
neonwave
snapshotmgr
raidmgr
```

---

# Install All Bundled App Sources Directly

For development, this refreshes all app `src/www` directories into `/srv/pqnas/apps/installed/<id>/<version>/`.

```bash
cd ~/CLionProjects/pq-nas

for manifest in apps/bundled/*/src/manifest.json; do
  app_src_dir="$(dirname "$manifest")"

  app_id="$(jq -r '.id // empty' "$manifest")"
  app_version="$(jq -r '.version // empty' "$manifest")"

  if [ -z "$app_id" ] || [ -z "$app_version" ]; then
    echo "Skipping $manifest: missing id or version"
    continue
  fi

  install_dir="/srv/pqnas/apps/installed/$app_id/$app_version"

  echo "Installing app source: $app_id $app_version"

  sudo install -d -o pqnas -g pqnas "$install_dir"
  sudo install -m 0644 -o pqnas -g pqnas "$manifest" "$install_dir/manifest.json"

  if [ -d "$app_src_dir/www" ]; then
    sudo install -d -o pqnas -g pqnas "$install_dir/www"

    sudo rsync -a --delete \
      --chown=pqnas:pqnas \
      --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
      "$app_src_dir/www/" \
      "$install_dir/www/"
  fi
done
```

---

# Install Default Config Files

Default config files live in:

```text
config/
```

Install missing defaults into:

```text
/etc/pqnas/
```

Do **not** overwrite existing production config unless you intentionally want to reset settings.

```bash
cd ~/CLionProjects/pq-nas

sudo install -d -o pqnas -g pqnas /etc/pqnas

for name in admin_settings.json policy.json users.json shares.json pools.json; do
  if [ ! -f "/etc/pqnas/$name" ]; then
    sudo install -m 0640 -o pqnas -g pqnas "config/$name" "/etc/pqnas/$name"
  else
    echo "Keeping existing /etc/pqnas/$name"
  fi
done
```

Create app auth state if missing:

```bash
if [ ! -f /etc/pqnas/app_auth.json ]; then
  sudo tee /etc/pqnas/app_auth.json >/dev/null <<'EOF'
{
  "version": 1,
  "devices": {},
  "refresh_tokens": {}
}
EOF
  sudo chown pqnas:pqnas /etc/pqnas/app_auth.json
  sudo chmod 0640 /etc/pqnas/app_auth.json
fi
```

---

# Generate Server Keys

Generate `/etc/pqnas/keys.env` using `pqnas_keygen`:

```bash
sudo /usr/local/bin/pqnas_keygen | sudo tee /etc/pqnas/keys.env >/dev/null
sudo chown root:pqnas /etc/pqnas/keys.env
sudo chmod 0600 /etc/pqnas/keys.env
```

The file should contain values such as:

```text
PQNAS_SERVER_PK_B64URL=...
PQNAS_SERVER_SK_B64URL=...
PQNAS_COOKIE_KEY_B64URL=...
```

Do not commit or share `keys.env`.

---

# Write Environment File

Create `/etc/pqnas/pqnas.env`:

```bash
sudo tee /etc/pqnas/pqnas.env >/dev/null <<'EOF'
PQNAS_ROOT=/srv/pqnas
PQNAS_CONFIG=/etc/pqnas

PQNAS_ADMIN_SETTINGS_PATH=/etc/pqnas/admin_settings.json
PQNAS_POLICY_PATH=/etc/pqnas/policy.json
PQNAS_USERS_PATH=/etc/pqnas/users.json
PQNAS_SHARES_PATH=/etc/pqnas/shares.json
PQNAS_POOLS_PATH=/etc/pqnas/pools.json
PQNAS_APP_AUTH_PATH=/etc/pqnas/app_auth.json

PQNAS_AUDIT_DIR=/srv/pqnas/audit
PQNAS_LOG_DIR=/srv/pqnas/logs
PQNAS_TMP_DIR=/srv/pqnas/tmp

PQNAS_DATA_ROOT=/srv/pqnas/data
PQNAS_STATIC_ROOT=/opt/pqnas/static
PQNAS_APPS_ROOT=/srv/pqnas/apps

PQNAS_AUTH_MODE=v5
PQNAS_DNA_LIB=/opt/pqnas/lib/dna/libdna_lib.so
EOF

sudo chown root:pqnas /etc/pqnas/pqnas.env
sudo chmod 0640 /etc/pqnas/pqnas.env
```

If the server has a public URL, add:

```text
PQNAS_ORIGIN=https://your-server.example
PQNAS_RP_ID=your-server.example
```

If Android trusted-device pairing is used with HTTPS, also configure:

```text
PQNAS_TLS_SPKI_SHA256_PIN=sha256/...
```

---

# Install smartctl Sudoers Rule

Drive health probing uses `smartctl`. The installer gives the `pqnas` service user permission to run it without a password.

Create the rule safely:

```bash
tmp="$(mktemp)"
cat > "$tmp" <<'EOF'
pqnas ALL=(root) NOPASSWD: /usr/sbin/smartctl
EOF

sudo chmod 0440 "$tmp"
sudo visudo -c -f "$tmp"
sudo install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/pqnas-smartctl
rm -f "$tmp"
```

Validate:

```bash
sudo -u pqnas sudo -n /usr/sbin/smartctl --version
```

---

# Install systemd Service

Create `/etc/systemd/system/pqnas.service`:

```bash
sudo tee /etc/systemd/system/pqnas.service >/dev/null <<'EOF'
[Unit]
Description=DNA-Nexus Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pqnas
Group=pqnas
EnvironmentFile=/etc/pqnas/pqnas.env
EnvironmentFile=/etc/pqnas/keys.env
ExecStart=/usr/local/bin/pqnas_server
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable and start:

```bash
sudo systemctl enable --now pqnas.service
```

Check status:

```bash
systemctl status pqnas.service --no-pager
```

Follow live logs:

```bash
sudo journalctl -u pqnas.service -f
```

---

# Fast Development Update

This is the normal quick loop when changing backend C++ and frontend assets:

```bash
cd ~/CLionProjects/pq-nas

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

sudo install -m 0755 -o root -g root \
  ./build/bin/pqnas_server \
  /usr/local/bin/pqnas_server

sudo install -m 0755 -o root -g root \
  ./build/bin/pqnas_keygen \
  /usr/local/bin/pqnas_keygen

sudo install -d -o pqnas -g pqnas /opt/pqnas/static

sudo rsync -a --delete \
  --chown=pqnas:pqnas \
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
  server/src/static/ \
  /opt/pqnas/static/

for manifest in apps/bundled/*/src/manifest.json; do
  app_src_dir="$(dirname "$manifest")"

  app_id="$(jq -r '.id // empty' "$manifest")"
  app_version="$(jq -r '.version // empty' "$manifest")"

  if [ -z "$app_id" ] || [ -z "$app_version" ]; then
    echo "Skipping $manifest: missing id or version"
    continue
  fi

  install_dir="/srv/pqnas/apps/installed/$app_id/$app_version"

  echo "Installing app source: $app_id $app_version"

  sudo install -d -o pqnas -g pqnas "$install_dir"
  sudo install -m 0644 -o pqnas -g pqnas "$manifest" "$install_dir/manifest.json"

  if [ -d "$app_src_dir/www" ]; then
    sudo install -d -o pqnas -g pqnas "$install_dir/www"

    sudo rsync -a --delete \
      --chown=pqnas:pqnas \
      --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
      "$app_src_dir/www/" \
      "$install_dir/www/"
  fi
done

sudo systemctl restart pqnas.service
```

After frontend updates, hard-refresh the browser.

---

# Updating Only the Server Binary

If only C++ backend code changed:

```bash
cd ~/CLionProjects/pq-nas

cmake --build build -j

sudo install -m 0755 -o root -g root \
  ./build/bin/pqnas_server \
  /usr/local/bin/pqnas_server

sudo systemctl restart pqnas.service
```

---

# Updating Only Main Static Files

If only files under `server/src/static/` changed:

```bash
cd ~/CLionProjects/pq-nas

sudo rsync -a --delete \
  --chown=pqnas:pqnas \
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
  server/src/static/ \
  /opt/pqnas/static/

sudo systemctl restart pqnas.service
```

Then hard-refresh the browser.

---

# Updating Only One Bundled App

Example for File Manager:

```bash
cd ~/CLionProjects/pq-nas

app_id="filemgr"
manifest="apps/bundled/$app_id/src/manifest.json"
app_version="$(jq -r '.version' "$manifest")"
install_dir="/srv/pqnas/apps/installed/$app_id/$app_version"

sudo install -d -o pqnas -g pqnas "$install_dir"
sudo install -m 0644 -o pqnas -g pqnas "$manifest" "$install_dir/manifest.json"

sudo install -d -o pqnas -g pqnas "$install_dir/www"

sudo rsync -a --delete \
  --chown=pqnas:pqnas \
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
  "apps/bundled/$app_id/src/www/" \
  "$install_dir/www/"

sudo systemctl restart pqnas.service
```

---

# Useful Runtime Inspection Commands

## Watch Live Logs

```bash
sudo journalctl -u pqnas.service -f
```

## Recent Logs

```bash
sudo journalctl -u pqnas.service -n 100 --no-pager
```

## Check Service Status

```bash
systemctl status pqnas.service --no-pager
```

## Check Runtime Environment

```bash
sudo cat /etc/pqnas/pqnas.env
```

## Check Policy

```bash
sudo cat /etc/pqnas/policy.json | jq
```

## Check Users

```bash
sudo cat /etc/pqnas/users.json | jq
```

## Check Pools

```bash
sudo cat /etc/pqnas/pools.json | jq
```

## Check Admin Settings

```bash
sudo cat /etc/pqnas/admin_settings.json | jq
```

## Check Share Metadata

```bash
sudo cat /etc/pqnas/shares.json | jq
```

## Check Installed Apps

```bash
find /srv/pqnas/apps/installed -maxdepth 3 -type f -name manifest.json -print
```

Show app ids and versions:

```bash
for manifest in /srv/pqnas/apps/installed/*/*/manifest.json; do
  echo "$manifest"
  jq '{id, name, version, entry, api_base, category, surfaces}' "$manifest"
done
```

## Check Bundled App ZIPs

```bash
find /srv/pqnas/apps/bundled -type f -name '*.zip' -print
```

---

# Tracing File Writes During Development

Watch service logs:

```bash
sudo journalctl -fu pqnas.service
```

In another terminal, watch runtime filesystem writes:

```bash
sudo inotifywait -m /srv/pqnas /etc/pqnas /opt/pqnas
```

This is useful when debugging config, metadata, app installation, and runtime writes.

---

# Testing Static File Availability

For a public HTTPS server:

```bash
curl -I https://your-server.example/static/app.js
curl -I https://your-server.example/static/app.html
curl -I https://your-server.example/static/theme.css
```

For local testing, adjust the URL to your server address and port.

---

# Testing Drive Health API

When authenticated, drive health can be inspected through the system API.

Set:

```bash
export BASE="https://your-server.example"
export COOKIE="your_session_cookie_here"
```

Then:

```bash
curl -sS "$BASE/api/v4/system/drives" \
  -H "Cookie: $COOKIE" | jq '.drives[] | {
  dev,
  model,
  transport,
  kind,
  health_status,
  health_text,
  temperature_c,
  power_on_hours,
  reallocated_sectors,
  current_pending_sectors,
  offline_uncorrectable,
  reported_uncorrect,
  udma_crc_errors,
  selftest_supported,
  selftest_status,
  selftest_short_minutes,
  selftest_extended_minutes,
  warning
}'
```

---

# Runtime Dependency Debugging

Check linked libraries:

```bash
ldd /usr/local/bin/pqnas_server
ldd /opt/pqnas/lib/dna/libdna_lib.so
```

Show missing libraries only:

```bash
ldd /usr/local/bin/pqnas_server | grep "not found" || true
ldd /opt/pqnas/lib/dna/libdna_lib.so | grep "not found" || true
```

Common runtime packages:

```text
libqrencode4
libsqlite3-0
libfmt9
libjsoncpp25
libsodium23
libssl3
libstdc++6
libgcc-s1
```

Package names may differ between Ubuntu/Debian releases.

---

# Service Management

Start:

```bash
sudo systemctl start pqnas.service
```

Stop:

```bash
sudo systemctl stop pqnas.service
```

Restart:

```bash
sudo systemctl restart pqnas.service
```

Enable at boot:

```bash
sudo systemctl enable pqnas.service
```

Disable at boot:

```bash
sudo systemctl disable pqnas.service
```

Status:

```bash
systemctl status pqnas.service --no-pager
```

Logs:

```bash
sudo journalctl -u pqnas.service -f
```

---

# Notes for Contributors

When building from source, remember that updating the backend binary is not always enough.

You may need to update:

```text
/usr/local/bin/pqnas_server
/usr/local/bin/pqnas_keygen
/opt/pqnas/lib/dna/libdna_lib.so
/opt/pqnas/static/
/srv/pqnas/apps/bundled/
/srv/pqnas/apps/installed/<app>/<version>/
/etc/pqnas/pqnas.env
/etc/pqnas/keys.env
/etc/pqnas/*.json
```

Common mismatch symptoms:

```text
Backend changed, browser still old:
  Static files or installed app files were not updated.

App source changed, browser still old:
  The app was not copied into /srv/pqnas/apps/installed/<app>/<version>/.

Manifest changed, app still behaves old:
  The installed manifest was not updated.

Authentication or pairing changed:
  Check /etc/pqnas/pqnas.env and /etc/pqnas/keys.env.

Drive health missing:
  Check smartmontools and /etc/sudoers.d/pqnas-smartctl.
```

After frontend or app updates, hard-refresh the browser.

---

# Important Safety Note

This document intentionally avoids destructive reset commands.

Do not delete or wipe anything under these paths unless you know exactly what you are doing:

```text
/srv/pqnas
/etc/pqnas
/opt/pqnas
/srv/pqnas/pools
/srv/pqnas/data/users
/srv/pqnas/data/shares
/srv/pqnas/apps
/srv/pqnas/audit
```

These locations may contain real users, real files, share metadata, storage pool metadata, audit logs, app data, and server configuration.

Use a dedicated test machine or VM for destructive storage testing.