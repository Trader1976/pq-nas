# PQ-NAS Apps (Bundling + Install) — Developer Notes

This document is for **PQ-NAS developers** and **app authors**. It describes:

- the current app package format
- the current `manifest.json` format
- where apps live on disk
- how apps are installed, listed, served, and uninstalled
- how desktop / launcher / sidebar surfaces work
- how app icons work, including the new monochrome sidebar icons
- how launch policy works
- the main PQ-NAS APIs apps use today

> Status: current model is still **static web apps** served by PQ-NAS.  
> Apps run in the browser and use PQ-NAS HTTP APIs with cookie-based auth.  
> There is still **no real sandbox** beyond server-side auth, path validation, and static serving restrictions.

---

## 1) App model (current)

An app is a **static web bundle** containing:

- HTML
- CSS
- JavaScript
- images / icons / fonts / other assets
- a `manifest.json`

Installed apps are served at:

```text
/apps/<id>/<version>/www/...
```

Typical entry URL:

```text
/apps/<id>/<version>/www/index.html
```

Apps run in the browser and call PQ-NAS APIs with cookie-based auth, for example:

```js
fetch("/api/v4/...", {
  credentials: "include",
  cache: "no-store"
})
```

Authentication is based on the normal PQ-NAS session cookie.

Apps should assume:

- they may be opened embedded inside the PQ-NAS shell
- they may be opened detached in a real browser window
- their installed app directory is **read-only from the app’s point of view**
- all persistent data must go through PQ-NAS APIs or app-specific server-side routes

---

## 2) Runtime roots and directory layout

PQ-NAS resolves app paths **env-first**.

### Apps root

The server resolves the apps root like this:

1. `PQNAS_APPS_ROOT` environment variable
2. `/srv/pqnas/apps`
3. repo fallback in development, usually `<repo>/apps`

From that root the server uses:

```text
APPS_BUNDLED_DIR   = <apps_root>/bundled
APPS_INSTALLED_DIR = <apps_root>/installed
APPS_USERS_DIR     = <apps_root>/users
```

Typical runtime layout:

```text
/srv/pqnas/apps/
  bundled/
  installed/
  users/
```

### Installed apps

Installed apps live under:

```text
<apps_root>/installed/<appId>/<version>/
  manifest.json
  www/
    index.html
    app.js
    app.css
    icon.svg
    nav_icon.svg
    other assets...
```

Example:

```text
/srv/pqnas/apps/installed/echostack/1.0.0/
  manifest.json
  www/
    index.html
    app.js
    style.css
    background.css
    icon.svg
    nav_icon.svg
```

### Bundled app source

Bundled app source currently lives in the repo under:

```text
apps/bundled/<appId>/src/
  manifest.json
  www/
    index.html
    app.js
    app.css
    icon.svg
    nav_icon.svg
```

Example:

```text
apps/bundled/dropzone/src/
  manifest.json
  www/
    index.html
    app.js
    style.css
    icon.svg
    nav_icon.svg
```

### Bundled app zips

Bundled app zips are currently expected under:

```text
<apps_root>/bundled/<appId>/*.zip
```

Example:

```text
/srv/pqnas/apps/bundled/filemgr/filemgr-1.0.0.zip
/srv/pqnas/apps/bundled/sharesmgr/sharesmgr-1.0.0.zip
```

### Important repo/runtime note

`apps/installed/` is **runtime state** and must not be committed.

If development falls back to repo-local `apps/`, that is still treated as runtime/install state, not source-of-truth source code.

### Ownership requirement

Installed runtime app files should be owned by the service user:

```text
pqnas:pqnas
```

For example:

```bash
sudo chown -R pqnas:pqnas /srv/pqnas/apps/installed/<appId>
sudo chmod -R u+rwX,g+rX /srv/pqnas/apps/installed/<appId>
```

If installed app directories are accidentally owned by `root:root`, uninstall can fail with permission errors such as:

```text
failed to remove app: Permission denied
```

---

## 3) Zip package format (required)

Your zip **must** contain at minimum:

```text
manifest.json
www/index.html
```

Recommended structure:

```text
myapp-1.0.0.zip
  manifest.json
  www/
    index.html
    app.js
    app.css
    icon.svg
    nav_icon.svg
    assets/
      ...
```

If either `manifest.json` or `www/index.html` is missing, install should be treated as invalid.

Do **not** put the app under an extra top-level directory inside the zip unless the installer explicitly supports that shape.

Good:

```text
manifest.json
www/index.html
```

Avoid:

```text
myapp/
  manifest.json
  www/index.html
```

---

## 4) Current bundled app inventory

Current shipped app versions:

```text
dropzone      1.0.0
echostack     1.0.0
filemgr       1.0.0
neonwave      1.0.0
photogallery  1.0.0
raidmgr       1.0.0
sharesmgr     1.0.0
snapshotmgr   1.0.1
```

Current bundled apps include:

- Drop Zone
- Echo Stack
- File Manager
- NeonWave
- Photo Gallery
- Storage Manager
- Shares Manager
- Snapshot Manager

---

## 5) `manifest.json` format

Current practical manifest example:

```json
{
  "id": "dropzone",
  "name": "Drop Zone",
  "version": "1.0.0",
  "entry": "www/index.html",
  "api_base": "/api/v4/dropzones",
  "permissions": [],
  "category": "sharing",
  "surfaces": {
    "desktop": {
      "enabled": true
    },
    "launcher": {
      "enabled": true
    },
    "sidebar": {
      "enabled": false,
      "user_pinnable": true,
      "section": "sharing",
      "label": "Drop Zone",
      "order": 80
    }
  },
  "icons": {
    "win_classic": "www/icon.svg",
    "cpunk_orange": "www/icon.svg",
    "dark": "www/icon.svg",
    "bright": "www/icon.svg",
    "default": "www/icon.svg"
  }
}
```

### Required fields

```json
{
  "id": "myapp",
  "name": "My App",
  "version": "1.0.0",
  "entry": "www/index.html"
}
```

### Recommended fields

```json
{
  "api_base": "/api/v4/myapp",
  "permissions": [],
  "category": "utility",
  "surfaces": {
    "desktop": {
      "enabled": true
    },
    "launcher": {
      "enabled": true
    },
    "sidebar": {
      "enabled": false,
      "user_pinnable": true,
      "section": "utility",
      "label": "My App",
      "order": 100
    }
  },
  "icons": {
    "win_classic": "www/icon.svg",
    "cpunk_orange": "www/icon.svg",
    "dark": "www/icon.svg",
    "bright": "www/icon.svg",
    "default": "www/icon.svg",
    "sidebar": "www/nav_icon.svg"
  }
}
```

### Field notes

#### `id`

Install identity.

Rules:

- stable
- lowercase recommended
- should match source/runtime app folder identity
- should not contain path separators
- should not be changed casually after shipping

Example:

```json
"id": "echostack"
```

#### `name`

Human-readable display name.

Example:

```json
"name": "Echo Stack"
```

The shell should prefer `name` for desktop labels, sidebar labels, and app UI labels.

#### `version`

Install version.

Example:

```json
"version": "1.0.0"
```

The version is used as the install directory name:

```text
/apps/<id>/<version>/...
```

#### `entry`

Entry page relative to app root.

Current serving still expects:

```json
"entry": "www/index.html"
```

Even if `entry` is present, current app serving and shell logic still assume `www/index.html`.

#### `api_base`

Informational for most apps, but useful for documentation and app self-description.

Examples:

```json
"api_base": "/api/v4/dropzones"
```

```json
"api_base": "/api/v4/echostack"
```

#### `permissions`

Currently informational.

There is not yet a real manifest-enforced app permission model.

Example:

```json
"permissions": []
```

Future app permission work may use this field.

#### `category`

Used for organization and future launcher/sidebar grouping.

Examples:

```json
"category": "sharing"
```

```json
"category": "files"
```

```json
"category": "media"
```

#### `surfaces`

Controls where an app should appear.

Current practical shape:

```json
"surfaces": {
  "desktop": {
    "enabled": true
  },
  "launcher": {
    "enabled": true
  },
  "sidebar": {
    "enabled": false,
    "user_pinnable": true,
    "section": "sharing",
    "label": "Drop Zone",
    "order": 80
  }
}
```

Meaning:

- `desktop.enabled`
    - app may appear as an icon on the main desktop surface
- `launcher.enabled`
    - app may appear in an app launcher / app catalog surface
- `sidebar.enabled`
    - app appears in the left sidebar by default
- `sidebar.user_pinnable`
    - app may later be user-pinnable even if not shown by default
- `sidebar.section`
    - intended grouping/category
- `sidebar.label`
    - optional sidebar-specific display label
- `sidebar.order`
    - intended sort/order hint

Important rule:

```text
Small utility apps should usually be desktop/launcher enabled, but sidebar disabled by default.
```

Example:

```json
"sidebar": {
  "enabled": false,
  "user_pinnable": true,
  "section": "sharing",
  "label": "Drop Zone",
  "order": 80
}
```

Large primary apps may opt into the sidebar:

```json
"sidebar": {
  "enabled": true,
  "user_pinnable": true,
  "section": "primary",
  "label": "File Manager",
  "order": 10
}
```

### Backward compatibility behavior

Older manifests without `surfaces` are treated as visible in legacy locations.

Current intended behavior:

- old manifests without `surfaces` remain visible on the desktop
- old manifests without `surfaces` remain visible in the sidebar
- new manifests with `surfaces` must opt into sidebar visibility explicitly

---

## 6) App icons

PQ-NAS now uses two icon concepts:

1. **Desktop / launcher icon**
2. **Sidebar navigation icon**

They should be treated separately.

---

## 6.1) Desktop / launcher icons

Desktop icons are the app’s main colorful product icons.

They are resolved from `manifest.json` using the `icons` object.

Example:

```json
"icons": {
  "win_classic": "www/icon.svg",
  "cpunk_orange": "www/icon.svg",
  "dark": "www/icon.svg",
  "bright": "www/icon.svg",
  "default": "www/icon.svg"
}
```

Current desktop icon resolution roughly prefers:

1. exact current theme key
2. mapped theme alias
3. `default`
4. first icon entry found
5. fallback to `www/icon.png`

Known theme alias mapping may include:

```text
cpunk   -> cpunk_orange
orange  -> cpunk_orange
win     -> win_classic
classic -> win_classic
```

Recommended desktop icon file:

```text
www/icon.svg
```

PNG icons are still usable, but SVG is preferred for new bundled apps.

---

## 6.2) Sidebar navigation icons

The collapsed/expanded left sidebar now supports small monochrome app glyphs.

Recommended file:

```text
www/nav_icon.svg
```

The sidebar icon is used as a CSS mask and colored by the active theme.

Important design rule:

```text
nav_icon.svg should be monochrome / mask-friendly.
```

Recommended SVG style:

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <g fill="none" stroke="#000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    ...
  </g>
</svg>
```

The actual stroke/fill color inside the SVG is not the displayed color. The shell uses the SVG as a mask and paints it with CSS, usually gray or theme foreground.

Current sidebar icon resolution order:

1. `manifest.icons.sidebar`
2. `manifest.icons.nav`
3. `manifest.sidebar_icon`
4. fallback to `www/nav_icon.svg`

Recommended manifest if you want to be explicit:

```json
"icons": {
  "default": "www/icon.svg",
  "sidebar": "www/nav_icon.svg"
}
```

or:

```json
"sidebar_icon": "www/nav_icon.svg"
```

If no sidebar icon exists, shell code may fall back to initials or a missing/blank icon depending on the current branch. New apps should include `www/nav_icon.svg`.

---

## 6.3) Current bundled sidebar icons

Current bundled app source includes:

```text
apps/bundled/dropzone/src/www/nav_icon.svg
apps/bundled/echostack/src/www/nav_icon.svg
apps/bundled/filemgr/src/www/nav_icon.svg
apps/bundled/neonwave/src/www/nav_icon.svg
apps/bundled/photogallery/src/www/nav_icon.svg
apps/bundled/raidmgr/src/www/nav_icon.svg
apps/bundled/sharesmgr/src/www/nav_icon.svg
apps/bundled/snapshotmgr/src/www/nav_icon.svg
```

When testing existing installed apps without reinstalling, remember to copy new `nav_icon.svg` files into the installed runtime app directories too:

```bash
for m in apps/bundled/*/src/manifest.json; do
  id="$(jq -r '.id' "$m")"
  ver="$(jq -r '.version // .ver' "$m")"
  src="apps/bundled/$id/src/www/nav_icon.svg"
  dst="/srv/pqnas/apps/installed/$id/$ver/www/nav_icon.svg"

  if [ -f "$src" ] && sudo test -d "$(dirname "$dst")"; then
    sudo install -m 0644 -o pqnas -g pqnas "$src" "$dst"
    echo "installed $dst"
  fi
done
```

---

## 7) App version display

Shipping apps should display their own version somewhere visible but non-intrusive.

Current app convention:

```text
App Name v1.0.0
```

or:

```text
App subtitle text • v1.0.0
```

Do **not** hardcode versions in app HTML/JS if possible.

Recommended app-side version resolver:

```js
async function getAppVersion() {
  const m = location.pathname.match(/^\/apps\/([^/]+)\/([^/]+)\//);
  if (m && m[2]) return decodeURIComponent(m[2]);

  for (const url of ["../manifest.json", "./manifest.json"]) {
    try {
      const r = await fetch(url, {
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });
      if (!r.ok) continue;
      const j = await r.json();
      const ver = j && typeof j.version === "string" ? j.version.trim() : "";
      if (ver) return ver;
    } catch (_) {}
  }

  return "";
}
```

Normal installed app path:

```text
/apps/<id>/<version>/www/index.html
```

Example:

```text
/apps/echostack/1.0.0/www/index.html
```

So apps can infer:

```text
1.0.0
```

from the URL.

Fallback for dev/source paths:

```text
../manifest.json
./manifest.json
```

---

## 8) Serving model

Once installed, files are reachable at URLs like:

```text
/apps/<id>/<version>/www/index.html
/apps/<id>/<version>/www/app.js
/apps/<id>/<version>/www/icon.svg
/apps/<id>/<version>/www/nav_icon.svg
/apps/<id>/<version>/manifest.json
```

Example:

```bash
curl -i http://127.0.0.1:8081/apps/sharesmgr/1.0.0/www/index.html | head
```

Apps are still plain browser apps. There is no iframe-to-native bridge or separate app runtime.

Static serving must prevent traversal outside the installed app root.

---

## 9) App listing, install, and uninstall flow

There are two practical listing views in current code paths:

- admin/app-management view
- shell/desktop app list view

---

## 9.1) Admin app-management list

Current admin/app-management UI uses:

```text
GET /api/v4/apps
```

Typical response includes:

- installed apps
- bundled zip info for admin visibility
- launch policy data

Typical installed entry fields may include:

```text
id
version
root
has_manifest
```

The admin apps page can also display and edit launch policy fields.

---

## 9.2) Shell / desktop app list

Some shell code paths use:

```text
GET /api/v4/apps/list
```

This is intended for app-shell-friendly installed app rendering.

Typical shell needs:

- `id`
- `version` or normalized `ver`
- display name/title
- manifest-derived metadata
- surface visibility
- icon paths

Exact response shape may vary by branch. Check current server code before wiring new UI.

---

## 9.3) Check whether an app exists

Current code also has a lightweight check endpoint:

```text
GET /api/v4/apps/has?id=<appId>
```

Example:

```bash
curl -s "http://127.0.0.1:8081/api/v4/apps/has?id=dropzone" | jq .
```

This endpoint is useful for features that need to know whether an optional app is installed without exposing unnecessary install details.

---

## 9.4) Upload and install a zip

Current admin install flow uses:

```text
POST /api/v4/apps/upload_install
```

Request style:

```text
body = raw zip bytes
Content-Type: application/zip
X-PQNAS-Filename: <original filename>
X-PQNAS-Admin-Only: 1 | 0
```

Example:

```bash
curl -X POST http://127.0.0.1:8081/api/v4/apps/upload_install \
  -H 'Content-Type: application/zip' \
  -H 'X-PQNAS-Filename: sharesmgr-1.0.0.zip' \
  -H 'X-PQNAS-Admin-Only: 0' \
  --data-binary @sharesmgr-1.0.0.zip
```

The install route should validate:

- admin auth
- zip readability
- safe filename
- `manifest.json` exists
- `manifest.json` is valid JSON
- `id` and `version` are valid
- `www/index.html` exists
- extraction does not escape the target directory

---

## 9.5) Install bundled app

Current code also contains a bundled install route:

```text
POST /api/v4/apps/install_bundled
```

This is for installing a server-known bundled zip rather than uploading a new zip.

Check current server code for exact request body.

---

## 9.6) Uninstall

Uninstall endpoint:

```text
POST /api/v4/apps/uninstall
```

Body:

```json
{
  "id": "sharesmgr",
  "version": "1.0.0"
}
```

Example:

```bash
curl -s -X POST http://127.0.0.1:8081/api/v4/apps/uninstall \
  -H 'Content-Type: application/json' \
  -d '{"id":"sharesmgr","version":"1.0.0"}' | jq .
```

Uninstall should only remove the installed app code directory:

```text
/srv/pqnas/apps/installed/<id>/<version>
```

It should **not** delete user data.

Example Echo Stack user data lives separately under a user data area such as:

```text
/srv/pqnas/data/users/<fingerprint>/.pqnas_echostack
```

---

## 10) Admin-only visibility

The app manager supports installing apps as admin-only through:

```text
X-PQNAS-Admin-Only: 1
```

The launch policy UI also supports app visibility as:

```text
admin_only: true | false
```

Admin-only means normal users should not see/launch the app from the shell.

This is server-owned policy, not a security promise from the client UI alone. Server routes must still enforce authorization.

---

## 11) Launch behavior and launch policy

PQ-NAS has a separate **app launch policy** concept.

### Important design rule

Launch behavior is **not stored inside app zips**.

It is stored separately in server config so admins can change policy without repackaging apps.

Current config path:

```text
/srv/pqnas/config/app_launch_policy.json
```

### Current policy shape

```json
{
  "schema": 1,
  "defaults": {
    "default_launch": "embedded",
    "window_profile": "auto",
    "allow_user_override": true,
    "admin_only": false
  },
  "by_app_id": {
    "filemgr": {
      "default_launch": "detached",
      "window_profile": "large",
      "allow_user_override": false,
      "admin_only": false
    },
    "sharesmgr": {
      "default_launch": "embedded",
      "window_profile": "full",
      "allow_user_override": false,
      "admin_only": false
    },
    "dropzone": {
      "default_launch": "embedded",
      "window_profile": "normal",
      "allow_user_override": false,
      "admin_only": true
    }
  }
}
```

### Policy endpoint

Current admin UI saves policy with:

```text
POST /api/v4/apps/launch_policy
```

Typical body:

```json
{
  "id": "filemgr",
  "default_launch": "embedded",
  "window_profile": "large",
  "allow_user_override": false,
  "admin_only": false
}
```

### Current supported values

`default_launch`:

```text
auto
embedded
detached
```

`window_profile`:

```text
auto
small
normal
large
full
```

`allow_user_override`:

```text
true
false
```

`admin_only`:

```text
true
false
```

### Meaning

- `embedded`
    - open inside the PQ-NAS app workspace
- `detached`
    - currently opens a real browser popup/window
- `auto`
    - let shell logic choose
- `window_profile`
    - hint for detached/embedded sizing behavior
- `allow_user_override`
    - whether user preference may override admin default
- `admin_only`
    - hide from normal users and require admin visibility/authorization

### Current implementation note

“Detached” currently means a real browser window / popup via browser behavior, not a fake internal sub-window rendered inside the main workspace.

That may change later if PQ-NAS gets its own internal window manager model.

---

## 12) Shell sidebar behavior

The main shell now supports a collapsible left sidebar.

Relevant files:

```text
server/src/static/shell_menu.css
server/src/static/shell_sidebar.js
server/src/static/app.html
```

All shell/admin pages that use `shell_menu.css` should load:

```html
<script src="/static/shell_sidebar.js"></script>
```

The collapse state is stored in localStorage:

```text
pqnas_sidebar_collapsed_v1
```

Expanded sidebar:

```text
label + small app/sidebar icon
```

Collapsed sidebar:

```text
icon rail only
```

Main app sidebar icons use:

```text
www/nav_icon.svg
```

The icon is injected as a real child element and painted using CSS mask styling so it follows the active theme.

---

## 13) Development workflow

Recommended workflow:

1. edit the app source under `apps/bundled/<appId>/src`
2. make sure `manifest.json` is current
3. make sure `www/index.html` exists
4. make sure `www/icon.svg` exists
5. make sure `www/nav_icon.svg` exists
6. build a zip containing `manifest.json` and `www/...`
7. upload/install through Admin → Apps
8. refresh the PQ-NAS shell
9. uninstall old version if needed
10. bump version during development when reinstall flow requires it

### Practical rule

- If you edit files under `/srv/pqnas/apps/installed/...`, you are editing the installed runtime copy.
- If you edit files under `apps/bundled/<id>/src/...`, you are editing source.
- If you edit source, nothing changes in the running install until you rebuild/reinstall or manually copy the changed files for dev testing.

### Static dev copy helper

For static shell files in development:

```bash
sudo install -d -o pqnas -g pqnas /opt/pqnas/static

for f in server/src/static/*.{html,js,css}; do
  [ -f "$f" ] || continue
  sudo install -m 0644 -o pqnas -g pqnas "$f" "/opt/pqnas/static/$(basename "$f")"
done
```

For one specific file:

```bash
sudo install -m 0644 -o pqnas -g pqnas \
  server/src/static/shell_menu.css \
  /opt/pqnas/static/shell_menu.css
```

No server restart is usually needed for static file changes, but browser hard refresh may be required.

---

## 14) Example minimal app bundle

Create a working folder:

```bash
mkdir -p /tmp/pqnas_myapp/www
```

Create manifest:

```bash
cat > /tmp/pqnas_myapp/manifest.json <<'EOF'
{
  "id": "myapp",
  "name": "My App",
  "version": "1.0.0",
  "entry": "www/index.html",
  "api_base": "/api/v4/files",
  "permissions": [],
  "category": "utility",
  "surfaces": {
    "desktop": {
      "enabled": true
    },
    "launcher": {
      "enabled": true
    },
    "sidebar": {
      "enabled": false,
      "user_pinnable": true,
      "section": "utility",
      "label": "My App",
      "order": 100
    }
  },
  "icons": {
    "win_classic": "www/icon.svg",
    "cpunk_orange": "www/icon.svg",
    "dark": "www/icon.svg",
    "bright": "www/icon.svg",
    "default": "www/icon.svg",
    "sidebar": "www/nav_icon.svg"
  }
}
EOF
```

Create entry page:

```bash
cat > /tmp/pqnas_myapp/www/index.html <<'EOF'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>My App</title>
</head>
<body>
  <h1>My App <span id="appVersion"></span></h1>
  <script src="./app.js"></script>
</body>
</html>
EOF
```

Create JS:

```bash
cat > /tmp/pqnas_myapp/www/app.js <<'EOF'
async function getAppVersion() {
  const m = location.pathname.match(/^\/apps\/([^/]+)\/([^/]+)\//);
  if (m && m[2]) return decodeURIComponent(m[2]);

  for (const url of ["../manifest.json", "./manifest.json"]) {
    try {
      const r = await fetch(url, {
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });
      if (!r.ok) continue;
      const j = await r.json();
      const ver = j && typeof j.version === "string" ? j.version.trim() : "";
      if (ver) return ver;
    } catch (_) {}
  }

  return "";
}

(async () => {
  const el = document.getElementById("appVersion");
  const ver = await getAppVersion();
  if (el && ver) el.textContent = `v${ver}`;
})();
EOF
```

Create a simple desktop icon:

```bash
cat > /tmp/pqnas_myapp/www/icon.svg <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect x="8" y="8" width="48" height="48" rx="14" fill="#222"/>
  <circle cx="32" cy="32" r="14" fill="#ff9f1c"/>
</svg>
EOF
```

Create a simple sidebar mask icon:

```bash
cat > /tmp/pqnas_myapp/www/nav_icon.svg <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <g fill="none" stroke="#000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <rect x="4" y="4" width="16" height="16" rx="3"/>
    <path d="M8 12h8"/>
    <path d="M12 8v8"/>
  </g>
</svg>
EOF
```

Zip it:

```bash
cd /tmp/pqnas_myapp
zip -r myapp-1.0.0.zip manifest.json www
```

Then upload/install via the current Admin → Apps manager.

---

## 15) Identity/session API apps commonly use

### Identity/session

```text
GET /api/v4/me
```

Typical use:

- confirm session is valid
- get fingerprint
- get role
- get storage state

Typical response fields may include:

```text
ok
fingerprint_hex
role
storage_state
exp
```

Apps should handle:

```text
401 = not signed in
403 = signed in but blocked / disabled / not allowed
```

User-disabled UX should be friendly. If a user is disabled/pending approval, the UI should clearly say they must wait for admin approval rather than showing a vague failure.

---

## 16) Apps / desktop APIs commonly used

### Admin app manager

```text
GET  /api/v4/apps
POST /api/v4/apps/upload_install
POST /api/v4/apps/uninstall
POST /api/v4/apps/launch_policy
```

### Shell / desktop list

```text
GET /api/v4/apps/list
```

### App existence check

```text
GET /api/v4/apps/has?id=<appId>
```

---

## 17) File APIs apps commonly use

Apps still use the normal PQ-NAS file APIs.

### Upload/download / archive

```text
PUT  /api/v4/files/put
GET  /api/v4/files/get
POST /api/v4/files/zip
POST /api/v4/files/zip_sel
```

### Browse / inspect

```text
GET  /api/v4/files/list
POST /api/v4/files/tree
POST /api/v4/files/search
POST /api/v4/files/exists
POST /api/v4/files/du
POST /api/v4/files/hash
POST /api/v4/files/cat
POST /api/v4/files/touch
POST /api/v4/files/save_text
GET  /api/v4/files/stat
POST /api/v4/files/stat
POST /api/v4/files/stat_sel
```

### Mutations

```text
POST   /api/v4/files/mkdir
POST   /api/v4/files/rmdir
POST   /api/v4/files/rmrf
DELETE /api/v4/files/delete
POST   /api/v4/files/move
POST   /api/v4/files/copy
```

### Trash

Current delete UX should prefer moving files to trash where applicable.

Trash endpoints include:

```text
GET  /api/v4/trash/list
POST /api/v4/trash/restore
POST /api/v4/trash/purge
```

Apps that delete files should use the current server-supported delete/trash behavior and should not permanently remove files unless the user clearly requests purge/permanent delete.

### Storage assumptions

All file APIs assume:

- cookie auth
- user-root confinement
- storage allocation present
- server-side path validation
- server-side audit logging

### `stat` notes

`/api/v4/files/stat` returns metadata about a file or directory.

Typical fields may include:

Common:

```text
ok
path
path_norm
name
type
exists
mode_octal
mtime_epoch
```

File only:

```text
bytes
mime
is_text
```

Directory only:

```text
children.files
children.dirs
children.other
bytes_recursive
recursive_scanned_entries
recursive_complete
scan_cap
time_cap_ms
```

---

## 18) Shares / public links APIs

### Authenticated share management

```text
POST /api/v4/shares/create
POST /api/v4/shares/revoke
GET  /api/v4/shares/list
```

Typical create body:

```json
{
  "path": "<rel>",
  "expires_sec": 86400
}
```

Typical list response contains entries like:

```text
token
url
owner_fp
path
type
created_at
expires_at
downloads
```

### Public share URL

```text
GET /s/<token>
```

Behavior:

- file token downloads the file
- directory token may return a zip
- expired token should return `410`
- server should not leak unnecessary internal details

### App-side share badge pattern

If your app wants shared badges:

1. load `GET /api/v4/shares/list`
2. build a map keyed by path or type+path
3. overlay a share badge in your grid/list
4. refresh after create/revoke

### Move/rename warning

If an app supports moving files/folders, and a moved item is shared, the app should warn:

```text
This item has active share links. Moving it may break existing share URLs.
```

For folders, the app should check whether any shared file exists inside the folder and warn accordingly.

This applies to normal shares and PQ shares where supported.

---

## 19) PQ shares / secure share manager

PQ share flows exist in the tree, and Shares Manager may distinguish:

- normal shares
- PQ shares
- recipient / invite-based secure share flows

If your app needs PQ-share-specific behavior, inspect the current route set in your branch.

Relevant static files may include:

```text
share_pq_mlkem.js
share_pq_keys.js
share_pq_invite.js
share_pq_open.js
share_pq_unlock_modal.js
```

Relevant backend code may include PQ share manifest handling and secure share routes.

Do not assume normal public share token behavior is the same as PQ share behavior.

---

## 20) Drop Zone APIs

Drop Zone is a one-way public upload-link app.

Typical manifest:

```json
{
  "id": "dropzone",
  "name": "Drop Zone",
  "version": "1.0.0",
  "entry": "www/index.html",
  "api_base": "/api/v4/dropzones",
  "permissions": [],
  "category": "sharing"
}
```

Admin/authenticated Drop Zone management routes live under:

```text
/api/v4/dropzones
```

Drop Zone concepts:

- one-way upload page/link
- optional password
- expiry
- max file size
- max total upload
- user-defined destination folder
- uploaded files appear in File Manager

Drop Zone should usually be:

```json
"surfaces": {
  "desktop": {
    "enabled": true
  },
  "launcher": {
    "enabled": true
  },
  "sidebar": {
    "enabled": false,
    "user_pinnable": true,
    "section": "sharing",
    "label": "Drop Zone",
    "order": 80
  }
}
```

Reason:

```text
Drop Zone is a utility app. It should be reachable from desktop/launcher, but should not clutter the left sidebar by default.
```

---

## 21) Echo Stack APIs

Echo Stack is the bookmarks/link vault/read-it-later/archive app.

Typical manifest:

```json
{
  "id": "echostack",
  "name": "Echo Stack",
  "version": "1.0.0",
  "entry": "www/index.html",
  "api_base": "/api/v4/echostack",
  "permissions": [],
  "category": "knowledge"
}
```

Echo Stack concepts:

- save links
- tags
- collections
- notes
- page preview/archive metadata
- archived website snapshots

Important archive storage rule:

```text
Before archiving a page, the server must check the user’s storage quota using actual estimated/streamed archived bytes.
```

Web snapshots must not bypass quota or unexpectedly exceed quota.

Current archive hardening note:

```text
HTML archive can save/rewrite page HTML, images, and linked CSS well enough for many pages.
Future hardening should rewrite CSS url(...) assets too, especially background images and fonts.
```

---

## 22) Photo Gallery APIs

Photo Gallery uses file/gallery APIs for:

- browsing image folders
- thumbnail loading
- ratings
- tags
- notes
- albums
- shares
- EXIF/deep search
- map/GPS features where present
- burst grouping where present

Known gallery metadata endpoints include:

```text
GET  /api/v4/gallery/meta/get
POST /api/v4/gallery/meta/set
GET  /api/v4/gallery/thumb?path=...&size=...
```

Album endpoints may include:

```text
/api/v4/gallery/albums/list
/api/v4/gallery/albums/create
/api/v4/gallery/albums/items
/api/v4/gallery/albums/add
/api/v4/gallery/albums/remove
/api/v4/gallery/albums/set_cover
```

Photo Gallery may also call:

```text
GET /api/v4/shares/list
```

to show share badges or public share links.

---

## 23) File Manager app notes

File Manager is a primary app and should normally be shown in the sidebar.

Typical surfaces:

```json
"surfaces": {
  "desktop": {
    "enabled": true
  },
  "launcher": {
    "enabled": true
  },
  "sidebar": {
    "enabled": true,
    "user_pinnable": true,
    "section": "primary",
    "label": "File Manager",
    "order": 10
  }
}
```

File Manager commonly uses broad `/api/v4/files/...` routes, shares routes, trash routes, zip routes, and workspace-aware routes where present.

Major File Manager features should avoid bloating one monolithic JS file when a separate module is cleaner.

---

## 24) NeonWave app notes

NeonWave is the music/audio library app.

Typical category:

```json
"category": "media"
```

NeonWave uses file APIs to browse music folders and play audio files through browser media APIs.

NeonWave may use:

- scanned track state
- playlists in browser storage
- favorites
- media session handlers
- sleep timer
- audio metadata
- cover art detection

It should display version in the subtitle area.

---

## 25) Storage Manager / RAID Manager app notes

Storage Manager is currently app id:

```text
raidmgr
```

Display name:

```text
Storage Manager
```

Typical category:

```json
"category": "system"
```

It is a primary/admin-ish storage management app and may be visible to admins or selected users depending on policy.

Storage Manager uses storage/pool/admin routes and must treat destructive operations carefully.

---

## 26) Snapshot Manager app notes

Snapshot Manager current version is:

```text
1.0.1
```

It should display:

```text
Snapshot Manager v1.0.1
```

Snapshot Manager interacts with Btrfs snapshot configuration and restore flows.

Snapshot Manager may need sudo-backed server operations, but browser app code must not assume direct system access.

---

## 27) Security notes

Apps are not sandboxed yet.

### File APIs must enforce

- cookie auth
- user root confinement
- workspace confinement where applicable
- storage allocation requirement
- strict path validation
- symlink rejection where applicable
- server-side audit logging

### Static serving must enforce

- no traversal escapes
- correct content type
- `X-Content-Type-Options: nosniff`
- sensible `Cache-Control`, especially during development and on sensitive pages

### Shares must enforce

- no traversal through stored share paths
- expired tokens return `410`
- avoid leaking internal path existence unnecessarily
- tokens should not expose unnecessary internal metadata

### Drop Zone must enforce

- upload path confinement
- expiry
- optional password validation where enabled
- per-file size limits
- total upload limits
- quota checks based on actual streamed bytes
- no browse/download/delete capability for public uploaders

### App launch policy must remain server-owned

Launch behavior and admin-only visibility should stay in server config, not inside app bundles, so admins can change policy without repackaging apps.

Manifest metadata is display/organization metadata, not a security boundary.

---

## 28) Versioning rules

- use semantic-ish versions like `1.0.0`
- bump versions when shipping meaningful changes
- uninstall same version before reinstalling if required by the current flow
- do not commit runtime `apps/installed` state
- apps can infer their own version from URL:

```text
/apps/<id>/<version>/...
```

Example:

```text
/apps/dropzone/1.0.0/www/index.html
```

Apps should display version from URL or manifest, not hardcoded strings.

---

## 29) Practical guidance for app authors

Prefer these rules:

- keep app bundles small and static
- include `manifest.json`
- include `www/index.html`
- include `www/icon.svg`
- include `www/nav_icon.svg`
- do not assume a writable app directory
- treat manifest metadata as display metadata, not security policy
- always handle `401` and `403`
- assume some users may open the app embedded and others detached
- do not hardcode repo-local absolute paths
- do not assume bundled and installed roots are the same
- do not make every small app appear in the sidebar by default
- use `surfaces.sidebar.enabled=false` for small utilities
- use `surfaces.sidebar.user_pinnable=true` if the app should be pinnable later
- prefer source changes under `apps/bundled/<id>/src`, then rebuild/reinstall

---

## 30) Troubleshooting

### App installed but old UI appears

Likely causes:

- browser cache
- static files copied to wrong runtime path
- app was edited in source but not reinstalled
- app was edited in installed runtime but source still differs

Check installed manifest:

```bash
sudo find /srv/pqnas/apps/installed -path '*/manifest.json' -print | sort
```

Check one app:

```bash
sudo jq . /srv/pqnas/apps/installed/echostack/1.0.0/manifest.json
```

### Uninstall fails with HTTP 500

Check audit log:

```bash
sudo grep -RIn "admin.apps_uninstall" /srv/pqnas/audit/pqnas_audit.jsonl | tail
```

If reason is permission denied, check ownership:

```bash
sudo namei -l /srv/pqnas/apps/installed/<appId>/<version>
sudo find /srv/pqnas/apps/installed/<appId> -maxdepth 3 \
  -printf '%M %u:%g %p\n' | sort | head -80
```

Fix ownership:

```bash
sudo chown -R pqnas:pqnas /srv/pqnas/apps/installed/<appId>
sudo chmod -R u+rwX,g+rX /srv/pqnas/apps/installed/<appId>
```

### Sidebar icons do not show

Check that installed app has:

```text
www/nav_icon.svg
```

Example:

```bash
curl -i http://127.0.0.1:8081/apps/echostack/1.0.0/www/nav_icon.svg | head
```

Expected:

```text
HTTP/1.1 200 OK
```

Check source and installed shell static files:

```bash
rg -n "shell_sidebar|shellSidebarCollapsed|appNavIcon|nav_icon" server/src/static
rg -n "shell_sidebar|shellSidebarCollapsed|appNavIcon|nav_icon" /opt/pqnas/static
```

Make sure `shell_sidebar.js` is installed:

```bash
sudo install -m 0644 -o pqnas -g pqnas \
  server/src/static/shell_sidebar.js \
  /opt/pqnas/static/shell_sidebar.js
```

### Browser reports loading failure for `shell_sidebar.js`

Install the file:

```bash
sudo install -m 0644 -o pqnas -g pqnas \
  server/src/static/shell_sidebar.js \
  /opt/pqnas/static/shell_sidebar.js
```

Then verify:

```bash
curl -i http://127.0.0.1:8081/static/shell_sidebar.js | head
```

---

## 31) TODO / future ideas

- real app permission model
- app signing
- app integrity verification
- admin allow/deny apps
- per-user app installs
- user-pinnable sidebar apps
- app launcher/catalog UI
- better app registry UI
- user preferences for launch mode
- internal detached-window manager instead of browser popup windows
- manifest-declared preferred window hints if needed later
- tighter app-to-shell integration
- app update/upgrade flow without manual uninstall
- duplicate app id/version guardrails
- better install conflict messages
- better uninstall error messages
- cleanup old runtime install ownership problems automatically where safe