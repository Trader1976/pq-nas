# PQ-NAS Apps (Bundling + Install) — Developer Notes

This document is for **PQ-NAS developers** and **app authors**. It describes:

- the current app package format
- where apps live on disk
- how apps are installed and served
- how launch behavior currently works
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

`/apps/<id>/<version>/www/...`

Typical entry URL:

`/apps/<id>/<version>/www/index.html`

Apps run in the browser and call PQ-NAS APIs with:

```js
fetch("/api/v4/...", {
  credentials: "include",
  cache: "no-store"
})
```

Authentication is still based on the normal PQ-NAS session cookie.

---

## 2) Runtime roots and directory layout

PQ-NAS now resolves app paths **env-first**.

### Apps root

The server resolves the apps root like this:

1. `PQNAS_APPS_ROOT` environment variable
2. `/srv/pqnas/apps`
3. repo fallback in development (`<repo>/apps`)

From that root the server uses:

- `APPS_BUNDLED_DIR   = <apps_root>/bundled`
- `APPS_INSTALLED_DIR = <apps_root>/installed`
- `APPS_USERS_DIR     = <apps_root>/users`

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
    icons/
    img/
    ...
```

Example:

```text
/srv/pqnas/apps/installed/sharesmgr/1.0.0/
  manifest.json
  www/
    index.html
    app.js
    app.css
```

### Bundled apps

Bundled app zips are currently expected under:

```text
<apps_root>/bundled/<appId>/*.zip
```

Example:

```text
/srv/pqnas/apps/bundled/filemgr/filemgr-1.0.0.zip
/srv/pqnas/apps/bundled/sharesmgr/sharesmgr-1.0.0.zip
```

### Important repo note

`apps/installed/` is **runtime state** and must not be committed.

If development falls back to repo-local `apps/`, that is still treated as runtime/install state, not source-of-truth source code.

---

## 3) Zip package format (required)

Your zip **must** contain at minimum:

```text
manifest.json
www/index.html
```

Typical structure:

```text
myapp-0.1.0.zip
  manifest.json
  www/
    index.html
    app.js
    app.css
    icons/
      ...
    img/
      ...
```

If either `manifest.json` or `www/index.html` is missing, install should be treated as invalid.

---

## 4) `manifest.json` (current practical fields)

Example:

```json
{
  "id": "sharesmgr",
  "name": "Shares Manager",
  "version": "1.0.0",
  "entry": "www/index.html",
  "icons": {
    "win_classic": "www/share_win.png",
    "cpunk_orange": "www/share_ora.png",
    "dark": "www/share_dark.png",
    "bright": "www/share_bright.png",
    "default": "www/share_dark.png"
  },
  "api_base": "/api/v4/shares",
  "permissions": []
}
```

### Notes

- `id` must match the app folder/install identity.
- `version` is used as the install directory name.
- `entry` is informational today; current serving still expects `www/index.html`.
- `icons` is used by the desktop/app shell for per-theme icons.
- `name` is what the desktop/shell should prefer to display.
- `api_base` and `permissions` are informational today unless your own UI uses them.

### Current desktop icon behavior

The desktop/app shell tries to resolve icons from `manifest.json` using the current theme, typically preferring:

1. exact current theme key
2. mapped theme alias if applicable
3. `default`
4. first icon entry found
5. fallback to `www/icon.png`

---

## 5) Serving model

Once installed, files are reachable at URLs like:

- `/apps/<id>/<version>/www/index.html`
- `/apps/<id>/<version>/www/app.js`
- `/apps/<id>/<version>/manifest.json`

Example:

```bash
curl -i http://127.0.0.1:8081/apps/sharesmgr/1.0.0/www/index.html | head
```

Apps are still plain browser apps. There is no iframe-to-native bridge or separate app runtime.

---

## 6) Current install / uninstall flow

### List apps

Current admin/app-management UI uses:

- `GET /api/v4/apps`

This returns a JSON view of installed apps, and bundled zips for admin-only visibility.

Typical installed entry fields currently include:

- `id`
- `version`
- `root`
- `has_manifest`

Depending on UI path / server version, other endpoints may also exist for app-shell-friendly listing.

### Upload and install a zip

Current admin install flow uses:

- `POST /api/v4/apps/upload_install`

Request style:

- body = raw zip bytes
- `Content-Type: application/zip`
- `X-PQNAS-Filename: <original filename>`

Example:

```bash
curl -X POST http://127.0.0.1:8081/api/v4/apps/upload_install \
  -H 'Content-Type: application/zip' \
  -H 'X-PQNAS-Filename: sharesmgr-1.0.0.zip' \
  --data-binary @sharesmgr-1.0.0.zip
```

### Uninstall

- `POST /api/v4/apps/uninstall`

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

---

## 7) Launch behavior (embedded vs detached)

PQ-NAS now has a separate **app launch policy** concept.

### Important design rule

Launch behavior is **not stored inside app zips**.

It is stored separately in server config so it remains flexible even when the system later has many apps.

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
    "allow_user_override": true
  },
  "by_app_id": {
    "filemgr": {
      "default_launch": "detached",
      "window_profile": "large",
      "allow_user_override": false
    },
    "sharesmgr": {
      "default_launch": "embedded",
      "window_profile": "full",
      "allow_user_override": false
    }
  }
}
```

### Current supported values

`default_launch`:

- `auto`
- `embedded`
- `detached`

`window_profile`:

- `auto`
- `small`
- `normal`
- `large`
- `full`

`allow_user_override`:

- `true`
- `false`

### Meaning

- **embedded** = open inside the PQ-NAS app workspace
- **detached** = currently opens a real browser popup/window
- **auto** = let shell logic choose

### Current implementation note

“Detached” currently means a real browser window / popup via browser behavior, not a fake internal sub-window rendered inside the main workspace.

That may change later if PQ-NAS gets its own internal window manager model.

---

## 8) Development workflow

Recommended workflow:

1. build/edit the app in a working folder
2. make sure zip contains `manifest.json` + `www/index.html`
3. upload/install through the current app manager flow
4. refresh the PQ-NAS shell
5. uninstall old version if needed
6. bump version aggressively during development

### Practical rule

- If you edit files under `apps/installed/...`, you are editing the installed copy.
- If you edit a temp/dev folder, nothing changes until you install again.

---

## 9) Example minimal app bundle

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
  "version": "0.1.0",
  "entry": "www/index.html",
  "icons": {
    "dark": "www/icon_dark.png",
    "bright": "www/icon_bright.png",
    "default": "www/icon_dark.png"
  },
  "api_base": "/api/v4/files",
  "permissions": []
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
  <h1>My App</h1>
  <script src="./app.js"></script>
</body>
</html>
EOF
```

Create JS:

```bash
cat > /tmp/pqnas_myapp/www/app.js <<'EOF'
console.log("hello from myapp");
EOF
```

Zip it:

```bash
cd /tmp/pqnas_myapp
zip -r myapp-0.1.0.zip manifest.json www
```

Then upload/install via the current admin app manager flow.

---

## 10) Identity/session API apps commonly use

### Identity/session

- `GET /api/v4/me`

Typical use:

- confirm session is valid
- get fingerprint
- get role
- get storage state

Typical response shape includes fields like:

- `ok`
- `fingerprint_hex`
- `role`
- `storage_state`
- `exp`

Apps should handle:

- `401` = not signed in
- `403` = signed in but blocked / disabled / not allowed

---

## 11) Apps / desktop APIs commonly used

### App manager

- `GET /api/v4/apps`
- `POST /api/v4/apps/upload_install`
- `POST /api/v4/apps/uninstall`

### App shell / desktop list

Some shell code paths may use a list endpoint intended for installed apps and desktop rendering.  
Check your current server tree for the exact shape if you are wiring shell/app-launch UI.

---

## 12) File APIs apps commonly use

Apps still use the normal PQ-NAS file APIs.

### Upload/download / archive

- `PUT /api/v4/files/put`
- `GET /api/v4/files/get`
- `POST /api/v4/files/zip`
- `POST /api/v4/files/zip_sel` (if present in your tree)

### Browse / inspect

- `GET /api/v4/files/list`
- `POST /api/v4/files/tree`
- `POST /api/v4/files/search`
- `POST /api/v4/files/exists`
- `POST /api/v4/files/du`
- `POST /api/v4/files/hash`
- `POST /api/v4/files/cat`
- `POST /api/v4/files/touch`
- `POST /api/v4/files/save_text`
- `GET /api/v4/files/stat`
- `POST /api/v4/files/stat`
- `POST /api/v4/files/stat_sel`

### Mutations

- `POST /api/v4/files/mkdir`
- `POST /api/v4/files/rmdir`
- `POST /api/v4/files/rmrf`
- `DELETE /api/v4/files/delete`
- `POST /api/v4/files/move`
- `POST /api/v4/files/copy`

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

- `ok`
- `path`
- `path_norm`
- `name`
- `type`
- `exists`
- `mode_octal`
- `mtime_epoch`

File only:

- `bytes`
- `mime`
- `is_text`

Directory only:

- `children.files`
- `children.dirs`
- `children.other`
- `bytes_recursive`
- `recursive_scanned_entries`
- `recursive_complete`
- `scan_cap`
- `time_cap_ms`

---

## 13) Shares / public links APIs

### Authenticated share management

- `POST /api/v4/shares/create`
- `POST /api/v4/shares/revoke`
- `GET /api/v4/shares/list`

Typical create body:

```json
{
  "path": "<rel>",
  "expires_sec": 86400
}
```

Typical list response contains entries like:

- `token`
- `url`
- `owner_fp`
- `path`
- `type`
- `created_at`
- `expires_at`
- `downloads`

### Public share URL

- `GET /s/<token>`

Behavior:

- file token downloads the file
- directory token may return a zip
- expired token should return `410`
- should not leak unnecessary internal details

### App-side share badge pattern

If your app wants “shared” badges:

1. load `GET /api/v4/shares/list`
2. build a map keyed by path or type+path
3. overlay a share badge in your grid/list
4. refresh after create/revoke

### PQ shares / secure share manager

PQ share flows now also exist in the tree, and a dedicated shares manager UI may distinguish:

- normal shares
- PQ shares
- recipient / invite-based secure share flows

If your app needs PQ-share-specific behavior, inspect the current tree for the exact route set in your branch.

---

## 14) Security notes

Apps are not sandboxed yet.

### File APIs must enforce

- cookie auth
- user root confinement
- storage allocation requirement
- strict path validation
- symlink rejection where applicable

### Static serving must enforce

- no traversal escapes
- correct content type
- `X-Content-Type-Options: nosniff`
- sensible `Cache-Control` behavior, especially during development and on sensitive pages

### Shares must enforce

- no traversal through stored share paths
- expired tokens return `410`
- avoid leaking internal path existence unnecessarily

### App launch policy must remain server-owned

Launch behavior should stay in server config, not inside app bundles, so admins can change policy without repackaging apps and so future installations with many apps remain manageable.

---

## 15) Versioning rules

- uninstall same version before reinstalling when required by your current server flow
- bump versions aggressively during development
- apps can infer their own version from URL:

```text
/apps/<id>/<version>/...
```

---

## 16) Practical guidance for app authors

Prefer these rules:

- keep app bundles small and static
- do not assume a writable app directory
- treat manifest metadata as display metadata, not security policy
- always handle `401` and `403`
- assume some users may open the app embedded and others detached
- do not hardcode repo-local absolute paths
- do not assume bundled and installed roots are the same

---

## 17) TODO / future ideas

- app permission model
- admin allow/deny apps
- per-user app installs
- app signing
- better app registry UI
- user preferences for launch mode
- internal detached-window manager instead of browser popup windows
- manifest-declared preferred window hints if needed later
- tighter app-to-shell integration
```