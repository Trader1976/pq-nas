# PQ-NAS Apps (Bundling + Install) — Developer Notes

This document is for **PQ-NAS developers** and **app authors**. It describes:

- App package format (zip)
- Where apps live on disk after install
- How to bundle and install apps
- Current server endpoints (“app manager” + file APIs) available to apps

> Status: early, “static web app in a zip” model. No sandboxing beyond path-based restrictions yet.

---

## 1) App model (today)

An “app” is a **static web bundle**:

- HTML/CSS/JS
- icons/images/fonts/etc.
- a `manifest.json`

PQ-NAS installs the zip under an “installed apps” directory and serves it at:

`/apps/<id>/<version>/www/...`

Apps run in the browser and call PQ-NAS APIs via `fetch()` (cookie-based auth).

---

## 2) Directory layout

### Repo layout (source tree)

Bundled zips shipped with PQ-NAS live in:

```
apps/bundled/<appId>/<appId>-<version>.zip
```

Installed apps live in:

```
apps/installed/<appId>/<version>/
  manifest.json
  www/
    index.html
    app.js
    icons/
    ...
```

> Note: In development you may also see absolute paths in API responses depending on build; the server tries to return repo-relative paths where possible.

---

## 3) Zip package format (required)

Your zip **must** contain at minimum:

```
manifest.json
www/index.html
```

Typical structure:

```
myapp-0.1.0.zip
  manifest.json
  www/
    index.html
    app.js
    icons/
      file.png
      folder.png
      updir_small.png
    css/
    img/
```

### manifest.json (current fields)

Example:

```json
{
  "id": "filemgr",
  "name": "File Manager",
  "version": "0.1.0",
  "entry": "www/index.html",
  "api_base": "/api/v4/files",
  "permissions": []
}
```

Notes:

- id must match the app folder and install request id.
- version is used as the install directory name.
- entry is informational today (we currently serve /www/index.html directly).
- api_base and permissions are informational today (future use).

---

## 4) Bundling an app zip (example)

Create a working directory:

```bash
mkdir -p /tmp/pqnas_myapp/www
```

Put your files there:

```bash
cat > /tmp/pqnas_myapp/manifest.json <<'EOF'
{
  "id": "myapp",
  "name": "My App",
  "version": "0.1.0",
  "entry": "www/index.html",
  "api_base": "/api/v4/files",
  "permissions": []
}
EOF

cat > /tmp/pqnas_myapp/www/index.html <<'EOF'
<!doctype html>
<html>
<head><meta charset="utf-8"><title>My App</title></head>
<body>
  <h1>My App</h1>
  <script src="./app.js"></script>
</body>
</html>
EOF

cat > /tmp/pqnas_myapp/www/app.js <<'EOF'
console.log("hello from myapp");
EOF
```

Build the zip into the PQ-NAS repo bundled directory:

```bash
mkdir -p apps/bundled/myapp
(cd /tmp/pqnas_myapp && zip -r "$OLDPWD/apps/bundled/myapp/myapp-0.1.0.zip" .)
```

---

## 5) Listing bundled and installed apps

Endpoint:

- GET /api/v4/apps

---

## 6) Installing a bundled app

Endpoint:

- POST /api/v4/apps/install_bundled
  JSON body: { "id": "<appId>", "zip": "<zipFileName>" }

Example:

```bash
curl -s -X POST http://127.0.0.1:8081/api/v4/apps/install_bundled \
  -H 'Content-Type: application/json' \
  -d '{"id":"filemgr","zip":"filemgr-0.1.0.zip"}' | jq .
```

Notes:

- Server installs into apps/installed/<id>/<version>/
- If that version already exists, install returns a conflict (remove first).

---

## 7) Uninstalling an installed version

Endpoint:

- POST /api/v4/apps/uninstall
  JSON body: { "id": "<appId>", "version": "<version>" }

Example:

```bash
curl -s -X POST http://127.0.0.1:8081/api/v4/apps/uninstall \
  -H 'Content-Type: application/json' \
  -d '{"id":"filemgr","version":"0.1.0"}' | jq .
```

---

## 8) Serving an installed app (URL)

Once installed, files are reachable at:

- /apps/<id>/<version>/www/index.html
- /apps/<id>/<version>/www/app.js
- /apps/<id>/<version>/www/icons/...

Example:

```bash
curl -i http://127.0.0.1:8081/apps/filemgr/0.1.0/www/index.html | head
```

---

## 9) Editing apps during development

Quick rule:

- If you edit files under apps/installed/..., you are editing the installed copy.
- If you edit /tmp/..., you are editing a staging folder (nothing changes until you re-zip and re-install).

Recommended workflow:

1. Edit in a working folder (/tmp/pqnas_myapp/... or a real repo folder)
2. Zip → apps/bundled/<id>/<id>-<ver>.zip
3. Uninstall old version
4. Install new version

---

## 10) API endpoints apps can use (current)

Apps run in the user’s browser and can call PQ-NAS endpoints with:

```js
fetch("/api/v4/...", { credentials: "include", cache: "no-store" })
```

### Identity/session

- GET /api/v4/me

Returns { ok, fingerprint_hex, role, exp, ... } when signed in.

### Apps (app manager)

- GET /api/v4/apps
- POST /api/v4/apps/install_bundled
- POST /api/v4/apps/uninstall

### File manager APIs (user-scoped)

All file operations are scoped to:

build/bin/data/users/<fingerprint>/

Current endpoints:

PUT  /api/v4/files/put  
GET  /api/v4/files/get  
POST /api/v4/files/zip

Browse / inspect:

GET  /api/v4/files/list  
POST /api/v4/files/tree  
POST /api/v4/files/search  
POST /api/v4/files/exists  
POST /api/v4/files/du  
POST /api/v4/files/hash  
POST /api/v4/files/cat  
POST /api/v4/files/touch  
POST /api/v4/files/save_text

Mutations:

POST   /api/v4/files/mkdir  
POST   /api/v4/files/rmdir  
POST   /api/v4/files/rmrf  
DELETE /api/v4/files/delete  
POST   /api/v4/files/move  
POST   /api/v4/files/copy

All assume:

- cookie auth
- storage allocated
- audit logging server-side

---

## 11) Security notes

Apps are not sandboxed yet.

File APIs must enforce:

- cookie auth
- user root confinement
- storage allocation requirement

Static serving must ensure:

- no traversal escapes
- correct content-type
- X-Content-Type-Options: nosniff
- Cache-Control: no-store during dev

---

## 12) Versioning rules

- Uninstall same version before reinstalling.
- Bump versions aggressively during dev.

---

## 13) TODO / future ideas

- App permissions model
- Admin allow/deny apps
- Per-user app installs
- App signing
- Built-in filemgr bundled
- App registry UI
