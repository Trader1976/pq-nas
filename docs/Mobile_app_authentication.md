# PQ-NAS Authentication & Trusted Device Pairing Workflow

## Overview

PQ-NAS currently supports two related mobile/app authentication flows:

1. **Legacy v5 app login flow**
    - Server issues a login session
    - UI shows a QR code
    - External app scans it
    - Server approval is polled
    - App consumes approval and receives bearer tokens

2. **Trusted device pairing flow** *(new)*
    - Already authenticated PQ-NAS user opens **Trusted Devices**
    - PQ-NAS shows a pairing QR code
    - PQ-NAS Android app scans the QR
    - User confirms pairing in the app
    - Server issues app bearer tokens and creates a trusted device entry

The new pairing flow is the preferred model for PQ-NAS mobile app onboarding because it is more explicit, safer, and fits the trusted-device concept better.

---

## Core identity model

PQ-NAS user storage and authorization are fundamentally tied to the user's:

- `fingerprint_hex`
- `role` (`admin` or `user`)

The Android app does **not** resolve user files by filesystem path itself.

Instead:

1. The app stores the bearer tokens returned by PQ-NAS
2. The app sends `Authorization: Bearer <access_token>`
3. Server verifies the bearer token
4. Server resolves:
    - `fingerprint_hex`
    - `role`
    - `device_id`
5. Server serves files for that fingerprint

This means the server remains authoritative for file access and storage mapping.

---

## Existing app token model

Trusted mobile devices use app bearer auth backed by `AppTokenStore`.

### Stored device/session concepts

- `TrustedAppDevice`
- `AppAccessSession`
- `AppRefreshSession`

### Important fields

#### TrustedAppDevice
- `device_id`
- `fingerprint_hex`
- `role`
- `platform`
- `device_name`
- `app_version`
- `created_at`
- `last_seen_at`
- `last_ip`
- `revoked`

#### Access token session
- short-lived bearer token
- currently 15 minutes

#### Refresh token session
- long-lived refresh token
- currently 30 days

### Main token operations
- mint trusted device + tokens from approved fingerprint
- verify access token
- refresh access token
- revoke device
- list devices for fingerprint

---

## Legacy v5 app login flow

This flow is implemented in `routes_v5.cc` and is based around short-lived QR login sessions.

### Route summary

#### `POST /api/v5/session`
Issues a signed request token and correlation key.

Response includes:
- `sid`
- `st`
- `k`
- `iat`
- `exp`
- `qr_svg`

#### `GET /api/v5/qr.svg?st=...`
Returns QR SVG for login flow.

QR payload format:

```text
dna://auth?v=5&st=...&origin=...&app=PQ-NAS

GET /api/v5/status
POST /api/v5/status

Checks whether login request is:

pending
approved
missing
POST /api/v5/consume

Consumes approved login and sets session cookie.

POST /api/v5/consume_app

Consumes approved login and returns app bearer tokens instead of cookie.

POST /api/v5/token/refresh

Refreshes app access token using refresh token + device id.

Notes

This flow remains useful as a compatibility path, but it is not the clearest trusted-device UX for PQ-NAS mobile onboarding.

New trusted-device pairing flow

This is the preferred PQ-NAS mobile onboarding flow.

Security model

Pairing is initiated only by an already authenticated PQ-NAS user in the web UI.

That means:

only a signed-in PQ-NAS user can start pairing
both normal users and admins can pair their own mobile device
pairing token is short-lived
pairing token is single-use
mobile app still requires explicit confirmation
UX flow
Web side
User is already logged in to PQ-NAS web UI
User opens Trusted Devices
User clicks Pair New Device
PQ-NAS creates a short-lived pairing session
PQ-NAS shows pairing QR code
Android side
User opens PQ-NAS Android app
User chooses Scan pairing QR
App scans PQ-NAS pairing QR
App parses pairing payload
App shows confirmation screen with:
server origin
app name
editable device name
User confirms pairing
App calls pairing consume endpoint
Server mints trusted device + tokens
App stores:
baseUrl
access_token
refresh_token
device_id
fingerprint_hex
role
App proceeds to file view
Web side after success
PQ-NAS polls pairing status
UI updates to show:
pairing consumed
paired device id
Pairing QR payload

The new dedicated pairing QR type is:

dna://pair?v=1&pt=<pair_token>&origin=<origin>&app=PQ-NAS
Fields
v
pairing payload version
pt
short-lived pairing token
origin
PQ-NAS server origin
app
display app name, currently PQ-NAS
Why separate dna://pair exists

A dedicated QR type is clearer than overloading the older auth QR flow.

Benefits:

clearer semantics
easier Android parsing
easier future extension
cleaner separation from browser login/session workflows
Pairing server module
Files
server/include/app_pairing.h
server/src/app_pairing.cpp
Responsibility

This module owns short-lived pairing session logic.

It is intentionally:

in-memory only
single-use
short-lived
separate from long-lived trusted device/token storage
Main structure
AppPairingSession

Contains:

pair_id
pair_token
fingerprint_hex
role
issued_at
expires_at
consumed
consumed_at
consumed_device_id
AppPairingStore

Responsibilities:

start pairing session
retrieve by pair_id
retrieve by pair_token
consume pair token
mark consumed device
prune expired sessions
build pairing QR URI
Current storage model

Pairing sessions are in memory only.

This is acceptable for v1 because:

pairing sessions are short-lived
tokens are one-time use
server restart can safely invalidate outstanding pairing requests
Pairing API routes

Implemented in routes_v5.cc.

POST /api/v5/app_pair/start

Starts a pairing session for the currently authenticated cookie user.

Auth:

requires normal PQ-NAS session cookie
available to both admin and user

Response:

{
  "ok": true,
  "pair_id": "...",
  "expires_at": 1775000000,
  "qr_uri": "dna://pair?v=1&pt=...&origin=...&app=PQ-NAS",
  "qr_svg": "/api/v5/app_pair/qr.svg?pt=..."
}
GET /api/v5/app_pair/qr.svg?pt=...

Returns QR SVG for pairing flow.

Behavior:

builds dna://pair?...
renders SVG QR
response is image/svg+xml
GET /api/v5/app_pair/status?pair_id=...

Returns pairing state.

States:

pending
consumed
expired
missing

Example pending:

{
  "ok": true,
  "state": "pending",
  "pair_id": "...",
  "expires_at": 1775000000
}

Example consumed:

{
  "ok": true,
  "state": "consumed",
  "pair_id": "...",
  "device_id": "..."
}
POST /api/v5/app_pair/consume

Consumes a pairing token and mints trusted app tokens.

Request:

{
  "pair_token": "...",
  "device_name": "Timo Android",
  "platform": "android",
  "app_version": "0.1.0"
}

Response:

{
  "ok": true,
  "token_type": "Bearer",
  "access_token": "...",
  "expires_in": 900,
  "refresh_token": "...",
  "refresh_expires_in": 2592000,
  "device_id": "...",
  "fingerprint_hex": "...",
  "role": "user"
}
Important consume behavior
pairing token must exist
pairing token must not be expired
pairing token must not already be consumed
token is single-use
trusted device is created by reusing existing app token minting logic
Reuse of existing app token minting

The pairing flow does not invent a second app-token system.

Instead, pairing consume reuses the existing trusted app minting path:

AppTokenStore::mint_from_approved_fingerprint(...)

This is important because it keeps:

one source of truth for app bearer tokens
one trusted device model
one refresh token model
one access-token verification path
Web UI integration
Location

Regular user shell:

server/src/static/app.html
server/src/static/app.js
Why it is in /app

This feature must be available to:

admins
normal users

So it belongs in the normal signed-in app shell, not admin-only UI.

Current UX

Left navigation now includes:

Trusted Devices

Current Trusted Devices page supports:

Pair New Device
Clear
QR display
pairing status polling
success message after consumption
Current status behavior

After starting pairing:

page polls /api/v5/app_pair/status
updates UI automatically
shows paired device id on success
Android app integration
Current Android app screens
ServerSetupScreen
QrLoginScreen (legacy path)
ScanPairQrScreen
PairConfirmScreen
FilesScreen
Current Android auth storage

TokenStore stores:

baseUrl
accessToken
refreshToken
deviceId
fingerprintHex
role
Current Android pairing flow
User enters/selects PQ-NAS server
User chooses Scan pairing QR
App scans QR code
App parses dna://pair
App displays confirmation
App calls /api/v5/app_pair/consume
App stores tokens and identity metadata
App opens file view
Pair QR parsing

Android parses:

dna://pair?v=1&pt=...&origin=...&app=PQ-NAS

Extracted fields:

version
pair token
origin
app name
Important Android behavior

The Android app does not need to understand PQ-NAS storage layout.

After pairing, it just uses bearer auth against routes like:

/api/v4/files/list
Current tested behavior

The following have been tested successfully:

Pairing backend
POST /api/v5/app_pair/start
GET /api/v5/app_pair/status
POST /api/v5/app_pair/consume
One-time token protection

Second consume attempt correctly fails with:

pair_token_already_consumed
Bearer auth after pair

Access token returned by pairing flow successfully works against:

/api/v4/files/list
Web UX
QR shown in Trusted Devices page
status updates from pending to consumed
paired device id shown after success
Android UX
app scans PQ-NAS pairing QR
pairing completes
app gains access
Important invariants
Identity invariant

All app file access is resolved server-side from:

verified bearer token
token-associated fingerprint
Pairing invariant

A pairing token:

is short-lived
is one-time use
belongs to one already authenticated PQ-NAS user
cannot be consumed twice
Token invariant

Trusted device app tokens are always minted through the existing app token system, not a separate pairing-only token system.

UI availability invariant

Trusted device pairing is available to:

enabled admins
enabled normal users
Current limitations / v1 choices
In-memory pairing store

Pairing sessions are not persisted.
If server restarts:

outstanding pairing QR sessions are lost

This is acceptable for v1.

No device list in regular user UI yet

Trusted Devices page currently supports pairing flow, but not full listing/revoke UI yet.

No revoke flow in Android app yet

Device management remains server-side.

Legacy QR login still exists

The old QR login flow still remains for compatibility/testing.

Recommended next steps
Server/web
Add trusted device list to regular user UI
Add revoke device action
Show:
device name
platform
created at
last seen
Add audits for pairing start/consume if not already present
Android
Add better scan UX polish
Add logout
Add file browser navigation improvements
Add paired device display in app settings
Future hardening
Consider hashing pair_token in memory
Consider durable pairing session storage only if needed
Add richer device metadata
Add explicit revoke/rename flows
Summary

PQ-NAS now supports a proper trusted-device pairing workflow:

initiated from an already authenticated PQ-NAS web session
encoded as dedicated dna://pair QR payload
consumed by PQ-NAS Android app
backed by existing trusted app token system
resolved server-side to fingerprint-based storage access

This provides a clean and secure mobile onboarding path for both admins and normal users.
