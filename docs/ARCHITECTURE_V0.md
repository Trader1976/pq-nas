# PQ-NAS v0 Architecture

PQ-NAS v0 is an identity-first personal storage server. It focuses on a secure access layer and minimal file operations, using DNA identity and device-mediated QR authentication instead of passwords.

The goal of v0 is to prove an end-to-end flow:
**browser → QR → phone approval → post-quantum-capable signature verification → authorized file access**.

This is intentionally not a full NAS replacement yet.

---

## Goals

PQ-NAS v0 must provide:

- QR-code login from a browser without usernames/passwords
- Device-mediated approval in DNA-Messenger
- Stateless verification option (server does not need sticky sessions)
- Identity-based authorization (DNA fingerprint → policy)
- Minimal file access operations (list, download, upload)
- Auditable security events (append-only style log)

---

## Non-Goals (v0)

Explicitly out of scope for v0:

- RAID management UI, snapshots UI, quotas UI
- Multi-user enterprise features (groups/roles/SSO)
- Sync/replication/DHT distribution
- WebDAV/S3 compatibility (maybe later)
- Full “OS-as-a-NAS” appliance experience

---

## Components

### 1) pq-nas-core (daemon)
A local service responsible for file operations and policy enforcement.

Responsibilities:
- Serve a restricted filesystem root (configured “share roots”)
- Enforce authorization checks per request
- Produce security audit events (login approvals, denials, file access)
- Provide a stable local API for the web UI

Recommended interface:
- HTTP on localhost (or unix socket), JSON for control + streaming for downloads

Key rule:
- The web UI must not directly access the filesystem. Only pq-nas-core does.

---

### 2) pq-nas-web (UI + public endpoints)
The user-facing web UI and the entry point for browser traffic.

Responsibilities:
- Render login page with QR code
- Poll for login completion
- On success: provide a minimal file browser UI
- Proxy authenticated file operations to pq-nas-core

Notes:
- v0 can be a simple server-rendered UI (FastAPI/Flask/Node) or static UI + small API.
- Keep this thin. The security and permissions belong in pq-nas-core.

---

### 3) dna-verify (signature verification module)
A verification module used by pq-nas-web (and/or pq-nas-core).

Responsibilities:
- Validate DNA-Messenger approvals:
  - signature verification (post-quantum capable)
  - challenge/nonce freshness
  - binding between fingerprint and presented public key
- Provide a single “verifyApproval(payload) -> decision” function

Implementation notes:
- Can reuse your existing PQClean-backed verifier approach.
- Keep the verification code as close to “pure verification” as possible:
  - deterministic validation rules
  - no UI concerns
  - no filesystem access

---

## Data Model (v0)

### Identity
- **DNA Fingerprint**: primary identity identifier (e.g., SHA3-512 hex)
- Optional metadata:
  - nickname
  - enrollment date
  - allowed roots (shares)

Identity is referenced by fingerprint in logs and policies.

### Policies
Policy is a mapping:
- fingerprint → permissions

v0 permissions:
- allowed share roots (paths)
- read-only vs read-write

Policies should be stored in a simple file:
- `config/policies.json`

Example shape (illustrative):
- fingerprint: allow read-write to `/data/share1`, read-only to `/data/share2`

---

## Authentication Flow (QR Login)

v0 uses device-mediated authentication:

1. Browser opens PQ-NAS URL
2. pq-nas-web creates a short-lived login request:
   - `session_id`
   - `challenge` (random)
   - `expires_at`
   - `origin` (domain/host)
3. pq-nas-web renders a QR code encoding the request
4. DNA-Messenger scans, shows details (domain, request), user approves
5. DNA-Messenger returns an approval payload to pq-nas-web:
   - fingerprint
   - public key (or reference)
   - signature over canonical payload (incl. challenge)
   - timestamp / expiry
6. pq-nas-web calls dna-verify to validate:
   - signature correct
   - challenge matches and not expired
   - fingerprint ↔ public key binding is valid
7. pq-nas-web issues a browser session token (short TTL)
8. File UI loads using that token

### Stateless Verification Mode (optional in v0)
Instead of storing server-side session state, pq-nas-web can encode `session_id + challenge + expiry + origin` into a signed token (server-signed).

- QR carries this signed token
- Approval references it
- Verification nodes can validate it without DB/session storage

This enables scaling later (CDN-style verification), but is optional for v0.

---

## Browser Session Model (v0)

After approval, the browser receives an access token.

Requirements:
- short TTL (e.g., 15–60 minutes)
- bound to fingerprint
- includes minimal claims:
  - fingerprint
  - allowed permissions
  - expiry
- revocable by rotation (signing key change) in v0

Implementation options:
- Signed JWT-like token (server-signed)
- Opaque token stored in a local map (simpler, not stateless)

Preferred for v0:
- Start with an opaque token map (simple)
- Move to signed tokens once flows are stable

---

## File Operations (v0)

Supported operations:
- List directory (under allowed roots)
- Download file
- Upload file (optional but recommended)
- Create folder (optional)

Rules:
- All paths must be resolved safely:
  - normalize and reject traversal (`..`, symlinks escaping root)
  - enforce allowed root prefixes
- Prefer streaming for downloads/uploads
- Limit upload size (configurable)

---

## Security Boundaries

### Trust boundaries
- Browser is untrusted
- Web UI is semi-trusted but must not bypass policy
- pq-nas-core is the authority on filesystem and permissions
- DNA-Messenger is the user’s trust anchor for approvals

### Required protections
- Strict input validation for all paths
- Canonical message format for signatures
- Short-lived challenges (replay resistance)
- Rate limiting on login endpoints
- Audit logging of all decisions and sensitive operations

---

## Audit Logging (v0)

v0 should log security-relevant events:

- login_requested
- login_approved
- login_denied
- login_expired
- file_list
- file_download
- file_upload
- policy_denied

Minimum fields:
- timestamp (ISO-8601)
- event type
- fingerprint (if known)
- session_id (or request id)
- request metadata (IP, user agent where applicable)

Optional enhancement:
- hash chaining (append-only tamper evidence)

---

## Deployment Model (v0)

Recommended deployment:

- pq-nas-core running locally as a systemd service
- pq-nas-web behind nginx (TLS termination)
- Optional:
  - Cloudflare Tunnel for remote access without port forwarding
  - allowlist of origins/domains in config

Keep v0 deployment boring and reliable.

---

## Future (v1+)

Not required for v0, but v0 should avoid blocking these:

- Multi-device approvals / delegated sessions
- PQ-SSH bridge: “Open terminal” from PQ-NAS after QR login
- Multiple shares, per-share permissions UI
- Stateless verification nodes (CDN-scale)
- Replication / DHT distribution of encrypted blobs
- Hardware-backed key storage on phone

---

## Repo Structure (suggested)

- `docs/`
  - `ARCHITECTURE_V0.md`
- `core/` (pq-nas-core)
- `web/` (pq-nas-web)
- `verify/` (dna-verify module)
- `config/`
  - `policies.json`
  - `settings.example.json`
- `scripts/`
- `deploy/`
  - `systemd/`
  - `nginx/`

---

## Definition of “Done” for v0

v0 is complete when:

- A browser can open PQ-NAS and see a QR login
- DNA-Messenger approval grants access without passwords
- Authorization is enforced by fingerprint-based policy
- User can list and download a file from an allowed share
- All security events are logged
