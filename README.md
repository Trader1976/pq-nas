
<img width="1174" height="757" alt="Pasted image" src="https://github.com/user-attachments/assets/521c5a73-6457-44de-8de5-1cb646ed757c" />

<img width="1174" height="757" alt="Pasted image (2)" src="https://github.com/user-attachments/assets/7ee1f614-e2ed-4685-855f-069e5da07dd8" />

# PQ-NAS

## 🚀 Quick Install (Linux x86_64)

Download the release tarball and run:

```bash
tar -xzf pqnas-<version>-linux-x86_64.tar.gz
cd pqnas
sudo ./install.sh



# PQ-NAS

**PQ-NAS** is an identity-first, post-quantum–ready personal storage server.

Instead of usernames, passwords, or browser-stored secrets, PQ-NAS uses
**DNA identity** and **device-mediated QR authentication** to grant access.
Your phone is the key. The server never trusts the browser alone.

This project is part of the broader **CPUNK ecosystem**, alongside
DNA-Messenger and PQ-SSH.

---

## What PQ-NAS is (v0)

PQ-NAS v0 is intentionally minimal.

It is **not** a traditional NAS replacement yet.
It is a secure access layer that proves the identity model works end-to-end.

Core ideas:
- No passwords
- No long-lived browser secrets
- No VPN required
- No server-side session state required
- Post-quantum–capable identity verification

---

## Core Features (v0)

- QR-code–based login via DNA-Messenger
- Device-mediated approval (user confirms on phone)
- Stateless signature verification on the NAS
- Identity-based authorization (DNA fingerprint)
- Simple web UI for file access
- Designed to integrate with PQ-SSH

---

## Authentication Model

1. Browser requests access
2. PQ-NAS displays a QR code
3. DNA-Messenger scans and verifies the request
4. User approves on the phone
5. DNA-Messenger signs a challenge using the user’s DNA identity
6. PQ-NAS verifies the signature (post-quantum capable)
7. Access is granted without passwords or stored browser secrets

---

## Non-Goals (for now)

- Multi-tenant enterprise features
- Full NAS management UI (RAID, snapshots, quotas)
- Cloud sync or replication
- Usernames, passwords, or WebAuthn

These may come later, but **not in v0**.

---

## Status

🚧 Early development / v0  
Architecture and authentication flow are the current focus.

---

## License

Apache License 2.0

---

## Philosophy

> Identity should belong to the user, not the server.
>
> If the browser is compromised, the attacker still should not get in.
>
> The phone is the trust anchor.
