
<img width="1518" height="1100" alt="pqnas_system" src="https://github.com/user-attachments/assets/0d32cc2d-fdbc-4232-bfab-048a7533a22e" />
<img width="1518" height="1100" alt="pqnas_log" src="https://github.com/user-attachments/assets/e4ffa438-b4f6-4823-92bc-6b2b8f7ba7c2" />

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
