# PQ-NAS

**PQ-NAS** is a lightweight, identity-first personal storage server designed around **device-mediated authentication** and **post-quantum–ready identity verification**.

Instead of usernames, passwords, or browser-stored credentials, PQ-NAS uses **DNA identity** and **QR-based authentication via DNA-Messenger**. Your phone becomes the trust anchor. The server never trusts the browser alone.

PQ-NAS is part of the broader **CPUNK ecosystem**, alongside:

- **DNA-Messenger** – identity and secure messaging  
- **PQ-SSH** – identity-based SSH access  
- **PQ-NAS** – identity-secured storage  

---

# 🚀 Quick Install (Linux x86_64)

Download the release tarball and run:

```bash
tar -xzf pqnas-<version>-linux-x86_64.tar.gz
cd pqnas
sudo ./install.sh
```

The installer launches a **Textual TUI installer** that guides you through:

- selecting storage
- configuring networking
- enabling HTTPS (optional)
- initializing PQ-NAS

After installation the server starts automatically.

---

# What PQ-NAS Is

PQ-NAS is **not a traditional NAS distribution**.

It is a **secure storage service focused on identity and access control**, designed to demonstrate a different security model:

- no passwords
- no browser secrets
- no long-lived server sessions
- no VPN required
- identity verification performed by the user’s device

The core idea:

> The **phone proves identity**, not the browser.

---

# Core Features

Current PQ-NAS builds include:

- QR-code login via **DNA-Messenger**
- Device-mediated login approval
- Stateless identity verification
- Identity-based authorization (DNA fingerprint)
- Web File Manager
- Admin interface
- Btrfs storage backend
- Storage pools
- Background tiering (SSD → HDD landing pools)
- User storage migration
- Share links for files
- Built-in audit logging
- Drive health monitoring (SMART / NVMe)

PQ-NAS is designed to stay **minimal and transparent**, avoiding large frameworks and unnecessary services.

---

# Authentication Model

Login works through a device-mediated challenge:

1. Browser requests access
2. PQ-NAS displays a QR code
3. DNA-Messenger scans the QR
4. User approves the login on their phone
5. DNA-Messenger signs a challenge using the user’s DNA identity
6. PQ-NAS verifies the signature
7. Access is granted

This model means:

- no passwords exist
- the browser cannot authenticate alone
- stolen browser sessions are useless without the phone

---

# Storage Model

PQ-NAS uses a **pool-based storage layout** built on Btrfs.

Typical structure:

```
/srv/pqnas
├─ pools/
├─ users/
├─ data/
├─ audit/
└─ metadata/
```

Pools can represent:

- HDD storage
- SSD landing pools
- archive storage
- backup storage

Files uploaded by users are stored under their identity-derived directories.

---

# System Requirements

PQ-NAS is intentionally extremely lightweight.

## Runtime Requirements

Measured on a real installation:

| Resource | Usage |
|--------|------|
RAM | ~11 MB |
Application disk footprint | ~7–8 MB |
Storage overhead | ~300 KB |

Example measurements:

```
/srv/pqnas        316K
/opt/pqnas        7.1M
/etc/pqnas        28K
```

Server memory usage:

```
RSS: ~11 MB
```

## Installation Requirements

The installer uses a temporary Python environment to run the TUI installer.

Typical space usage:

| Component | Size |
|----------|------|
Installer environment | ~40–50 MB |
System dependencies | up to ~400–500 MB |

Recommended minimum free disk space before installation:

```
500 MB
```

After installation the runtime system itself occupies only a few megabytes.

---

# Architecture

PQ-NAS is intentionally simple:

- **C++ backend server**
- **static web UI**
- **Btrfs-based storage**
- **identity-first security model**

This architecture keeps the runtime footprint extremely small compared to container-heavy NAS systems.

---

# Status

🚧 Early development

PQ-NAS already supports:

- identity login
- file manager
- admin UI
- Btrfs pools
- background storage operations

But the project is still evolving.

Expect changes while core architecture stabilizes.

---

# Non-Goals (for now)

PQ-NAS deliberately avoids many traditional NAS features in early versions.

Not currently included:

- large enterprise cluster features
- heavy container ecosystems
- traditional password authentication
- complex virtualization layers

The goal is to keep the system **simple, secure, and lightweight**.

---

# License

Apache License 2.0

---

# Philosophy

> Identity should belong to the user, not the server.  
>  
> If the browser is compromised, the attacker should still not get access.  
>  
> The phone is the trust anchor.