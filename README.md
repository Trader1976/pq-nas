# DNA-Nexus Server

**DNA-Nexus Server** is a lightweight, identity-first personal storage and collaboration server built around **device-mediated authentication**, **DNA identity**, and a minimal self-hosted NAS architecture.

Instead of relying on usernames, passwords, browser-stored credentials, or VPN-only access, DNA-Nexus Server uses **QR-based login approval through DNA-Messenger**. The phone acts as the trust anchor, and the server does not trust the browser alone.

DNA-Nexus Server is part of the broader **CPUNK / DNA-Nexus ecosystem**, alongside:

- **DNA-Messenger** — identity, secure messaging, and QR-based authentication
- **PQ-SSH** — identity-based SSH access
- **DNA-Nexus Server** — identity-secured storage, sharing, apps, and collaboration

> The core idea is simple:
>
> **The phone proves identity, not the browser.**

---

# What DNA-Nexus Server Is

DNA-Nexus Server is **not a traditional NAS distribution** and it is not trying to become a heavy container platform.

It is a focused, identity-first storage server designed for:

- personal and family storage
- small private groups
- secure file sharing
- workspace collaboration
- app-based NAS features
- lightweight self-hosting
- identity-based access control

The project started as PQ-NAS, but the product identity has moved forward. The public name is now:

> **DNA-Nexus Server**

Some internal paths, service names, package names, or source identifiers may still use `pqnas` during the transition. These are implementation details and may be cleaned up over time.

---

# Key Design Goals

DNA-Nexus Server is designed around a few strong principles:

- no traditional password login
- no browser-only trust
- no unnecessary heavyweight services
- no forced cloud dependency
- no complex enterprise stack for simple personal storage
- identity belongs to the user, not the server
- access decisions are tied to DNA fingerprints
- the user’s trusted device is part of authentication

The goal is to keep the system **small, transparent, understandable, and secure by design**.

---

# Core Features

Current DNA-Nexus Server builds include:

- QR-code login via **DNA-Messenger**
- device-mediated login approval
- identity-based authorization using DNA fingerprints
- stateless identity verification flow
- web-based File Manager
- multi-user storage
- admin interface
- user approval flow
- user settings and theme selection
- Btrfs-based storage backend
- storage pools
- background storage operations
- user storage migration
- share links for files
- public file sharing
- external workspace access
- QR-based external workspace invites
- workspace roles such as viewer, editor, and owner
- workspace file browsing, upload, and download
- Drop Zone public upload links
- activity logging
- audit logging
- drive health monitoring using SMART / NVMe tools
- bundled web apps
- app manifest system
- theme-aware UI

DNA-Nexus Server has grown beyond the first demo phase. It is now a serious self-hosted storage platform with a real app model, real sharing flows, and a growing collaboration layer.

---

# Included Apps and Interfaces

DNA-Nexus Server is built as a small platform with bundled apps.

Current and planned app areas include:

- **File Manager** — browse, upload, download, rename, delete, share, and manage files
- **Photo Gallery** — photo browsing, thumbnails, metadata, and gallery views
- **Shares Manager** — manage shared files and links
- **Drop Zone** — one-way public upload links
- **Workspace tools** — shared folders with member roles and external access
- **Echo Stack** — bookmark and web archive app
- **Reel Stack** — video gallery app
- **Music Library** — music browsing and playback
- **Snapshot Manager** — storage snapshot management
- **RAID Manager** — storage/RAID related management tools

Apps are served through the DNA-Nexus app system and can define where they appear, such as the desktop, launcher, or sidebar.

---

# Authentication Model

DNA-Nexus Server login works through a device-mediated challenge.

Typical flow:

1. Browser requests access
2. DNA-Nexus Server displays a QR code
3. DNA-Messenger scans the QR code
4. User approves the login on their phone
5. DNA-Messenger signs a challenge using the user’s DNA identity
6. DNA-Nexus Server verifies the signature
7. Access is granted

This means:

- passwords do not exist in the login flow
- the browser cannot authenticate alone
- stolen browser state is not enough
- the phone remains part of the trust model
- access can be tied directly to a DNA fingerprint

The browser is treated as a user interface, not as the root of trust.

---

# Storage Model

DNA-Nexus Server uses a pool-based storage layout, currently built around Btrfs.

Typical runtime structure may look like:

```text
/srv/pqnas
├─ pools/
├─ users/
├─ data/
├─ audit/
└─ metadata/
```

The `pqnas` path name is currently retained for compatibility with existing development builds. It may be renamed or abstracted later as the DNA-Nexus branding transition continues.

Storage pools can represent:

- HDD storage
- SSD landing pools
- archive storage
- backup storage
- user-specific storage roots
- workspace storage areas

Files are stored under server-managed directories and access is controlled through DNA-Nexus authorization logic rather than direct filesystem exposure.

---

# Workspaces

DNA-Nexus Server supports workspace-style collaboration.

Workspaces can be used for:

- shared folders
- small team collaboration
- family folders
- external member access
- file review and exchange
- controlled upload/download access

Workspace members can have roles such as:

- **viewer** — can browse and download
- **editor** — can upload and modify content
- **owner** — can manage the workspace

External workspace access allows invited users to join through a QR-based flow without becoming normal local server users.

---

# Sharing

DNA-Nexus Server supports multiple sharing models.

## File Share Links

Users can create share links for files. These links allow selected files to be opened or downloaded without exposing the entire user account.

## Drop Zone Upload Links

Drop Zone provides one-way public upload pages.

A Drop Zone can be used when someone should be allowed to send files to the server without seeing the destination folder or browsing server content.

Possible uses:

- receiving documents
- collecting photos
- client uploads
- family file drop
- temporary upload links

Drop Zone links can be configured with limits such as expiry, password, destination folder, and upload size policy.

## External Workspace Invites

Workspace owners can invite external users through QR-based access links. External users can be allowed to browse, download, or upload depending on their role.

---

# App Model

DNA-Nexus Server includes a bundled app model.

Apps can define metadata such as:

- app id
- name
- version
- entry point
- API base
- permissions
- category
- icons
- UI surfaces

Apps can appear in different places depending on their manifest, for example:

- desktop
- app launcher
- sidebar

This allows larger primary apps to appear prominently while smaller utility apps can stay in the launcher unless pinned or enabled.

---

# System Requirements

DNA-Nexus Server is intentionally lightweight.

## Runtime Requirements

The server is designed to use very little memory and disk space compared to container-heavy NAS systems.

Earlier real installation measurements for the core runtime were approximately:

| Resource | Usage |
|---|---:|
| RAM | ~11 MB |
| Application disk footprint | ~7–8 MB |
| Storage metadata overhead | ~300 KB |

Example measurements from an earlier installation:

```text
/srv/pqnas        316K
/opt/pqnas        7.1M
/etc/pqnas        28K
```

Server memory usage:

```text
RSS: ~11 MB
```

Actual usage depends on enabled apps, storage configuration, number of users, background tasks, thumbnails, metadata indexing, and future features.

## Installation Requirements

The installer may use a temporary Python environment for the Textual TUI installer.

Typical temporary installation space may include:

| Component | Approximate Size |
|---|---:|
| Installer environment | ~40–50 MB |
| System dependencies | up to ~400–500 MB |

Recommended minimum free disk space before installation:

```text
500 MB
```

For real storage use, the actual storage pool should of course be much larger.

---

# Quick Install

Release packaging may still use transitional `pqnas` naming while the project branding moves to DNA-Nexus Server.

Typical install flow:

```bash
tar -xzf dna-nexus-server-<version>-linux-x86_64.tar.gz
cd dna-nexus-server
sudo ./install.sh
```

During the transition period, some builds may still use package names like:

```bash
tar -xzf pqnas-<version>-linux-x86_64.tar.gz
cd pqnas
sudo ./install.sh
```

The installer guides you through:

- selecting storage
- configuring server settings
- enabling HTTPS when available
- initializing the server
- preparing runtime directories
- starting the service

After installation, the server starts automatically.

---

# Architecture

DNA-Nexus Server is intentionally simple.

Core architecture:

- **C++ backend server**
- **static web UI**
- **bundled app system**
- **Btrfs-based storage support**
- **identity-first authentication**
- **DNA fingerprint based authorization**
- **small runtime footprint**
- **minimal service dependencies**

The project avoids unnecessary runtime complexity. The goal is that the server remains understandable, inspectable, and practical to run on modest hardware.

---

# Why Not a Traditional NAS?

Traditional NAS systems often rely on:

- local usernames and passwords
- browser sessions
- large web stacks
- plugin ecosystems with heavy dependencies
- VPN recommendations for safe remote access
- complex admin surfaces

DNA-Nexus Server takes a different approach.

It focuses on:

- identity-first access
- phone-mediated login
- minimal backend design
- strong separation between browser UI and identity proof
- lightweight bundled apps
- simple storage primitives
- practical self-hosting

It is not trying to replace every enterprise NAS feature. It is trying to provide a secure, understandable, identity-first storage system.

---

# Current Status

DNA-Nexus Server is in **active development**.

It is no longer just an early demonstration. The project already includes a working server, authentication flow, file manager, admin interface, storage handling, sharing, workspaces, external access flows, and multiple bundled apps.

At the same time, the project is still evolving. Some APIs, UI flows, internal paths, and package names may change as the system matures.

Current focus areas include:

- polishing the app platform
- improving workspace collaboration
- expanding activity and audit visibility
- improving external sharing flows
- strengthening bundled apps
- improving installer and release packaging
- continuing the transition from PQ-NAS naming to DNA-Nexus Server branding

---

# Non-Goals

DNA-Nexus Server deliberately avoids some traditional NAS directions.

Not primary goals:

- becoming a Kubernetes platform
- becoming a heavy virtualization system
- replacing large enterprise storage clusters
- adding traditional password login as the main model
- depending on a large container stack for normal operation
- hiding the system behind unnecessary complexity

The project may integrate with other tools where useful, but the core server should remain small, direct, and identity-first.

---

# Security Philosophy

DNA-Nexus Server is built around the idea that the browser should not be the root of trust.

Important principles:

- identity should belong to the user
- authentication should involve the user’s trusted device
- the server should not depend on browser-stored secrets alone
- access should be tied to cryptographic identity
- compromised browser state should not automatically mean full account compromise
- sharing should be explicit and controlled
- external access should be role-based and limited

> If the browser is compromised, the attacker should still not automatically get access.
>
> The phone is the trust anchor.
>
> The server verifies identity instead of merely trusting a session.

---

# Naming Notes

The project was originally called **PQ-NAS**.

The current product name is:

> **DNA-Nexus Server**

During the transition, some of the following may still contain `pqnas`:

- repository name
- binary name
- service name
- install paths
- configuration paths
- source code identifiers
- package artifacts

This is expected during the migration period.

Public-facing documentation, branding, and user-facing language should prefer **DNA-Nexus Server**.

---

# License

Apache License 2.0

---

# Philosophy

> Identity should belong to the user, not the server.
>
> Storage should be private by default, but easy to share intentionally.
>
> The browser is only the interface.
>
> The phone proves identity.
>
> DNA-Nexus Server should stay lightweight, transparent, and understandable.