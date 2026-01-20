# Security Model – PQ-NAS

This document describes the security model, trust boundaries, and design
decisions of **PQ-NAS v0**.

PQ-NAS is an **identity-first access system**, not a traditional NAS security
stack. Its primary goal is to demonstrate a **device-mediated,
post-quantum–capable authentication model** where the browser is never a trust
anchor.

---

## Threat Model

PQ-NAS is designed under the following assumptions:

### Assumed Adversaries

An attacker may:

- Control or compromise the browser
- Steal browser cookies or local storage
- Observe or manipulate network traffic
- Attempt replay or token substitution attacks
- Attempt to authenticate without owning a valid identity key

### Trusted Components

- The **PQ-NAS server** process
- The **user’s mobile device** running DNA-Messenger
- The **DNA identity private key** stored on the device

The browser is treated as **untrusted transport only**.

---

## Core Security Principles

### 1. No Browser-Resident Secrets

- The browser does not store passwords, private keys, or long-lived credentials.
- A compromised browser alone is insufficient to authenticate.

### 2. Device-Mediated Authentication

- All authentication approvals originate from the user’s mobile device.
- The user explicitly confirms login on the phone.
- The phone produces a cryptographic proof using the user’s DNA identity key.

### 3. Cryptographic Proof, Not Assertions

PQ-NAS does not trust:

- Browser claims
- Client-side state
- JavaScript-only validation

All access decisions are based on **server-side cryptographic verification**.

---

## Authentication Flow (v4)

1. The browser requests access from PQ-NAS.
2. PQ-NAS issues a short-lived, server-signed request token (`req`).
3. The browser displays a QR code containing the request token.
4. DNA-Messenger scans the QR code.
5. The user approves the request on the phone.
6. DNA-Messenger produces a cryptographic proof bound to the request.
7. PQ-NAS verifies the proof and issues a short-lived browser session cookie.

At no point does the browser authenticate itself.

---

## Cryptographic Verification (v4)

Verification is **fail-closed** and performed conceptually in the following order:

- **Server authenticity**
    - The request token is verified using **Ed25519** (server key).
- **Request binding**
    - The proof is bound to the *exact* request token issued by the server.
- **Canonical payload verification**
    - Signatures are verified over canonical, byte-stable payloads.
- **Identity proof**
    - User approval is verified using **post-quantum–capable signatures**
      (ML-DSA-87 / Dilithium-class via PQClean).
- **Fingerprint binding**
    - The identity fingerprint is cryptographically bound to the public key.
- **Origin / relying party binding**
    - Prevents cross-site or cross-service replay.
- **Policy enforcement**
    - The fingerprint identity is checked against the allowlist.

Only if **all** checks succeed is access granted.

---

## Identity Representation

After successful verification, the server extracts a canonical identity string
(`fingerprint_b64`).

- This value uniquely represents the user’s DNA identity.
- It is treated as an **opaque identifier** outside the verifier.
- Policy checks, session cookies, and audit logs use this value directly.

---

## Authorization Model

PQ-NAS separates **authentication** from **authorization**:

- Authentication proves *who* approved the request.
- Authorization decides *whether* that identity is allowed.

Authorization is enforced via:

- A fingerprint-based allowlist
- Explicit user/admin roles
- Fail-closed policy checks

A cryptographically valid identity may still be denied access.

---

## Session Security

- Browser sessions are represented by **short-lived, signed cookies**.
- Cookies are issued only after successful verification and authorization.
- Cookie properties:
    - `HttpOnly`
    - `Secure`
    - `SameSite=Lax`
- Session expiry is enforced server-side.

Session cookies are **bearer tokens** and are intentionally short-lived.

---

## Stateless Verification

- Cryptographic verification does **not** rely on server-side authentication
  session state.
- Request tokens and proofs are self-contained and signed.
- Verification can be performed without shared state between requests.

Note:

- PQ-NAS intentionally maintains **audit logs** and **one-time consume
  semantics** to prevent replay and to support accountability.
- The system is *verification-stateless*, not globally stateless.

---

## Audit & Accountability

All security-relevant events are recorded in an append-only audit log:

- Request token issuance
- Verification attempts (success/failure)
- Authorization decisions
- Session minting and consumption

Audit logs are:

- Hash-chained
- Append-only
- Verifiable for tampering

Audit data is intended for:

- Incident analysis
- Forensics
- Security review

---

## Non-Goals (v0)

The following are explicitly **out of scope** for PQ-NAS v0:

- Password-based authentication
- WebAuthn / passkeys
- Multi-factor authentication beyond device mediation
- Enterprise identity federation
- Hardware-backed key storage guarantees
- Resistance against a fully compromised server

These may be explored in future versions.

---

## Security Philosophy

> Identity should belong to the user, not the server.
>
> The browser is a convenience layer, not a trust anchor.
>
> If a user’s phone is not involved, access should not be possible.

---

## Responsible Disclosure

If you discover a security issue:

- Do **not** open a public issue.
- Contact the project maintainers privately.
- Provide a minimal reproduction and impact assessment.

Security issues will be acknowledged and addressed responsibly.

---

*PQ-NAS v0 — security-first by design, minimal by intent.*
