# Security Model – PQ-NAS

This document describes the security model, trust boundaries, and design
decisions of **PQ-NAS v0**.

PQ-NAS currently has **two distinct security contexts**:

1. **Authentication and session establishment**
2. **Post-quantum share protection and browser-side file opening**

These contexts have different trust assumptions and must not be conflated.

PQ-NAS remains an **identity-first access system**, not a traditional NAS
security stack. Its primary goal is to demonstrate a **device-mediated,
post-quantum–capable authentication model** with explicit server-side
verification, while also experimenting with **post-quantum protected file
sharing**.

---

## Threat Model

PQ-NAS is designed under the following assumptions.

### Assumed Adversaries

An attacker may:

- Control or compromise the browser
- Steal browser cookies or local storage
- Observe or manipulate network traffic
- Attempt replay or token substitution attacks
- Attempt to authenticate without owning a valid identity key
- Attempt to misuse a PQ share link or wrapped key material
- Attempt ciphertext tampering during PQ share delivery

### Trusted Components

For **authentication**:

- The **PQ-NAS server** process
- The **user’s mobile device** running DNA-Messenger
- The **DNA identity private key** stored on the device

For **PQ share opening**:

- The **PQ-NAS server** process
- The **recipient browser runtime** performing local unwrap/decrypt
- The **recipient browser-side share identity key material** used for share opening

This distinction matters: the browser is **not trusted as an authentication
authority**, but it **is** currently used as the local decryption endpoint for
PQ share opening.

---

## Core Security Principles

### 1. Authentication does not depend on browser-held identity secrets

For login/session authentication:

- The browser does not store passwords or the user’s DNA identity private key.
- A compromised browser alone is insufficient to authenticate as the user.

### 2. Device-mediated authentication

- All authentication approvals originate from the user’s mobile device.
- The user explicitly confirms login on the phone.
- The phone produces a cryptographic proof using the user’s DNA identity key.

### 3. Cryptographic proof, not assertions

PQ-NAS does not trust:

- Browser claims
- Client-side state
- JavaScript-only validation

All authentication access decisions are based on **server-side cryptographic verification**.

### 4. PQ share opening is local-decrypt by design

For PQ share opening:

- The file content encryption key is unwrapped in the browser.
- File decryption happens locally in the browser before download.
- Share confidentiality therefore depends on the browser/device used to open the share.

This is a different trust model from the login flow and is documented separately below.

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

## Post-Quantum Share Security Model

PQ share opening is a separate security path from login.

### PQ share goals

The PQ share flow is designed so that:

- a file content encryption key (CEK) is wrapped for the intended recipient
- CEK unwrap and file decryption occur locally in the browser
- the server can deliver encrypted payloads without directly exposing plaintext in transit

### Current PQ share browser role

For PQ share opening, the browser is **not merely transport**. It is currently:

- the CEK unwrap endpoint
- the payload decrypt endpoint
- the holder of browser-side share identity material used for opening protected shares

This means the browser remains untrusted for **authentication**, but is an active security endpoint for **share decryption**.

### Browser-resident share secrets

PQ share opening may require browser-resident private key material associated
with share-opening identity records.

That means the broad statement “the browser stores no private keys” is true for
**authentication**, but **not universally true** for the PQ share subsystem.

The current design should therefore be understood as:

- **No browser-resident authentication identity secrets**
- **Browser-resident share-opening private key material may exist**

### PQ share cryptographic model

At a high level, PQ share opening uses:

- **ML-KEM-768** for recipient-oriented key encapsulation / key wrapping
- **AES-256-GCM** for payload encryption
- local browser unwrap/decrypt before download
- integrity verification of decrypted payload metadata such as size and digest

### PQ share ciphertext tampering behavior

Correctly sized but tampered PQ KEM ciphertext is handled via implicit rejection behavior in the ML-KEM provider path.

In practice this means:

- malformed lengths are treated as API failures
- correctly sized but invalid ciphertext does not become an API failure
- decapsulation still returns a shared secret
- the resulting secret differs from the valid untampered case

This is intentional and aligns with the ML-KEM boundary contract used by PQ-NAS.

### PQ share trust implications

If the browser used to open a PQ share is compromised, then:

- locally unwrapped CEK material may be exposed
- plaintext file content may be exposed after decryption
- integrity verification may still detect tampering, but confidentiality at the endpoint is lost

This is an accepted limitation of the current local-browser-decrypt share model.

---

## ML-KEM Provider Model

PQ-NAS now routes its ML-KEM operations through a **DNA-owned wrapper boundary**
rather than having share code depend directly on vendored ML-KEM symbols.

### Current provider state

In the current lab/dev path:

- the default selected ML-KEM provider is the **DNA provider**
- the vendored native provider remains available as a tested fallback

### Security significance

This means:

- PQ share server code depends on the stable DNA wrapper API
- provider choice is isolated behind an internal selector seam
- native fallback remains available if needed
- provider behavior is exercised through:
  - default lane
  - forced-DNA lane
  - forced-native lane

### Important current limitation

The current DNA ML-KEM provider still uses a **native-backed validation bridge**
for boundary-compatible structural validation of some key material.

Therefore, vendored native code is still part of the effective security story and
must not yet be considered fully removable.

---

## Audit & Accountability

All security-relevant events are recorded in an append-only audit log:

- Request token issuance
- Verification attempts (success/failure)
- Authorization decisions
- Session minting and consumption
- PQ share operations where audit instrumentation is present

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
- A claim that browser-side PQ share decryption is safe under full browser compromise
- A claim that vendored ML-KEM code has already been completely removed from the security path

These may be explored in future versions.

---

## Security Philosophy

> Identity should belong to the user, not the server.
>
> The browser is not trusted as an authentication authority.
>
> For PQ share opening, the browser currently acts as the local decryption endpoint.
>
> If a user’s phone is not involved, authentication should not be possible.

---

## Current Security Posture Summary

At this checkpoint:

- Authentication remains device-mediated and server-verified.
- The browser is not a trust anchor for login.
- PQ share opening uses local browser unwrap/decrypt and therefore has a distinct endpoint trust model.
- ML-KEM operations are routed through a DNA-owned wrapper boundary.
- The DNA provider is the default lab/dev path.
- Native remains as a tested fallback.
- Vendored native code is still present in the effective security path due to the current validation bridge.

This is a stronger and cleaner architecture than the earlier direct-vendored integration, but it is **not yet the final de-vendored state**.

---

## Responsible Disclosure

If you discover a security issue:

- Do **not** open a public issue.
- Contact the project maintainers privately.
- Provide a minimal reproduction and impact assessment.

Security issues will be acknowledged and addressed responsibly.

---

*PQ-NAS v0 — security-first by design, staged by intent.*