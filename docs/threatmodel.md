# IronHand Threat Model

## Document Scope

This document models threats for the current IronHand architecture and implementation across:

- `/Users/jmcleod/Development/Personal/ironhand/README.md`
- `/Users/jmcleod/Development/Personal/ironhand/docs/design.md`
- `/Users/jmcleod/Development/Personal/ironhand/docs/encryption.md`
- Backend (`/Users/jmcleod/Development/Personal/ironhand/api`, `/Users/jmcleod/Development/Personal/ironhand/vault`, `/Users/jmcleod/Development/Personal/ironhand/pki`, `/Users/jmcleod/Development/Personal/ironhand/storage`)
- Web UI (`/Users/jmcleod/Development/Personal/ironhand/web`)

The focus is confidentiality, integrity, and availability for account credentials, vault data, PKI keys, and audit trails.

## Methodology

Threats are identified using a STRIDE-style approach over the main trust boundaries:

- Browser <-> API (HTTPS + cookies)
- API <-> storage backend (BBolt or PostgreSQL)
- In-process memory handling of cryptographic keys
- Multi-member vault sharing and epoch rotation
- PKI operations over vault items

Severity labels in this document are qualitative:

- `Critical`: high impact and likely in realistic deployments
- `High`: high impact with practical preconditions
- `Medium`: meaningful risk with narrower conditions
- `Low`: hygiene or defense-in-depth improvements

## Security Objectives

- Protect vault plaintext and private keys at rest and in transit.
- Ensure revoked members cannot read newly protected data.
- Prevent credential guessing and account takeover at practical attack rates.
- Preserve integrity of encrypted records against swapping/replay/rollback.
- Provide reliable, tamper-evident auditability of sensitive actions.
- Minimize blast radius if Web UI/browser context is compromised.

## Assets

High-value assets:

- Account secret keys and passphrases
- Derived MUK/record keys/KEKs/DEKs
- Vault item plaintext and attachments
- PKI CA private keys and issued certificate private keys
- Session tokens and server-side session credential blobs
- Audit logs (security-relevant event evidence)

## Trust Boundaries And Data Flows

1. User registers or logs in via Web UI/API.
1. API stores encrypted account records in a reserved storage vault (`__accounts`).
1. API creates in-memory auth session containing exported credentials blob + random session passphrase.
1. API sets `ironhand_session` HttpOnly cookie.
1. Authenticated requests open vault sessions, decrypt item fields, and perform CRUD/PKI operations.
1. Storage backends persist encrypted envelopes, plus plaintext JSON audit entries (`AUDIT` record type).

## Attacker Profiles

- Remote unauthenticated attacker on the network
- Remote authenticated low-privilege user (reader/writer)
- Malicious vault member attempting privilege escalation or post-revocation access
- Browser-side attacker (XSS, malicious extension, local machine compromise)
- Infrastructure attacker with storage snapshot/database access
- Misconfigured reverse proxy or TLS termination layer

## Existing Strengths

- Strong cryptographic design: AES-256-GCM + contextual AAD binding, HKDF key hierarchy, Argon2id passphrase branch, two-secret-key MUK derivation.
- Per-epoch KEK rotation for member add/revoke and stale session detection.
- Member role enforcement in vault session authorization.
- Account lookup IDs and rate-limit keys avoid storing raw secret keys.
- Secret key displayed once at registration; no retrieval endpoint.
- 2FA (TOTP) supported with setup TTL and verification window.
- Input validation limits for IDs, field sizes, and attachment sizes.

## Threat Analysis

### 1) Authentication And Session Management

`High`: Session store is in-memory only and non-distributed.

- Impact: session invalidation/rate-limit state resets on restart; multi-instance consistency issues unless sticky routing is perfect.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/api.go` (`sessions map`, `rateLimiter` in-memory).

`Medium`: Session lifetime is fixed (24h absolute), no idle timeout or renewal policy.

- Impact: stolen session cookie remains useful until expiry.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/auth_handlers.go` (`sessionDuration = 24h`).

`Medium`: Cookie `Secure` depends on request/proxy headers.

- Impact: proxy misconfiguration can reduce transport assurance.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/middleware.go` (`requestIsSecure`).

`Low`: TOTP brute-force is indirectly protected by login limiter but no explicit per-code-attempt counter/lock in 2FA enable flow.

- Impact: limited additional online guessing window during setup/enable.

### 2) Header-Based Credential Authentication

`High`: `AuthMiddleware` accepts `X-Credentials` + `X-Passphrase` headers when no session cookie exists.

- Impact: credentials can be exposed in logs, observability pipelines, proxy middleware, or client-side traces; bypasses cookie-only hardening model.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/middleware.go`.

### 3) CSRF And Browser Session Risks

`Medium`: Cookie auth uses `SameSite=Lax` but no explicit CSRF token/origin enforcement on state-changing endpoints.

- Impact: reduced but not fully eliminated CSRF risk under edge browser behaviors and deployment quirks.
- Evidence: session cookie config in `/Users/jmcleod/Development/Personal/ironhand/api/middleware.go`.

`Medium`: Optional Web UI secret-key persistence in `localStorage` is vulnerable to XSS/extension theft.

- Impact: account takeover if passphrase also captured or weak.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/web/src/pages/UnlockPage.tsx`.

### 4) Audit Log Integrity And Confidentiality

`High`: Per-vault audit entries are stored unencrypted as `plain-json` envelopes.

- Impact: storage attacker can read/modify/delete audit evidence; conflicts with docs that claim encrypted audit entries.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/audit_store.go` vs `/Users/jmcleod/Development/Personal/ironhand/docs/design.md`.

`Medium`: Audit trail is not tamper-evident (no chained hashes/signatures).

- Impact: post-compromise forensics trust is weaker.

### 5) Vault Enumeration And Metadata Exposure

`Medium`: `ListVaults` calls `repo.ListVaults()` globally, then attempts open on each vault and skips inaccessible ones.

- Impact: reveals existence patterns indirectly via timing/log behavior; poor scalability for large shared storage.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/handlers.go` (`ListVaults`).

### 6) PKI-Specific Risks

`High`: CA private key is retrievable by any role with read access to the certificate item fields if membership allows reading those items.

- Impact: catastrophic compromise of CA trust if vault roles are mis-assigned.
- Evidence: PKI stores `private_key` in certificate items (`/Users/jmcleod/Development/Personal/ironhand/pki/pki.go`) and item reads expose full fields.

`Medium`: No hardware-backed key option (HSM/KMS) for CA key custody.

- Impact: key compromise risk tied to application host security posture.

### 7) Availability And Resource Exhaustion

`Medium`: Login rate limiting is per-account only; no IP/device/global pressure controls.

- Impact: distributed guessing/noise across many account IDs can still cause service load.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/ratelimit.go`.

`Medium`: `ListVaults` and item summarization perform repeated opens/reads and can be expensive on large datasets.

- Impact: authenticated DoS amplification.

`Low`: Import/export endpoints allow large payload processing (50 MB), increasing CPU/memory pressure during Argon2id and JSON handling.

### 8) Deployment And Transport

`Medium`: Default self-signed TLS certificate at startup if no cert/key provided.

- Impact: insecure trust posture if operators do not replace certs in production.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/cmd/ironhand/cmd/server.go`.

`Low`: Missing explicit hardened response headers (CSP, HSTS, X-Frame-Options, etc.) in server middleware.

- Impact: weaker browser hardening and XSS blast-radius control.

## Top Risks To Prioritize

1. `High`: Plaintext/tamperable audit storage.
1. `High`: Header-based credential auth in production path.
1. `High`: PKI private-key exposure model tied to generic item read permissions.
1. `Medium`: CSRF hardening gaps for cookie-auth state-changing endpoints.
1. `Medium`: Global vault enumeration pattern in `ListVaults`.

## Recommended Mitigation Roadmap

### Immediate (P0)

1. Encrypt audit entries at rest using vault/session cryptographic model; add integrity checks (at minimum AAD-bound envelopes, ideally hash-chaining/signatures).
1. Disable `X-Credentials`/`X-Passphrase` auth by default; gate behind explicit admin config for non-browser clients.
1. Add CSRF defenses for mutating endpoints: origin/referer validation plus CSRF token.
1. Restrict PKI private key access: separate privileged endpoint, role gate (`owner` only), and default redaction from generic item reads.

### Near-Term (P1)

1. Replace `ListVaults` global scan with account-to-vault index records (per-account listing source of truth).
1. Add persistent/shared session store option (PostgreSQL/Redis) with revocation support and optional idle timeout.
1. Add security headers middleware for Web UI/API responses (CSP, HSTS in TLS deployments, frame and MIME protections).
1. Add per-IP and global login throttling alongside per-account limiter.

### Mid-Term (P2)

1. Add tamper-evident signed audit export and retention policy controls.
1. Add optional WebAuthn/passkey MFA for phishing-resistant second factor.
1. Add HSM/KMS-backed PKI key mode for CA operations.
1. Add anomaly detection metrics/alerts (failed login spikes, unusual item access patterns, bulk exports).

## Test And Verification Gaps

Add or extend tests for:

- Header-auth disabled-by-default behavior and explicit enable flag.
- CSRF enforcement (mutating endpoints rejected without valid origin/token).
- Audit record encryption and tamper-detection failure paths.
- PKI key-field redaction and owner-only key export flows.
- Session revocation and expiry behavior across process restarts (with persistent session backend).
- `ListVaults` scalability and authorization correctness with account-indexed listing.

## Residual Risk Summary

After P0/P1 controls, the largest residual risks are host compromise, XSS in the Web UI supply chain, and operational misconfiguration (TLS/proxy/storage hardening). These require deployment hardening, dependency hygiene, and monitoring, in addition to application-level controls.

## Notes

- This assessment is implementation-grounded and reflects current code behavior.
- Where documentation and implementation differ, this document treats code behavior as authoritative and flags the mismatch for correction.
