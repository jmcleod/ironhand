# IronHand Threat Model

## Scope And Baseline

This is a refreshed threat model based on the current codebase state and docs review of:

- `/Users/jmcleod/Development/Personal/ironhand/README.md`
- `/Users/jmcleod/Development/Personal/ironhand/docs/design.md`
- `/Users/jmcleod/Development/Personal/ironhand/docs/encryption.md`
- Backend code under `/Users/jmcleod/Development/Personal/ironhand/api`, `/Users/jmcleod/Development/Personal/ironhand/vault`, `/Users/jmcleod/Development/Personal/ironhand/pki`, `/Users/jmcleod/Development/Personal/ironhand/storage`
- Web UI code under `/Users/jmcleod/Development/Personal/ironhand/web`

## Revalidation Summary (P0/P1/P2)

### P0 Status

1. Encrypt audit entries + integrity protections: `Addressed`
- Implemented in `/Users/jmcleod/Development/Personal/ironhand/api/audit_store.go` using `session.SealAuditRecord`/`OpenAuditRecord` with audit-specific AAD, plus hash-chain (`PrevHash`) and signed export (`HMACAudit`).

1. Disable header-auth by default: `Addressed`
- `X-Credentials`/`X-Passphrase` now gated by `headerAuthEnabled` in `/Users/jmcleod/Development/Personal/ironhand/api/middleware.go`, with server flag `--enable-header-auth` in `/Users/jmcleod/Development/Personal/ironhand/cmd/ironhand/cmd/server.go`.

1. CSRF defenses for mutating endpoints: `Addressed (backend), Gap (WebUI integration)`
- Backend double-submit CSRF exists in `/Users/jmcleod/Development/Personal/ironhand/api/csrf.go` and is wired on mutating routes.
- WebUI currently does not send `X-CSRF-Token`; no CSRF token handling exists in `/Users/jmcleod/Development/Personal/ironhand/web/src/lib/api.ts`.

1. PKI private key redaction + owner-only retrieval: `Addressed`
- Redaction in standard item responses via `fieldsToAPIRedacted` in `/Users/jmcleod/Development/Personal/ironhand/api/handlers.go`.
- Owner-only retrieval endpoint `GET /vaults/{vaultID}/items/{itemID}/private-key` implemented with `RequireAdmin`.

### P1 Status

1. Replace global vault scan with account vault index: `Addressed`
- Encrypted per-account vault index (`VAULT_INDEX`) implemented in `/Users/jmcleod/Development/Personal/ironhand/api/accounts.go` and used by `ListVaults` in `/Users/jmcleod/Development/Personal/ironhand/api/handlers.go`.

1. Persistent/shared session store: `Not Addressed`
- Sessions remain in-memory map (`sessionStore`) in `/Users/jmcleod/Development/Personal/ironhand/api/api.go`.
- Idle timeout was added, but that does not provide persistence or cross-instance revocation.

1. Security headers middleware: `Addressed`
- Implemented in `/Users/jmcleod/Development/Personal/ironhand/api/security_headers.go` and mounted in server middleware chain.

1. Per-IP and global login throttling: `Addressed`
- Implemented in `/Users/jmcleod/Development/Personal/ironhand/api/ratelimit.go` and enforced in login flow.

### P2 Status

1. Tamper-evident signed audit export: `Addressed`
- `GET /vaults/{vaultID}/audit/export` implemented with signed response (`HMAC-SHA256`).

1. Retention policy controls: `Not Addressed`
- No audit retention/pruning policy controls found.

1. WebAuthn/passkey MFA: `Partially Addressed`
- WebAuthn ceremony endpoints implemented in `/Users/jmcleod/Development/Personal/ironhand/api/webauthn.go`.
- Server bootstrap does not configure WebAuthn (`WithWebAuthn` not wired in default `server` command), so feature is not active by default.

1. HSM/KMS-backed PKI key mode: `Partially Addressed`
- `pki.KeyStore` abstraction exists in `/Users/jmcleod/Development/Personal/ironhand/pki/keystore.go` and PKI APIs accept a keystore.
- Default server path does not wire a non-software keystore; production-grade HSM/KMS integration remains incomplete.

1. Anomaly detection/alerts: `Partially Addressed`
- `metricsCollector` and alert callback plumbing exist in `/Users/jmcleod/Development/Personal/ironhand/api/metrics.go` and `/Users/jmcleod/Development/Personal/ironhand/api/api.go`.
- Default server command does not enable alerting callback, so no runtime alerts by default.

## Original Issues Rechecked

The original top risks from the prior model were mostly reduced:

- Audit confidentiality/integrity: significantly improved.
- Header-auth default exposure: improved.
- PKI private key broad exposure: improved.
- Vault enumeration via global scan: improved.

Remaining high-impact unresolved/partial areas are session persistence/distributed revocation, complete WebAuthn operationalization, and retention/governance controls for audit data.

## Newly Identified Risks

### 1) WebUI does not send CSRF header (`High` operational risk)

- Backend now enforces CSRF for mutating cookie-auth requests.
- Web client request wrapper does not attach `X-CSRF-Token` from `ironhand_csrf` cookie.
- Likely impact: mutating WebUI operations fail with `403` after login/register, or teams disable CSRF to restore UX (security regression).
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/web/src/lib/api.ts` (no CSRF token logic).

### 2) Certificate update path can overwrite redacted private key (`High` integrity/availability risk)

- `GetItem` now returns `private_key: "[REDACTED]"`.
- WebUI edit flow merges fetched fields and writes full item on update.
- For certificate items this can persist the literal redacted marker, destroying usable private key material.
- Evidence:
  - `/Users/jmcleod/Development/Personal/ironhand/api/handlers.go` (`fieldsToAPIRedacted`)
  - `/Users/jmcleod/Development/Personal/ironhand/web/src/contexts/VaultContext.tsx` (`updateItem` merges existing fields)
  - `/Users/jmcleod/Development/Personal/ironhand/web/src/components/EditItemDialog.tsx` (sets/sends `private_key`).

### 3) WebAuthn login does not establish authenticated session (`Medium` design gap)

- `FinishWebAuthnLogin` returns `webauthn_verified` but does not create session cookie/credentials context.
- Impact: feature is not a complete login path and may create false assurance.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/webauthn.go`.

### 4) API/OpenAPI/docs drift (`Medium`)

- Security-relevant endpoints/headers/behavior changes are not reflected in public docs/spec.
- Impact: client misimplementation and insecure usage patterns.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/openapi.yaml`, `/Users/jmcleod/Development/Personal/ironhand/README.md`, `/Users/jmcleod/Development/Personal/ironhand/docs/design.md`.

### 5) Audit chain update is non-atomic (`Medium` integrity gap)

- Audit entry write and chain-tip write are separate operations; partial failure can desynchronize chain head.
- Impact: false tamper alerts or ambiguity during forensics.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/audit_store.go`.

### 6) IP limiter effectiveness depends on deployment topology (`Low/Medium`)

- `extractClientIP` uses `RemoteAddr`; in reverse-proxy setups this may collapse all users to one IP unless trusted forwarding logic is added.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/api/ratelimit.go`.

## Updated Priority Queue

1. `High`: Fix WebUI CSRF header integration.
1. `High`: Prevent certificate private key corruption in edit/update flows.
1. `Medium`: Complete WebAuthn to create/refresh authenticated sessions, or clearly scope it as supplemental verification.
1. `Medium`: Make audit append + tip update atomic (single batch transaction).
1. `Medium`: Add persistent/shared session backend for multi-instance and restart-resilient revocation.
1. `Medium`: Update OpenAPI + README + design docs to match security behavior.
1. `Low/Medium`: Improve client IP extraction strategy for proxy deployments.
1. `Low`: Add configurable audit retention controls.

## Verification Notes

- Full test suite currently passes: `go test ./...`.
- Passing tests do not currently cover WebUI CSRF token handling and certificate redaction/update interaction end-to-end.
