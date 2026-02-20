# IronHand Threat Model

## Scope

Current potential issues identified from the active implementation and deployment model.

## Current Known Potential Issues

### 1) Audit retention defaults (`Low`)

Audit retention controls exist but default to disabled (`--audit-retention-days=0`, `--audit-max-entries=0`).

- Impact: deployments that keep defaults may accumulate unbounded audit history, creating governance/compliance and storage-management risk.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/cmd/ironhand/cmd/server.go`, `/Users/jmcleod/Development/Personal/ironhand/api/audit_store.go`.
- Mitigation: set environment-appropriate retention policy in deployment baselines.

### 2) PKI backend portability (`Low`)

PKCS#11 is implemented for hardware-backed key custody, but cloud KMS backends (AWS/GCP/Azure) are not included in-tree.

- Impact: environments without PKCS#11 may run software key custody unless they implement custom keystore integration.
- Evidence: `/Users/jmcleod/Development/Personal/ironhand/pki/keystore.go`, `/Users/jmcleod/Development/Personal/ironhand/pki/keystore_pkcs11.go`.
- Mitigation: add cloud KMS keystore adapters or provide deployment guidance for external integration.

## Resolved Since Prior Review

### Client IP trust boundary (`was Low → Addressed`)

`--trusted-proxies` flag controls forwarded-header trust. Proxy headers (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`) are only honored if (1) trusted proxies are explicitly configured AND (2) the direct TCP peer falls within a trusted CIDR range. When `--trusted-proxies` is not set (the default), proxy headers are never consulted and `RemoteAddr` is always used — a fail-safe default aligned with OWASP guidance (A05: Security Misconfiguration).

- Evidence: `api/ratelimit.go` (`extractClientIPWithProxies`), `api/ratelimit_test.go` (`TestExtractClientIPWithTrustedProxies`), `cmd/ironhand/cmd/server.go` (`--trusted-proxies` flag).

### WebAuthn ceremony state management (`was P1 → Addressed`)

- Expired/abandoned WebAuthn login ceremonies are now proactively evicted before each new insertion (bounded to `maxCeremonyEntries`).
- The raw passphrase is no longer stored in ceremony state. Instead, the pre-derived login passphrase (`passphrase:secretKey`) is computed immediately and stored, minimizing the lifetime of plaintext passphrase material in memory.
- SessionData is stored as the typed `webauthn.SessionData` directly, eliminating unnecessary JSON marshal/unmarshal churn.

- Evidence: `api/webauthn.go` (`evictExpiredCeremoniesLocked`, `webauthnCeremonyState`).

### Audit retention performance (`was P1 → Addressed`)

Retention pruning has been moved from inline (every append) to threshold-triggered: pruning runs every N appends (where N is derived from `auditMaxEntries` or a default of 50). The append path itself is O(1) — it writes only the new entry and chain tip. Timestamps are parsed once during deserialization (`parseCreatedAt`) and reused as `time.Time` values for comparisons, eliminating repeated string parsing.

- Evidence: `api/audit_store.go` (`auditRetentionThreshold`, `auditRetentionCheckThreshold`, `parseCreatedAt`), `api/api.go` (`auditAppendsSinceRetention`).

### Registration brute-force/abuse controls (`was P1 → Addressed`)

Registration now enforces two-tier rate limiting (per-IP + global) before any expensive Argon2id KDF work is performed. Per-IP allows 5 registrations before exponential backoff (5 min → 1 hr). Global allows 50 registrations/min before a 5-minute cooldown. MFA setup routes share the per-IP limiter to prevent TOTP secret generation spam. All throttled requests are audit-logged (`register_rate_limited`).

- Evidence: `api/ratelimit.go` (`registrationIPLimiter`, `registrationGlobalLimiter`), `api/auth_handlers.go` (Register, SetupTwoFactor), `api/ratelimit_test.go`.

### Excessive error detail in API responses (`was P1 → Addressed`)

All API handlers now return stable generic messages to clients instead of concatenating raw `err.Error()` details. Internal errors are logged server-side with a unique correlation ID via `writeInternalError`. The `ErrorResponse` includes an optional `correlation_id` field so operators can match user reports to log entries. Approximately 40 instances across `handlers.go`, `auth_handlers.go`, `webauthn.go`, and `errors.go` were remediated.

- Evidence: `api/errors.go` (`writeInternalError`), `api/handlers.go`, `api/auth_handlers.go`, `api/webauthn.go`, `api/models.go` (`CorrelationID`).

## Operational Recommendations

1. When deploying behind a reverse proxy, set `--trusted-proxies` to the CIDR ranges of your proxy/load balancer so that rate limiters see real client IPs instead of the proxy's address.
2. Set `--audit-retention-days` and/or `--audit-max-entries` explicitly in production.
3. Choose hardware-backed PKI key custody (PKCS#11 or custom KMS backend) for high-assurance CA deployments.
