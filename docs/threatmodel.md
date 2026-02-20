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

- Expired/abandoned WebAuthn login ceremonies are now proactively evicted before each new insertion.
- Hard cap enforced: after TTL eviction, if active ceremonies still meet or exceed `maxCeremonyEntries` (1000), the new ceremony is rejected with HTTP 503. This prevents an attacker from flooding the map faster than entries expire.
- Cap-exceeded events are audit-logged (`ceremony_cap_exceeded`) and fire a `ceremony_pressure` alert.
- The raw passphrase is no longer stored in ceremony state. Instead, the pre-derived login passphrase (`passphrase:secretKey`) is computed immediately and stored, minimizing the lifetime of plaintext passphrase material in memory.
- SessionData is stored as the typed `webauthn.SessionData` directly, eliminating unnecessary JSON marshal/unmarshal churn.

- Evidence: `api/webauthn.go` (`evictExpiredCeremoniesLocked`, hard-cap check in `BeginWebAuthnLogin`), `api/audit.go` (`AuditCeremonyCapExceeded`), `api/metrics.go` (`AlertCeremonyPressure`), `api/webauthn_test.go` (`TestCeremonyCap_*`).

### Audit retention performance (`was P1 → Addressed`)

Retention pruning has been moved from inline (every append) to threshold-triggered: pruning runs every N appends (where N is derived from `auditMaxEntries` or a default of 50). The append path itself is O(1) — it writes only the new entry and chain tip. Timestamps are parsed once during deserialization (`parseCreatedAt`) and reused as `time.Time` values for comparisons, eliminating repeated string parsing.

- Evidence: `api/audit_store.go` (`auditRetentionThreshold`, `auditRetentionCheckThreshold`, `parseCreatedAt`), `api/api.go` (`auditAppendsSinceRetention`).

### Registration brute-force/abuse controls (`was P1 → Addressed`)

Registration now enforces two-tier rate limiting (per-IP + global) before any expensive Argon2id KDF work is performed. Per-IP allows 5 registrations before exponential backoff (5 min → 1 hr). Global allows 50 registrations/min before a 5-minute cooldown. MFA setup routes share the per-IP limiter to prevent TOTP secret generation spam. All throttled requests are audit-logged (`register_rate_limited`).

- Evidence: `api/ratelimit.go` (`registrationIPLimiter`, `registrationGlobalLimiter`), `api/auth_handlers.go` (Register, SetupTwoFactor), `api/ratelimit_test.go`.

### Excessive error detail in API responses (`was P1 → Addressed`)

All API handlers now return stable generic messages to clients instead of concatenating raw `err.Error()` details. Internal errors are logged server-side with a unique correlation ID via `writeInternalError`. The `ErrorResponse` includes an optional `correlation_id` field so operators can match user reports to log entries. Approximately 40 instances across `handlers.go`, `auth_handlers.go`, `webauthn.go`, and `errors.go` were remediated.

- Evidence: `api/errors.go` (`writeInternalError`), `api/handlers.go`, `api/auth_handlers.go`, `api/webauthn.go`, `api/models.go` (`CorrelationID`).

### WebUI secret key storage scope (`was Low → Addressed`)

The "Remember secret key" checkbox previously persisted the secret key in `localStorage`, which survives browser restarts and is accessible to any script running on the same origin indefinitely. This has been changed to `sessionStorage`, which is scoped to the browser tab lifetime — the key is automatically cleared when the tab or window closes. A one-time migration (`useEffect`) removes any key previously stored in `localStorage`. When the checkbox is enabled, an inline risk warning is displayed to the user explaining that the key could be read by malicious scripts (XSS) while the tab is open.

- Evidence: `web/src/pages/UnlockPage.tsx` (`sessionStorage`, migration `useEffect`, risk warning text).

### GET CRL endpoint mutated CA state / CSRF bypass (`was P1 → Addressed`)

The `GET /pki/crl.pem` endpoint previously called `GenerateCRL` directly, which increments the CA's `CRLNumber` and persists it — a state-mutating operation. Because the CSRF middleware exempts safe methods (GET, HEAD, OPTIONS), this mutation could be triggered by a cross-site request (e.g. `<img src=".../crl.pem">`). The fix separates read and write:

- **`GET /pki/crl.pem`** — now read-only; calls `pki.LoadCRL()` to return the most recently cached CRL without mutating any state. No CRLNumber increment, no CA state write.
- **`POST /pki/crl`** — new endpoint; calls `pki.GenerateCRL()` (state-mutating, increments CRLNumber). Protected by CSRF middleware on mutating methods.
- **Auto-generation** — `InitCA` generates and caches CRL #1 automatically so GET works immediately. `RevokeCert` auto-regenerates the cached CRL so it always reflects the latest revocation state.
- **Backward compatibility** — cached CRL is stored in a new reserved item (`__ca_crl`). For vaults initialised before this change, the first `POST /crl` or `RevokeCert` creates the item via upsert (Update → Put fallback).

- Evidence: `pki/pki.go` (`LoadCRL`, `storeCRL`, `GenerateCRL` persistence, `InitCA` auto-gen), `api/handlers.go` (`GetCRL` read-only, `GenerateCRL` POST handler, `RevokeCert` auto-regen), `api/api.go` (route table), `api/api_test.go` (`TestCRL_*`), `pki/pki_test.go` (`TestLoadCRL_ReturnsCachedCRL`).

### Forwarded-proto header trust without proxy validation (`was P1 → Addressed`)

`requestIsSecure` previously trusted `X-Forwarded-Proto` and `Forwarded` headers from any peer, allowing an untrusted client to spoof HTTPS status. This influenced the `Secure` flag on session/CSRF cookies and HSTS header emission. The fix applies the same trusted-proxy validation model used for client IP extraction: forwarded-protocol headers are only honored when `--trusted-proxies` is configured AND the request's `RemoteAddr` falls within a trusted CIDR range. A shared `isPeerTrusted` helper (also used by `extractClientIPWithProxies`) enforces the check consistently. `SecurityHeaders` was converted from a standalone function to an `*API` method so it has access to the trusted-proxy configuration.

- Evidence: `api/middleware.go` (`requestIsSecureWithProxies`, `isPeerTrusted`), `api/security_headers.go` (`SecurityHeaders` method), `api/csrf.go` (proxy-aware cookie functions), `api/auth_handlers.go` / `api/webauthn.go` (updated callsites), `api/ratelimit_test.go` (`TestRequestIsSecure_*`).

### Revoke-cert handler accepted malformed JSON (`was P1 → Addressed`)

The `POST /pki/items/{itemID}/revoke` handler previously caught all `json.Decode` errors with a blanket fallback to `reason = "unspecified"`, silently accepting malformed JSON, unknown fields, and oversized bodies. This masked client bugs and bypassed request validation. The fix distinguishes intentionally empty bodies (`io.EOF`) — which are allowed as a convenience — from actual errors: malformed JSON and unknown fields return 400, oversized bodies return 413.

- Evidence: `api/handlers.go` (`RevokeCert` decode error handling), `api/api_test.go` (`TestRevokeCert_EmptyBodyDefaultsToUnspecified`, `TestRevokeCert_MalformedJSONReturns400`, `TestRevokeCert_UnknownFieldReturns400`, `TestRevokeCert_OversizedBodyReturns413`).

### Sensitive data exposure via caching (`was P1 → Addressed`)

All API responses now include `Cache-Control: no-store` and `Pragma: no-cache` headers via the `noCacheHeaders` middleware applied at the API router level. This prevents browsers and intermediate proxies from persisting secret keys, decrypted vault items, private keys, TOTP secrets, and other sensitive data to disk caches. The middleware is scoped to the API router only — non-API routes (health, web UI) are unaffected.

- Evidence: `api/security_headers.go` (`noCacheHeaders`), `api/api.go` (`Router()` middleware chain), `api/api_test.go` (`TestNoCacheHeaders_*`).

### CSP permitted inline styles (`was P1 → Addressed`)

The Content-Security-Policy `style-src` directive previously included `'unsafe-inline'`, allowing any injected `<style>` element or inline `style` attribute to execute — a common XSS escalation vector. The fix replaces `'unsafe-inline'` with per-request cryptographic nonces:

- A 16-byte base64-encoded nonce is generated per request in the `SecurityHeaders` middleware and stored in the request context.
- The web handler injects the nonce into served HTML via a `<meta name="csp-nonce">` tag so client-side code can read it.
- The only component with runtime `<style>` injection (`ChartStyle`) applies the nonce attribute, allowing its styles to load under the stricter policy.
- Additional hardening directives added: `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`.

- Evidence: `api/security_headers.go` (`generateCSPNonce`, `CSPNonce`, nonce in CSP header), `web/web.go` (`NonceFunc`, nonce meta tag injection), `web/src/lib/utils.ts` (`getCSPNonce`), `web/src/components/ui/chart.tsx` (nonce on `<style>`), `api/api_test.go` (`TestCSP_NoUnsafeInline`, `TestCSP_ContainsNonce`, `TestCSP_NonceIsUniquePerRequest`, `TestCSP_NonceAvailableInContext`, `TestCSP_TighterDirectives`).

### Argon2id defaults below contemporary hardware targets (`was Low → Addressed`)

The default Argon2id parameters were `Time=1, Memory=64 MiB`, which — while not broken — fell below OWASP Password Storage Cheat Sheet recommended baselines for Argon2id. The fix raises defaults and introduces named profiles with enforced minimums:

- **Default raised** to `Time=3, Memory=64 MiB, Parallelism=4` (the "moderate" profile), aligned with OWASP guidance.
- **Named profiles** — three deployment-appropriate presets: `interactive` (t=2, m=19 MiB — OWASP minimum), `moderate` (t=3, m=64 MiB — production default), and `sensitive` (t=4, m=128 MiB — high-value secrets).
- **CLI flag** `--kdf-profile` allows operators to select a profile at server startup. Backup and credential export blobs now use the `sensitive` profile.
- **Validation** — `ValidateArgon2idParams` enforces minimum thresholds (Time≥1, Memory≥19 MiB, Parallelism≥1) to prevent dangerously weak configurations.
- **Backward compatibility** — existing vaults are unaffected because KDF parameters are persisted in vault state at creation time. Only newly created vaults and credentials use the updated defaults.

- Evidence: `internal/util/argon2id.go` (`DefaultArgon2idParams`, `Argon2idProfile`, `ValidateArgon2idParams`, minimum constants), `crypto/keys.go` (profile/validation exposure), `vault/credentials.go` (`WithCredentialKDFParams`, `exportKDFParams` → sensitive), `api/handlers.go` (`backupKDFParams` → sensitive), `api/api.go` (`WithKDFProfile`, `kdfParamsForNewVault`), `api/auth_handlers.go` (Register uses configured profile), `cmd/ironhand/cmd/server.go` (`--kdf-profile` flag), `internal/util/util_test.go` (`TestDefaultArgon2idParams_MeetsOWASPMinimums`, `TestArgon2idProfile_*`, `TestValidateArgon2idParams`), `vault/vault_test.go` (`TestVault_BackwardCompat_OldKDFParams`, `TestVault_WithCredentialKDFParams_OverridesDefault`), `api/api_test.go` (`TestWithKDFProfile_*`).

### Sensitive secrets handled as Go strings in auth paths (`was Medium → Addressed`)

Several authentication paths created and passed sensitive secrets as Go `string` values which are immutable and cannot be zeroed. This widened the residual memory exposure window for derived passphrases, ceremony state, and plaintext intermediates. The fix uses memguard (already in use in the `vault/` package) to protect secrets consistently throughout the `api/` layer:

- **Derived secrets in locked memory** — `combineLoginPassphrase` and `deriveSessionPassphrase` now return `*memguard.LockedBuffer` (mlock'd, guard-paged, deterministically wiped via `Destroy()`). All callers use `defer buf.Destroy()`.
- **Ceremony state encrypted at rest** — `webauthnCeremonyState.SecretKey` and `.LoginPassphrase` changed from plain `string` to `*memguard.Enclave` (encrypted in memory). Secrets sit in the ceremony map for up to 5 minutes but are only decrypted briefly when the ceremony completes.
- **`[]byte` passphrase variants** — Added `ExportCredentialsBytes`/`ImportCredentialsBytes` in `vault/credentials.go` to accept `[]byte` passphrases from locked buffers without creating intermediate heap-allocated strings.
- **Missing `[]byte` wipes fixed** — `defer util.WipeBytes(plaintext)` added in ExportVault and ImportVault handlers; TOTP decoded secrets and HMAC sums wiped after use; decrypted session data wiped in persistent session store.
- **Session store cleanup** — `MemorySessionStore.Delete` now zeros sensitive string fields (CredentialsBlob, PendingTOTPSecret, WebAuthnSessionData) before map removal (best-effort reference removal).
- **Known limitation** — Go string immutability means JSON-decoded request fields (`req.Passphrase`) and HTTP cookie values cannot be truly wiped. Best-effort reference zeroing (`req.Passphrase = ""`) is applied to shorten the reachability window but cannot guarantee the GC-managed backing array is cleared.

- Evidence: `api/middleware.go` (`combineLoginPassphrase`, `deriveSessionPassphrase` → `*memguard.LockedBuffer`, `credentialsFromSessionCookie` uses `ImportCredentialsBytes`), `api/webauthn.go` (`webauthnCeremonyState` fields → `*memguard.Enclave`), `vault/credentials.go` (`ExportCredentialsBytes`, `ImportCredentialsBytes`), `api/auth_handlers.go` (all handlers use locked buffers + string zeroing), `api/handlers.go` (`defer util.WipeBytes(plaintext)` in Export/Import), `api/totp.go` (wipe decoded secret + HMAC sum), `api/session_store_memory.go` (field zeroing on Delete), `api/session_store_persistent.go` (wipe decrypted data), `vault/credentials_test.go` (`TestExportImportCredentialsBytes_*`), `api/webauthn_test.go` (`TestCeremonyState_SecretsInEnclaves`).

## Operational Recommendations

1. When deploying behind a reverse proxy, set `--trusted-proxies` to the CIDR ranges of your proxy/load balancer so that rate limiters see real client IPs instead of the proxy's address.
2. Set `--audit-retention-days` and/or `--audit-max-entries` explicitly in production.
3. Choose hardware-backed PKI key custody (PKCS#11 or custom KMS backend) for high-assurance CA deployments.
4. Review the `--kdf-profile` setting. The default `moderate` profile is appropriate for most deployments. Use `sensitive` for environments with high-value secrets where additional derivation latency is acceptable.
5. For maximum secret protection, deploy with `mlockall(2)` support (e.g., `--rlimit-memlock=unlimited` or `LimitMEMLOCK=infinity` in systemd) so that memguard's locked buffers are never swapped to disk.
