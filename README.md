# IronHand

A secure, encrypted vault library for Go with member-based access control, epoch-based key rotation, and rollback detection.

## Features

- **AES-256-GCM encryption** with Authenticated Associated Data (AAD) on every layer
- **Two-secret-key MUK derivation** — requires both a passphrase and a secret key (Argon2id + HKDF + XOR)
- **X25519 member key wrapping** — per-member public-key sealed KEK distribution
- **Epoch-based key rotation** — adding or revoking members rotates the vault KEK and re-wraps all items atomically
- **Rollback detection** — persistent epoch cache detects storage rollback attacks
- **Credential export/import** — single encrypted blob for portable vault access
- **Vault export/import** — full vault backup encrypted with a user-provided passphrase; requires owner access and step-up authentication
- **Pluggable storage** — in-memory (testing), BBolt (default), or PostgreSQL backends
- **Built-in Certificate Authority** — turn any vault into a CA, issue/revoke/renew X.509 certificates, generate CRLs, and sign CSRs; optional PKCS#11 HSM backend for hardware-protected CA keys
- **WebAuthn/Passkey MFA** — phishing-resistant second factor using browser passkeys (replaces TOTP as the recommended MFA method); passkey management (list, label, delete) with safety checks
- **TOTP MFA** — time-based one-time passwords as an alternative second factor; can be enabled and disabled
- **Step-up authentication** — time-limited re-authentication (5-minute TTL) via TOTP or passkey for sensitive operations like vault export
- **Recovery codes** — one-time-use backup codes for account recovery when MFA devices are unavailable
- **Passkey policy** — configurable per-account policy (`optional` or `required`) controlling whether passkey authentication is mandatory
- **Vault sharing** — invite-based vault sharing with configurable member roles; time-limited invite tokens
- **Cross-vault search** — search items across all vaults by name, type, or content (sensitive fields excluded from results)
- **CSRF protection** — double-submit cookie pattern on all mutating endpoints
- **Security headers** — CSP with per-request nonces, HSTS, X-Frame-Options, and Permissions-Policy on every response
- **Rate limiting** — per-account, per-IP, and global login throttling with exponential backoff
- **Session management** — 24-hour absolute expiry with 30-minute idle timeout; optional persistent session storage
- **Private key redaction** — certificate private keys returned as `[REDACTED]` via the standard API; dedicated owner-only endpoint for retrieval
- **Encrypted audit trail** — AES-256-GCM encrypted audit entries with tamper-evident hash chains; offline verification CLI
- **Audit webhook** — forward audit events in real-time to external SIEM/webhook endpoints
- **Anomaly detection** — automated alerting for login failure spikes and bulk data exports

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

- **[Design](docs/design.md)** — Architecture, vault lifecycle, sessions, membership, storage backends, REST API, PKI, and audit system
- **[Encryption](docs/encryption.md)** — Cryptographic schemes: MUK derivation, key hierarchy, AES-256-GCM, AAD construction, field-level encryption, epoch rotation, and credential export
- **[Threat Model](docs/threatmodel.md)** — Current and resolved security issues, operational recommendations

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/jmcleod/ironhand/storage/memory"
    "github.com/jmcleod/ironhand/vault"
)

func main() {
    ctx := context.Background()

    // Create credentials from a passphrase
    creds, err := vault.NewCredentials("correct horse battery staple")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Secret Key: %s\n", creds.SecretKey())

    // Create a vault
    repo := memory.NewRepository()
    v := vault.New("my-vault", repo)
    session, err := v.Create(ctx, creds)
    if err != nil {
        log.Fatal(err)
    }
    defer session.Close()

    // Store and retrieve an encrypted item
    _ = session.Put(ctx, "api-key", []byte("sk-secret-value"), vault.WithContentType("text/plain"))
    plaintext, _ := session.Get(ctx, "api-key")
    fmt.Printf("Decrypted: %s\n", plaintext)

    // List items
    ids, _ := session.List(ctx)
    fmt.Printf("Items: %v\n", ids)

    // Export credentials for later use
    blob, _ := vault.ExportCredentials(creds, "export-password")

    // Import and re-open
    imported, _ := vault.ImportCredentials(blob, "export-password")
    session2, _ := v.Open(ctx, imported)
    defer session2.Close()
}
```

## Architecture

### Key Hierarchy

```
Passphrase + SecretKey
        │
        ▼
  MUK (Master Unlock Key)         Argon2id(passphrase) ⊕ HKDF(secretKey)
        │
        ▼
  Record Key                       HKDF(MUK, vaultID)
        │
        ▼
  KEK (Key Encryption Key)        Random 32-byte, wrapped per-member via X25519
        │
        ▼
  DEK (Data Encryption Key)       Random 32-byte per item, wrapped with KEK
        │
        ▼
  Ciphertext                       AES-256-GCM with structured AAD
```

### Epoch Rotation

When a member is added or revoked, the vault advances to a new epoch:

1. Generate a fresh KEK
2. Re-wrap the KEK for all active members using X25519
3. Re-wrap all item DEKs with the new KEK
4. Update vault state atomically via batch transaction

Revoked members cannot decrypt items at the new epoch.

### Storage

All records are stored as AES-256-GCM encrypted envelopes with AAD that binds the ciphertext to its vault, record type, record ID, epoch, and version. This prevents record swapping and cross-vault replay attacks.

Three backends are provided:

- `storage/memory` — in-memory, suitable for testing
- `storage/bbolt` — persistent BBolt-backed storage (default)
- `storage/postgres` — PostgreSQL-backed storage for multi-instance deployments

#### Running with PostgreSQL

The server defaults to BBolt. To use PostgreSQL instead, pass `--storage postgres` and a connection string:

```sh
# Start a local PostgreSQL (e.g. via Docker Compose)
docker compose up -d postgres

# Run IronHand with PostgreSQL
go run ./cmd/ironhand server --storage postgres \
    --postgres-dsn "postgres://ironhand:ironhand@localhost:5432/ironhand?sslmode=disable"
```

The DSN can also be provided via the `IRONHAND_POSTGRES_DSN` environment variable.

To run the full stack (IronHand + PostgreSQL) with Docker Compose:

```sh
docker compose up
```

The schema is created automatically on first startup. Pool parameters can be tuned via the DSN (e.g. `pool_max_conns=20`).

### Threat Model

IronHand protects against:

- **Data-at-rest compromise** — all content is AES-256-GCM encrypted
- **Passphrase-only attacks** — MUK requires both passphrase and secret key
- **Member revocation** — epoch rotation ensures revoked members lose access to new and re-wrapped data
- **Storage rollback** — epoch cache detects if storage is reverted to a prior state
- **Record swapping** — AAD binds ciphertext to its identity, preventing substitution
- **Brute-force** — Argon2id with configurable memory-hard parameters
- **Phishing** — WebAuthn/passkey MFA with configurable policy (optional or required)
- **MFA lockout** — one-time recovery codes for account access when MFA devices are unavailable
- **Privilege escalation** — step-up authentication (5-minute TTL) required for sensitive operations like vault export
- **CSRF attacks** — double-submit cookie token required on all mutating endpoints
- **Clickjacking** — X-Frame-Options: DENY and CSP frame-ancestors 'none'
- **XSS** — Content Security Policy with per-request cryptographic nonces; no `unsafe-inline`
- **Credential leakage** — header-based auth disabled by default; private keys redacted in API responses
- **Session fixation** — CSRF token rotated on login; idle timeout invalidates stale sessions
- **Session store compromise** — persistent session encryption key wrapped with external key; session passphrase split across server and client cookie via HMAC-SHA256
- **IP spoofing via proxy headers** — proxy headers ignored by default; `--trusted-proxies` must be explicitly set to trust forwarded headers from known CIDR ranges
- **Cache-based data leakage** — all API responses set `Cache-Control: no-store` to prevent browsers and proxies from persisting sensitive data to disk
- **Audit tampering** — tamper-evident SHA-256 hash chains with offline verification tooling and optional SIEM webhook forwarding

IronHand does **not** protect against:

- Compromise of a running process (memory dumps)
- Side-channel attacks on the host
- Denial of service at the storage layer

See [docs/threatmodel.md](docs/threatmodel.md) for the full threat model with mitigations and resolved issues.

## Security

### CSRF Protection

All mutating API requests (POST, PUT, DELETE) that use cookie-based session authentication require a `X-CSRF-Token` header matching the value of the `ironhand_csrf` cookie. The token is set automatically on login/register and cleared on logout. GET requests and header-authenticated requests are exempt.

### Rate Limiting

**Login** endpoints enforce three levels of rate limiting:

- **Per-account** — 5 consecutive failures trigger exponential backoff (1 min → 15 min max)
- **Per-IP** — 20 failures from the same IP trigger IP-level throttling
- **Global** — 100 failures per minute trigger a global cooldown

Rate limits apply to both password-based and WebAuthn login flows.

**Registration** endpoints enforce separate per-IP and global rate limiting before any expensive Argon2id KDF work is performed:

- **Per-IP** — 5 registrations trigger exponential backoff (5 min → 1 hr max)
- **Global** — 50 registrations per minute trigger a global cooldown

MFA setup routes share the registration per-IP limiter to prevent TOTP secret generation spam.

#### Trusted Proxies

By default, proxy headers (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`) are **ignored** and the TCP peer address (`RemoteAddr`) is always used for client IP extraction. This fail-safe default prevents IP spoofing when the server is deployed directly or without a properly configured reverse proxy.

When deploying behind a reverse proxy, configure `--trusted-proxies` so that rate limiters see real client IPs:

```sh
ironhand server --trusted-proxies 10.0.0.0/8,172.16.0.0/12
```

When configured, proxy headers are only honored if the request originates from one of the specified CIDR ranges. Requests from other sources still use the TCP peer address directly.

### Session Management

Sessions have a 24-hour absolute expiry and a 30-minute idle timeout (configurable via `--idle-timeout`). Session storage defaults to in-memory but can be switched to persistent encrypted storage via `--session-storage persistent`.

**Persistent session storage** requires an externally-provided 32-byte wrapping key to protect the session encryption key at rest. The wrapping key can be provided via:

| Source | Format |
|---|---|
| `--session-key` flag | Hex-encoded 32 bytes (64 hex characters) |
| `IRONHAND_SESSION_KEY` env var | Hex-encoded 32 bytes |
| `--session-key-file` flag | Raw 32 bytes on disk |

Example:

```sh
# Generate a wrapping key
openssl rand -hex 32 > session.key

# Start with persistent sessions
ironhand server --session-storage persistent --session-key-file session.key
```

The server will refuse to start if `--session-storage=persistent` is selected without a wrapping key. The session passphrase is derived from a split-secret scheme using both a server-side session ID and a client-held cookie, ensuring that neither a session store compromise nor a stolen cookie alone can reconstruct vault credentials.

### Audit

#### Retention

Per-vault audit retention can be enforced automatically with:

- `--audit-retention-days N` — drop audit entries older than `N` days
- `--audit-max-entries N` — keep only the newest `N` entries per vault

Both settings are optional and disabled by default (`0`). When pruning occurs, retained entries are re-anchored to a fresh genesis hash so the exported audit chain remains verifiable.

#### Webhook Forwarding

Audit events can be forwarded in real-time to an external SIEM or webhook endpoint:

```sh
ironhand server --audit-webhook-url https://siem.example.com/ingest \
    --audit-webhook-header "Authorization: Bearer my-token"
```

Events are dispatched asynchronously via a bounded queue (capacity 1024). If the queue is full, events are dropped with a warning log. The dispatcher retries once on 5xx errors; 4xx errors are not retried.

#### Offline Verification

Exported audit chains can be verified offline using the CLI:

```sh
# Verify an exported audit log
ironhand audit verify /path/to/audit-export.json

# Machine-readable JSON output
ironhand audit verify --json /path/to/audit-export.json
```

Verification checks:
1. **Genesis anchor** — first entry links to the zero hash
2. **Chain continuity** — each entry's `prev_hash` matches `SHA-256(prevID || prevHash || prevCreatedAt)`
3. **No duplicate IDs** — all entry IDs are unique
4. **Monotonic timestamps** — `created_at` values are non-decreasing
5. **Consistent vault IDs** — all entries match the top-level `vault_id`

Exit codes: `0` = valid, `1` = invalid, `2` = file/parse error.

### Header-Based Authentication

The `X-Credentials` / `X-Passphrase` header authentication method is **disabled by default**. Enable it only for non-browser API clients via `--enable-header-auth`.

## Certificate Authority (PKI)

Any vault can be initialized as a Certificate Authority. CA private keys, certificates, and revocation lists are stored as encrypted vault items, benefiting from the same AES-256-GCM field-level encryption, epoch-based key rotation, and access control as all other vault data.

### Concepts

- **Root CA** — A self-signed CA that acts as the trust anchor. Suitable for internal PKI, development environments, or private infrastructure.
- **Intermediate CA** — A CA whose certificate is signed by another authority. Useful for delegating certificate issuance while keeping the root CA offline.
- **Certificate items** — X.509 certificates stored as first-class vault items with structured fields (subject, issuer, serial number, validity dates, PEM-encoded certificate and private key).
- **Revocation** — Certificates can be revoked, which updates their status and adds them to the CA's revocation list.
- **CRL (Certificate Revocation List)** — Cached and served read-only via `GET /crl.pem`. Regenerated automatically on revocation or explicitly via `POST /crl`.

### How It Works

1. **Initialize a CA** — Choose a vault and initialize it as a Root or Intermediate CA. This generates an ECDSA P-256 keypair, creates a self-signed CA certificate, and stores the CA state in reserved vault items.
2. **Issue certificates** — Specify a Common Name, SANs (DNS names, IPs, emails), key usages, and validity period. The CA signs a new leaf certificate with a fresh ECDSA P-256 keypair. Both the certificate and private key are stored as an encrypted vault item.
3. **Revoke certificates** — Mark a certificate as revoked with an optional reason code. The certificate's status field is updated and it is added to the revocation list.
4. **Renew certificates** — Reissue a certificate with the same subject and SANs but a new serial number and validity period. The old certificate is automatically revoked.
5. **Generate CRLs** — `POST /crl` regenerates the CRL (incrementing CRLNumber) and caches it. `GET /crl.pem` returns the cached CRL without mutating CA state. CRLs are also auto-regenerated after each revocation.
6. **Sign CSRs** — Accept a PEM-encoded Certificate Signing Request, validate it, and issue a signed certificate using the requester's public key (no private key is generated or stored).
7. **Import certificates** — Manually add externally-issued certificates to the vault for centralized management.

### CA Storage Model

CA state is stored in reserved items within the vault (prefixed with `__ca_`). These items are hidden from the regular item listing API and protected from direct CRUD operations.

| Reserved Item | Contents |
|---|---|
| `__ca_state` | CA metadata: subject, validity, next serial number, CRL number, intermediate flag |
| `__ca_cert` | PEM-encoded CA certificate |
| `__ca_key` | PEM-encoded CA private key (encrypted by vault field-level encryption) |
| `__ca_revocations` | JSON array of revocation entries (serial, timestamp, reason, item ID) |
| `__ca_crl` | Most recently generated PEM-encoded CRL (cached for read-only retrieval) |

### HSM-Backed PKI Keys (PKCS#11)

By default, PKI private keys are generated in software and stored encrypted in the vault. For production deployments requiring hardware-level key protection, IronHand supports PKCS#11 hardware security modules. When enabled, private keys are generated and held inside the HSM — the vault stores only a `PKCS11:<label>` reference string, and key material never leaves the hardware.

PKCS#11 support requires CGo and the `pkcs11` build tag:

```sh
go build -tags pkcs11 -o ironhand ./cmd/ironhand/
```

#### Configuration

| Flag | Environment Variable | Description |
|---|---|---|
| `--pki-keystore` | | Key store backend: `software` (default) or `pkcs11` |
| `--pkcs11-module` | `IRONHAND_PKCS11_MODULE` | Path to PKCS#11 shared library (`.so` / `.dylib`) |
| `--pkcs11-token-label` | `IRONHAND_PKCS11_TOKEN_LABEL` | HSM token label |
| `--pkcs11-pin` | `IRONHAND_PKCS11_PIN` | User PIN for the token |

Example:

```sh
ironhand server --pki-keystore pkcs11 \
    --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
    --pkcs11-token-label ironhand \
    --pkcs11-pin 1234
```

#### SoftHSM2 (Development/Testing)

[SoftHSM2](https://www.opendnssec.org/softhsm/) is a software PKCS#11 implementation suitable for development and testing. It provides the same PKCS#11 interface as a hardware HSM without requiring physical hardware.

**Install:**

```sh
# macOS (Homebrew)
brew install softhsm

# Ubuntu / Debian
sudo apt-get install -y softhsm2
```

**Initialize a token:**

```sh
softhsm2-util --init-token --free --label "ironhand" --pin 1234 --so-pin 0000
```

**Module paths:**

| Platform | Path |
|---|---|
| macOS (Homebrew, Apple Silicon) | `/opt/homebrew/lib/softhsm/libsofthsm2.so` |
| macOS (Homebrew, Intel) | `/usr/local/lib/softhsm/libsofthsm2.so` |
| Ubuntu / Debian | `/usr/lib/softhsm/libsofthsm2.so` |

**Start the server with SoftHSM2:**

```sh
go build -tags pkcs11 -o ironhand ./cmd/ironhand/

./ironhand server --pki-keystore pkcs11 \
    --pkcs11-module /opt/homebrew/lib/softhsm/libsofthsm2.so \
    --pkcs11-token-label ironhand \
    --pkcs11-pin 1234
```

**Running PKCS#11 tests:**

```sh
softhsm2-util --init-token --free --label "ironhand-test" --pin 1234 --so-pin 0000

SOFTHSM2_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
SOFTHSM2_TOKEN_LABEL=ironhand-test \
SOFTHSM2_PIN=1234 \
go test -tags pkcs11 ./pki/ -v -run TestPKCS11
```

#### How Reference Strings Work

When `--pki-keystore=pkcs11` is set, the PKI subsystem stores a reference to the HSM key instead of the actual key material:

1. **Key generation** — `GenerateKey()` creates an ECDSA P-256 key pair inside the HSM with a label like `ironhand-<uuid>`.
2. **Storage** — `ExportPEM()` returns `PKCS11:ironhand-<uuid>` (not PEM data). This reference string is stored in the vault's encrypted `private_key` field.
3. **Retrieval** — `ImportPEM()` detects the `PKCS11:` prefix, looks up the key by label in the HSM, and returns a `crypto.Signer` backed by the hardware.

The vault encryption, access control, and audit trail work identically regardless of whether the key store is software or hardware-backed.

### Certificate Item Fields

Each issued certificate is stored as a vault item of type `certificate` with the following well-known fields:

| Field | Description |
|---|---|
| `subject` | Distinguished Name (e.g., `CN=example.com, O=Acme`) |
| `issuer` | Issuer Distinguished Name |
| `serial_number` | Hex-encoded serial number |
| `not_before` | Validity start (RFC 3339) |
| `not_after` | Validity end (RFC 3339) |
| `certificate` | PEM-encoded X.509 certificate |
| `private_key` | PEM-encoded ECDSA private key (redacted to `[REDACTED]` in API responses; use `/private-key` endpoint) |
| `chain` | PEM bundle of intermediate certificates (optional) |
| `fingerprint_sha256` | Hex SHA-256 fingerprint of the DER-encoded certificate |
| `key_algorithm` | Key algorithm (e.g., `ECDSA P-256`) |
| `status` | `active`, `expired`, or `revoked` |
| `issued_by_ca` | `true` if issued by this vault's CA |
| `previous_item_id` | Links to the predecessor certificate after renewal |
| `notes` | Optional user notes |

### PKI REST API

All PKI endpoints are scoped to a vault and require session authentication.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/vaults/{vaultID}/pki/init` | Initialize the vault as a CA |
| `GET` | `/api/v1/vaults/{vaultID}/pki/info` | Get CA status and metadata |
| `GET` | `/api/v1/vaults/{vaultID}/pki/ca.pem` | Download the CA certificate (PEM) |
| `POST` | `/api/v1/vaults/{vaultID}/pki/issue` | Issue a new certificate |
| `POST` | `/api/v1/vaults/{vaultID}/pki/items/{itemID}/revoke` | Revoke a certificate |
| `POST` | `/api/v1/vaults/{vaultID}/pki/items/{itemID}/renew` | Renew a certificate |
| `GET` | `/api/v1/vaults/{vaultID}/pki/crl.pem` | Download the cached CRL (PEM, read-only) |
| `POST` | `/api/v1/vaults/{vaultID}/pki/crl` | Regenerate CRL (state-mutating, CSRF-protected) |
| `POST` | `/api/v1/vaults/{vaultID}/pki/sign-csr` | Sign a Certificate Signing Request |

### PKI Go Package

The `pki` package provides programmatic access to CA operations:

| Function | Description |
|---|---|
| `pki.InitCA(ctx, session, subject, validityYears, isIntermediate)` | Initialize a vault as a CA |
| `pki.IssueCertificate(ctx, session, request)` | Issue a signed certificate |
| `pki.RevokeCertificate(ctx, session, itemID, reason)` | Revoke a certificate |
| `pki.RenewCertificate(ctx, session, itemID, validityDays)` | Renew a certificate (revokes the old one) |
| `pki.GenerateCRL(ctx, session)` | Regenerate the CRL, increment CRLNumber, and cache it |
| `pki.LoadCRL(ctx, session)` | Return the most recently cached CRL (read-only) |
| `pki.GetCACertificate(ctx, session)` | Retrieve the CA certificate PEM |
| `pki.GetCAInfo(ctx, session)` | Get CA metadata and certificate count |
| `pki.SignCSR(ctx, session, csrPEM, validityDays, extKeyUsages)` | Sign a CSR |
| `pki.ParseCertificatePEM(certPEM)` | Parse a PEM certificate into structured fields |

## API Overview

### REST API

The service provides a REST API exposed by default on port `8443`.

- **Auth**:
  - `POST /api/v1/auth/register` — register (passphrase → secret key + session cookie)
  - `POST /api/v1/auth/login` — login (passphrase + secret key + optional `totp_code` / `recovery_code` → session cookie)
  - `POST /api/v1/auth/logout` — logout (clear session)
  - `GET /api/v1/auth/2fa` — get 2FA status
  - `POST /api/v1/auth/2fa/setup` — begin TOTP setup (returns temporary secret + QR URI)
  - `POST /api/v1/auth/2fa/enable` — verify TOTP code and enable 2FA
  - `POST /api/v1/auth/2fa/disable` — disable TOTP 2FA (requires valid code)
  - `GET /api/v1/auth/settings` — get auth settings (passkey policy, TOTP status)
  - `PUT /api/v1/auth/settings` — update auth settings (passkey policy: `optional` or `required`)
  - `GET /api/v1/auth/recovery-codes` — get recovery code status (count of unused codes)
  - `POST /api/v1/auth/recovery-codes` — generate new recovery codes (replaces existing)
  - `POST /api/v1/auth/step-up` — step-up authentication via TOTP (5-minute TTL)
  - `POST /api/v1/auth/step-up/passkey/begin` — begin step-up via passkey
  - `POST /api/v1/auth/step-up/passkey/finish` — complete step-up via passkey
- **WebAuthn/Passkeys**:
  - `GET /api/v1/auth/webauthn/status` — passkey status and credential count
  - `POST /api/v1/auth/webauthn/register/begin` — start passkey registration ceremony
  - `POST /api/v1/auth/webauthn/register/finish` — complete passkey registration
  - `POST /api/v1/auth/webauthn/login/begin` — start passkey login ceremony
  - `POST /api/v1/auth/webauthn/login/finish` — complete passkey login (sets session cookie)
  - `GET /api/v1/auth/webauthn/credentials` — list registered passkeys (label, created, last used)
  - `PUT /api/v1/auth/webauthn/credentials/{credentialID}` — update passkey label
  - `DELETE /api/v1/auth/webauthn/credentials/{credentialID}` — delete passkey (prevents deleting last passkey without recovery codes)
- **Vaults**:
  - `POST /api/v1/vaults` — create a vault (server-generated ID)
  - `GET /api/v1/vaults` — list vaults (paginated)
  - `DELETE /api/v1/vaults/{vaultID}` — delete a vault
  - `POST /api/v1/vaults/{vaultID}/open` — open vault session
- **Items**:
  - `POST /api/v1/vaults/{vaultID}/items/{itemID}` — create item
  - `GET /api/v1/vaults/{vaultID}/items/{itemID}` — get item
  - `PUT /api/v1/vaults/{vaultID}/items/{itemID}` — update item
  - `DELETE /api/v1/vaults/{vaultID}/items/{itemID}` — delete item
  - `GET /api/v1/vaults/{vaultID}/items` — list items (paginated)
  - `GET /api/v1/vaults/{vaultID}/items/versions` — item version manifest (lightweight, no decryption)
  - `GET /api/v1/vaults/{vaultID}/items/{itemID}/history` — list item history
  - `GET /api/v1/vaults/{vaultID}/items/{itemID}/history/{version}` — get specific version
  - `GET /api/v1/vaults/{vaultID}/items/{itemID}/private-key` — get private key (owner only)
- **Members & Sharing**:
  - `GET /api/v1/vaults/{vaultID}/members` — list members
  - `POST /api/v1/vaults/{vaultID}/members` — add member
  - `PUT /api/v1/vaults/{vaultID}/members/{memberID}` — change member role
  - `DELETE /api/v1/vaults/{vaultID}/members/{memberID}` — revoke member
  - `POST /api/v1/vaults/{vaultID}/invites` — create invite (with role)
  - `GET /api/v1/vaults/{vaultID}/invites` — list active invites
  - `DELETE /api/v1/vaults/{vaultID}/invites/{token}` — cancel invite
  - `GET /api/v1/invites/{token}` — get invite info (no vault auth required)
  - `POST /api/v1/invites/{token}/accept` — accept invite
- **Export/Import**:
  - `POST /api/v1/vaults/{vaultID}/export` — export vault (owner + step-up required)
  - `POST /api/v1/vaults/{vaultID}/import` — import vault data (multipart, 50 MiB limit)
- **Audit**:
  - `GET /api/v1/vaults/{vaultID}/audit` — audit trail (paginated; optional `item_id` filter)
  - `GET /api/v1/vaults/{vaultID}/audit/export` — export tamper-evident audit log with HMAC signature
- **Search**:
  - `GET /api/v1/search` — cross-vault item search (query: `q`, `type`, `vault_id`, `limit`, `offset`)
- **OpenAPI Spec**: `/api/v1/openapi.yaml`
- **Swagger UI**: `/api/v1/docs`
- **Redoc**: `/api/v1/redoc`

### Web UI

IronHand includes a browser-based Web UI in `/web` that uses the REST API.

- **Served by the Go server** at `/` (same host/port as the API)
- **Development docs**: `web/README.md`

To run the backend server:

```sh
go run ./cmd/ironhand server
```

Then open:

- `https://localhost:8443/` for the Web UI
- `https://localhost:8443/api/v1/openapi.yaml` for the OpenAPI spec

Important: the server only returns a user's secret key during registration. There is no API to reveal it later.

### Library Credentials

| Function | Description |
|---|---|
| `vault.NewCredentials(passphrase, ...opts)` | Generate new credentials with a fresh secret key and keypair |
| `vault.OpenCredentials(secretKey, passphrase, memberID, privateKey, ...opts)` | Reconstruct credentials from existing key material |
| `vault.ExportCredentials(creds, passphrase)` | Encrypt credentials into a portable blob |
| `vault.ImportCredentials(data, passphrase)` | Decrypt and reconstruct credentials from an export blob |

### Vault

| Method | Description |
|---|---|
| `vault.New(id, repo, ...opts)` | Create a vault handle |
| `v.Create(ctx, creds, ...opts)` | Initialize a new vault, returns a Session |
| `v.Open(ctx, creds)` | Open an existing vault, returns a Session |

### Session

| Method | Description |
|---|---|
| `s.Put(ctx, itemID, plaintext, ...opts)` | Encrypt and store a new item |
| `s.Get(ctx, itemID)` | Retrieve and decrypt an item |
| `s.Update(ctx, itemID, plaintext, ...opts)` | Re-encrypt an existing item (CAS protected) |
| `s.List(ctx)` | List all item IDs in the vault |
| `s.Delete(ctx, itemID)` | Delete an item from the vault |
| `s.AddMember(ctx, memberID, pubKey, role)` | Add a member and rotate epoch |
| `s.RevokeMember(ctx, memberID)` | Revoke a member and rotate epoch |
| `s.Close()` | Wipe session key material from memory |

### Member Roles

- `owner` — full admin access (add/revoke members, read, write)
- `writer` — read and write items
- `reader` — read-only access
