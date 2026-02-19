# IronHand

A secure, encrypted vault library for Go with member-based access control, epoch-based key rotation, and rollback detection.

## Features

- **AES-256-GCM encryption** with Authenticated Associated Data (AAD) on every layer
- **Two-secret-key MUK derivation** — requires both a passphrase and a secret key (Argon2id + HKDF + XOR)
- **X25519 member key wrapping** — per-member public-key sealed KEK distribution
- **Epoch-based key rotation** — adding or revoking members rotates the vault KEK and re-wraps all items atomically
- **Rollback detection** — persistent epoch cache detects storage rollback attacks
- **Credential export/import** — single encrypted blob for portable vault access
- **Pluggable storage** — in-memory (testing), BBolt (default), or PostgreSQL backends
- **Built-in Certificate Authority** — turn any vault into a CA, issue/revoke/renew X.509 certificates, generate CRLs, and sign CSRs
- **WebAuthn/Passkey MFA** — phishing-resistant second factor using browser passkeys (replaces TOTP as the recommended MFA method)
- **CSRF protection** — double-submit cookie pattern on all mutating endpoints
- **Security headers** — CSP, HSTS, X-Frame-Options, and Permissions-Policy on every response
- **Rate limiting** — per-account, per-IP, and global login throttling with exponential backoff
- **Session management** — 24-hour absolute expiry with 30-minute idle timeout; optional persistent session storage
- **Private key redaction** — certificate private keys returned as `[REDACTED]` via the standard API; dedicated owner-only endpoint for retrieval
- **Encrypted audit trail** — AES-256-GCM encrypted audit entries with tamper-evident hash chains
- **Anomaly detection** — automated alerting for login failure spikes and bulk data exports

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

- **[Design](docs/design.md)** — Architecture, vault lifecycle, sessions, membership, storage backends, REST API, PKI, and audit system
- **[Encryption](docs/encryption.md)** — Cryptographic schemes: MUK derivation, key hierarchy, AES-256-GCM, AAD construction, field-level encryption, epoch rotation, and credential export

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
- **CSRF attacks** — double-submit cookie token required on all mutating endpoints
- **Clickjacking** — X-Frame-Options: DENY and CSP frame-ancestors 'none'
- **Credential leakage** — header-based auth disabled by default; private keys redacted in API responses
- **Session fixation** — CSRF token rotated on login; idle timeout invalidates stale sessions
- **Session store compromise** — persistent session encryption key wrapped with external key; session passphrase split across server and client cookie via HMAC-SHA256

IronHand does **not** protect against:

- Compromise of a running process (memory dumps)
- Side-channel attacks on the host
- Denial of service at the storage layer

## Security

### CSRF Protection

All mutating API requests (POST, PUT, DELETE) that use cookie-based session authentication require a `X-CSRF-Token` header matching the value of the `ironhand_csrf` cookie. The token is set automatically on login/register and cleared on logout. GET requests and header-authenticated requests are exempt.

### Rate Limiting

Login endpoints enforce three levels of rate limiting:

- **Per-account** — 5 consecutive failures trigger exponential backoff (1 min → 30 min max)
- **Per-IP** — 20 failures from the same IP trigger IP-level throttling
- **Global** — 100 failures per minute trigger a global cooldown

Rate limits apply to both password-based and WebAuthn login flows.

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

### Header-Based Authentication

The `X-Credentials` / `X-Passphrase` header authentication method is **disabled by default**. Enable it only for non-browser API clients via `--enable-header-auth`.

## Certificate Authority (PKI)

Any vault can be initialized as a Certificate Authority. CA private keys, certificates, and revocation lists are stored as encrypted vault items, benefiting from the same AES-256-GCM field-level encryption, epoch-based key rotation, and access control as all other vault data.

### Concepts

- **Root CA** — A self-signed CA that acts as the trust anchor. Suitable for internal PKI, development environments, or private infrastructure.
- **Intermediate CA** — A CA whose certificate is signed by another authority. Useful for delegating certificate issuance while keeping the root CA offline.
- **Certificate items** — X.509 certificates stored as first-class vault items with structured fields (subject, issuer, serial number, validity dates, PEM-encoded certificate and private key).
- **Revocation** — Certificates can be revoked, which updates their status and adds them to the CA's revocation list.
- **CRL (Certificate Revocation List)** — Generated on demand from the CA's revocation records. Clients can fetch the CRL to verify certificate validity.

### How It Works

1. **Initialize a CA** — Choose a vault and initialize it as a Root or Intermediate CA. This generates an ECDSA P-256 keypair, creates a self-signed CA certificate, and stores the CA state in reserved vault items.
2. **Issue certificates** — Specify a Common Name, SANs (DNS names, IPs, emails), key usages, and validity period. The CA signs a new leaf certificate with a fresh ECDSA P-256 keypair. Both the certificate and private key are stored as an encrypted vault item.
3. **Revoke certificates** — Mark a certificate as revoked with an optional reason code. The certificate's status field is updated and it is added to the revocation list.
4. **Renew certificates** — Reissue a certificate with the same subject and SANs but a new serial number and validity period. The old certificate is automatically revoked.
5. **Generate CRLs** — Produce a PEM-encoded CRL containing all revoked certificates, signed by the CA.
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
| `GET` | `/api/v1/vaults/{vaultID}/pki/crl.pem` | Generate and download the CRL (PEM) |
| `POST` | `/api/v1/vaults/{vaultID}/pki/sign-csr` | Sign a Certificate Signing Request |

### PKI Go Package

The `pki` package provides programmatic access to CA operations:

| Function | Description |
|---|---|
| `pki.InitCA(ctx, session, subject, validityYears, isIntermediate)` | Initialize a vault as a CA |
| `pki.IssueCertificate(ctx, session, request)` | Issue a signed certificate |
| `pki.RevokeCertificate(ctx, session, itemID, reason)` | Revoke a certificate |
| `pki.RenewCertificate(ctx, session, itemID, validityDays)` | Renew a certificate (revokes the old one) |
| `pki.GenerateCRL(ctx, session)` | Generate a PEM-encoded CRL |
| `pki.GetCACertificate(ctx, session)` | Retrieve the CA certificate PEM |
| `pki.GetCAInfo(ctx, session)` | Get CA metadata and certificate count |
| `pki.SignCSR(ctx, session, csrPEM, validityDays, extKeyUsages)` | Sign a CSR |
| `pki.ParseCertificatePEM(certPEM)` | Parse a PEM certificate into structured fields |

## API Overview

### REST API

The service provides a REST API exposed by default on port `8443`.

- **Auth**:
  - `POST /api/v1/auth/register` (passphrase -> returns secret key + sets session cookie)
  - `POST /api/v1/auth/login` (passphrase + secret key + optional `totp_code` -> sets session cookie; `totp_code` required when 2FA enabled)
  - `POST /api/v1/auth/logout`
  - `GET /api/v1/auth/2fa` (session auth; returns 2FA status)
  - `POST /api/v1/auth/2fa/setup` (session auth; returns temporary TOTP secret)
  - `POST /api/v1/auth/2fa/enable` (session auth; verifies code and enables 2FA)
  - `GET /api/v1/auth/webauthn/status` (session auth; returns passkey status and credential count)
  - `POST /api/v1/auth/webauthn/register/begin` (session auth; starts passkey registration ceremony)
  - `POST /api/v1/auth/webauthn/register/finish` (session auth; completes passkey registration)
  - `POST /api/v1/auth/webauthn/login/begin` (secret key + passphrase; starts passkey login ceremony)
  - `POST /api/v1/auth/webauthn/login/finish` (completes passkey login; sets session cookie)
- **Vaults**:
  - `POST /api/v1/vaults` (authenticated, server-generated vault ID)
  - `GET /api/v1/vaults`
  - `DELETE /api/v1/vaults/{vaultID}`
  - `GET /api/v1/vaults/{vaultID}/audit` (audit trail of item access/changes; optional `item_id` query filter)
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
