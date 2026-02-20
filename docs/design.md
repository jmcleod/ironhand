# IronHand Design Documentation

This document describes the architecture and design of the IronHand library and server. For details on the cryptographic schemes used, see [encryption.md](encryption.md).

## Overview

IronHand is a secure, encrypted vault library written in Go. It provides member-based access control, epoch-based key rotation, rollback detection, and a pluggable storage layer. The library can be used directly as a Go package or accessed through a REST API served by the built-in HTTPS server.

## Package Structure

### Public Packages

| Package | Purpose |
|---|---|
| `vault/` | Core vault operations, sessions, membership, epoch rotation |
| `crypto/` | Credential and key generation abstractions |
| `storage/` | Storage abstraction layer with pluggable backends |
| `pki/` | Certificate Authority operations built on vault sessions |
| `api/` | REST API handlers and HTTP middleware |
| `web/` | Embedded web UI assets and handler |

### Internal Packages

| Package | Purpose |
|---|---|
| `internal/util/` | Low-level crypto primitives (AES-256-GCM, X25519, Argon2id, HKDF) |
| `internal/crypto/` | Mid-level crypto operations (AAD construction, member key wrapping) |
| `internal/uuid/` | UUID generation |

### CLI

| Package | Purpose |
|---|---|
| `cmd/ironhand/` | Cobra-based CLI with `server` subcommand |

## Vault Lifecycle

### Creating a Vault Handle

A `Vault` struct combines a vault identifier, a storage backend, and an epoch cache:

```go
type Vault struct {
    id         string
    repo       storage.Repository
    epochCache EpochCache
}
```

Create a handle with `vault.New(id, repo, ...opts)`. By default an in-memory epoch cache is used; production deployments should supply a persistent cache via the `WithEpochCache` option to retain rollback protection across restarts.

### Vault Creation

`v.Create(ctx, creds, ...opts)` initialises a new vault:

1. Validates the vault ID and credentials.
2. Derives a record key from the owner's Master Unlock Key (MUK) and the vault ID.
3. Generates a random 32-byte KEK (Key Encryption Key) for epoch 1.
4. Builds a `vaultState` containing epoch number, KDF parameters, and salts.
5. Creates the owner's member record with role `owner` and status `active`.
6. Wraps the KEK for the owner using X25519 public-key sealing.
7. Writes state, member, and KEK wrap atomically via `repo.Batch()`.
8. Returns an open `Session` with the KEK and record key held in memguard Enclaves.

### Opening a Vault

`v.Open(ctx, creds)` opens an existing vault for a member:

1. Loads vault state and verifies the KDF profile matches the credentials.
2. Checks the epoch cache for rollback (`GetMaxEpochSeen`). If the stored epoch exceeds the vault's current epoch, returns `ErrRollbackDetected`.
3. Loads the member record and verifies status is `active`.
4. Loads and unwraps the member's KEK wrap using their X25519 private key.
5. Updates the epoch cache with the current epoch.
6. Returns an active `Session`.

### Vault State

Vault state is stored as a single encrypted record:

```go
type vaultState struct {
    VaultID    string
    Epoch      uint64
    KDFParams  Argon2idParams
    SaltPass   []byte    // 16 bytes
    SaltSecret []byte    // 16 bytes
    CreatedAt  time.Time
    Ver        int       // currently 1
}
```

The KDF parameters and salts are shared across all vault members, enabling any member with the correct passphrase and secret key to derive the same MUK.

### KDF Profiles

Argon2id parameters are configurable via named profiles selected with the `--kdf-profile` flag:

| Profile | Time | Memory | Parallelism | Use Case |
|---|---|---|---|---|
| `interactive` | 2 | 19 MiB | 4 | Development, testing, high-throughput APIs |
| `moderate` (default) | 3 | 64 MiB | 4 | Production web applications |
| `sensitive` | 4 | 128 MiB | 4 | CA root keys, backups, credential export |

Enforced minimums prevent dangerously weak configurations: Time≥1, Memory≥19 MiB (OWASP minimum for Argon2id), Parallelism≥1.

KDF parameters are persisted in vault state at creation time — changing the server-side profile does not affect existing vaults.

## Sessions

### Session Structure

A `Session` holds the decrypted key material for an authenticated vault member:

```go
type Session struct {
    vault     *Vault
    epoch     uint64
    MemberID  string
    kek       *memguard.Enclave
    recordKey *memguard.Enclave
}
```

Both the KEK and record key are stored in memguard Enclaves, which encrypt keys at rest in process memory. Keys are decrypted briefly into mlock'd `LockedBuffer` instances only during operations, then wiped immediately. Callers must call `Close()` when finished.

### Item Operations

**Put** creates a new encrypted item:
1. Generates a random 32-byte DEK (Data Encryption Key) for the item.
2. Encrypts each field independently with the DEK and field-specific AAD.
3. Wraps the DEK with the vault KEK and epoch-specific AAD.
4. Serialises the item and seals it with the record key.
5. Stores via `PutCAS` with `expectedVersion=0` (create-only semantics).

**Get** retrieves and decrypts an item:
1. Loads the sealed envelope from storage.
2. Opens the envelope with the record key and verifies AAD.
3. Unwraps the DEK using the KEK.
4. Decrypts each field with the DEK and field-specific AAD.
5. Returns a `Fields` map (`map[string][]byte`).

**Update** re-encrypts an existing item:
1. Loads the current item to obtain its version number.
2. Snapshots the current item to an `ITEM_HISTORY` record.
3. Generates a new DEK and increments the item version.
4. Encrypts fields and wraps the DEK as in Put.
5. Stores via `PutCAS` with the previous version as the expected version (optimistic concurrency).

**Delete** removes an item from the vault.

**List** returns all item IDs in the vault.

### Field Constraints

| Constraint | Limit |
|---|---|
| Field name length | 128 characters |
| Fields per item | 64 |
| Field value size | 1 MB (1,048,576 bytes) |
| Attachment size | 768 KiB (raw, before base64 encoding) |
| Filename length | 119 characters |
| ID length | 256 characters |
| Forbidden ID characters | `:`, `/`, control characters |

### Well-Known Fields

- `_name` — Display name
- `_type` — Item type
- `_created` — Creation timestamp
- `_updated` — Last update timestamp
- `_att.<filename>` — Attachment content (base64-encoded at API boundary)
- `_attmeta.<filename>` — Attachment metadata (JSON)

### Item History

Updates automatically snapshot the previous version to `ITEM_HISTORY` records. History operations:

- `GetHistory(ctx, itemID)` — Returns a list of past versions (newest first), each with version number, timestamp, and updating member ID.
- `GetHistoryVersion(ctx, itemID, version)` — Decrypts a specific historical version.

History records use the key format `{itemID}#{version}` and are re-encrypted during epoch rotation alongside current items.

## Membership Model

### Member Structure

```go
type Member struct {
    MemberID     string
    PubKey       [32]byte      // X25519 public key
    Role         MemberRole    // owner, writer, or reader
    Status       MemberStatus  // active or revoked
    AddedEpoch   uint64
    RevokedEpoch uint64
}
```

### Roles and Access Control

| Role | Read | Write | Admin (add/revoke members) |
|---|---|---|---|
| `owner` | Yes | Yes | Yes |
| `writer` | Yes | Yes | No |
| `reader` | Yes | No | No |

Every session operation checks the member's role before proceeding via an internal `authorize()` call.

### Epoch Rotation

Adding or revoking a member triggers epoch rotation, which is the core mechanism for forward secrecy:

1. **Generate a new KEK** — A fresh random 32-byte key.
2. **Update the member list** — Add the new member or mark the revoked member.
3. **Re-wrap KEK for all active members** — Each active member's X25519 public key is used to seal the new KEK. The wrap record ID is `{epoch}:{memberID}`.
4. **Re-encrypt all items** — For each item: decrypt the DEK with the old KEK, decrypt all fields, re-encrypt fields with new-epoch AAD, re-wrap the DEK with the new KEK.
5. **Re-encrypt all history records** — Same process as items.
6. **Update vault state** — Increment the epoch number.
7. **Atomic batch write** — All records are written in a single `repo.Batch()` transaction.
8. **Update session** — The session's KEK Enclave is replaced with the new KEK.

After rotation, revoked members cannot decrypt data at the new epoch because they do not have a KEK wrap for that epoch.

### Rollback Detection

The `EpochCache` interface tracks the highest epoch seen per vault:

```go
type EpochCache interface {
    GetMaxEpochSeen(vaultID string) uint64
    SetMaxEpochSeen(vaultID string, epoch uint64) error
}
```

Three implementations are provided:

| Implementation | Persistence | Use Case |
|---|---|---|
| `MemoryEpochCache` | None | Testing |
| `BoltEpochCache` | BBolt file | Single-instance production |
| PostgreSQL `EpochCache` | Database | Multi-instance production |

On `Open()`, if the vault's current epoch is lower than the cached maximum, `ErrRollbackDetected` is returned. This prevents an attacker from reverting storage to a prior state to re-grant access to revoked members.

## Storage Layer

### Repository Interface

All storage backends implement the `Repository` interface:

```go
type Repository interface {
    Put(vaultID, recordType, recordID string, envelope *Envelope) error
    Get(vaultID, recordType, recordID string) (*Envelope, error)
    List(vaultID, recordType string) ([]string, error)
    ListVaults() ([]string, error)
    Delete(vaultID, recordType, recordID string) error
    DeleteVault(vaultID string) error
    PutCAS(vaultID, recordType, recordID string, expectedVersion uint64, envelope *Envelope) error
    Batch(vaultID string, fn func(tx BatchTx) error) error
}
```

`BatchTx` provides `Put`, `PutCAS`, and `Delete` scoped to a single vault for atomic multi-record writes (used by epoch rotation).

### Envelope

Every record is stored as an `Envelope`:

```go
type Envelope struct {
    Ver        int    // 1
    Scheme     string // "aes256gcm"
    Nonce      []byte // 12 bytes
    Ciphertext []byte
    Version    uint64 // CAS tracking
}
```

Envelopes are created with `SealRecord(recordKey, plaintext, aad)` and opened with `OpenRecord(recordKey, envelope, aad)`.

### Record Types

| Type | Description | Record ID Pattern |
|---|---|---|
| `STATE` | Vault metadata | `current` |
| `MEMBER` | Member records | `{memberID}` |
| `KEKWRAP` | Per-member KEK wraps | `{epoch}:{memberID}` |
| `ITEM` | Encrypted items | `{itemID}` |
| `ITEM_HISTORY` | Historical item snapshots | `{itemID}#{version}` |
| `AUDIT` | Audit trail entries | `{auditID}` |
| `AUDIT_TIP` | Latest audit chain hash | `tip` |
| `SESSION` | Encrypted session data (persistent mode) | `{token}` |
| `SESSION_KEY` | Session encryption key (persistent mode) | `current` |

### Sentinel Errors

| Error | Meaning |
|---|---|
| `ErrNotFound` | Record does not exist |
| `ErrVaultNotFound` | Vault does not exist |
| `ErrCASFailed` | Compare-and-swap version mismatch |

### Backend: In-Memory

- **Package:** `storage/memory`
- **Structure:** Thread-safe `map[vaultID]map[key]Envelope` with `sync.RWMutex`
- **Persistence:** None
- **Use case:** Testing and demos

### Backend: BBolt

- **Package:** `storage/bbolt`
- **Structure:** One BBolt bucket per vault, key format `{recordType}:{recordID}`
- **Persistence:** Single file on disk
- **Transactions:** BBolt's `Update()` and `View()` callbacks provide serialised access
- **Use case:** Default backend for single-instance deployments

### Backend: PostgreSQL

- **Package:** `storage/postgres`
- **Schema:** `records` table with composite primary key `(vault_id, record_type, record_id)`, plus `epoch_cache` table
- **Connection:** `pgx/v5` with connection pooling via `pgxpool`
- **CAS:** `SELECT ... FOR UPDATE` row locks within transactions
- **Batch:** PostgreSQL transactions for atomic multi-record writes
- **Use case:** Multi-instance deployments

The PostgreSQL schema is embedded in the binary via `//go:embed` and applied automatically on first connection through `EnsureSchema()`.

## REST API

### Server Setup

The server is started with:

```sh
ironhand server [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--port` | 8443 | HTTPS listen port |
| `--data-dir` | `./data` | Directory for BBolt files |
| `--storage` | `bbolt` | Storage backend (`bbolt` or `postgres`) |
| `--postgres-dsn` | | PostgreSQL connection string |
| `--tls-cert` | | Path to TLS certificate |
| `--tls-key` | | Path to TLS key |
| `--enable-header-auth` | `false` | Allow X-Credentials/X-Passphrase header-based authentication |
| `--session-storage` | `memory` | Session storage: `memory` or `persistent` |
| `--session-key` | | Hex-encoded 32-byte wrapping key for persistent session storage |
| `--session-key-file` | | Path to file containing raw 32-byte wrapping key |
| `--pki-keystore` | `software` | PKI key store backend: `software` or `pkcs11` |
| `--pkcs11-module` | | Path to PKCS#11 shared library |
| `--pkcs11-token-label` | | PKCS#11 token label |
| `--pkcs11-pin` | | PKCS#11 user PIN |
| `--webauthn-rp-id` | `localhost` | WebAuthn Relying Party ID (domain) |
| `--webauthn-rp-origin` | | WebAuthn Relying Party origin (default: `https://localhost:<port>`) |
| `--webauthn-rp-name` | `IronHand` | WebAuthn Relying Party display name |
| `--kdf-profile` | `moderate` | Argon2id KDF profile for new accounts: `interactive`, `moderate`, `sensitive` |
| `--audit-retention-days` | `0` | Automatically prune audit entries older than N days (`0` disables) |
| `--audit-max-entries` | `0` | Automatically keep only newest N audit entries per vault (`0` disables) |
| `--trusted-proxies` | | Comma-separated CIDR ranges of trusted reverse proxies |

If no TLS certificate is provided, the server generates a self-signed certificate at startup.

### Routing

The server uses Chi for HTTP routing with middleware:

- `middleware.Logger` — Request logging
- `middleware.Recoverer` — Panic recovery
- `SecurityHeaders` — CSP, HSTS (proxy-aware: only trusts forwarded-proto from `--trusted-proxies`), X-Frame-Options, Permissions-Policy, X-Content-Type-Options
- `noCacheHeaders` — `Cache-Control: no-store` and `Pragma: no-cache` on all API responses (prevents sensitive data caching)
- `AuthMiddleware` — Session cookie or header-based authentication (header auth disabled by default)
- `CSRFMiddleware` — Double-submit cookie CSRF protection for mutating requests

### API Structure

```go
type API struct {
    repo               storage.Repository
    epochCache         vault.EpochCache
    sessions           SessionStore
    rateLimiter        *loginRateLimiter
    ipLimiter          *ipRateLimiter
    globalLimiter      *globalRateLimiter
    audit              *auditLogger
    metrics            *metricsCollector
    headerAuthEnabled  bool
    idleTimeout        time.Duration
    keyStore           pki.KeyStore
    webauthn           *webauthn.WebAuthn
}
```

### Endpoint Summary

#### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Register (passphrase -> secret key + session cookie) |
| `POST` | `/api/v1/auth/login` | Login (passphrase + secret key -> session cookie) |
| `POST` | `/api/v1/auth/logout` | Logout (clear session) |
| `GET` | `/api/v1/auth/2fa` | Get 2FA status |
| `POST` | `/api/v1/auth/2fa/setup` | Begin TOTP setup |
| `POST` | `/api/v1/auth/2fa/enable` | Verify code and enable 2FA |
| `GET` | `/api/v1/auth/webauthn/status` | Get passkey status and credential count |
| `POST` | `/api/v1/auth/webauthn/register/begin` | Start passkey registration ceremony |
| `POST` | `/api/v1/auth/webauthn/register/finish` | Complete passkey registration |
| `POST` | `/api/v1/auth/webauthn/login/begin` | Start passkey login ceremony |
| `POST` | `/api/v1/auth/webauthn/login/finish` | Complete passkey login (creates session) |

#### Vaults

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/vaults` | Create a vault |
| `GET` | `/api/v1/vaults` | List vaults |
| `DELETE` | `/api/v1/vaults/{vaultID}` | Delete a vault |
| `GET` | `/api/v1/vaults/{vaultID}/audit` | Audit trail |
| `GET` | `/api/v1/vaults/{vaultID}/audit/export` | Export tamper-evident audit log |

#### Items

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/vaults/{vaultID}/items/{itemID}` | Create item |
| `GET` | `/api/v1/vaults/{vaultID}/items/{itemID}` | Get item |
| `PUT` | `/api/v1/vaults/{vaultID}/items/{itemID}` | Update item |
| `DELETE` | `/api/v1/vaults/{vaultID}/items/{itemID}` | Delete item |
| `GET` | `/api/v1/vaults/{vaultID}/items` | List items |
| `GET` | `/api/v1/vaults/{vaultID}/items/{itemID}/history` | List history |
| `GET` | `/api/v1/vaults/{vaultID}/items/{itemID}/history/{version}` | Get version |
| `GET` | `/api/v1/vaults/{vaultID}/items/{itemID}/private-key` | Get private key (owner only) |

#### Members

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/vaults/{vaultID}/members` | Add member |
| `DELETE` | `/api/v1/vaults/{vaultID}/members/{memberID}` | Revoke member |

#### Export/Import

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/vaults/{vaultID}/export` | Export vault data |
| `POST` | `/api/v1/vaults/{vaultID}/import` | Import vault data |

#### PKI (Certificate Authority)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/vaults/{vaultID}/pki/init` | Initialise vault as a CA |
| `GET` | `/api/v1/vaults/{vaultID}/pki/info` | Get CA metadata |
| `GET` | `/api/v1/vaults/{vaultID}/pki/ca.pem` | Download CA certificate |
| `POST` | `/api/v1/vaults/{vaultID}/pki/issue` | Issue certificate |
| `POST` | `/api/v1/vaults/{vaultID}/pki/items/{itemID}/revoke` | Revoke certificate |
| `POST` | `/api/v1/vaults/{vaultID}/pki/items/{itemID}/renew` | Renew certificate |
| `GET` | `/api/v1/vaults/{vaultID}/pki/crl.pem` | Download cached CRL (read-only) |
| `POST` | `/api/v1/vaults/{vaultID}/pki/crl` | Regenerate CRL (state-mutating, CSRF-protected) |
| `POST` | `/api/v1/vaults/{vaultID}/pki/sign-csr` | Sign a CSR |

#### Documentation

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/openapi.yaml` | OpenAPI specification |
| `GET` | `/api/v1/docs` | Swagger UI |
| `GET` | `/api/v1/redoc` | ReDoc |

### Authentication

Sessions are managed via a `SessionStore` interface with two implementations:

- **`MemorySessionStore`** (default) — in-memory with `sync.RWMutex`; sessions lost on restart. Suitable for development and testing.
- **`PersistentSessionStore`** — backed by the storage layer with AES-256-GCM encryption; sessions survive restarts. Requires an externally-provided 32-byte wrapping key (see [Session Key Wrapping](#session-key-wrapping)).

```go
type AuthSession struct {
    SecretKeyID           string
    CredentialsBlob       string
    ExpiresAt             time.Time
    LastAccessedAt        time.Time
    PendingTOTPSecret     string
    PendingTOTPExpiry     time.Time
    WebAuthnSessionData   string
    WebAuthnSessionExpiry time.Time
}
```

The session passphrase is intentionally **not** stored in the session record. It is derived at request time from the session token and a client-held secret cookie using HMAC-SHA256 (see [Session Passphrase Derivation](#session-passphrase-derivation)). This ensures that a session store compromise alone cannot reconstruct credentials.

Sessions have a 24-hour absolute expiry and a 30-minute idle timeout. The idle timeout is reset on each request.

#### Session Key Wrapping

The persistent session store encrypts all session records with a 32-byte AES-256-GCM session encryption key. This key is itself wrapped (sealed) with an externally-provided wrapping key before being stored in the repository, ensuring that a repository compromise alone cannot recover session data.

The wrapping key is provided via one of (in priority order):

| Source | Format |
|---|---|
| `--session-key` flag | Hex-encoded 32 bytes (64 hex characters) |
| `IRONHAND_SESSION_KEY` env var | Hex-encoded 32 bytes |
| `--session-key-file` flag | Raw 32 bytes on disk |

If `--session-storage=persistent` is selected without a wrapping key, the server refuses to start.

**Legacy migration:** If the server encounters a session encryption key stored in the legacy `raw` scheme (pre-wrapping), it automatically migrates the key to the wrapped `aes256gcm` scheme on first access. If the wrapping key changes, a new session encryption key is generated and all previous sessions become unreadable (correct security behaviour — stale sessions expire naturally).

#### Session Passphrase Derivation

Session credential blobs are encrypted with a passphrase that is derived from two independent sources using HMAC-SHA256:

1. **Session ID** — stored in the `ironhand_session` cookie (`SameSite=Lax`)
2. **Session secret** — stored in the `ironhand_session_key` cookie (`SameSite=Strict`)

```
passphrase = HMAC-SHA256(key=sessionSecret, data="ironhand:session_passphrase:v1:" || sessionID)
```

This split ensures that:

- A server-side session store compromise (which holds the encrypted credentials blob and the session ID) cannot reconstruct the passphrase without the client cookie.
- A stolen client cookie alone is useless without the server-side credentials blob.
- The `SameSite=Strict` attribute on the secret cookie provides additional CSRF protection for the credential derivation path.

#### Authentication Flow

The `AuthMiddleware` checks for a session cookie (`ironhand_session`) and the companion secret cookie (`ironhand_session_key`) first. If both are present, the session passphrase is derived and the credentials blob is decrypted. Header-based authentication via `X-Credentials` and `X-Passphrase` is **disabled by default** and must be explicitly enabled with `--enable-header-auth`.

All mutating requests (POST/PUT/DELETE) with cookie-based auth require a `X-CSRF-Token` header matching the `ironhand_csrf` cookie (double-submit cookie pattern). The CSRF token is set on login/register and cleared on logout.

Registration returns the secret key only once; there is no API to retrieve it later.

### WebAuthn/Passkey MFA

WebAuthn provides phishing-resistant second-factor authentication. The passphrase is still required for vault decryption (zero-knowledge architecture). WebAuthn replaces TOTP as the recommended MFA method.

- **Registration** — Authenticated users register passkeys via a two-step ceremony (`/register/begin` → browser prompt → `/register/finish`)
- **Login** — Users provide their secret key and passphrase, then complete the WebAuthn assertion (`/login/begin` → browser prompt → `/login/finish`)
- **Configuration** — WebAuthn is auto-configured on server startup using `--webauthn-rp-id`, `--webauthn-rp-origin`, and `--webauthn-rp-name`

### Rate Limiting

#### Login rate limiting

Login endpoints enforce three tiers of rate limiting:

| Tier | Key | Max Failures | Lockout Range |
|---|---|---|---|
| Per-account | SHA-256(secret_key) | 5 | 1 min → 15 min (exponential) |
| Per-IP | Client IP | 20 | 1 min → 30 min |
| Global | — | 100/min | 5 min |

Rate limits apply to both password-based and WebAuthn login flows. Successful login clears per-account and per-IP counters.

#### Registration rate limiting

Registration performs expensive Argon2id KDF work on every call. Separate rate limiters prevent resource-exhaustion and credential-stuffing abuse:

| Tier | Key | Max Requests | Lockout Range |
|---|---|---|---|
| Per-IP | Client IP | 5 | 5 min → 1 hr (exponential) |
| Global | — | 50/min | 5 min |

Every registration request (success or failure) counts toward the limit. The per-IP limiter uses the same exponential backoff model as login but with tighter thresholds appropriate for the low-frequency nature of registration.

#### MFA setup rate limiting

MFA setup routes (`/auth/2fa/setup`) share the registration per-IP limiter to prevent TOTP secret generation spam.

## Certificate Authority (PKI)

### Overview

Any vault can be initialised as a Certificate Authority. CA private keys, certificates, and revocation lists are stored as encrypted vault items, benefiting from the same field-level encryption, epoch-based rotation, and access control as all other vault data.

### CA State Storage

CA state is stored in reserved items prefixed with `__ca_`:

| Item ID | Contents |
|---|---|
| `__ca_state` | CA metadata: subject, validity, next serial number, CRL number, intermediate flag |
| `__ca_cert` | PEM-encoded CA certificate |
| `__ca_key` | CA private key: PEM-encoded (software) or `PKCS11:<label>` reference (HSM) |
| `__ca_revocations` | JSON array of revocation entries |
| `__ca_crl` | Most recently generated PEM-encoded CRL (cached for read-only retrieval) |

These items are hidden from the regular item listing API and blocked from direct CRUD operations via `isReservedItemID()`.

### CA Operations

| Operation | Description |
|---|---|
| `InitCA` | Generate an ECDSA P-256 keypair, create a self-signed CA certificate, store CA state |
| `IssueCertificate` | Sign a new leaf certificate with SANs, key usages, and validity period |
| `RevokeCertificate` | Mark a certificate as revoked with an optional reason code |
| `RenewCertificate` | Reissue with new serial and validity, automatically revoke the old certificate |
| `GenerateCRL` | Produce a PEM-encoded CRL, increment CRLNumber, and cache the result |
| `LoadCRL` | Return the most recently cached CRL (read-only, no state mutation) |
| `SignCSR` | Accept a PEM-encoded CSR and issue a signed certificate using the requester's public key |

### KeyStore Architecture

The PKI subsystem abstracts private-key operations through the `pki.KeyStore` interface:

| Method | Description |
|---|---|
| `GenerateKey()` | Create a new signing key, return an opaque key ID |
| `Signer(keyID)` | Return a `crypto.Signer` for the given key |
| `ExportPEM(keyID)` | Export key material (or a reference string for HSM keys) |
| `ImportPEM(pemData)` | Import a key from PEM data or a reference string |
| `Delete(keyID)` | Remove a key from the store |

Two implementations are provided:

| Implementation | Key Storage | Export Behavior | Build Tag |
|---|---|---|---|
| `SoftwareKeyStore` | In-memory ECDSA P-256 | Returns PEM-encoded private key | (default) |
| `PKCS11KeyStore` | PKCS#11 HSM | Returns `PKCS11:<label>` reference string | `pkcs11` |

The PKCS#11 keystore uses a **reference-string strategy**: `ExportPEM` returns a `PKCS11:<label>` string (not actual PEM data), which is stored in the vault's `private_key` field. When `ImportPEM` receives this string, it detects the prefix and looks up the key in the HSM by label. This approach requires no changes to the PKI core logic — the vault transparently stores and retrieves the reference while the actual private key material never leaves the HSM.

The PKCS#11 implementation requires CGo and the `pkcs11` build tag:

```sh
go build -tags pkcs11 ./cmd/ironhand/
```

Default builds (without the tag) remain pure Go. The stub implementation returns clear errors directing users to rebuild with the tag.

### Certificate Item Fields

Each issued certificate is stored as a vault item with these well-known fields:

| Field | Description |
|---|---|
| `subject` | Distinguished Name |
| `issuer` | Issuer Distinguished Name |
| `serial_number` | Hex-encoded serial number |
| `not_before` / `not_after` | Validity period (RFC 3339) |
| `certificate` | PEM-encoded X.509 certificate |
| `private_key` | PEM-encoded ECDSA private key (software) or `PKCS11:<label>` reference (HSM) |
| `chain` | PEM bundle of intermediate certificates (optional) |
| `fingerprint_sha256` | Hex SHA-256 fingerprint |
| `key_algorithm` | Key algorithm (e.g., `ECDSA P-256`) |
| `status` | `active`, `expired`, or `revoked` |
| `issued_by_ca` | Whether issued by this vault's CA |
| `previous_item_id` | Links to predecessor after renewal |

## Audit System

### Audit Events

The API layer logs security-relevant events:

| Category | Events |
|---|---|
| Authentication | `login_success`, `login_failure`, `login_rate_limited`, `register`, `logout` |
| 2FA | `two_factor_setup`, `two_factor_enabled` |
| WebAuthn | `webauthn_registered`, `webauthn_login_success` |
| Vault | `vault_created`, `vault_deleted` |
| Membership | `member_added`, `member_revoked` |
| Items | `item_created`, `item_updated`, `item_deleted` |
| Credentials | `credentials_exported`, `vault_exported`, `vault_imported` |
| PKI | `ca_initialized`, `cert_issued`, `cert_revoked`, `cert_renewed`, `crl_generated`, `csr_signed`, `private_key_accessed` |

Audit entries include timestamp, client IP, account ID (secret key ID, not the raw key), and event-specific context. They are written as structured JSON via `log/slog` and stored as AES-256-GCM encrypted records under the `AUDIT` record type. Each entry contains a `prev_hash` field forming a tamper-evident hash chain (SHA-256). The audit entry and chain tip are written atomically via `repo.Batch()`. Exported audit logs include an HMAC-SHA256 signature for forensic integrity verification.

## Web UI

The web UI is a browser-based SPA served by the Go server:

- **Embedding:** Assets in `web/dist/` are embedded via `//go:embed` and served at `/`.
- **SPA routing:** Deep links are redirected to `index.html`.
- **Same origin:** The UI and API share the same host and port, avoiding CORS configuration.

## Concurrency and Thread Safety

| Component | Mechanism |
|---|---|
| In-memory storage | `sync.RWMutex` |
| Session store | `sync.RWMutex` (memory) or encrypted persistent storage with background cleanup |
| Rate limiters | `sync.Mutex` per limiter (per-account, per-IP, global) |
| Audit appends | Per-vault `vaultMutex` + `repo.Batch()` atomic writes |
| Epoch caches | `sync.RWMutex` (in-memory map) + backend persistence |
| BBolt | Database-level serialised transactions |
| PostgreSQL | Connection pool + SQL transactions |
| WebAuthn ceremonies | `sync.Mutex` on ceremony map |
| memguard Enclaves | Thread-safe by design |

Vault and Session operations are stateless beyond the Repository interface, so concurrent access to different vaults is fully parallel.

## Error Types

| Error | Meaning |
|---|---|
| `UnauthorizedError` | Invalid credentials or insufficient permissions |
| `StaleSessionError` | Session epoch is behind the vault's current epoch |
| `SessionClosedError` | Session key material has been destroyed |
| `RollbackError` | Epoch cache detected a storage rollback |
| `ValidationError` | Invalid input (ID format, field limits, etc.) |
| `VaultExistsError` | Vault with this ID already exists |

## Threat Model

### Protected Against

- **Data-at-rest compromise** — All content is AES-256-GCM encrypted with unique per-item keys.
- **Passphrase-only attacks** — MUK derivation requires both passphrase and secret key.
- **Member revocation** — Epoch rotation ensures revoked members lose access to new and re-wrapped data.
- **Storage rollback** — Epoch cache detects if storage is reverted to a prior state.
- **Record swapping** — AAD binds ciphertext to its identity (vault, type, ID, epoch, version), preventing substitution.
- **Brute-force** — Argon2id with configurable memory-hard parameters (named profiles: `interactive`, `moderate`, `sensitive`; enforced minimums per OWASP guidance).

### Not Protected Against

- Compromise of a running process (memory dumps).
- Side-channel attacks on the host.
- Denial of service at the storage layer.

## Deployment

### Single Instance (BBolt)

```sh
ironhand server --port 8443 --data-dir ./data
```

### Single Instance with Persistent Sessions

```sh
# Generate a wrapping key (once)
openssl rand -hex 32 > session.key

# Start with persistent sessions
ironhand server --port 8443 --data-dir ./data \
    --session-storage persistent \
    --session-key-file session.key
```

Or via environment variable:

```sh
export IRONHAND_SESSION_KEY=$(openssl rand -hex 32)
ironhand server --session-storage persistent
```

### Multi-Instance (PostgreSQL)

```sh
ironhand server --port 8443 --storage postgres \
    --postgres-dsn "postgres://ironhand:pass@localhost:5432/ironhand?sslmode=disable"
```

The DSN can also be set via the `IRONHAND_POSTGRES_DSN` environment variable.

### Docker Compose

A `docker-compose.yml` is provided for running IronHand with PostgreSQL:

```sh
docker compose up
```

This starts PostgreSQL 17 and the IronHand server with the PostgreSQL backend configured automatically.

### HSM-Backed PKI (PKCS#11)

```sh
# Build with PKCS#11 support (requires CGo)
go build -tags pkcs11 -o ironhand ./cmd/ironhand/

# Start with HSM-backed PKI keys
ironhand server --port 8443 --data-dir ./data \
    --pki-keystore pkcs11 \
    --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
    --pkcs11-token-label ironhand \
    --pkcs11-pin 1234
```

Or via environment variables:

```sh
export IRONHAND_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export IRONHAND_PKCS11_TOKEN_LABEL=ironhand
export IRONHAND_PKCS11_PIN=1234
ironhand server --pki-keystore pkcs11
```

When `--pki-keystore=pkcs11` is set, all CA and certificate private keys are generated and held inside the HSM. The vault stores a `PKCS11:<label>` reference string instead of actual key material. See the [README](../README.md) for SoftHSM2 setup instructions.

### Configuration Summary

| Setting | Flag | Environment Variable | Default |
|---|---|---|---|
| Port | `--port` | | 8443 |
| Data directory | `--data-dir` | | `./data` |
| Storage backend | `--storage` | | `bbolt` |
| PostgreSQL DSN | `--postgres-dsn` | `IRONHAND_POSTGRES_DSN` | |
| TLS certificate | `--tls-cert` | | (self-signed) |
| TLS key | `--tls-key` | | (self-signed) |
| Header auth | `--enable-header-auth` | | `false` |
| Session storage | `--session-storage` | | `memory` |
| Session wrapping key | `--session-key` | `IRONHAND_SESSION_KEY` | |
| Session key file | `--session-key-file` | | |
| WebAuthn RP ID | `--webauthn-rp-id` | | `localhost` |
| WebAuthn RP origin | `--webauthn-rp-origin` | | `https://localhost:<port>` |
| WebAuthn RP name | `--webauthn-rp-name` | | `IronHand` |
| PKI key store | `--pki-keystore` | | `software` |
| PKCS#11 module | `--pkcs11-module` | `IRONHAND_PKCS11_MODULE` | |
| PKCS#11 token label | `--pkcs11-token-label` | `IRONHAND_PKCS11_TOKEN_LABEL` | |
| PKCS#11 PIN | `--pkcs11-pin` | `IRONHAND_PKCS11_PIN` | |
| KDF profile | `--kdf-profile` | | `moderate` |
| Audit retention (days) | `--audit-retention-days` | | `0` (disabled) |
| Audit max entries | `--audit-max-entries` | | `0` (disabled) |
| Trusted proxies | `--trusted-proxies` | | (trust none) |
