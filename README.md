# IronHand

A secure, encrypted vault library for Go with member-based access control, epoch-based key rotation, and rollback detection.

## Features

- **AES-256-GCM encryption** with Authenticated Associated Data (AAD) on every layer
- **Two-secret-key MUK derivation** — requires both a passphrase and a secret key (Argon2id + HKDF + XOR)
- **X25519 member key wrapping** — per-member public-key sealed KEK distribution
- **Epoch-based key rotation** — adding or revoking members rotates the vault KEK and re-wraps all items atomically
- **Rollback detection** — persistent epoch cache detects storage rollback attacks
- **Credential export/import** — single encrypted blob for portable vault access
- **Pluggable storage** — in-memory (testing) or BBolt (production) backends

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

Two backends are provided:

- `storage/memory` — in-memory, suitable for testing
- `storage/bbolt` — persistent BBolt-backed storage for production

### Threat Model

IronHand protects against:

- **Data-at-rest compromise** — all content is AES-256-GCM encrypted
- **Passphrase-only attacks** — MUK requires both passphrase and secret key
- **Member revocation** — epoch rotation ensures revoked members lose access to new and re-wrapped data
- **Storage rollback** — epoch cache detects if storage is reverted to a prior state
- **Record swapping** — AAD binds ciphertext to its identity, preventing substitution
- **Brute-force** — Argon2id with configurable memory-hard parameters

IronHand does **not** protect against:

- Compromise of a running process (memory dumps)
- Side-channel attacks on the host
- Denial of service at the storage layer

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
- **Vaults**:
  - `POST /api/v1/vaults` (authenticated, server-generated vault ID)
  - `GET /api/v1/vaults`
  - `DELETE /api/v1/vaults/{vaultID}`
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
