# IronHand Encryption

This document details the cryptographic schemes used throughout IronHand, from account credential generation through field-level encryption and key rotation. For the broader system design, see [design.md](design.md).

## Overview

IronHand encrypts all data at rest using AES-256-GCM with a layered key hierarchy:

```
Passphrase + Secret Key
        │
        ▼
       MUK  (Master Unlock Key — Argon2id + HKDF + XOR)
        │
        ▼
   Record Key  (HKDF — one per vault)
        │
        ▼
   Vault Records  (encrypted envelopes in storage)
        │
        ├── Vault State
        ├── Member Records
        ├── KEK Wraps
        └── Items
              │
              ├── DEK  (random — one per item, wrapped by KEK)
              │    │
              │    └── Field ciphertexts  (AES-256-GCM per field)
              │
              └── History snapshots
```

Every encryption operation includes Authenticated Associated Data (AAD) that binds the ciphertext to its identity — vault, record type, record ID, epoch, and version — preventing record swapping and replay attacks.

## Credential Generation

### Secret Key

Each account has a secret key that serves as one of the two inputs to MUK derivation.

**Generation** (`crypto/secret_key.go`):

- **Alphabet:** 30 characters — `23456789ABCDEFGHJKLMNPQRSTVWXYZ` (no `0`, `1`, `I`, `O`, `U` to avoid ambiguity)
- **ID:** 6 random characters (identifier only, not part of the secret)
- **Secret:** 26 random characters drawn from the same alphabet via `crypto/rand`
- **Entropy:** log₂(30²⁶) ≈ 127.5 bits

**Format:**

```
V{version}-{id:6}-{part1:6}-{part2:5}-{part3:5}-{part4:5}-{part5:5}

Example: V1-A3BCD5-FGH2JK-LMNPQ-RSTVW-XYZ23-456AB
```

The secret key is shown to the user once at registration and never stored in plaintext by the server.

### X25519 Keypair

Each member has an X25519 keypair used for KEK wrapping.

**Generation** (`internal/util/x25519.go`):

1. Generate 32 random bytes via `crypto/rand`.
2. Clamp the private key per the Curve25519 specification:
   - `private[0] &= 248` — clear the three lowest bits
   - `private[31] &= 127` — clear the highest bit
   - `private[31] |= 64` — set the second-highest bit
3. Derive the public key via `curve25519.ScalarBaseMult`.

Both keys are 32 bytes. The private key is stored in a memguard Enclave within the `Credentials` struct.

## Master Unlock Key (MUK)

The MUK is derived from two independent secrets using a two-secret-key scheme that ensures neither the passphrase nor the secret key alone can reconstruct it.

### Derivation

**Source:** `internal/util/two_secret_key.go`, `crypto/keys.go`

```
kPass    = Argon2id(NFKD(passphrase), saltPass, params)     → 32 bytes
kSecret  = HKDF-SHA256(secretKey, saltSecret, "vault:muk:v1") → 32 bytes

MUK = kPass XOR kSecret                                       → 32 bytes
```

Both intermediate keys are wiped from memory immediately after the XOR.

### Passphrase Branch (Argon2id)

**Source:** `internal/util/argon2id.go`

| Parameter | Default Value |
|---|---|
| Time (iterations) | 1 |
| Memory | 64 × 1024 KiB (64 MiB) |
| Parallelism | 4 threads |
| Key length | 32 bytes (strictly enforced) |
| Salt | `saltPass` — 16 random bytes, generated at vault creation |

The passphrase is normalised to Unicode NFKD form before hashing to ensure consistent derivation across platforms.

### Secret Key Branch (HKDF)

**Source:** `internal/util/hkdf.go`

| Parameter | Value |
|---|---|
| Algorithm | HKDF-SHA256 (RFC 5869) |
| Input key material | Secret key bytes (26 bytes) |
| Salt | `saltSecret` — 16 random bytes, generated at vault creation |
| Info | `"vault:muk:v1"` (12 bytes) |
| Output | 32 bytes |

### Security Properties

- **Two-factor derivation:** Compromising only the passphrase or only the secret key is insufficient.
- **Memory-hard:** Argon2id resists GPU/ASIC brute-force attacks.
- **Deterministic per vault:** The same passphrase and secret key with the same salts always produce the same MUK.
- **Shared salts:** All members of a vault share the same `saltPass`, `saltSecret`, and Argon2id parameters (stored in vault state). This allows any member with the correct credentials to derive the same MUK.

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│              Passphrase  +  Secret Key                  │
│              (human)        (cryptographic)              │
└───────────────────────────┬─────────────────────────────┘
                            │
                   Argon2id + HKDF + XOR
                            │
                   ┌────────▼────────┐
                   │   MUK (32 B)    │
                   │   per account   │
                   └────────┬────────┘
                            │
                 HKDF(MUK, vaultID, info)
                            │
                 ┌──────────▼──────────┐
                 │  Record Key (32 B)  │
                 │  per vault          │
                 └──────────┬──────────┘
                            │
              Encrypts vault records (envelopes)
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
    Vault State       Member Records      KEK Wraps
                                              │
                                    ┌─────────▼──────────┐
                                    │   KEK (32 B)       │
                                    │   per vault epoch  │
                                    │   (random)         │
                                    └─────────┬──────────┘
                                              │
                                    Wraps per-item DEKs
                                              │
                                    ┌─────────▼──────────┐
                                    │   DEK (32 B)       │
                                    │   per item         │
                                    │   (random)         │
                                    └─────────┬──────────┘
                                              │
                                   Encrypts each field
                                   independently
```

### Record Key

**Source:** `internal/crypto/recordkeys.go`

```
RecordKey = HKDF-SHA256(MUK, salt=vaultID, info="vault:record-key:v1")
```

- Unique per vault (different vault IDs produce different record keys).
- Used to seal and open all record envelopes in storage.

### Key Encryption Key (KEK)

- **Size:** 32 bytes, randomly generated.
- **Lifetime:** One per vault epoch. A new KEK is generated at every epoch rotation (member add or revoke).
- **Storage:** Wrapped individually for each active member's X25519 public key (see [Member KEK Wrapping](#member-kek-wrapping)).

### Data Encryption Key (DEK)

- **Size:** 32 bytes, randomly generated.
- **Lifetime:** One per item. A new DEK is generated when the item is created and on each update.
- **Storage:** Wrapped with the current KEK inside the item record.

## Cryptographic Primitives

### AES-256-GCM

**Source:** `internal/util/aes.go`

| Parameter | Value |
|---|---|
| Cipher | AES-256 in Galois/Counter Mode |
| Key size | 32 bytes (256-bit, strictly enforced) |
| Nonce size | 12 bytes (96-bit, standard GCM) |
| Authentication tag | 16 bytes (128-bit) |
| Nonce generation | Random via `crypto/rand` per encryption |

**Output format:**

```
nonce (12 bytes) || ciphertext + auth tag (variable)
```

All encryption uses the AAD variant (`EncryptAESWithAAD`). The non-AAD wrapper passes `nil` AAD.

### HKDF-SHA256

**Source:** `internal/util/hkdf.go`

| Parameter | Value |
|---|---|
| Hash | SHA-256 |
| Output length | 32 bytes (constant) |
| Standard | RFC 5869 |

Used for:
- MUK derivation (secret key branch)
- Record key derivation
- KEK wrap key derivation

### X25519 (Curve25519 ECDH)

**Source:** `internal/util/x25519.go`

| Parameter | Value |
|---|---|
| Curve | Curve25519 |
| Key size | 32 bytes |
| Operation | Elliptic-curve Diffie–Hellman |

Used for member KEK wrapping: ephemeral keypair + recipient public key → shared secret → HKDF → wrap key.

### Argon2id

**Source:** `internal/util/argon2id.go`

| Parameter | Value |
|---|---|
| Variant | Argon2id (hybrid, resists both side-channel and GPU attacks) |
| Output | 32 bytes (strictly enforced) |
| Salt | 16 bytes |

Parameters are configurable per vault and stored in the vault state.

## Authenticated Associated Data (AAD)

**Source:** `internal/crypto/aad.go`

AAD binds every ciphertext to its context, preventing record swapping, field substitution, and epoch replay. All AAD is constructed with a deterministic binary encoding.

### Encoding Format

Each part is encoded sequentially:

| Type | Encoding |
|---|---|
| `string` / `[]byte` | 4-byte big-endian length prefix, then raw bytes |
| `uint64` | 8 bytes, big-endian |
| `int` | 4 bytes, big-endian (cast to `uint32`) |

### AAD Types

**AADRecord** — Used for vault state, member records, and KEK wrap records:

```
[len("RECORD")]  "RECORD"
[len(vaultID)]   vaultID
[len(recordType)] recordType
[len(recordID)]  recordID
[epoch as uint64]
[version as int]
```

**AADFieldContent** — Used for individual field encryption within items:

```
[len("FIELD")]    "FIELD"
[len(vaultID)]    vaultID
[len(itemID)]     itemID
[len(fieldName)]  fieldName
[itemVersion as uint64]
[epoch as uint64]
[version as int]
```

**AADDEKWrap** — Used when wrapping an item's DEK with the vault KEK:

```
[len("DEKWRAP")] "DEKWRAP"
[len(vaultID)]   vaultID
[len(itemID)]    itemID
[epoch as uint64]
[version as int]
```

**AADKEKWrap** — Used when wrapping the vault KEK for a specific member:

```
[len("KEKWRAP")] "KEKWRAP"
[len(vaultID)]   vaultID
[len(memberID)]  memberID
[epoch as uint64]
[version as int]
```

### Special Cases

- **Vault state:** `AADRecord(vaultID, "STATE", "current", 0, 0)` — epoch and version are always zero.

## Record Encryption (Envelope)

**Source:** `storage/envelope.go`

Every record in storage is wrapped in an `Envelope`:

```json
{
  "ver": 1,
  "scheme": "aes256gcm",
  "nonce": "<12 bytes, base64>",
  "ciphertext": "<variable, base64>",
  "version": 0
}
```

### Sealing

```
SealRecord(recordKey, plaintext, aad, version?)
    → EncryptAESWithAAD(plaintext, recordKey, aad)
    → split output into nonce (first 12 bytes) and ciphertext (rest)
    → return Envelope{ver=1, scheme="aes256gcm", nonce, ciphertext, version}
```

### Opening

```
OpenRecord(recordKey, envelope, aad)
    → verify envelope.Ver == 1 and envelope.Scheme == "aes256gcm"
    → reconstruct nonce || ciphertext
    → DecryptAESWithAAD(nonceCiphertext, recordKey, aad)
    → return plaintext
```

The `Version` field is used for optimistic concurrency control (compare-and-swap) and is not part of the encryption.

## Field-Level Encryption

**Source:** `vault/session.go`

Items are encrypted with two layers: the item record is sealed in an envelope with the record key, and within that record, each field is independently encrypted with a per-item DEK.

### Encrypting an Item (Put)

```
1. Generate DEK = random 32 bytes

2. For each field (name → plaintext):
   aad  = AADFieldContent(vaultID, itemID, name, itemVersion, epoch, 1)
   ct   = AES-256-GCM(plaintext, DEK, aad)
   Store ct in item.Fields[name]

3. Wrap DEK with KEK:
   aad        = AADDEKWrap(vaultID, itemID, epoch, 1)
   wrappedDEK = AES-256-GCM(DEK, KEK, aad)

4. Serialise item struct to JSON
5. Seal with record key:
   aad      = AADRecord(vaultID, "ITEM", itemID, epoch, version)
   envelope = SealRecord(recordKey, json, aad, version)

6. Store envelope via PutCAS (version=0 for create)
```

### Decrypting an Item (Get)

```
1. Load envelope from storage
2. Open envelope:
   aad       = AADRecord(vaultID, "ITEM", itemID, epoch, version)
   json      = OpenRecord(recordKey, envelope, aad)

3. Deserialise item struct

4. Unwrap DEK:
   aad = AADDEKWrap(vaultID, itemID, wrappedEpoch, 1)
   DEK = AES-256-GCM-Decrypt(wrappedDEK, KEK, aad)

5. For each field:
   aad       = AADFieldContent(vaultID, itemID, name, itemVersion, wrappedEpoch, 1)
   plaintext = AES-256-GCM-Decrypt(ct, DEK, aad)
```

### Security Properties

- **Field independence:** Each field is encrypted separately. Compromising the ciphertext of one field does not help decrypt another.
- **Field name binding:** The field name is included in the AAD, so a field cannot be swapped between different names or items.
- **Version binding:** The item version and epoch in the AAD prevent replaying old field values.
- **DEK isolation:** Different items have different DEKs. Compromising one item's DEK does not affect other items.

## Member KEK Wrapping

**Source:** `internal/crypto/memberwrap.go`

When a vault is created or the epoch rotates, the KEK is wrapped individually for each active member using their X25519 public key.

### Sealing (SealToMember)

```
1. Generate ephemeral X25519 keypair (ephPriv, ephPub)
2. Compute shared secret:
   shared = X25519(ephPriv, recipientPub)                      → 32 bytes
3. Generate random salt (32 bytes)
4. Derive wrap key:
   wrapKey = HKDF-SHA256(shared, salt, "vault:kek-wrap:v1")    → 32 bytes
5. Encrypt KEK:
   ct = AES-256-GCM(KEK, wrapKey, aad)
6. Split ct into nonce (12 bytes) and ciphertext (rest)
7. Wipe ephPriv, shared, wrapKey
```

The result is a `SealedWrap`:

```json
{
  "ver": 1,
  "eph_pub": "<32 bytes — ephemeral public key>",
  "salt": "<32 bytes>",
  "nonce": "<12 bytes>",
  "ciphertext": "<encrypted KEK + auth tag>"
}
```

The AAD is `AADKEKWrap(vaultID, memberID, epoch, 1)`.

### Opening (OpenFromMember)

```
1. Compute shared secret:
   shared  = X25519(recipientPriv, wrap.EphPub)
2. Derive wrap key:
   wrapKey = HKDF-SHA256(shared, wrap.Salt, "vault:kek-wrap:v1")
3. Reconstruct nonce || ciphertext
4. Decrypt:
   KEK = AES-256-GCM-Decrypt(nonceCiphertext, wrapKey, aad)
5. Wipe shared, wrapKey
```

### Security Properties

- **Ephemeral keys:** A fresh ephemeral keypair is generated for each wrap operation, so the same KEK wrapped for the same member at different epochs produces different ciphertexts.
- **AAD binding:** The wrap is bound to the vault, member, and epoch.
- **Forward secrecy:** Ephemeral private keys are wiped immediately after use.

## Epoch Rotation Cryptography

When a member is added or revoked, the vault undergoes epoch rotation — a complete re-keying of the vault.

### Process

```
1. Generate newKEK = random 32 bytes
   newEpoch = currentEpoch + 1

2. For each active member:
   aad  = AADKEKWrap(vaultID, memberID, newEpoch, 1)
   wrap = SealToMember(member.PubKey, newKEK, aad)
   → Store as KEKWRAP record with ID "{newEpoch}:{memberID}"

3. For each item (and each history version):
   a. Unwrap DEK with old KEK:
      oldAAD = AADDEKWrap(vaultID, itemID, oldEpoch, 1)
      DEK    = Decrypt(wrappedDEK, oldKEK, oldAAD)

   b. Re-encrypt each field with new-epoch AAD:
      For each field:
        oldFieldAAD = AADFieldContent(vaultID, itemID, name, ver, oldEpoch, 1)
        plaintext   = Decrypt(fieldCT, DEK, oldFieldAAD)

        newFieldAAD = AADFieldContent(vaultID, itemID, name, ver, newEpoch, 1)
        newCT       = Encrypt(plaintext, DEK, newFieldAAD)

   c. Re-wrap DEK with new KEK:
      newAAD     = AADDEKWrap(vaultID, itemID, newEpoch, 1)
      wrappedDEK = Encrypt(DEK, newKEK, newAAD)

4. Update vault state: Epoch = newEpoch

5. Write all changes atomically via repo.Batch()

6. Update epoch cache: SetMaxEpochSeen(vaultID, newEpoch)

7. Update session: replace KEK Enclave with newKEK
```

### Security Properties

- **Atomicity:** All writes (state, members, KEK wraps, items, history) are committed in a single transaction. A failure rolls back everything.
- **Forward secrecy:** The old KEK is discarded. Revoked members do not receive a `SealedWrap` for the new epoch and cannot decrypt new data.
- **AAD refresh:** Re-encrypting fields with new-epoch AAD ensures old ciphertexts cannot be replayed at the new epoch.
- **Complete re-keying:** The DEK for each item is not regenerated (it is reused), but its wrapping changes to the new KEK and its field ciphertexts are re-encrypted with new AAD.

## Credential Export and Import

**Source:** `vault/credentials.go`

Credentials can be exported to a portable encrypted blob for backup or transfer between devices.

### Export Format

```
┌─────────────┬──────────────────┬──────────────────────────────────┐
│ Version (1B)│ Salt (16 B)      │ AES-256-GCM ciphertext           │
└─────────────┴──────────────────┴──────────────────────────────────┘
```

### Export Encryption

| Parameter | Value |
|---|---|
| KDF | Argon2id |
| Time | 3 (higher than vault default for added brute-force resistance) |
| Memory | 64 × 1024 KiB (64 MiB) |
| Parallelism | 4 |
| Key length | 32 bytes |
| Salt | 16 random bytes (included in output) |

The export passphrase is normalised to NFKD before deriving the encryption key.

### Encrypted Contents

The plaintext is a JSON object containing all credential material:

```json
{
  "member_id":   "uuid",
  "secret_key":  "V1-XXXXXX-...",
  "private_key": [32 bytes],
  "muk":         [32 bytes],
  "kdf_params":  {"time": 1, "memory": 65536, "parallelism": 4, "key_len": 32},
  "salt_pass":   [16 bytes],
  "salt_secret": [16 bytes]
}
```

### Security Warning

The exported blob contains the MUK, private key, secret key, and all KDF parameters. Anyone with the blob and the export passphrase can access every vault associated with these credentials. Exported blobs should be stored only in encrypted storage and deleted after import.

## Memory Protection

**Source:** `github.com/awnumar/memguard`

IronHand uses memguard to protect sensitive key material in process memory.

### Enclaves

The MUK, KEK, and record key are stored in `memguard.Enclave` objects, which encrypt the data at rest in memory using a session key. Data is decrypted into `LockedBuffer` instances only when needed for cryptographic operations:

```go
kekBuf, err := session.kek.Open()  // Decrypt into mlock'd buffer
defer kekBuf.Destroy()              // Wipe and free immediately
// Use kekBuf.Bytes() for the operation
```

`LockedBuffer` memory is:
- Locked to physical RAM (`mlock`) to prevent swapping to disk.
- Guarded with canary pages to detect buffer overflows.
- Wiped on `Destroy()`.

### Explicit Wiping

All intermediate key material is wiped after use:

- `util.WipeBytes(b []byte)` — Zeroes a byte slice.
- `util.WipeArray32(a *[32]byte)` — Zeroes a 32-byte array.

These are called via `defer` immediately after key material is derived or decrypted.

## Summary

### Algorithm Reference

| Component | Algorithm | Key Size | Nonce / Salt | Output |
|---|---|---|---|---|
| Passphrase KDF | Argon2id | — | 16 B salt | 32 B |
| Secret key KDF | HKDF-SHA256 | — | 16 B salt | 32 B |
| MUK combination | XOR | — | — | 32 B |
| Record key | HKDF-SHA256 | 32 B (MUK) | vaultID | 32 B |
| KEK | Random | — | — | 32 B |
| DEK | Random | — | — | 32 B |
| Record encryption | AES-256-GCM | 32 B | 12 B nonce | nonce ‖ ciphertext |
| Field encryption | AES-256-GCM | 32 B (DEK) | 12 B nonce | nonce ‖ ciphertext |
| DEK wrapping | AES-256-GCM | 32 B (KEK) | 12 B nonce | nonce ‖ ciphertext |
| KEK wrapping | X25519 + HKDF + GCM | 32 B (derived) | 32 B salt + 12 B nonce | SealedWrap |
| Credential export | Argon2id + AES-256-GCM | — | 16 B salt + 12 B nonce | ver ‖ salt ‖ ciphertext |

### Key Sizes

All cryptographic keys in IronHand are **32 bytes (256-bit)**, strictly enforced at the primitive level. All GCM nonces are **12 bytes (96-bit)**, randomly generated per encryption. All GCM authentication tags are **16 bytes (128-bit)**.

### Dependencies

| Library | Version | Purpose |
|---|---|---|
| `golang.org/x/crypto` | v0.47.0 | Argon2id, X25519/Curve25519, HKDF |
| `crypto/aes`, `crypto/cipher` | stdlib | AES-256-GCM |
| `crypto/rand` | stdlib | Key and nonce generation |
| `golang.org/x/text` | v0.33.0 | Unicode NFKD normalisation |
| `github.com/awnumar/memguard` | v0.23.0 | In-memory key protection |
