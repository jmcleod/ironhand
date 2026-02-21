package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	scrypto "github.com/jmcleod/ironhand/crypto"
	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/storage"
)

const (
	accountVaultID       = "__accounts"
	accountRecordType    = "ACCOUNT"
	accountAADPrefix     = "account:"
	vaultIndexRecordType = "VAULT_INDEX"
	vaultIndexAADPrefix  = "vault-index:"
)

// WebAuthnCredentialMeta holds user-facing metadata for a WebAuthn credential.
// It is stored separately from the webauthn.Credential struct (which comes from
// the third-party go-webauthn library) and keyed by the base64url credential ID.
type WebAuthnCredentialMeta struct {
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// HashedRecoveryCode is a single-use break-glass recovery code stored as its
// SHA-256 hash. The plaintext is shown to the user once at generation time and
// never persisted.
type HashedRecoveryCode struct {
	Hash string `json:"hash"` // hex(SHA-256(code))
	Used bool   `json:"used"`
}

type accountRecord struct {
	SecretKeyID            string                            `json:"secret_key_id"`
	CredentialsBlob        string                            `json:"credentials_blob"`
	CreatedAt              time.Time                         `json:"created_at"`
	TOTPEnabled            bool                              `json:"totp_enabled,omitempty"`
	TOTPSecret             string                            `json:"totp_secret,omitempty"`
	WebAuthnCredentials    []webauthn.Credential             `json:"webauthn_credentials,omitempty"`
	WebAuthnCredentialMeta map[string]WebAuthnCredentialMeta `json:"webauthn_credential_meta,omitempty"`
	RecoveryCodes          []HashedRecoveryCode              `json:"recovery_codes,omitempty"`
	VaultCredentials       map[string]string                 `json:"vault_credentials,omitempty"` // vaultID → base64(AES(serialized creds))
}

func (a *API) saveAccountRecord(secretKey string, record accountRecord) error {
	accountID, err := accountLookupID(secretKey)
	if err != nil {
		return err
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	recordKey, aad, err := deriveAccountRecordKey(secretKey)
	if err != nil {
		return err
	}
	defer util.WipeBytes(recordKey)

	env, err := storage.SealRecord(recordKey, data, aad)
	if err != nil {
		return err
	}
	return a.repo.Put(accountVaultID, accountRecordType, accountID, env)
}

func (a *API) updateAccountRecord(secretKey string, record accountRecord) error {
	accountID, err := accountLookupID(secretKey)
	if err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	recordKey, aad, err := deriveAccountRecordKey(secretKey)
	if err != nil {
		return err
	}
	defer util.WipeBytes(recordKey)
	env, err := storage.SealRecord(recordKey, data, aad)
	if err != nil {
		return err
	}
	return a.repo.Put(accountVaultID, accountRecordType, accountID, env)
}

func (a *API) loadAccountRecord(secretKey string) (*accountRecord, error) {
	accountID, err := accountLookupID(secretKey)
	if err != nil {
		return nil, err
	}
	recordKey, aad, err := deriveAccountRecordKey(secretKey)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(recordKey)

	env, err := a.repo.Get(accountVaultID, accountRecordType, accountID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrVaultNotFound) {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}
	if env == nil {
		return nil, fmt.Errorf("account not found")
	}

	if env.Scheme != "aes256gcm" {
		return nil, fmt.Errorf("unsupported account record scheme: %s", env.Scheme)
	}
	data, err := storage.OpenRecord(recordKey, env, aad)
	if err != nil {
		return nil, err
	}

	var record accountRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func accountLookupID(secretKey string) (string, error) {
	sk, err := scrypto.ParseSecretKey(secretKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(sk.String()))
	return hex.EncodeToString(sum[:]), nil
}

func deriveAccountRecordKey(secretKey string) ([]byte, []byte, error) {
	sk, err := scrypto.ParseSecretKey(secretKey)
	if err != nil {
		return nil, nil, err
	}
	secretBytes := sk.Bytes()
	defer util.WipeBytes(secretBytes)
	accountID, err := accountLookupID(secretKey)
	if err != nil {
		return nil, nil, err
	}
	recordKey, err := icrypto.DeriveRecordKey(secretBytes, accountID)
	if err != nil {
		return nil, nil, err
	}
	return recordKey, []byte(accountAADPrefix + accountID), nil
}

// ---------------------------------------------------------------------------
// Vault index — maps account → list of vault IDs the account can access.
// ---------------------------------------------------------------------------

type vaultIndexRecord struct {
	VaultIDs []string `json:"vault_ids"`
}

func (a *API) loadVaultIndex(secretKey string) (vaultIndexRecord, error) {
	accountID, err := accountLookupID(secretKey)
	if err != nil {
		return vaultIndexRecord{}, err
	}
	recordKey, _, err := deriveAccountRecordKey(secretKey)
	if err != nil {
		return vaultIndexRecord{}, err
	}
	defer util.WipeBytes(recordKey)
	aad := []byte(vaultIndexAADPrefix + accountID)

	env, err := a.repo.Get(accountVaultID, vaultIndexRecordType, accountID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrVaultNotFound) {
			return vaultIndexRecord{}, nil // no index yet
		}
		return vaultIndexRecord{}, err
	}
	if env == nil {
		return vaultIndexRecord{}, nil
	}

	data, err := storage.OpenRecord(recordKey, env, aad)
	if err != nil {
		return vaultIndexRecord{}, err
	}
	var idx vaultIndexRecord
	if err := json.Unmarshal(data, &idx); err != nil {
		return vaultIndexRecord{}, err
	}
	return idx, nil
}

func (a *API) saveVaultIndex(secretKey string, idx vaultIndexRecord) error {
	accountID, err := accountLookupID(secretKey)
	if err != nil {
		return err
	}
	recordKey, _, err := deriveAccountRecordKey(secretKey)
	if err != nil {
		return err
	}
	defer util.WipeBytes(recordKey)
	aad := []byte(vaultIndexAADPrefix + accountID)

	data, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	env, err := storage.SealRecord(recordKey, data, aad)
	if err != nil {
		return err
	}
	return a.repo.Put(accountVaultID, vaultIndexRecordType, accountID, env)
}

func (a *API) addVaultToIndex(secretKey, vaultID string) error {
	idx, err := a.loadVaultIndex(secretKey)
	if err != nil {
		return err
	}
	// Avoid duplicates.
	for _, id := range idx.VaultIDs {
		if id == vaultID {
			return nil
		}
	}
	idx.VaultIDs = append(idx.VaultIDs, vaultID)
	return a.saveVaultIndex(secretKey, idx)
}

func (a *API) removeVaultFromIndex(secretKey, vaultID string) error {
	idx, err := a.loadVaultIndex(secretKey)
	if err != nil {
		return err
	}
	filtered := idx.VaultIDs[:0]
	for _, id := range idx.VaultIDs {
		if id != vaultID {
			filtered = append(filtered, id)
		}
	}
	idx.VaultIDs = filtered
	return a.saveVaultIndex(secretKey, idx)
}
