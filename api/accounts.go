package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	scrypto "github.com/jmcleod/ironhand/crypto"
	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/storage"
)

const (
	accountVaultID    = "__accounts"
	accountRecordType = "ACCOUNT"
	accountAADPrefix  = "account:"
)

type accountRecord struct {
	SecretKeyID     string    `json:"secret_key_id"`
	CredentialsBlob string    `json:"credentials_blob"`
	CreatedAt       time.Time `json:"created_at"`
	TOTPEnabled     bool      `json:"totp_enabled,omitempty"`
	TOTPSecret      string    `json:"totp_secret,omitempty"`
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
