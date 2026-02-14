package api

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmcleod/ironhand/storage"
)

const (
	accountVaultID    = "__accounts"
	accountRecordType = "ACCOUNT"
)

type accountRecord struct {
	SecretKeyID     string    `json:"secret_key_id"`
	CredentialsBlob string    `json:"credentials_blob"`
	CreatedAt       time.Time `json:"created_at"`
}

func (a *API) saveAccountRecord(record accountRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	env := &storage.Envelope{
		Ver:        1,
		Scheme:     "plain-json",
		Nonce:      nil,
		Ciphertext: data,
	}
	return a.repo.Put(accountVaultID, accountRecordType, record.SecretKeyID, env)
}

func (a *API) loadAccountRecord(secretKeyID string) (*accountRecord, error) {
	env, err := a.repo.Get(accountVaultID, accountRecordType, secretKeyID)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, fmt.Errorf("account not found")
	}
	var record accountRecord
	if err := json.Unmarshal(env.Ciphertext, &record); err != nil {
		return nil, err
	}
	return &record, nil
}
