package key

import (
	"encoding/json"
	"fmt"
)

type jsonEncryptedKey struct {
	KeyID       string `json:"keyId"`
	EncryptedBy string `json:"encryptedBy"`
	KeyType     Type   `json:"keyType"`
	Bytes       []byte `json:"bytes"`
}

func (ek *encryptedKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonEncryptedKey{
		KeyID:       ek.keyID,
		EncryptedBy: ek.encryptedBy,
		KeyType:     ek.keyType,
		Bytes:       ek.bytes,
	})
}

func (ek *encryptedKey) UnmarshalJSON(b []byte) error {
	return unmarshalEncryptedKey(&jsonEncryptedKey{}, ek, b)
}

func unmarshalEncryptedKey(jek *jsonEncryptedKey, ek *encryptedKey, b []byte) error {
	if err := json.Unmarshal(b, jek); err != nil {
		return fmt.Errorf("unmarshaling encrypted key JSON: %w", err)
	}

	ek.keyID = jek.KeyID
	ek.encryptedBy = jek.EncryptedBy
	ek.keyType = jek.KeyType
	ek.bytes = jek.Bytes

	return nil
}

// UnmarshalEncryptedKey deserializes an EncryptedKey from JSON.
func UnmarshalEncryptedKey(message json.RawMessage) (EncryptedKey, error) {
	jek := &jsonEncryptedKey{}
	ek := &encryptedKey{}

	if err := unmarshalEncryptedKey(jek, ek, message); err != nil {
		return nil, err
	}

	return ek, nil
}
