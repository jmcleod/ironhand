package key

import (
	"encoding/json"
	"fmt"
)

type jsonKey struct {
	KeyID   string `json:"keyId"`
	KeyType Type   `json:"keyType"`
	Bytes   []byte `json:"bytes"`
}

func (k *key) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonKey{
		KeyID:   k.keyID,
		KeyType: k.keyType,
		Bytes:   k.bytes,
	})
}

func (k *key) UnmarshalJSON(b []byte) error {
	return unmarshalKey(&jsonKey{}, k, b)
}

func unmarshalKey(jk *jsonKey, k *key, b []byte) error {
	if err := json.Unmarshal(b, jk); err != nil {
		return fmt.Errorf("unmarshaling key JSON: %w", err)
	}

	k.keyID = jk.KeyID
	k.keyType = jk.KeyType
	k.bytes = jk.Bytes

	return nil
}

// UnmarshalKey deserializes a Key from JSON.
func UnmarshalKey(message json.RawMessage) (Key, error) {
	jk := &jsonKey{}
	k := &key{}

	if err := unmarshalKey(jk, k, message); err != nil {
		return nil, err
	}

	return k, nil
}
