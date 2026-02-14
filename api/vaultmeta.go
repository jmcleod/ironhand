package api

import "encoding/json"

const (
	vaultMetadataItemID      = "__vault_meta"
	vaultMetadataContentType = "application/vnd.ironhand.vaultmeta+json"
)

type vaultMetadata struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

func encodeVaultMetadata(name, description string) ([]byte, error) {
	return json.Marshal(vaultMetadata{
		Name:        name,
		Description: description,
	})
}

func decodeVaultMetadata(data []byte) (vaultMetadata, error) {
	var meta vaultMetadata
	err := json.Unmarshal(data, &meta)
	return meta, err
}
