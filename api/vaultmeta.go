package api

import "github.com/jmcleod/ironhand/vault"

const vaultMetadataItemID = "__vault_meta"

type vaultMetadata struct {
	Name        string
	Description string
}

func encodeVaultMetadata(name, description string) vault.Fields {
	return vault.Fields{
		"name":        []byte(name),
		"description": []byte(description),
	}
}

func decodeVaultMetadata(fields vault.Fields) vaultMetadata {
	return vaultMetadata{
		Name:        string(fields["name"]),
		Description: string(fields["description"]),
	}
}
