package icrypto

import "github.com/jmcleod/ironhand/internal/util"

const recordKeyInfo = "vault:record-key:v1"

// DeriveRecordKey derives a vault-specific record encryption key from the MUK.
func DeriveRecordKey(muk []byte, vaultID string) ([]byte, error) {
	return util.HKDF(muk, []byte(vaultID), []byte(recordKeyInfo))
}
