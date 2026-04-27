package vault

import (
	"encoding/json"
	"fmt"

	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/storage"
)

const rootWrapEnvelopeScheme = "x25519-vault-root-wrap-v1"

func sealVaultRootKey(vaultID, memberID string, memberPub [32]byte, rootKey []byte) (*vaultRootWrap, error) {
	wrap, err := icrypto.SealToMember(memberPub, rootKey, rootWrapAAD(vaultID, memberID))
	if err != nil {
		return nil, err
	}
	return &vaultRootWrap{MemberID: memberID, Wrap: *wrap}, nil
}

func openVaultRootKey(vaultID string, repo storage.Repository, creds *Credentials) ([]byte, error) {
	env, err := repo.Get(vaultID, recordTypeRootWrap, creds.memberID)
	if err != nil {
		return nil, err
	}
	wrap, err := decodeVaultRootWrap(vaultID, creds.memberID, env)
	if err != nil {
		return nil, err
	}
	return icrypto.OpenFromMember(creds.keypair.Private, &wrap.Wrap, rootWrapAAD(vaultID, creds.memberID))
}

func encodeVaultRootWrap(vaultID string, wrap vaultRootWrap) (*storage.Envelope, error) {
	_ = vaultID
	if err := validateID(wrap.MemberID, "member ID"); err != nil {
		return nil, err
	}
	data, err := json.Marshal(wrap)
	if err != nil {
		return nil, err
	}
	return &storage.Envelope{
		Ver:        1,
		Scheme:     rootWrapEnvelopeScheme,
		Ciphertext: data,
	}, nil
}

func decodeVaultRootWrap(vaultID, memberID string, env *storage.Envelope) (*vaultRootWrap, error) {
	_ = vaultID
	if env.Ver != 1 {
		return nil, fmt.Errorf("unsupported root wrap envelope version: %d", env.Ver)
	}
	if env.Scheme != rootWrapEnvelopeScheme {
		return nil, fmt.Errorf("unsupported root wrap envelope scheme: %s", env.Scheme)
	}
	var wrap vaultRootWrap
	if err := json.Unmarshal(env.Ciphertext, &wrap); err != nil {
		return nil, err
	}
	if wrap.MemberID != memberID {
		return nil, fmt.Errorf("root wrap is bound to member %q, not %q", wrap.MemberID, memberID)
	}
	return &wrap, nil
}

func rootWrapAAD(vaultID, memberID string) []byte {
	return icrypto.AADRecord(vaultID, recordTypeRootWrap, memberID, 0, 1)
}
