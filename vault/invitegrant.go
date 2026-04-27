package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/awnumar/memguard"
	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/util"
)

const inviteGrantVersion = 1

type inviteGrant struct {
	Version         int    `json:"version"`
	VaultID         string `json:"vault_id"`
	CreatorMemberID string `json:"creator_member_id"`
	Epoch           uint64 `json:"epoch"`
	RootKey         []byte `json:"root_key"`
	KEK             []byte `json:"kek"`
}

// ExportInviteGrant encrypts the minimum vault material needed to accept an
// invite later. It intentionally does not include account credentials, MUKs,
// secret keys, or member private keys.
func (s *Session) ExportInviteGrant(ctx context.Context, passphrase string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	state, err := s.authorize(ctx, accessAdmin, recBuf.Bytes())
	if err != nil {
		return nil, err
	}
	rootBuf, err := s.rootKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening vault root key enclave: %w", err)
	}
	defer rootBuf.Destroy()
	kekBuf, err := s.kek.Open()
	if err != nil {
		return nil, fmt.Errorf("opening KEK enclave: %w", err)
	}
	defer kekBuf.Destroy()

	grant := inviteGrant{
		Version:         inviteGrantVersion,
		VaultID:         state.VaultID,
		CreatorMemberID: s.MemberID,
		Epoch:           state.Epoch,
		RootKey:         util.CopyBytes(rootBuf.Bytes()),
		KEK:             util.CopyBytes(kekBuf.Bytes()),
	}
	defer util.WipeBytes(grant.RootKey)
	defer util.WipeBytes(grant.KEK)
	return exportInviteGrant(grant, passphrase)
}

// OpenInviteGrant opens a temporary owner session from an invite grant so the
// pre-authorized member addition can be completed without credential cloning.
func (v *Vault) OpenInviteGrant(ctx context.Context, data []byte, passphrase string) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	grant, err := importInviteGrant(data, passphrase)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(grant.RootKey)
	defer util.WipeBytes(grant.KEK)
	if grant.Version != inviteGrantVersion {
		return nil, fmt.Errorf("unsupported invite grant version: %d", grant.Version)
	}
	if grant.VaultID != v.id {
		return nil, fmt.Errorf("invite grant is for vault %q", grant.VaultID)
	}
	recordKey, err := icrypto.DeriveRecordKey(grant.RootKey, v.id)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(recordKey)
	state, err := loadVaultState(v.id, v.repo, recordKey)
	if err != nil {
		return nil, err
	}
	if state.Epoch != grant.Epoch {
		return nil, ErrStaleSession
	}
	maxSeen := v.epochCache.GetMaxEpochSeen(v.id)
	if state.Epoch < maxSeen {
		return nil, ErrRollbackDetected
	}
	if err := v.epochCache.SetMaxEpochSeen(v.id, state.Epoch); err != nil {
		return nil, err
	}
	return &Session{
		vault:     v,
		epoch:     state.Epoch,
		MemberID:  grant.CreatorMemberID,
		kek:       memguard.NewEnclave(grant.KEK),
		recordKey: memguard.NewEnclave(util.CopyBytes(recordKey)),
		rootKey:   memguard.NewEnclave(grant.RootKey),
	}, nil
}

func exportInviteGrant(grant inviteGrant, passphrase string) ([]byte, error) {
	plaintext, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(plaintext)
	salt, err := util.RandomBytes(exportSaltLen)
	if err != nil {
		return nil, err
	}
	key, err := util.DeriveArgon2idKey(util.Normalize(passphrase), salt, exportKDFParams)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(key)
	ciphertext, err := util.EncryptAES(plaintext, key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+exportSaltLen+len(ciphertext))
	out = append(out, byte(inviteGrantVersion))
	out = append(out, salt...)
	out = append(out, ciphertext...)
	return out, nil
}

func importInviteGrant(data []byte, passphrase string) (*inviteGrant, error) {
	if len(data) < 1+exportSaltLen {
		return nil, fmt.Errorf("invite grant data too short")
	}
	if data[0] != inviteGrantVersion {
		return nil, fmt.Errorf("unsupported invite grant version: %d", data[0])
	}
	salt := data[1 : 1+exportSaltLen]
	ciphertext := data[1+exportSaltLen:]
	key, err := util.DeriveArgon2idKey(util.Normalize(passphrase), salt, exportKDFParams)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(key)
	plaintext, err := util.DecryptAES(ciphertext, key)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(plaintext)
	var grant inviteGrant
	if err := json.Unmarshal(plaintext, &grant); err != nil {
		return nil, err
	}
	return &grant, nil
}
