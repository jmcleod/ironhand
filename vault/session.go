package vault

import (
	"context"
	"errors"
	"fmt"

	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/util"
)

const defaultContentType = "application/octet-stream"

// Session holds the decrypted key material for an active vault session.
// Callers must call Close() when done (e.g. defer session.Close()) to zero
// sensitive key material from memory.
type Session struct {
	vault     *Vault
	epoch     uint64
	MemberID  string
	kek       [32]byte
	recordKey []byte
}

type requiredAccess int

const (
	accessRead requiredAccess = iota
	accessWrite
	accessAdmin
)

// Epoch returns the current epoch of the session.
func (s *Session) Epoch() uint64 {
	return s.epoch
}

// Close zeroes sensitive key material held by the session.
func (s *Session) Close() {
	for i := range s.kek {
		s.kek[i] = 0
	}
	util.WipeBytes(s.recordKey)
}

// Put encrypts and stores a new item in the vault.
func (s *Session) Put(ctx context.Context, itemID string, plaintext []byte, opts ...PutOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := s.authorize(ctx, accessWrite); err != nil {
		return err
	}

	o := putOptions{contentType: defaultContentType}
	for _, opt := range opts {
		opt(&o)
	}

	if err := validateID(itemID, "item ID"); err != nil {
		return err
	}
	if err := validateContentType(o.contentType); err != nil {
		return err
	}
	if err := validateContentSize(plaintext); err != nil {
		return err
	}

	dek, err := util.NewAESKey()
	if err != nil {
		return err
	}
	defer util.WipeBytes(dek)

	// Encrypt content
	itemVersion := uint64(1)
	aadContent := icrypto.AADItemContent(s.vault.id, itemID, o.contentType, itemVersion, s.epoch, 1)
	ciphertext, err := util.EncryptAESWithAAD(plaintext, dek, aadContent)
	if err != nil {
		return err
	}

	// Wrap DEK
	aadDEK := icrypto.AADDEKWrap(s.vault.id, itemID, s.epoch, 1)
	wrappedDEK, err := util.EncryptAESWithAAD(dek, s.kek[:], aadDEK)
	if err != nil {
		return err
	}

	itm := item{
		ItemID:       itemID,
		ContentType:  o.contentType,
		ItemVersion:  itemVersion,
		Ciphertext:   ciphertext,
		WrappedDEK:   wrappedDEK,
		WrappedEpoch: s.epoch,
		UpdatedBy:    s.MemberID,
	}

	envelope, err := sealItem(s.vault.id, s.recordKey, itm, s.epoch)
	if err != nil {
		return err
	}
	return s.vault.repo.PutCAS(s.vault.id, "ITEM", itm.ItemID, 0, envelope)
}

// Get retrieves and decrypts an item from the vault.
func (s *Session) Get(ctx context.Context, itemID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := s.authorize(ctx, accessRead); err != nil {
		return nil, err
	}

	itm, err := loadItem(s.vault.id, s.vault.repo, s.recordKey, itemID, s.epoch)
	if err != nil {
		return nil, err
	}

	// Unwrap DEK
	aadDEK := icrypto.AADDEKWrap(s.vault.id, itm.ItemID, itm.WrappedEpoch, 1)
	dek, err := util.DecryptAESWithAAD(itm.WrappedDEK, s.kek[:], aadDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}
	defer util.WipeBytes(dek)

	// Decrypt content
	aadContent := icrypto.AADItemContent(s.vault.id, itm.ItemID, itm.ContentType, itm.ItemVersion, itm.WrappedEpoch, 1)
	return util.DecryptAESWithAAD(itm.Ciphertext, dek, aadContent)
}

// Update re-encrypts and stores an existing item, using CAS to detect conflicts.
func (s *Session) Update(ctx context.Context, itemID string, plaintext []byte, opts ...PutOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := s.authorize(ctx, accessWrite); err != nil {
		return err
	}

	existing, err := loadItem(s.vault.id, s.vault.repo, s.recordKey, itemID, s.epoch)
	if err != nil {
		return err
	}

	o := putOptions{contentType: existing.ContentType}
	for _, opt := range opts {
		opt(&o)
	}

	if err := validateContentType(o.contentType); err != nil {
		return err
	}
	if err := validateContentSize(plaintext); err != nil {
		return err
	}

	dek, err := util.NewAESKey()
	if err != nil {
		return err
	}
	defer util.WipeBytes(dek)

	newVersion := existing.ItemVersion + 1

	// Encrypt content
	aadContent := icrypto.AADItemContent(s.vault.id, itemID, o.contentType, newVersion, s.epoch, 1)
	ciphertext, err := util.EncryptAESWithAAD(plaintext, dek, aadContent)
	if err != nil {
		return err
	}

	// Wrap DEK
	aadDEK := icrypto.AADDEKWrap(s.vault.id, itemID, s.epoch, 1)
	wrappedDEK, err := util.EncryptAESWithAAD(dek, s.kek[:], aadDEK)
	if err != nil {
		return err
	}

	itm := item{
		ItemID:       itemID,
		ContentType:  o.contentType,
		ItemVersion:  newVersion,
		Ciphertext:   ciphertext,
		WrappedDEK:   wrappedDEK,
		WrappedEpoch: s.epoch,
		UpdatedBy:    s.MemberID,
	}

	envelope, err := sealItem(s.vault.id, s.recordKey, itm, s.epoch)
	if err != nil {
		return err
	}
	return s.vault.repo.PutCAS(s.vault.id, "ITEM", itm.ItemID, existing.ItemVersion, envelope)
}

// AddMember adds a new member to the vault and rotates the epoch.
func (s *Session) AddMember(ctx context.Context, memberID string, pubKey [32]byte, role MemberRole) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRole(role); err != nil {
		return err
	}
	state, err := s.authorize(ctx, accessAdmin)
	if err != nil {
		return err
	}
	if err := validateID(memberID, "member ID"); err != nil {
		return err
	}

	newMember := &Member{
		MemberID: memberID,
		PubKey:   pubKey,
		Role:     role,
	}

	return s.rotateEpoch(ctx, state, newMember, nil)
}

// RevokeMember revokes a member's access to the vault and rotates the epoch.
func (s *Session) RevokeMember(ctx context.Context, memberID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := s.authorize(ctx, accessAdmin)
	if err != nil {
		return err
	}
	if err := validateID(memberID, "member ID"); err != nil {
		return err
	}

	return s.rotateEpoch(ctx, state, nil, &memberID)
}

func (s *Session) authorize(ctx context.Context, required requiredAccess) (*vaultState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := loadVaultState(s.vault.id, s.vault.repo, s.recordKey)
	if err != nil {
		return nil, err
	}
	if s.epoch != state.Epoch {
		return nil, ErrStaleSession
	}

	member, err := loadMember(s.vault.id, s.vault.repo, s.recordKey, s.MemberID, state.Epoch)
	if err != nil {
		return nil, fmt.Errorf("%w: member not found", ErrUnauthorized)
	}
	if member.Status != StatusActive {
		return nil, fmt.Errorf("%w: member is not active", ErrUnauthorized)
	}

	switch required {
	case accessRead:
		if member.Role != RoleOwner && member.Role != RoleWriter && member.Role != RoleReader {
			return nil, fmt.Errorf("%w: invalid role %q", ErrUnauthorized, member.Role)
		}
	case accessWrite:
		if member.Role != RoleOwner && member.Role != RoleWriter {
			return nil, fmt.Errorf("%w: write requires owner or writer role", ErrUnauthorized)
		}
	case accessAdmin:
		if member.Role != RoleOwner {
			return nil, fmt.Errorf("%w: admin requires owner role", ErrUnauthorized)
		}
	default:
		return nil, errors.New("invalid access requirement")
	}

	return state, nil
}
