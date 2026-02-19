package vault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/storage"
)

// Session holds the encrypted key material for an active vault session.
// Keys are stored in memguard Enclaves (encrypted at rest in memory) and
// decrypted briefly into mlock'd LockedBuffers only during operations.
// Callers must call Close() when done (e.g. defer session.Close()).
type Session struct {
	vault     *Vault
	epoch     uint64
	MemberID  string
	kek       *memguard.Enclave
	recordKey *memguard.Enclave
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

// Close destroys the encrypted key material held by the session.
func (s *Session) Close() {
	s.kek = nil
	s.recordKey = nil
}

func (s *Session) checkClosed() error {
	if s.kek == nil || s.recordKey == nil {
		return ErrSessionClosed
	}
	return nil
}

// Put encrypts and stores a new item in the vault.
// Each field is encrypted independently with the item's DEK.
func (s *Session) Put(ctx context.Context, itemID string, fields Fields) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkClosed(); err != nil {
		return err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	kekBuf, err := s.kek.Open()
	if err != nil {
		return fmt.Errorf("opening KEK enclave: %w", err)
	}
	defer kekBuf.Destroy()

	if _, err := s.authorize(ctx, accessWrite, recBuf.Bytes()); err != nil {
		return err
	}

	if err := validateID(itemID, "item ID"); err != nil {
		return err
	}
	if err := validateFields(fields); err != nil {
		return err
	}

	dek, err := util.NewAESKey()
	if err != nil {
		return err
	}
	defer util.WipeBytes(dek)

	itemVersion := uint64(1)

	// Encrypt each field independently with the same DEK
	encFields := make(map[string]field, len(fields))
	for name, plaintext := range fields {
		aad := icrypto.AADFieldContent(s.vault.id, itemID, name, itemVersion, s.epoch, 1)
		ct, err := util.EncryptAESWithAAD(plaintext, dek, aad)
		if err != nil {
			return fmt.Errorf("encrypting field %q: %w", name, err)
		}
		encFields[name] = field{Ciphertext: ct}
	}

	// Wrap DEK
	aadDEK := icrypto.AADDEKWrap(s.vault.id, itemID, s.epoch, 1)
	wrappedDEK, err := util.EncryptAESWithAAD(dek, kekBuf.Bytes(), aadDEK)
	if err != nil {
		return err
	}

	itm := item{
		ItemID:       itemID,
		ItemVersion:  itemVersion,
		Fields:       encFields,
		WrappedDEK:   wrappedDEK,
		WrappedEpoch: s.epoch,
		UpdatedBy:    s.MemberID,
	}

	envelope, err := sealItem(s.vault.id, recBuf.Bytes(), itm, s.epoch)
	if err != nil {
		return err
	}
	return s.vault.repo.PutCAS(s.vault.id, "ITEM", itm.ItemID, 0, envelope)
}

// Get retrieves and decrypts an item from the vault, returning all fields.
func (s *Session) Get(ctx context.Context, itemID string) (Fields, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	kekBuf, err := s.kek.Open()
	if err != nil {
		return nil, fmt.Errorf("opening KEK enclave: %w", err)
	}
	defer kekBuf.Destroy()

	if _, err := s.authorize(ctx, accessRead, recBuf.Bytes()); err != nil {
		return nil, err
	}

	itm, err := loadItem(s.vault.id, s.vault.repo, recBuf.Bytes(), itemID, s.epoch)
	if err != nil {
		return nil, err
	}

	// Unwrap DEK
	aadDEK := icrypto.AADDEKWrap(s.vault.id, itm.ItemID, itm.WrappedEpoch, 1)
	dek, err := util.DecryptAESWithAAD(itm.WrappedDEK, kekBuf.Bytes(), aadDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}
	defer util.WipeBytes(dek)

	// Decrypt each field
	result := make(Fields, len(itm.Fields))
	for name, f := range itm.Fields {
		aad := icrypto.AADFieldContent(s.vault.id, itm.ItemID, name, itm.ItemVersion, itm.WrappedEpoch, 1)
		plaintext, err := util.DecryptAESWithAAD(f.Ciphertext, dek, aad)
		if err != nil {
			return nil, fmt.Errorf("decrypting field %q: %w", name, err)
		}
		result[name] = plaintext
	}

	return result, nil
}

// Update re-encrypts and stores an existing item, using CAS to detect conflicts.
// All fields are replaced atomically. The previous version is preserved as an
// ITEM_HISTORY record so it can be retrieved later via GetHistory/GetHistoryVersion.
func (s *Session) Update(ctx context.Context, itemID string, fields Fields) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkClosed(); err != nil {
		return err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	kekBuf, err := s.kek.Open()
	if err != nil {
		return fmt.Errorf("opening KEK enclave: %w", err)
	}
	defer kekBuf.Destroy()

	if _, err := s.authorize(ctx, accessWrite, recBuf.Bytes()); err != nil {
		return err
	}

	existing, err := loadItem(s.vault.id, s.vault.repo, recBuf.Bytes(), itemID, s.epoch)
	if err != nil {
		return err
	}

	if err := validateFields(fields); err != nil {
		return err
	}

	// --- Snapshot the existing item into ITEM_HISTORY before overwriting ---
	historyRecordID := fmt.Sprintf("%s#%d", itemID, existing.ItemVersion)
	hist := itemHistory{
		ItemID:       existing.ItemID,
		Version:      existing.ItemVersion,
		Fields:       existing.Fields,
		WrappedDEK:   existing.WrappedDEK,
		WrappedEpoch: existing.WrappedEpoch,
		UpdatedBy:    existing.UpdatedBy,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	histEnvelope, err := sealItemHistory(s.vault.id, recBuf.Bytes(), hist, s.epoch)
	if err != nil {
		return fmt.Errorf("sealing history record: %w", err)
	}
	if err := s.vault.repo.Put(s.vault.id, recordTypeItemHistory, historyRecordID, histEnvelope); err != nil {
		return fmt.Errorf("storing history record: %w", err)
	}

	// --- Proceed with normal update ---
	dek, err := util.NewAESKey()
	if err != nil {
		return err
	}
	defer util.WipeBytes(dek)

	newVersion := existing.ItemVersion + 1

	// Encrypt each field independently with the same DEK
	encFields := make(map[string]field, len(fields))
	for name, plaintext := range fields {
		aad := icrypto.AADFieldContent(s.vault.id, itemID, name, newVersion, s.epoch, 1)
		ct, err := util.EncryptAESWithAAD(plaintext, dek, aad)
		if err != nil {
			return fmt.Errorf("encrypting field %q: %w", name, err)
		}
		encFields[name] = field{Ciphertext: ct}
	}

	// Wrap DEK
	aadDEK := icrypto.AADDEKWrap(s.vault.id, itemID, s.epoch, 1)
	wrappedDEK, err := util.EncryptAESWithAAD(dek, kekBuf.Bytes(), aadDEK)
	if err != nil {
		return err
	}

	itm := item{
		ItemID:       itemID,
		ItemVersion:  newVersion,
		Fields:       encFields,
		WrappedDEK:   wrappedDEK,
		WrappedEpoch: s.epoch,
		UpdatedBy:    s.MemberID,
	}

	envelope, err := sealItem(s.vault.id, recBuf.Bytes(), itm, s.epoch)
	if err != nil {
		return err
	}
	return s.vault.repo.PutCAS(s.vault.id, "ITEM", itm.ItemID, existing.ItemVersion, envelope)
}

// GetHistory returns a list of history entries for the given item, sorted newest-first.
func (s *Session) GetHistory(ctx context.Context, itemID string) ([]HistoryEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	if _, err := s.authorize(ctx, accessRead, recBuf.Bytes()); err != nil {
		return nil, err
	}

	allIDs, err := s.vault.repo.List(s.vault.id, recordTypeItemHistory)
	if err != nil {
		return nil, err
	}

	prefix := itemID + "#"
	var entries []HistoryEntry
	for _, id := range allIDs {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		hist, err := loadItemHistory(s.vault.id, s.vault.repo, recBuf.Bytes(), id, s.epoch)
		if err != nil {
			return nil, fmt.Errorf("loading history record %s: %w", id, err)
		}
		entries = append(entries, HistoryEntry{
			Version:   hist.Version,
			UpdatedAt: hist.UpdatedAt,
			UpdatedBy: hist.UpdatedBy,
		})
	}

	// Sort newest-first (highest version first).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Version > entries[j].Version
	})

	return entries, nil
}

// GetHistoryVersion decrypts and returns the fields from a specific history version.
func (s *Session) GetHistoryVersion(ctx context.Context, itemID string, version uint64) (Fields, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	kekBuf, err := s.kek.Open()
	if err != nil {
		return nil, fmt.Errorf("opening KEK enclave: %w", err)
	}
	defer kekBuf.Destroy()

	if _, err := s.authorize(ctx, accessRead, recBuf.Bytes()); err != nil {
		return nil, err
	}

	recordID := fmt.Sprintf("%s#%d", itemID, version)
	hist, err := loadItemHistory(s.vault.id, s.vault.repo, recBuf.Bytes(), recordID, s.epoch)
	if err != nil {
		return nil, err
	}

	// Unwrap DEK
	aadDEK := icrypto.AADDEKWrap(s.vault.id, hist.ItemID, hist.WrappedEpoch, 1)
	dek, err := util.DecryptAESWithAAD(hist.WrappedDEK, kekBuf.Bytes(), aadDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap history DEK: %w", err)
	}
	defer util.WipeBytes(dek)

	// Decrypt each field
	result := make(Fields, len(hist.Fields))
	for name, f := range hist.Fields {
		aad := icrypto.AADFieldContent(s.vault.id, hist.ItemID, name, hist.Version, hist.WrappedEpoch, 1)
		plaintext, err := util.DecryptAESWithAAD(f.Ciphertext, dek, aad)
		if err != nil {
			return nil, fmt.Errorf("decrypting history field %q: %w", name, err)
		}
		result[name] = plaintext
	}

	return result, nil
}

// List returns the IDs of all items stored in the vault.
func (s *Session) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	if _, err := s.authorize(ctx, accessRead, recBuf.Bytes()); err != nil {
		return nil, err
	}
	return s.vault.repo.List(s.vault.id, recordTypeItem)
}

// Delete removes an item from the vault.
func (s *Session) Delete(ctx context.Context, itemID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkClosed(); err != nil {
		return err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	if _, err := s.authorize(ctx, accessWrite, recBuf.Bytes()); err != nil {
		return err
	}
	if err := validateID(itemID, "item ID"); err != nil {
		return err
	}
	return s.vault.repo.Delete(s.vault.id, recordTypeItem, itemID)
}

// AddMember adds a new member to the vault and rotates the epoch.
func (s *Session) AddMember(ctx context.Context, memberID string, pubKey [32]byte, role MemberRole) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkClosed(); err != nil {
		return err
	}
	if err := validateRole(role); err != nil {
		return err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	state, err := s.authorize(ctx, accessAdmin, recBuf.Bytes())
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

	return s.rotateEpoch(ctx, state, newMember, nil, recBuf.Bytes())
}

// RevokeMember revokes a member's access to the vault and rotates the epoch.
func (s *Session) RevokeMember(ctx context.Context, memberID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkClosed(); err != nil {
		return err
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	state, err := s.authorize(ctx, accessAdmin, recBuf.Bytes())
	if err != nil {
		return err
	}
	if err := validateID(memberID, "member ID"); err != nil {
		return err
	}

	return s.rotateEpoch(ctx, state, nil, &memberID, recBuf.Bytes())
}

// RequireAdmin verifies the session member currently has owner/admin access.
func (s *Session) RequireAdmin(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkClosed(); err != nil {
		return err
	}
	recBuf, err := s.recordKey.Open()
	if err != nil {
		return fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	_, err = s.authorize(ctx, accessAdmin, recBuf.Bytes())
	return err
}

// SealAuditRecord encrypts an audit entry using the vault's record key.
// The caller provides AAD to bind the ciphertext to its context (e.g.
// vault ID and entry ID).
func (s *Session) SealAuditRecord(plaintext, aad []byte) (*storage.Envelope, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	return storage.SealRecord(recBuf.Bytes(), plaintext, aad)
}

// OpenAuditRecord decrypts an audit entry envelope using the vault's record key.
func (s *Session) OpenAuditRecord(env *storage.Envelope, aad []byte) ([]byte, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	return storage.OpenRecord(recBuf.Bytes(), env, aad)
}

// HMACAudit computes HMAC-SHA256 of the given data using the vault's record
// key. This is used to produce tamper-evident signatures over audit exports.
func (s *Session) HMACAudit(data []byte) ([]byte, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	mac := hmac.New(sha256.New, recBuf.Bytes())
	mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *Session) authorize(ctx context.Context, required requiredAccess, recordKey []byte) (*vaultState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := loadVaultState(s.vault.id, s.vault.repo, recordKey)
	if err != nil {
		return nil, err
	}
	if s.epoch != state.Epoch {
		return nil, ErrStaleSession
	}

	member, err := loadMember(s.vault.id, s.vault.repo, recordKey, s.MemberID, state.Epoch)
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
