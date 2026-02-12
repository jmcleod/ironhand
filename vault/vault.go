package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/awnumar/memguard"
	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/storage"
)

// Vault represents a secure encrypted vault backed by a Repository and EpochCache.
type Vault struct {
	id         string
	repo       storage.Repository
	epochCache EpochCache
}

// New creates a Vault handle for the given vault ID and storage backend.
//
// By default, it uses an in-memory epoch cache (MemoryEpochCache), which is
// suitable for testing or short-lived applications. For production use, it is
// strongly recommended to configure a persistent epoch cache, such as
// BoltEpochCache, using the WithEpochCache option. Failing to do so will
// result in the loss of rollback protection across application restarts.
func New(id string, repo storage.Repository, opts ...VaultOption) *Vault {
	v := &Vault{
		id:         id,
		repo:       repo,
		epochCache: NewMemoryEpochCache(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// ID returns the vault's identifier.
func (v *Vault) ID() string {
	return v.id
}

// Create initializes a new vault with the given credentials as the owner.
// It persists the vault state, owner membership, and KEK wrap, then returns
// an open Session for the owner.
func (v *Vault) Create(ctx context.Context, creds *Credentials, opts ...CreateOption) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, fmt.Errorf("credentials must not be nil")
	}
	if err := validateID(v.id, "vault ID"); err != nil {
		return nil, err
	}
	if err := validateID(creds.memberID, "member ID"); err != nil {
		return nil, err
	}

	state := newVaultState(v.id, opts...)
	if state.KDFParams != creds.kdfParams {
		return nil, fmt.Errorf("create options KDF params do not match credential profile")
	}
	state.SaltPass = util.CopyBytes(creds.saltPass)
	state.SaltSecret = util.CopyBytes(creds.saltSecret)
	if len(state.SaltPass) == 0 || len(state.SaltSecret) == 0 {
		return nil, fmt.Errorf("credential profile salts must not be empty")
	}

	mukBuf, err := creds.muk.Open()
	if err != nil {
		return nil, fmt.Errorf("opening MUK enclave: %w", err)
	}
	defer mukBuf.Destroy()

	recordKey, err := icrypto.DeriveRecordKey(mukBuf.Bytes(), v.id)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(recordKey)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Generate vault KEK
	kekBytes, err := util.NewAESKey()
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(kekBytes)
	var kek [32]byte
	copy(kek[:], kekBytes)

	// Set owner
	owner := Member{
		MemberID:   creds.memberID,
		PubKey:     creds.keypair.Public,
		Role:       RoleOwner,
		AddedEpoch: 1,
		Status:     StatusActive,
	}

	// Wrap KEK for the owner
	aadKEK := icrypto.AADKEKWrap(v.id, owner.MemberID, 1, 1)
	sealedWrap, err := icrypto.SealToMember(owner.PubKey, kek[:], aadKEK)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	kekWrap := memberKEKWrap{
		Epoch:    1,
		MemberID: owner.MemberID,
		Wrap:     *sealedWrap,
	}

	// Prepare and execute all writes atomically
	stateEnv, err := sealVaultState(recordKey, state)
	if err != nil {
		return nil, err
	}
	memberEnv, err := sealMember(v.id, recordKey, owner, 1)
	if err != nil {
		return nil, err
	}
	wrapEnv, err := sealMemberKEKWrap(v.id, recordKey, kekWrap)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	err = v.repo.Batch(v.id, func(tx storage.BatchTx) error {
		if err := tx.Put(recordTypeState, recordIDCurrent, stateEnv); err != nil {
			return err
		}
		if err := tx.Put(recordTypeMember, owner.MemberID, memberEnv); err != nil {
			return err
		}
		wrapID := fmt.Sprintf("%d:%s", kekWrap.Epoch, kekWrap.MemberID)
		return tx.Put(recordTypeKEKWrap, wrapID, wrapEnv)
	})
	if err != nil {
		return nil, fmt.Errorf("creating vault: %w", err)
	}

	if err := v.epochCache.SetMaxEpochSeen(v.id, state.Epoch); err != nil {
		return nil, err
	}

	return &Session{
		vault:     v,
		epoch:     state.Epoch,
		MemberID:  creds.memberID,
		kek:       memguard.NewEnclave(kek[:]),
		recordKey: memguard.NewEnclave(util.CopyBytes(recordKey)),
	}, nil
}

// Open opens an existing vault session for the given member.
func (v *Vault) Open(ctx context.Context, creds *Credentials) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, fmt.Errorf("credentials must not be nil")
	}
	if err := validateID(v.id, "vault ID"); err != nil {
		return nil, err
	}
	if err := validateID(creds.memberID, "member ID"); err != nil {
		return nil, err
	}

	mukBuf, err := creds.muk.Open()
	if err != nil {
		return nil, fmt.Errorf("opening MUK enclave: %w", err)
	}
	defer mukBuf.Destroy()

	recordKey, err := icrypto.DeriveRecordKey(mukBuf.Bytes(), v.id)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(recordKey)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	state, err := loadVaultState(v.id, v.repo, recordKey)
	if err != nil {
		return nil, err
	}
	if !creds.matchesProfile(state.KDFParams, state.SaltPass, state.SaltSecret) {
		return nil, fmt.Errorf("credential KDF profile does not match vault state")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Rollback check
	maxSeen := v.epochCache.GetMaxEpochSeen(v.id)
	if state.Epoch < maxSeen {
		return nil, ErrRollbackDetected
	}
	if err := v.epochCache.SetMaxEpochSeen(v.id, state.Epoch); err != nil {
		return nil, err
	}

	member, err := loadMember(v.id, v.repo, recordKey, creds.memberID, state.Epoch)
	if err != nil {
		return nil, fmt.Errorf("%w: member not found", ErrUnauthorized)
	}
	if member.Status != StatusActive {
		return nil, fmt.Errorf("%w: member is not active", ErrUnauthorized)
	}
	if member.Role != RoleOwner && member.Role != RoleWriter && member.Role != RoleReader {
		return nil, fmt.Errorf("%w: invalid member role", ErrUnauthorized)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Load memberKEKWrap for (memberID, epoch)
	wrapID := fmt.Sprintf("%d:%s", state.Epoch, creds.memberID)
	envelope, err := v.repo.Get(v.id, recordTypeKEKWrap, wrapID)
	if err != nil {
		return nil, fmt.Errorf("member KEK wrap not found: %w", err)
	}

	aadRecord := icrypto.AADRecord(v.id, recordTypeKEKWrap, wrapID, state.Epoch, 1)
	wrapData, err := storage.OpenRecord(recordKey, envelope, aadRecord)
	if err != nil {
		return nil, err
	}

	var kw memberKEKWrap
	if err := json.Unmarshal(wrapData, &kw); err != nil {
		return nil, err
	}

	// Unwrap KEK
	aadKEK := icrypto.AADKEKWrap(v.id, creds.memberID, state.Epoch, 1)
	kekBytes, err := icrypto.OpenFromMember(creds.keypair.Private, &kw.Wrap, aadKEK)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap KEK: %w", err)
	}
	defer util.WipeBytes(kekBytes)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &Session{
		vault:     v,
		epoch:     state.Epoch,
		MemberID:  creds.memberID,
		kek:       memguard.NewEnclave(kekBytes),
		recordKey: memguard.NewEnclave(util.CopyBytes(recordKey)),
	}, nil
}
