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

// rotateEpoch advances the vault to a new epoch, optionally adding or revoking a member.
// It re-wraps all item DEKs and member KEKs atomically.
// The recordKey parameter is the opened (plaintext) record key bytes from the caller's LockedBuffer.
func (s *Session) rotateEpoch(ctx context.Context, state *vaultState, addMember *Member, revokeMemberID *string, recordKey []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.epoch != state.Epoch {
		return ErrStaleSession
	}
	caller, err := loadMember(state.VaultID, s.vault.repo, recordKey, s.MemberID, state.Epoch)
	if err != nil {
		return fmt.Errorf("%w: member not found", ErrUnauthorized)
	}
	if caller.Status != StatusActive || caller.Role != RoleOwner {
		return fmt.Errorf("%w: only active owner can rotate epoch", ErrUnauthorized)
	}

	// Open old KEK for DEK re-wrapping
	oldKEKBuf, err := s.kek.Open()
	if err != nil {
		return fmt.Errorf("opening old KEK enclave: %w", err)
	}
	defer oldKEKBuf.Destroy()

	newEpoch := state.Epoch + 1

	// 1. Generate new KEK
	newKEK, err := util.NewAESKey()
	if err != nil {
		return err
	}
	defer util.WipeBytes(newKEK)
	var newKEK32 [32]byte
	copy(newKEK32[:], newKEK)

	// 2. Load all members
	members, err := loadMembers(s.vault.id, s.vault.repo, recordKey, state.Epoch)
	if err != nil {
		return err
	}

	// 3. Update members list
	if addMember != nil {
		for _, m := range members {
			if m.MemberID == addMember.MemberID {
				return fmt.Errorf("member %q already exists", addMember.MemberID)
			}
		}
		addMember.AddedEpoch = newEpoch
		addMember.Status = StatusActive
		members = append(members, *addMember)
	}
	if revokeMemberID != nil {
		revoked := false
		for i := range members {
			if members[i].MemberID == *revokeMemberID {
				revoked = true
				members[i].Status = StatusRevoked
				members[i].RevokedEpoch = newEpoch
			}
		}
		if !revoked {
			return fmt.Errorf("member %q not found", *revokeMemberID)
		}
	}

	// 4. Prepare all writes, then execute atomically via Batch
	type writeOp struct {
		recordType string
		recordID   string
		envelope   *storage.Envelope
	}
	var writes []writeOp

	// KEK wraps and member records
	for _, m := range members {
		if m.Status == StatusActive {
			aad := icrypto.AADKEKWrap(state.VaultID, m.MemberID, newEpoch, 1)
			wrap, err := icrypto.SealToMember(m.PubKey, newKEK32[:], aad)
			if err != nil {
				return err
			}
			kw := memberKEKWrap{
				Epoch:    newEpoch,
				MemberID: m.MemberID,
				Wrap:     *wrap,
			}
			env, err := sealMemberKEKWrap(state.VaultID, recordKey, kw)
			if err != nil {
				return err
			}
			writes = append(writes, writeOp{
				recordType: recordTypeKEKWrap,
				recordID:   fmt.Sprintf("%d:%s", kw.Epoch, kw.MemberID),
				envelope:   env,
			})
		}
		env, err := sealMember(state.VaultID, recordKey, m, newEpoch)
		if err != nil {
			return err
		}
		writes = append(writes, writeOp{
			recordType: recordTypeMember,
			recordID:   m.MemberID,
			envelope:   env,
		})
	}

	// 5. Rewrap all item DEKs
	itemIDs, err := s.vault.repo.List(state.VaultID, recordTypeItem)
	if err != nil {
		return err
	}
	for _, id := range itemIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		itm, err := loadItem(state.VaultID, s.vault.repo, recordKey, id, state.Epoch)
		if err != nil {
			return fmt.Errorf("failed to load item %s during rotation: %w", id, err)
		}

		// Decrypt DEK with old KEK
		aadOld := icrypto.AADDEKWrap(state.VaultID, itm.ItemID, state.Epoch, 1)
		dek, err := util.DecryptAESWithAAD(itm.WrappedDEK, oldKEKBuf.Bytes(), aadOld)
		if err != nil {
			return err
		}
		// Rewrap DEK with new KEK
		aadNew := icrypto.AADDEKWrap(state.VaultID, itm.ItemID, newEpoch, 1)
		newWrappedDEK, err := util.EncryptAESWithAAD(dek, newKEK32[:], aadNew)
		if err != nil {
			util.WipeBytes(dek)
			return err
		}
		util.WipeBytes(dek)

		itm.WrappedDEK = newWrappedDEK
		itm.WrappedEpoch = newEpoch

		env, err := sealItem(state.VaultID, recordKey, *itm, newEpoch)
		if err != nil {
			return err
		}
		writes = append(writes, writeOp{
			recordType: recordTypeItem,
			recordID:   itm.ItemID,
			envelope:   env,
		})
	}

	// 6. Update vaultState
	state.Epoch = newEpoch
	stateEnv, err := sealVaultState(recordKey, state)
	if err != nil {
		return err
	}
	writes = append(writes, writeOp{
		recordType: recordTypeState,
		recordID:   recordIDCurrent,
		envelope:   stateEnv,
	})

	// 7. Execute all writes atomically
	err = s.vault.repo.Batch(state.VaultID, func(tx storage.BatchTx) error {
		for _, w := range writes {
			if err := tx.Put(w.recordType, w.recordID, w.envelope); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 8. Update epoch cache
	if err := s.vault.epochCache.SetMaxEpochSeen(state.VaultID, newEpoch); err != nil {
		return err
	}

	// 9. Update session — seal new KEK into Enclave
	s.epoch = newEpoch
	s.kek = memguard.NewEnclave(newKEK32[:])

	return nil
}

// Helper functions

func loadVaultState(vaultID string, repo storage.Repository, recordKey []byte) (*vaultState, error) {
	envelope, err := repo.Get(vaultID, recordTypeState, recordIDCurrent)
	if err != nil {
		return nil, err
	}
	aad := icrypto.AADRecord(vaultID, recordTypeState, recordIDCurrent, 0, 0)
	data, err := storage.OpenRecord(recordKey, envelope, aad)
	if err != nil {
		return nil, err
	}
	var state vaultState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func sealVaultState(recordKey []byte, state *vaultState) (*storage.Envelope, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	aad := icrypto.AADRecord(state.VaultID, recordTypeState, recordIDCurrent, 0, 0)
	return storage.SealRecord(recordKey, data, aad)
}

func loadMembers(vaultID string, repo storage.Repository, recordKey []byte, epoch uint64) ([]Member, error) {
	ids, err := repo.List(vaultID, recordTypeMember)
	if err != nil {
		return nil, err
	}
	var members []Member
	for _, id := range ids {
		envelope, err := repo.Get(vaultID, recordTypeMember, id)
		if err != nil {
			return nil, fmt.Errorf("failed to load member %s: %w", id, err)
		}
		aad := icrypto.AADRecord(vaultID, recordTypeMember, id, epoch, 1)
		data, err := storage.OpenRecord(recordKey, envelope, aad)
		if err != nil {
			return nil, err
		}
		var m Member
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, nil
}

func loadMember(vaultID string, repo storage.Repository, recordKey []byte, memberID string, epoch uint64) (*Member, error) {
	envelope, err := repo.Get(vaultID, recordTypeMember, memberID)
	if err != nil {
		return nil, fmt.Errorf("failed to load member %s: %w", memberID, err)
	}
	aad := icrypto.AADRecord(vaultID, recordTypeMember, memberID, epoch, 1)
	data, err := storage.OpenRecord(recordKey, envelope, aad)
	if err != nil {
		return nil, err
	}
	var m Member
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func sealMember(vaultID string, recordKey []byte, m Member, epoch uint64) (*storage.Envelope, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	aad := icrypto.AADRecord(vaultID, recordTypeMember, m.MemberID, epoch, 1)
	return storage.SealRecord(recordKey, data, aad)
}

func sealMemberKEKWrap(vaultID string, recordKey []byte, wrap memberKEKWrap) (*storage.Envelope, error) {
	data, err := json.Marshal(wrap)
	if err != nil {
		return nil, err
	}
	aad := icrypto.AADRecord(vaultID, recordTypeKEKWrap, fmt.Sprintf("%d:%s", wrap.Epoch, wrap.MemberID), wrap.Epoch, 1)
	return storage.SealRecord(recordKey, data, aad)
}

func loadItem(vaultID string, repo storage.Repository, recordKey []byte, itemID string, epoch uint64) (*item, error) {
	envelope, err := repo.Get(vaultID, recordTypeItem, itemID)
	if err != nil {
		return nil, err
	}
	aad := icrypto.AADRecord(vaultID, recordTypeItem, itemID, epoch, 1)
	data, err := storage.OpenRecord(recordKey, envelope, aad)
	if err != nil {
		return nil, err
	}
	var itm item
	if err := json.Unmarshal(data, &itm); err != nil {
		return nil, err
	}
	return &itm, nil
}

func sealItem(vaultID string, recordKey []byte, itm item, epoch uint64) (*storage.Envelope, error) {
	data, err := json.Marshal(itm)
	if err != nil {
		return nil, err
	}
	aad := icrypto.AADRecord(vaultID, recordTypeItem, itm.ItemID, epoch, 1)
	return storage.SealRecord(recordKey, data, aad, itm.ItemVersion)
}
