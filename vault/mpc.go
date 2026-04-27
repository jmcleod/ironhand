package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/mpc"
	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/storage"
)

const MPCAlgorithmExperimentalP256Schnorr = "experimental-p256-schnorr-v1"

type MPCKeyStatus string

const (
	MPCKeyStatusActive   MPCKeyStatus = "active"
	MPCKeyStatusDisabled MPCKeyStatus = "disabled"
)

type MPCSigningSessionStatus string

const (
	MPCSigningSessionPending   MPCSigningSessionStatus = "pending"
	MPCSigningSessionCompleted MPCSigningSessionStatus = "completed"
	MPCSigningSessionExpired   MPCSigningSessionStatus = "expired"
	MPCSigningSessionFailed    MPCSigningSessionStatus = "failed"
)

type MPCSignerRegistration struct {
	URL                 string          `json:"url"`
	EncryptionPublicKey string          `json:"encryption_public_key"`
	ApprovalPublicKey   string          `json:"approval_public_key"`
	Status              MPCSignerStatus `json:"status,omitempty"`
}

type MPCParticipant struct {
	MemberID              string          `json:"member_id"`
	PartyID               uint32          `json:"party_id"`
	Role                  MemberRole      `json:"role"`
	SignerURL             string          `json:"signer_url"`
	EncryptionPublicKey   string          `json:"encryption_public_key"`
	ApprovalPublicKey     string          `json:"approval_public_key"`
	SignerStatus          MPCSignerStatus `json:"signer_status"`
	PublicShareCommitment mpc.Point       `json:"public_share_commitment"`
}

type MPCKeyCreate struct {
	KeyID       string                           `json:"key_id,omitempty"`
	Algorithm   string                           `json:"algorithm,omitempty"`
	Threshold   int                              `json:"threshold"`
	MemberIDs   []string                         `json:"member_ids,omitempty"`
	Commitments []mpc.PublicCommitment           `json:"commitments"`
	Fragments   map[string]mpc.EncryptedFragment `json:"fragments"`
}

type MPCKey struct {
	KeyID        string                 `json:"key_id"`
	VaultID      string                 `json:"vault_id"`
	Algorithm    string                 `json:"algorithm"`
	Curve        string                 `json:"curve"`
	Threshold    int                    `json:"threshold"`
	Status       MPCKeyStatus           `json:"status"`
	CreatedAt    time.Time              `json:"created_at"`
	PublicKey    mpc.PublicKey          `json:"public_key"`
	Participants []MPCParticipant       `json:"participants"`
	Commitments  []mpc.PublicCommitment `json:"commitments"`
}

type MPCKeyFragment struct {
	KeyID    string                `json:"key_id"`
	MemberID string                `json:"member_id"`
	PartyID  uint32                `json:"party_id"`
	Fragment mpc.EncryptedFragment `json:"fragment"`
}

type MPCSigningSession struct {
	SessionID    string                  `json:"session_id"`
	VaultID      string                  `json:"vault_id"`
	KeyID        string                  `json:"key_id"`
	Status       MPCSigningSessionStatus `json:"status"`
	Message      []byte                  `json:"message"`
	MessageHash  string                  `json:"message_hash"`
	Participants []uint32                `json:"participants"`
	Commitments  []mpc.Commitment        `json:"commitments,omitempty"`
	Approvals    []mpc.Approval          `json:"approvals,omitempty"`
	Signature    *mpc.Signature          `json:"signature,omitempty"`
	CreatedAt    time.Time               `json:"created_at"`
	ExpiresAt    time.Time               `json:"expires_at"`
}

func (s *Session) RegisterMPCSigner(ctx context.Context, memberID string, reg MPCSignerRegistration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkClosed(); err != nil {
		return err
	}
	if err := validateID(memberID, "member ID"); err != nil {
		return err
	}
	if reg.EncryptionPublicKey == "" || reg.ApprovalPublicKey == "" {
		return validationErrorf("MPC signer public keys must not be empty")
	}
	if reg.Status == "" {
		reg.Status = MPCSignerStatusActive
	}
	if reg.Status != MPCSignerStatusActive && reg.Status != MPCSignerStatusDisabled && reg.Status != MPCSignerStatusUnregistered {
		return validationErrorf("invalid MPC signer status %q", reg.Status)
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()

	if _, err := s.authorize(ctx, accessAdmin, recBuf.Bytes()); err != nil {
		return err
	}
	member, err := loadMember(s.vault.id, s.vault.repo, recBuf.Bytes(), memberID, s.epoch)
	if err != nil {
		return err
	}
	if member.Status != StatusActive {
		return fmt.Errorf("member %q is not active", memberID)
	}
	if member.MPCPartyID == 0 {
		members, err := loadMembers(s.vault.id, s.vault.repo, recBuf.Bytes(), s.epoch)
		if err != nil {
			return err
		}
		member.MPCPartyID = nextMPCPartyID(members)
	}
	member.MPCSignerURL = reg.URL
	member.MPCEncryptionPublicKey = reg.EncryptionPublicKey
	member.MPCApprovalPublicKey = reg.ApprovalPublicKey
	member.MPCSignerStatus = reg.Status

	env, err := sealMember(s.vault.id, recBuf.Bytes(), *member, s.epoch)
	if err != nil {
		return err
	}
	return s.vault.repo.Put(s.vault.id, recordTypeMember, memberID, env)
}

func (s *Session) CreateMPCKey(ctx context.Context, create MPCKeyCreate) (*MPCKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if create.KeyID == "" {
		create.KeyID = uuid.New()
	}
	if err := validateID(create.KeyID, "MPC key ID"); err != nil {
		return nil, err
	}
	if create.Algorithm == "" {
		create.Algorithm = MPCAlgorithmExperimentalP256Schnorr
	}
	if create.Algorithm != MPCAlgorithmExperimentalP256Schnorr {
		return nil, validationErrorf("unsupported MPC algorithm %q", create.Algorithm)
	}

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	if _, err := s.authorize(ctx, accessAdmin, recBuf.Bytes()); err != nil {
		return nil, err
	}

	members, err := loadMembers(s.vault.id, s.vault.repo, recBuf.Bytes(), s.epoch)
	if err != nil {
		return nil, err
	}
	selected, err := selectMPCParticipants(members, create.MemberIDs)
	if err != nil {
		return nil, err
	}
	if len(selected) < create.Threshold {
		return nil, fmt.Errorf("%w: need at least %d MPC participants", mpc.ErrInvalidParticipants, create.Threshold)
	}
	if err := validateMPCCommitments(selected, create.Commitments); err != nil {
		return nil, err
	}
	parties := make([]mpc.PartyInfo, 0, len(selected))
	participants := make([]MPCParticipant, 0, len(selected))
	for _, member := range selected {
		parties = append(parties, mpc.PartyInfo{ID: int(member.MPCPartyID), URL: member.MPCSignerURL})
		fragment, ok := create.Fragments[member.MemberID]
		if !ok {
			return nil, fmt.Errorf("missing encrypted fragment for member %q", member.MemberID)
		}
		if fragment.KeyID != create.KeyID || fragment.PartyID != int(member.MPCPartyID) {
			return nil, fmt.Errorf("fragment for member %q is bound to the wrong MPC key or party", member.MemberID)
		}
		participants = append(participants, MPCParticipant{
			MemberID:              member.MemberID,
			PartyID:               member.MPCPartyID,
			Role:                  member.Role,
			SignerURL:             member.MPCSignerURL,
			EncryptionPublicKey:   member.MPCEncryptionPublicKey,
			ApprovalPublicKey:     member.MPCApprovalPublicKey,
			SignerStatus:          member.MPCSignerStatus,
			PublicShareCommitment: fragment.PublicShareCommitment,
		})
	}
	meta, err := mpc.NewKeyMeta(create.KeyID, create.Threshold, parties, create.Commitments)
	if err != nil {
		return nil, err
	}
	key := &MPCKey{
		KeyID:        create.KeyID,
		VaultID:      s.vault.id,
		Algorithm:    create.Algorithm,
		Curve:        mpc.CurveName,
		Threshold:    create.Threshold,
		Status:       MPCKeyStatusActive,
		CreatedAt:    time.Now().UTC(),
		PublicKey:    meta.Public(),
		Participants: participants,
		Commitments:  append([]mpc.PublicCommitment(nil), create.Commitments...),
	}
	keyEnv, err := sealMPCRecord(s.vault.id, recordTypeMPCKey, key.KeyID, recBuf.Bytes(), key)
	if err != nil {
		return nil, err
	}
	err = s.vault.repo.Batch(s.vault.id, func(tx storage.BatchTx) error {
		if err := tx.PutCAS(recordTypeMPCKey, key.KeyID, 0, keyEnv); err != nil {
			return err
		}
		for _, member := range selected {
			fragment := MPCKeyFragment{
				KeyID:    key.KeyID,
				MemberID: member.MemberID,
				PartyID:  member.MPCPartyID,
				Fragment: create.Fragments[member.MemberID],
			}
			recordID := mpcFragmentRecordID(key.KeyID, member.MemberID)
			env, err := sealMPCRecord(s.vault.id, recordTypeMPCFragment, recordID, recBuf.Bytes(), fragment)
			if err != nil {
				return err
			}
			if err := tx.Put(recordTypeMPCFragment, recordID, env); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, storage.ErrCASFailed) {
			return nil, fmt.Errorf("MPC key %q already exists", key.KeyID)
		}
		return nil, err
	}
	return key, nil
}

func (s *Session) ListMPCKeys(ctx context.Context) ([]MPCKey, error) {
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
	ids, err := s.vault.repo.List(s.vault.id, recordTypeMPCKey)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	keys := make([]MPCKey, 0, len(ids))
	for _, id := range ids {
		key, err := loadMPCKey(s.vault.id, s.vault.repo, recBuf.Bytes(), id)
		if err != nil {
			return nil, err
		}
		keys = append(keys, *key)
	}
	return keys, nil
}

func (s *Session) GetMPCKey(ctx context.Context, keyID string) (*MPCKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if err := validateID(keyID, "MPC key ID"); err != nil {
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
	return loadMPCKey(s.vault.id, s.vault.repo, recBuf.Bytes(), keyID)
}

func (s *Session) GetMPCKeyFragment(ctx context.Context, keyID, memberID string) (*MPCKeyFragment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if err := validateID(keyID, "MPC key ID"); err != nil {
		return nil, err
	}
	if err := validateID(memberID, "member ID"); err != nil {
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
	recordID := mpcFragmentRecordID(keyID, memberID)
	env, err := s.vault.repo.Get(s.vault.id, recordTypeMPCFragment, recordID)
	if err != nil {
		return nil, err
	}
	return openMPCRecord[MPCKeyFragment](s.vault.id, recordTypeMPCFragment, recordID, recBuf.Bytes(), env)
}

func (s *Session) CreateMPCSigningSession(ctx context.Context, keyID string, message []byte, participants []uint32, ttl time.Duration) (*MPCSigningSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if err := validateID(keyID, "MPC key ID"); err != nil {
		return nil, err
	}
	if len(message) == 0 {
		return nil, validationErrorf("MPC signing message must not be empty")
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	if _, err := s.authorize(ctx, accessWrite, recBuf.Bytes()); err != nil {
		return nil, err
	}
	key, err := loadMPCKey(s.vault.id, s.vault.repo, recBuf.Bytes(), keyID)
	if err != nil {
		return nil, err
	}
	partyIDs := make([]int, 0, len(key.Participants))
	for _, participant := range key.Participants {
		partyIDs = append(partyIDs, int(participant.PartyID))
	}
	requested := make([]int, 0, len(participants))
	for _, partyID := range participants {
		requested = append(requested, int(partyID))
	}
	normalized, err := mpc.NormalizeParticipants(requested, key.Threshold, partyIDs)
	if err != nil {
		return nil, err
	}
	normalizedU32 := make([]uint32, 0, len(normalized))
	for _, partyID := range normalized {
		normalizedU32 = append(normalizedU32, uint32(partyID))
	}
	now := time.Now().UTC()
	session := &MPCSigningSession{
		SessionID:    uuid.New(),
		VaultID:      s.vault.id,
		KeyID:        keyID,
		Status:       MPCSigningSessionPending,
		Message:      append([]byte(nil), message...),
		MessageHash:  mpc.MessageHash(message),
		Participants: normalizedU32,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}
	env, err := sealMPCRecord(s.vault.id, recordTypeMPCSession, session.SessionID, recBuf.Bytes(), session)
	if err != nil {
		return nil, err
	}
	if err := s.vault.repo.PutCAS(s.vault.id, recordTypeMPCSession, session.SessionID, 0, env); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *Session) GetMPCSigningSession(ctx context.Context, sessionID string) (*MPCSigningSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if err := validateID(sessionID, "MPC signing session ID"); err != nil {
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
	env, err := s.vault.repo.Get(s.vault.id, recordTypeMPCSession, sessionID)
	if err != nil {
		return nil, err
	}
	return openMPCRecord[MPCSigningSession](s.vault.id, recordTypeMPCSession, sessionID, recBuf.Bytes(), env)
}

func (s *Session) AddMPCApproval(ctx context.Context, sessionID string, approval mpc.Approval) (*MPCSigningSession, error) {
	return s.updateMPCSigningSession(ctx, sessionID, func(recKey []byte, session *MPCSigningSession) error {
		if session.Status != MPCSigningSessionPending {
			return fmt.Errorf("MPC signing session %q is not pending", sessionID)
		}
		if time.Now().UTC().After(session.ExpiresAt) {
			session.Status = MPCSigningSessionExpired
			return fmt.Errorf("MPC signing session %q expired", sessionID)
		}
		if approval.VaultID != session.VaultID || approval.SessionID != session.SessionID || approval.KeyID != session.KeyID || approval.MessageHash != session.MessageHash {
			return fmt.Errorf("approval is not bound to this MPC signing session")
		}
		key, err := loadMPCKey(s.vault.id, s.vault.repo, recKey, session.KeyID)
		if err != nil {
			return err
		}
		if approval.Threshold != key.Threshold {
			return fmt.Errorf("approval threshold is not bound to this MPC key")
		}
		if !samePartySet(approval.Participants, session.Participants) {
			return fmt.Errorf("approval participants are not bound to this MPC signing session")
		}
		participant, ok := key.participantByPartyID(uint32(approval.PartyID))
		if !ok {
			return fmt.Errorf("approval party %d is not part of MPC key %q", approval.PartyID, session.KeyID)
		}
		if !session.hasParticipant(uint32(approval.PartyID)) {
			return fmt.Errorf("approval party %d is not part of this signing session", approval.PartyID)
		}
		if !mpc.VerifyApproval(participant.ApprovalPublicKey, approval, time.Now().UTC()) {
			return fmt.Errorf("invalid MPC approval signature for party %d", approval.PartyID)
		}
		for i, existing := range session.Approvals {
			if existing.PartyID == approval.PartyID {
				session.Approvals[i] = approval
				return nil
			}
		}
		session.Approvals = append(session.Approvals, approval)
		return nil
	})
}

func (s *Session) CompleteMPCSigningSession(ctx context.Context, sessionID string, commitments []mpc.Commitment, signature *mpc.Signature) (*MPCSigningSession, error) {
	return s.updateMPCSigningSession(ctx, sessionID, func(recKey []byte, session *MPCSigningSession) error {
		if session.Status != MPCSigningSessionPending {
			return fmt.Errorf("MPC signing session %q is not pending", sessionID)
		}
		if time.Now().UTC().After(session.ExpiresAt) {
			return fmt.Errorf("MPC signing session %q expired", sessionID)
		}
		key, err := loadMPCKey(s.vault.id, s.vault.repo, recKey, session.KeyID)
		if err != nil {
			return err
		}
		approvalCount := countValidSessionApprovals(session, key)
		if approvalCount < key.Threshold {
			return fmt.Errorf("MPC signing session %q needs %d approvals, has %d", sessionID, key.Threshold, approvalCount)
		}
		if signature == nil || !mpc.Verify(session.Message, key.PublicKeyPoint(), signature) {
			session.Status = MPCSigningSessionFailed
			return fmt.Errorf("MPC signature verification failed")
		}
		session.Commitments = append([]mpc.Commitment(nil), commitments...)
		session.Signature = signature
		session.Status = MPCSigningSessionCompleted
		return nil
	})
}

func (k *MPCKey) PublicKeyPoint() mpc.Point {
	return mpc.Point{X: k.PublicKey.X, Y: k.PublicKey.Y}
}

func (k *MPCKey) participantByPartyID(partyID uint32) (MPCParticipant, bool) {
	for _, participant := range k.Participants {
		if participant.PartyID == partyID {
			return participant, true
		}
	}
	return MPCParticipant{}, false
}

func (s *MPCSigningSession) hasParticipant(partyID uint32) bool {
	for _, participant := range s.Participants {
		if participant == partyID {
			return true
		}
	}
	return false
}

func countValidSessionApprovals(session *MPCSigningSession, key *MPCKey) int {
	seen := make(map[int]struct{}, len(session.Approvals))
	now := time.Now().UTC()
	for _, approval := range session.Approvals {
		if _, ok := seen[approval.PartyID]; ok {
			continue
		}
		participant, ok := key.participantByPartyID(uint32(approval.PartyID))
		if !ok || !session.hasParticipant(uint32(approval.PartyID)) {
			continue
		}
		if approval.VaultID != session.VaultID || approval.SessionID != session.SessionID || approval.KeyID != session.KeyID || approval.MessageHash != session.MessageHash {
			continue
		}
		if approval.Threshold != key.Threshold || !samePartySet(approval.Participants, session.Participants) {
			continue
		}
		if !mpc.VerifyApproval(participant.ApprovalPublicKey, approval, now) {
			continue
		}
		seen[approval.PartyID] = struct{}{}
	}
	return len(seen)
}

func samePartySet(left []int, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[int]int, len(left))
	for _, partyID := range left {
		counts[partyID]++
	}
	for _, partyID := range right {
		counts[int(partyID)]--
		if counts[int(partyID)] < 0 {
			return false
		}
	}
	return true
}

func (s *Session) updateMPCSigningSession(ctx context.Context, sessionID string, update func(recordKey []byte, session *MPCSigningSession) error) (*MPCSigningSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if err := validateID(sessionID, "MPC signing session ID"); err != nil {
		return nil, err
	}
	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	if _, err := s.authorize(ctx, accessWrite, recBuf.Bytes()); err != nil {
		return nil, err
	}
	env, err := s.vault.repo.Get(s.vault.id, recordTypeMPCSession, sessionID)
	if err != nil {
		return nil, err
	}
	session, err := openMPCRecord[MPCSigningSession](s.vault.id, recordTypeMPCSession, sessionID, recBuf.Bytes(), env)
	if err != nil {
		return nil, err
	}
	if err := update(recBuf.Bytes(), session); err != nil {
		return nil, err
	}
	newEnv, err := sealMPCRecord(s.vault.id, recordTypeMPCSession, sessionID, recBuf.Bytes(), session)
	if err != nil {
		return nil, err
	}
	if err := s.vault.repo.PutCAS(s.vault.id, recordTypeMPCSession, sessionID, env.Version, newEnv); err != nil {
		return nil, err
	}
	return session, nil
}

func selectMPCParticipants(members []Member, memberIDs []string) ([]Member, error) {
	requested := make(map[string]struct{}, len(memberIDs))
	for _, memberID := range memberIDs {
		if err := validateID(memberID, "member ID"); err != nil {
			return nil, err
		}
		requested[memberID] = struct{}{}
	}
	selected := make([]Member, 0, len(members))
	for _, member := range members {
		if len(requested) > 0 {
			if _, ok := requested[member.MemberID]; !ok {
				continue
			}
		}
		if member.Status != StatusActive {
			continue
		}
		if member.MPCPartyID == 0 || member.MPCSignerStatus != MPCSignerStatusActive {
			continue
		}
		if member.MPCEncryptionPublicKey == "" || member.MPCApprovalPublicKey == "" {
			continue
		}
		selected = append(selected, member)
		delete(requested, member.MemberID)
	}
	if len(requested) > 0 {
		missing := make([]string, 0, len(requested))
		for memberID := range requested {
			missing = append(missing, memberID)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("members are not active MPC participants: %v", missing)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].MPCPartyID < selected[j].MPCPartyID })
	return selected, nil
}

func validateMPCCommitments(members []Member, commitments []mpc.PublicCommitment) error {
	if len(commitments) != len(members) {
		return fmt.Errorf("%w: commitment count must match participant count", mpc.ErrInvalidKey)
	}
	allowed := make(map[int]struct{}, len(members))
	for _, member := range members {
		allowed[int(member.MPCPartyID)] = struct{}{}
	}
	seen := make(map[int]struct{}, len(commitments))
	for _, commitment := range commitments {
		if _, ok := allowed[commitment.PartyID]; !ok {
			return fmt.Errorf("%w: commitment party %d is not selected for this key", mpc.ErrInvalidKey, commitment.PartyID)
		}
		if _, ok := seen[commitment.PartyID]; ok {
			return fmt.Errorf("%w: duplicate commitment for party %d", mpc.ErrInvalidKey, commitment.PartyID)
		}
		seen[commitment.PartyID] = struct{}{}
	}
	return nil
}

func loadMPCKey(vaultID string, repo storage.Repository, recordKey []byte, keyID string) (*MPCKey, error) {
	env, err := repo.Get(vaultID, recordTypeMPCKey, keyID)
	if err != nil {
		return nil, err
	}
	return openMPCRecord[MPCKey](vaultID, recordTypeMPCKey, keyID, recordKey, env)
}

func sealMPCRecord(vaultID, recordType, recordID string, recordKey []byte, value any) (*storage.Envelope, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return storage.SealRecord(recordKey, data, icrypto.AADRecord(vaultID, recordType, recordID, 0, 1))
}

func openMPCRecord[T any](vaultID, recordType, recordID string, recordKey []byte, env *storage.Envelope) (*T, error) {
	data, err := storage.OpenRecord(recordKey, env, icrypto.AADRecord(vaultID, recordType, recordID, 0, 1))
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func mpcFragmentRecordID(keyID, memberID string) string {
	return keyID + ":" + memberID
}
