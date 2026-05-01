package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/mpc"
	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/storage"
)

const MPCAlgorithmExperimentalP256Schnorr = mpc.AlgorithmExperimentalP256Schnorr

const (
	DefaultMPCSigningSessionTTL = 15 * time.Minute
	MaxMPCSigningSessionTTL     = 30 * time.Minute
)

type MPCKeyStatus string

const (
	MPCKeyStatusActive           MPCKeyStatus = "active"
	MPCKeyStatusDisabled         MPCKeyStatus = "disabled"
	MPCKeyStatusArchived         MPCKeyStatus = "archived"
	MPCKeyStatusRotationRequired MPCKeyStatus = "rotation_required"
	MPCKeyStatusReshareRequired  MPCKeyStatus = "reshare_required"
	MPCKeyStatusDestroyed        MPCKeyStatus = "destroyed"
)

type MPCApprovalMode string

const (
	MPCApprovalModeThreshold MPCApprovalMode = "threshold"
	MPCApprovalModeAll       MPCApprovalMode = "all"
)

type MPCKeyImportMode string

const (
	MPCKeyImportModeOrchestrated MPCKeyImportMode = "orchestrated"
	MPCKeyImportModeRecovery     MPCKeyImportMode = "recovery"
)

type MPCPolicy struct {
	ApprovalMode        MPCApprovalMode `json:"approval_mode,omitempty"`
	AllowedRoles        []MemberRole    `json:"allowed_roles,omitempty"`
	AllowedDestinations []string        `json:"allowed_destinations,omitempty"`
	DeniedDestinations  []string        `json:"denied_destinations,omitempty"`
	MaxValue            string          `json:"max_value,omitempty"`
}

type MPCTransactionMetadata struct {
	MessageType string         `json:"message_type"`
	Chain       string         `json:"chain,omitempty"`
	Network     string         `json:"network,omitempty"`
	Digest      string         `json:"digest"`
	Destination string         `json:"destination,omitempty"`
	Value       string         `json:"value,omitempty"`
	Fields      map[string]any `json:"fields,omitempty"`
}

type MPCPolicyDecision struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons,omitempty"`
}

type MPCSigningSessionStatus string

const (
	MPCSigningSessionPending   MPCSigningSessionStatus = "pending"
	MPCSigningSessionCompleted MPCSigningSessionStatus = "completed"
	MPCSigningSessionExpired   MPCSigningSessionStatus = "expired"
	MPCSigningSessionFailed    MPCSigningSessionStatus = "failed"
)

type MPCDKGStatus string

const (
	MPCDKGStatusStarted    MPCDKGStatus = "started"
	MPCDKGStatusFinalizing MPCDKGStatus = "finalizing"
	MPCDKGStatusCommitted  MPCDKGStatus = "committed"
	MPCDKGStatusAborted    MPCDKGStatus = "aborted"
	MPCDKGStatusFailed     MPCDKGStatus = "failed"
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
	KeyID         string                           `json:"key_id,omitempty"`
	Algorithm     string                           `json:"algorithm,omitempty"`
	ImportMode    MPCKeyImportMode                 `json:"import_mode,omitempty"`
	DKGSessionID  string                           `json:"dkg_session_id,omitempty"`
	Threshold     int                              `json:"threshold"`
	MemberIDs     []string                         `json:"member_ids,omitempty"`
	Commitments   []mpc.PublicCommitment           `json:"commitments"`
	Fragments     map[string]mpc.EncryptedFragment `json:"fragments"`
	Policy        MPCPolicy                        `json:"policy,omitempty"`
	ReplacesKeyID string                           `json:"replaces_key_id,omitempty"`
}

type MPCKey struct {
	KeyID           string                 `json:"key_id"`
	VaultID         string                 `json:"vault_id"`
	Algorithm       string                 `json:"algorithm"`
	Curve           string                 `json:"curve"`
	Provider        mpc.ProviderInfo       `json:"provider"`
	Threshold       int                    `json:"threshold"`
	Status          MPCKeyStatus           `json:"status"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ReplacesKeyID   string                 `json:"replaces_key_id,omitempty"`
	ReplacedByKeyID string                 `json:"replaced_by_key_id,omitempty"`
	PublicKey       mpc.PublicKey          `json:"public_key"`
	Participants    []MPCParticipant       `json:"participants"`
	Commitments     []mpc.PublicCommitment `json:"commitments"`
	Policy          MPCPolicy              `json:"policy"`
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
	MessageType  string                  `json:"message_type"`
	Chain        string                  `json:"chain,omitempty"`
	Network      string                  `json:"network,omitempty"`
	Transaction  MPCTransactionMetadata  `json:"transaction"`
	Policy       MPCPolicyDecision       `json:"policy"`
	Participants []uint32                `json:"participants"`
	Commitments  []mpc.Commitment        `json:"commitments,omitempty"`
	Approvals    []mpc.Approval          `json:"approvals,omitempty"`
	Signature    *mpc.Signature          `json:"signature,omitempty"`
	CreatedAt    time.Time               `json:"created_at"`
	ExpiresAt    time.Time               `json:"expires_at"`
}

type MPCDKGMember struct {
	MemberID            string `json:"member_id"`
	PartyID             uint32 `json:"party_id"`
	URL                 string `json:"url"`
	EncryptionPublicKey string `json:"encryption_public_key"`
	ApprovalPublicKey   string `json:"approval_public_key"`
}

type MPCDKGAttempt struct {
	DKGSessionID string                           `json:"dkg_session_id"`
	VaultID      string                           `json:"vault_id"`
	KeyID        string                           `json:"key_id"`
	Algorithm    string                           `json:"algorithm"`
	Threshold    int                              `json:"threshold"`
	Status       MPCDKGStatus                     `json:"status"`
	Members      []MPCDKGMember                   `json:"members"`
	Commitments  []mpc.PublicCommitment           `json:"commitments,omitempty"`
	Fragments    map[string]mpc.EncryptedFragment `json:"fragments,omitempty"`
	LastError    string                           `json:"last_error,omitempty"`
	CreatedAt    time.Time                        `json:"created_at"`
	UpdatedAt    time.Time                        `json:"updated_at"`
}

type MPCMetricsSnapshot struct {
	KeysByStatus            map[MPCKeyStatus]int            `json:"keys_by_status"`
	DKGAttemptsByStatus     map[MPCDKGStatus]int            `json:"dkg_attempts_by_status"`
	SigningSessionsByStatus map[MPCSigningSessionStatus]int `json:"signing_sessions_by_status"`
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
	if create.ReplacesKeyID != "" {
		if err := validateID(create.ReplacesKeyID, "replaced MPC key ID"); err != nil {
			return nil, err
		}
	}
	if create.Algorithm == "" {
		create.Algorithm = MPCAlgorithmExperimentalP256Schnorr
	}
	if create.ImportMode == "" {
		create.ImportMode = MPCKeyImportModeOrchestrated
	}
	if create.ImportMode != MPCKeyImportModeOrchestrated && create.ImportMode != MPCKeyImportModeRecovery {
		return nil, validationErrorf("unsupported MPC key import_mode %q", create.ImportMode)
	}
	if create.DKGSessionID == "" {
		return nil, validationErrorf("MPC key creation requires dkg_session_id")
	}
	if err := validateID(create.DKGSessionID, "MPC DKG session ID"); err != nil {
		return nil, err
	}
	provider, err := mpc.GetProvider(create.Algorithm)
	if err != nil {
		return nil, validationErrorf("%v", err)
	}
	providerInfo := provider.Info()
	if !providerInfo.SupportsKeygen {
		return nil, validationErrorf("MPC provider %q does not support key generation", providerInfo.Algorithm)
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
	keyFragments := make([]mpc.EncryptedFragment, 0, len(selected))
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
		keyFragments = append(keyFragments, fragment)
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
	if err := provider.ValidateKeyFragments(create.KeyID, parties, create.Commitments, keyFragments); err != nil {
		return nil, validationErrorf("%v", err)
	}
	if err := validateMPCFragmentAttestations(s.vault.id, create.KeyID, create.DKGSessionID, selected, create.Commitments, create.Fragments); err != nil {
		return nil, err
	}
	meta, err := provider.NewKeyMeta(create.KeyID, create.Threshold, parties, create.Commitments)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	key := &MPCKey{
		KeyID:         create.KeyID,
		VaultID:       s.vault.id,
		Algorithm:     providerInfo.Algorithm,
		Curve:         providerInfo.Curve,
		Provider:      providerInfo,
		Threshold:     create.Threshold,
		Status:        MPCKeyStatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ReplacesKeyID: create.ReplacesKeyID,
		PublicKey:     meta.Public(),
		Participants:  participants,
		Commitments:   append([]mpc.PublicCommitment(nil), create.Commitments...),
		Policy:        normalizeMPCPolicy(create.Policy),
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

func (s *Session) SetMPCKeyStatus(ctx context.Context, keyID string, status MPCKeyStatus) (*MPCKey, error) {
	if !validMPCKeyStatus(status) {
		return nil, validationErrorf("invalid MPC key status %q", status)
	}
	return s.updateMPCKey(ctx, keyID, func(key *MPCKey) error {
		key.Status = status
		key.UpdatedAt = time.Now().UTC()
		return nil
	})
}

func (s *Session) MarkMPCKeyReplaced(ctx context.Context, keyID, replacementKeyID string) (*MPCKey, error) {
	if err := validateID(replacementKeyID, "replacement MPC key ID"); err != nil {
		return nil, err
	}
	return s.updateMPCKey(ctx, keyID, func(key *MPCKey) error {
		if key.Status == MPCKeyStatusDestroyed {
			return validationErrorf("destroyed MPC key %q cannot be replaced", keyID)
		}
		key.Status = MPCKeyStatusArchived
		key.ReplacedByKeyID = replacementKeyID
		key.UpdatedAt = time.Now().UTC()
		return nil
	})
}

func (s *Session) SaveMPCDKGAttempt(ctx context.Context, attempt MPCDKGAttempt) (*MPCDKGAttempt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if err := validateID(attempt.DKGSessionID, "MPC DKG session ID"); err != nil {
		return nil, err
	}
	if err := validateID(attempt.KeyID, "MPC key ID"); err != nil {
		return nil, err
	}
	if attempt.Algorithm == "" {
		attempt.Algorithm = MPCAlgorithmExperimentalP256Schnorr
	}
	if _, err := mpc.GetProvider(attempt.Algorithm); err != nil {
		return nil, validationErrorf("%v", err)
	}
	if attempt.Status == "" {
		attempt.Status = MPCDKGStatusStarted
	}
	now := time.Now().UTC()
	if attempt.CreatedAt.IsZero() {
		attempt.CreatedAt = now
	}
	attempt.UpdatedAt = now
	attempt.VaultID = s.vault.id

	recBuf, err := s.recordKey.Open()
	if err != nil {
		return nil, fmt.Errorf("opening record key enclave: %w", err)
	}
	defer recBuf.Destroy()
	if _, err := s.authorize(ctx, accessAdmin, recBuf.Bytes()); err != nil {
		return nil, err
	}
	env, err := sealMPCRecord(s.vault.id, recordTypeMPCDKG, attempt.DKGSessionID, recBuf.Bytes(), attempt)
	if err != nil {
		return nil, err
	}
	version := uint64(0)
	if existing, err := s.vault.repo.Get(s.vault.id, recordTypeMPCDKG, attempt.DKGSessionID); err == nil {
		version = existing.Version
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	if err := s.vault.repo.PutCAS(s.vault.id, recordTypeMPCDKG, attempt.DKGSessionID, version, env); err != nil {
		return nil, err
	}
	return &attempt, nil
}

func (s *Session) ListMPCDKGAttempts(ctx context.Context) ([]MPCDKGAttempt, error) {
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
	ids, err := s.vault.repo.List(s.vault.id, recordTypeMPCDKG)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	attempts := make([]MPCDKGAttempt, 0, len(ids))
	for _, id := range ids {
		attempt, err := loadMPCDKGAttempt(s.vault.id, s.vault.repo, recBuf.Bytes(), id)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, *attempt)
	}
	return attempts, nil
}

func (s *Session) GetMPCDKGAttempt(ctx context.Context, dkgSessionID string) (*MPCDKGAttempt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	if err := validateID(dkgSessionID, "MPC DKG session ID"); err != nil {
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
	return loadMPCDKGAttempt(s.vault.id, s.vault.repo, recBuf.Bytes(), dkgSessionID)
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

type MPCSigningSessionCreate struct {
	MessageBase64 string         `json:"-"`
	Message       []byte         `json:"message,omitempty"`
	Participants  []uint32       `json:"participants,omitempty"`
	TTL           time.Duration  `json:"ttl,omitempty"`
	MessageType   string         `json:"message_type,omitempty"`
	Chain         string         `json:"chain,omitempty"`
	Network       string         `json:"network,omitempty"`
	Transaction   map[string]any `json:"transaction_metadata,omitempty"`
}

func (s *Session) CreateMPCSigningSession(ctx context.Context, keyID string, message []byte, participants []uint32, ttl time.Duration) (*MPCSigningSession, error) {
	return s.CreateMPCSigningSessionWithOptions(ctx, keyID, MPCSigningSessionCreate{Message: message, Participants: participants, TTL: ttl})
}

func (s *Session) CreateMPCSigningSessionWithOptions(ctx context.Context, keyID string, create MPCSigningSessionCreate) (*MPCSigningSession, error) {
	message := create.Message
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
	if create.TTL <= 0 {
		create.TTL = DefaultMPCSigningSessionTTL
	}
	if create.TTL > MaxMPCSigningSessionTTL {
		return nil, validationErrorf("MPC signing session TTL must not exceed %s", MaxMPCSigningSessionTTL)
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
	if key.Status != MPCKeyStatusActive {
		return nil, validationErrorf("MPC key %q is not active", keyID)
	}
	provider, err := mpc.GetProvider(key.Algorithm)
	if err != nil {
		return nil, validationErrorf("%v", err)
	}
	providerInfo := provider.Info()
	if !providerInfo.SupportsSigning {
		return nil, validationErrorf("MPC provider %q does not support signing", providerInfo.Algorithm)
	}
	partyIDs := make([]int, 0, len(key.Participants))
	for _, participant := range key.Participants {
		partyIDs = append(partyIDs, int(participant.PartyID))
	}
	requested := make([]int, 0, len(create.Participants))
	for _, partyID := range create.Participants {
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
	transaction, err := decodeMPCTransaction(message, create.MessageType, create.Chain, create.Network, create.Transaction)
	if err != nil {
		return nil, err
	}
	if !mpcProviderSupportsChain(providerInfo, transaction.Chain) {
		return nil, validationErrorf("MPC provider %q is not compatible with chain %q", providerInfo.Algorithm, transaction.Chain)
	}
	decision := evaluateMPCPolicy(key, normalizedU32, transaction)
	if !decision.Allowed {
		return nil, validationErrorf("MPC policy denied signing session: %v", decision.Reasons)
	}
	now := time.Now().UTC()
	session := &MPCSigningSession{
		SessionID:    uuid.New(),
		VaultID:      s.vault.id,
		KeyID:        keyID,
		Status:       MPCSigningSessionPending,
		Message:      append([]byte(nil), message...),
		MessageHash:  mpc.MessageHash(message),
		MessageType:  transaction.MessageType,
		Chain:        transaction.Chain,
		Network:      transaction.Network,
		Transaction:  transaction,
		Policy:       decision,
		Participants: normalizedU32,
		CreatedAt:    now,
		ExpiresAt:    now.Add(create.TTL),
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

func (s *Session) ListMPCSigningSessions(ctx context.Context) ([]MPCSigningSession, error) {
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
	ids, err := s.vault.repo.List(s.vault.id, recordTypeMPCSession)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	sessions := make([]MPCSigningSession, 0, len(ids))
	for _, id := range ids {
		env, err := s.vault.repo.Get(s.vault.id, recordTypeMPCSession, id)
		if err != nil {
			return nil, err
		}
		session, err := openMPCRecord[MPCSigningSession](s.vault.id, recordTypeMPCSession, id, recBuf.Bytes(), env)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, *session)
	}
	return sessions, nil
}

func (s *Session) MPCMetrics(ctx context.Context) (*MPCMetricsSnapshot, error) {
	keys, err := s.ListMPCKeys(ctx)
	if err != nil {
		return nil, err
	}
	dkgAttempts, err := s.ListMPCDKGAttempts(ctx)
	if err != nil {
		return nil, err
	}
	signingSessions, err := s.ListMPCSigningSessions(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := &MPCMetricsSnapshot{
		KeysByStatus:            make(map[MPCKeyStatus]int),
		DKGAttemptsByStatus:     make(map[MPCDKGStatus]int),
		SigningSessionsByStatus: make(map[MPCSigningSessionStatus]int),
	}
	for _, key := range keys {
		snapshot.KeysByStatus[key.Status]++
	}
	for _, attempt := range dkgAttempts {
		snapshot.DKGAttemptsByStatus[attempt.Status]++
	}
	for _, signingSession := range signingSessions {
		snapshot.SigningSessionsByStatus[signingSession.Status]++
	}
	return snapshot, nil
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
		if approval.MessageType != session.MessageType || approval.Chain != session.Chain || approval.Network != session.Network || approval.TransactionDigest != session.Transaction.Digest {
			return fmt.Errorf("approval transaction context is not bound to this MPC signing session")
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
		provider, err := mpc.GetProvider(key.Algorithm)
		if err != nil {
			return err
		}
		approvalCount := countValidSessionApprovals(session, key)
		if approvalCount < key.Threshold {
			return fmt.Errorf("MPC signing session %q needs %d approvals, has %d", sessionID, key.Threshold, approvalCount)
		}
		if err := validateMPCCompletionTranscript(session, key, commitments, signature); err != nil {
			return err
		}
		if !provider.Verify(session.Message, key.PublicKeyPoint(), signature) {
			session.Status = MPCSigningSessionFailed
			return fmt.Errorf("MPC signature verification failed")
		}
		session.Commitments = append([]mpc.Commitment(nil), signature.Commitments...)
		session.Signature = signature
		session.Status = MPCSigningSessionCompleted
		return nil
	})
}

func validateMPCCompletionTranscript(session *MPCSigningSession, key *MPCKey, commitments []mpc.Commitment, signature *mpc.Signature) error {
	if signature == nil {
		return fmt.Errorf("MPC signature is required")
	}
	if len(commitments) != len(signature.Commitments) {
		return fmt.Errorf("MPC completion commitments do not match signature transcript")
	}
	for i := range commitments {
		if commitments[i] != signature.Commitments[i] {
			return fmt.Errorf("MPC completion commitments do not match signature transcript")
		}
	}
	if len(signature.Commitments) < key.Threshold {
		return fmt.Errorf("MPC signature transcript needs at least %d commitments, has %d", key.Threshold, len(signature.Commitments))
	}
	if len(signature.Shares) != len(signature.Commitments) {
		return fmt.Errorf("MPC signature transcript needs one share per commitment")
	}
	sessionParties := make(map[uint32]struct{}, len(session.Participants))
	for _, partyID := range session.Participants {
		sessionParties[partyID] = struct{}{}
	}
	commitmentParties := make(map[int]struct{}, len(signature.Commitments))
	for _, commitment := range signature.Commitments {
		if commitment.PartyID <= 0 {
			return fmt.Errorf("MPC signature transcript has invalid party %d", commitment.PartyID)
		}
		if _, ok := sessionParties[uint32(commitment.PartyID)]; !ok {
			return fmt.Errorf("MPC signature transcript party %d was not selected for session", commitment.PartyID)
		}
		if _, ok := commitmentParties[commitment.PartyID]; ok {
			return fmt.Errorf("MPC signature transcript has duplicate commitment for party %d", commitment.PartyID)
		}
		commitmentParties[commitment.PartyID] = struct{}{}
	}
	shareParties := make(map[int]struct{}, len(signature.Shares))
	for _, share := range signature.Shares {
		if _, ok := commitmentParties[share.PartyID]; !ok {
			return fmt.Errorf("MPC signature share party %d has no matching commitment", share.PartyID)
		}
		if _, ok := shareParties[share.PartyID]; ok {
			return fmt.Errorf("MPC signature transcript has duplicate share for party %d", share.PartyID)
		}
		shareParties[share.PartyID] = struct{}{}
	}
	return nil
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
		if approval.MessageType != session.MessageType || approval.Chain != session.Chain || approval.Network != session.Network || approval.TransactionDigest != session.Transaction.Digest {
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

func normalizeMPCPolicy(policy MPCPolicy) MPCPolicy {
	if policy.ApprovalMode == "" {
		policy.ApprovalMode = MPCApprovalModeThreshold
	}
	return policy
}

func decodeMPCTransaction(message []byte, messageType, chain, network string, metadata map[string]any) (MPCTransactionMetadata, error) {
	if messageType == "" {
		messageType = "raw"
	}
	tx := MPCTransactionMetadata{
		MessageType: messageType,
		Chain:       chain,
		Network:     network,
		Digest:      mpc.MessageHash(message),
		Fields:      metadata,
	}
	if destination, ok := metadata["destination"].(string); ok {
		tx.Destination = destination
	}
	if value, ok := metadata["value"].(string); ok {
		tx.Value = value
	}
	switch messageType {
	case "raw":
		return tx, nil
	case "evm_tx_hash":
		if len(message) != 32 {
			return MPCTransactionMetadata{}, validationErrorf("evm_tx_hash messages must be 32 bytes")
		}
		tx.Digest = mpc.MessageHash(append([]byte("evm_tx_hash:"), message...))
		return tx, nil
	default:
		return MPCTransactionMetadata{}, validationErrorf("unsupported MPC message_type %q", messageType)
	}
}

func evaluateMPCPolicy(key *MPCKey, participants []uint32, tx MPCTransactionMetadata) MPCPolicyDecision {
	policy := normalizeMPCPolicy(key.Policy)
	reasons := make([]string, 0)
	if policy.ApprovalMode != MPCApprovalModeThreshold && policy.ApprovalMode != MPCApprovalModeAll {
		reasons = append(reasons, fmt.Sprintf("unsupported approval mode %q", policy.ApprovalMode))
	}
	if policy.ApprovalMode == MPCApprovalModeAll && len(participants) < len(key.Participants) {
		reasons = append(reasons, "all approval mode requires every key participant")
	}
	if len(policy.AllowedRoles) > 0 {
		allowed := make(map[MemberRole]struct{}, len(policy.AllowedRoles))
		for _, role := range policy.AllowedRoles {
			allowed[role] = struct{}{}
		}
		for _, partyID := range participants {
			participant, ok := key.participantByPartyID(partyID)
			if !ok {
				reasons = append(reasons, fmt.Sprintf("party %d is not part of key", partyID))
				continue
			}
			if _, ok := allowed[participant.Role]; !ok {
				reasons = append(reasons, fmt.Sprintf("party %d role %q is not allowed", partyID, participant.Role))
			}
		}
	}
	if tx.Destination != "" {
		for _, denied := range policy.DeniedDestinations {
			if strings.EqualFold(tx.Destination, denied) {
				reasons = append(reasons, "destination is denied by policy")
			}
		}
		if len(policy.AllowedDestinations) > 0 {
			found := false
			for _, allowed := range policy.AllowedDestinations {
				if strings.EqualFold(tx.Destination, allowed) {
					found = true
					break
				}
			}
			if !found {
				reasons = append(reasons, "destination is not allowed by policy")
			}
		}
	}
	if policy.MaxValue != "" {
		maxValue, err := parseMPCPolicyValue(policy.MaxValue)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("invalid max_value policy: %v", err))
		} else if tx.Value == "" {
			reasons = append(reasons, "transaction value is required by max_value policy")
		} else {
			txValue, err := parseMPCPolicyValue(tx.Value)
			if err != nil {
				reasons = append(reasons, fmt.Sprintf("invalid transaction value: %v", err))
			} else if txValue.Cmp(maxValue) > 0 {
				reasons = append(reasons, "transaction value exceeds max_value policy")
			}
		}
	}
	return MPCPolicyDecision{Allowed: len(reasons) == 0, Reasons: reasons}
}

func parseMPCPolicyValue(value string) (*big.Int, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("value is empty")
	}
	for _, r := range trimmed {
		if r < '0' || r > '9' {
			return nil, fmt.Errorf("value must be a non-negative decimal integer")
		}
	}
	parsed, ok := new(big.Int).SetString(trimmed, 10)
	if !ok {
		return nil, fmt.Errorf("value must be a non-negative decimal integer")
	}
	return parsed, nil
}

func mpcProviderSupportsChain(provider mpc.ProviderInfo, chain string) bool {
	if chain == "" {
		return true
	}
	for _, compatible := range provider.ChainCompatibility {
		if strings.EqualFold(compatible, chain) {
			return true
		}
	}
	return false
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

func (s *Session) updateMPCKey(ctx context.Context, keyID string, update func(key *MPCKey) error) (*MPCKey, error) {
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
	if _, err := s.authorize(ctx, accessAdmin, recBuf.Bytes()); err != nil {
		return nil, err
	}
	env, err := s.vault.repo.Get(s.vault.id, recordTypeMPCKey, keyID)
	if err != nil {
		return nil, err
	}
	key, err := openMPCRecord[MPCKey](s.vault.id, recordTypeMPCKey, keyID, recBuf.Bytes(), env)
	if err != nil {
		return nil, err
	}
	if err := update(key); err != nil {
		return nil, err
	}
	newEnv, err := sealMPCRecord(s.vault.id, recordTypeMPCKey, keyID, recBuf.Bytes(), key)
	if err != nil {
		return nil, err
	}
	if err := s.vault.repo.PutCAS(s.vault.id, recordTypeMPCKey, keyID, env.Version, newEnv); err != nil {
		return nil, err
	}
	return key, nil
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

func validMPCKeyStatus(status MPCKeyStatus) bool {
	switch status {
	case MPCKeyStatusActive, MPCKeyStatusDisabled, MPCKeyStatusArchived, MPCKeyStatusRotationRequired, MPCKeyStatusReshareRequired, MPCKeyStatusDestroyed:
		return true
	default:
		return false
	}
}

func (s *Session) syncMPCParticipantRole(ctx context.Context, recordKey []byte, memberID string, role MemberRole) error {
	ids, err := s.vault.repo.List(s.vault.id, recordTypeMPCKey)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		env, err := s.vault.repo.Get(s.vault.id, recordTypeMPCKey, id)
		if err != nil {
			return err
		}
		key, err := openMPCRecord[MPCKey](s.vault.id, recordTypeMPCKey, id, recordKey, env)
		if err != nil {
			return err
		}
		changed := false
		for i := range key.Participants {
			if key.Participants[i].MemberID == memberID && key.Participants[i].Role != role {
				key.Participants[i].Role = role
				changed = true
			}
		}
		if !changed {
			continue
		}
		key.UpdatedAt = time.Now().UTC()
		newEnv, err := sealMPCRecord(s.vault.id, recordTypeMPCKey, id, recordKey, key)
		if err != nil {
			return err
		}
		if err := s.vault.repo.PutCAS(s.vault.id, recordTypeMPCKey, id, env.Version, newEnv); err != nil {
			return err
		}
	}
	return nil
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

func validateMPCFragmentAttestations(vaultID, keyID, dkgSessionID string, members []Member, commitments []mpc.PublicCommitment, fragments map[string]mpc.EncryptedFragment) error {
	commitmentsHash, err := mpc.CommitmentsHash(commitments)
	if err != nil {
		return err
	}
	for _, member := range members {
		fragment := fragments[member.MemberID]
		if fragment.Attestation == nil {
			return validationErrorf("MPC fragment for member %q is missing signer attestation", member.MemberID)
		}
		attestation := *fragment.Attestation
		if attestation.VaultID != vaultID || attestation.KeyID != keyID || attestation.PartyID != int(member.MPCPartyID) || attestation.DKGSessionID != dkgSessionID {
			return validationErrorf("MPC fragment attestation for member %q is not bound to this vault DKG key or party", member.MemberID)
		}
		fragmentEnvelopeHash, err := mpc.FragmentEnvelopeHash(fragment)
		if err != nil {
			return err
		}
		if attestation.CommitmentsHash != commitmentsHash {
			return validationErrorf("MPC fragment attestation for member %q does not match DKG commitments", member.MemberID)
		}
		if attestation.FragmentEnvelopeHash != fragmentEnvelopeHash {
			return validationErrorf("MPC fragment attestation for member %q does not match encrypted fragment envelope", member.MemberID)
		}
		if attestation.PublicShareCommitment != fragment.PublicShareCommitment {
			return validationErrorf("MPC fragment attestation for member %q does not match fragment public share commitment", member.MemberID)
		}
		if attestation.ApprovalPublicKey != member.MPCApprovalPublicKey {
			return validationErrorf("MPC fragment attestation for member %q does not match registered approval key", member.MemberID)
		}
		if !mpc.VerifyFragmentAttestation(member.MPCApprovalPublicKey, attestation) {
			return validationErrorf("MPC fragment attestation for member %q has an invalid signature", member.MemberID)
		}
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

func loadMPCDKGAttempt(vaultID string, repo storage.Repository, recordKey []byte, dkgSessionID string) (*MPCDKGAttempt, error) {
	env, err := repo.Get(vaultID, recordTypeMPCDKG, dkgSessionID)
	if err != nil {
		return nil, err
	}
	return openMPCRecord[MPCDKGAttempt](vaultID, recordTypeMPCDKG, dkgSessionID, recordKey, env)
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
