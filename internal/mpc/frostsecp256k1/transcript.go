package frostsecp256k1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

const transcriptVersion = 1

type Participant struct {
	ID        uint16 `json:"id"`
	PublicKey string `json:"public_key,omitempty"`
}

type CommitmentTranscript struct {
	ParticipantID          uint16 `json:"participant_id"`
	HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
	BindingNonceCommitment string `json:"binding_nonce_commitment"`
	BindingFactorInput     string `json:"binding_factor_input,omitempty"`
	BindingFactor          string `json:"binding_factor,omitempty"`
	CommitmentID           uint64 `json:"commitment_id,omitempty"`
}

type SignatureShareTranscript struct {
	ParticipantID  uint16 `json:"participant_id"`
	SignatureShare string `json:"signature_share"`
}

type DKGTranscript struct {
	Kind          string        `json:"kind"`
	Version       int           `json:"version"`
	Provider      string        `json:"provider"`
	Ciphersuite   string        `json:"ciphersuite"`
	ContextString string        `json:"context_string"`
	Domain        string        `json:"domain"`
	VaultID       string        `json:"vault_id"`
	KeyID         string        `json:"key_id"`
	DKGID         string        `json:"dkg_id"`
	Threshold     uint16        `json:"threshold"`
	Participants  []Participant `json:"participants"`
	CreatedAtUnix int64         `json:"created_at_unix,omitempty"`
	UpdatedAtUnix int64         `json:"updated_at_unix,omitempty"`
}

type SigningTranscript struct {
	Kind          string                     `json:"kind"`
	Version       int                        `json:"version"`
	Provider      string                     `json:"provider"`
	Ciphersuite   string                     `json:"ciphersuite"`
	ContextString string                     `json:"context_string"`
	Domain        string                     `json:"domain"`
	VaultID       string                     `json:"vault_id"`
	KeyID         string                     `json:"key_id"`
	DKGID         string                     `json:"dkg_id"`
	SessionID     string                     `json:"session_id"`
	Threshold     uint16                     `json:"threshold"`
	Participants  []Participant              `json:"participants"`
	Chain         string                     `json:"chain"`
	MessageDigest string                     `json:"message_digest"`
	Commitments   []CommitmentTranscript     `json:"commitments,omitempty"`
	Shares        []SignatureShareTranscript `json:"signature_shares,omitempty"`
	CreatedAtUnix int64                      `json:"created_at_unix,omitempty"`
	UpdatedAtUnix int64                      `json:"updated_at_unix,omitempty"`
}

func NewDKGTranscript(vaultID, keyID, dkgID string, threshold uint16, participants []Participant) DKGTranscript {
	return DKGTranscript{
		Kind:          "frost-secp256k1-dkg",
		Version:       transcriptVersion,
		Provider:      Algorithm,
		Ciphersuite:   Ciphersuite,
		ContextString: ContextString,
		Domain:        Domain,
		VaultID:       vaultID,
		KeyID:         keyID,
		DKGID:         dkgID,
		Threshold:     threshold,
		Participants:  cloneParticipants(participants),
	}
}

func NewSigningTranscript(vaultID, keyID, dkgID, sessionID string, threshold uint16, participants []Participant, chain, messageDigest string) SigningTranscript {
	return SigningTranscript{
		Kind:          "frost-secp256k1-signing",
		Version:       transcriptVersion,
		Provider:      Algorithm,
		Ciphersuite:   Ciphersuite,
		ContextString: ContextString,
		Domain:        Domain,
		VaultID:       vaultID,
		KeyID:         keyID,
		DKGID:         dkgID,
		SessionID:     sessionID,
		Threshold:     threshold,
		Participants:  cloneParticipants(participants),
		Chain:         chain,
		MessageDigest: messageDigest,
	}
}

func CanonicalDKGTranscript(t DKGTranscript) ([]byte, error) {
	normalized, err := normalizeDKGTranscript(t)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func CanonicalSigningTranscript(t SigningTranscript) ([]byte, error) {
	normalized, err := normalizeSigningTranscript(t)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func DKGTranscriptDigest(t DKGTranscript) (string, error) {
	canonical, err := CanonicalDKGTranscript(t)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func SigningTranscriptDigest(t SigningTranscript) (string, error) {
	canonical, err := CanonicalSigningTranscript(t)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func normalizeDKGTranscript(t DKGTranscript) (DKGTranscript, error) {
	if err := validateCommon(t.Kind, "frost-secp256k1-dkg", t.Version, t.Provider, t.Ciphersuite, t.ContextString, t.Domain, t.VaultID, t.KeyID, t.DKGID, t.Threshold, t.Participants); err != nil {
		return DKGTranscript{}, err
	}
	t.Participants = normalizeParticipants(t.Participants)
	return t, nil
}

func normalizeSigningTranscript(t SigningTranscript) (SigningTranscript, error) {
	if err := validateCommon(t.Kind, "frost-secp256k1-signing", t.Version, t.Provider, t.Ciphersuite, t.ContextString, t.Domain, t.VaultID, t.KeyID, t.DKGID, t.Threshold, t.Participants); err != nil {
		return SigningTranscript{}, err
	}
	if t.SessionID == "" {
		return SigningTranscript{}, fmt.Errorf("signing transcript missing session ID")
	}
	if !chainSupported(t.Chain) {
		return SigningTranscript{}, fmt.Errorf("signing transcript chain %q is not supported", t.Chain)
	}
	if err := validateMessageDigest(t.MessageDigest); err != nil {
		return SigningTranscript{}, err
	}
	t.Participants = normalizeParticipants(t.Participants)
	participantIDs := participantSet(t.Participants)
	if err := validateCommitments(t.Commitments, participantIDs); err != nil {
		return SigningTranscript{}, err
	}
	if err := validateShares(t.Shares, participantIDs); err != nil {
		return SigningTranscript{}, err
	}
	t.Commitments = normalizeCommitments(t.Commitments)
	t.Shares = normalizeShares(t.Shares)
	return t, nil
}

func validateCommon(kind, expectedKind string, version int, provider, ciphersuite, contextString, domain, vaultID, keyID, dkgID string, threshold uint16, participants []Participant) error {
	if kind != expectedKind {
		return fmt.Errorf("transcript kind = %q, want %q", kind, expectedKind)
	}
	if version != transcriptVersion {
		return fmt.Errorf("transcript version = %d, want %d", version, transcriptVersion)
	}
	if provider != Algorithm {
		return fmt.Errorf("transcript provider = %q, want %q", provider, Algorithm)
	}
	if ciphersuite != Ciphersuite {
		return fmt.Errorf("transcript ciphersuite = %q, want %q", ciphersuite, Ciphersuite)
	}
	if contextString != ContextString {
		return fmt.Errorf("transcript context = %q, want %q", contextString, ContextString)
	}
	if domain != Domain {
		return fmt.Errorf("transcript domain = %q, want %q", domain, Domain)
	}
	if vaultID == "" || keyID == "" || dkgID == "" {
		return fmt.Errorf("transcript missing vault ID, key ID, or DKG ID")
	}
	return validateParticipantSet(threshold, participants)
}

func validateParticipantSet(threshold uint16, participants []Participant) error {
	if threshold == 0 {
		return fmt.Errorf("transcript threshold must be greater than zero")
	}
	if len(participants) == 0 {
		return fmt.Errorf("transcript must include participants")
	}
	if int(threshold) > len(participants) {
		return fmt.Errorf("transcript threshold %d exceeds participant count %d", threshold, len(participants))
	}
	seen := make(map[uint16]struct{}, len(participants))
	for _, participant := range participants {
		if participant.ID == 0 {
			return fmt.Errorf("transcript participant ID must be greater than zero")
		}
		if _, ok := seen[participant.ID]; ok {
			return fmt.Errorf("transcript participant %d appears more than once", participant.ID)
		}
		seen[participant.ID] = struct{}{}
	}
	return nil
}

func validateMessageDigest(digest string) error {
	decoded, err := hex.DecodeString(digest)
	if err != nil {
		return fmt.Errorf("signing transcript message digest is not hex: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("signing transcript message digest is %d bytes, want 32", len(decoded))
	}
	return nil
}

func validateCommitments(commitments []CommitmentTranscript, participantIDs map[uint16]struct{}) error {
	seen := make(map[uint16]struct{}, len(commitments))
	for _, commitment := range commitments {
		if commitment.ParticipantID == 0 {
			return fmt.Errorf("commitment participant ID must be greater than zero")
		}
		if _, ok := participantIDs[commitment.ParticipantID]; !ok {
			return fmt.Errorf("commitment participant %d is not part of transcript", commitment.ParticipantID)
		}
		if commitment.HidingNonceCommitment == "" || commitment.BindingNonceCommitment == "" {
			return fmt.Errorf("commitment for participant %d is missing nonce commitments", commitment.ParticipantID)
		}
		if _, ok := seen[commitment.ParticipantID]; ok {
			return fmt.Errorf("commitment for participant %d appears more than once", commitment.ParticipantID)
		}
		seen[commitment.ParticipantID] = struct{}{}
	}
	return nil
}

func validateShares(shares []SignatureShareTranscript, participantIDs map[uint16]struct{}) error {
	seen := make(map[uint16]struct{}, len(shares))
	for _, share := range shares {
		if share.ParticipantID == 0 {
			return fmt.Errorf("signature share participant ID must be greater than zero")
		}
		if _, ok := participantIDs[share.ParticipantID]; !ok {
			return fmt.Errorf("signature share participant %d is not part of transcript", share.ParticipantID)
		}
		if share.SignatureShare == "" {
			return fmt.Errorf("signature share for participant %d is empty", share.ParticipantID)
		}
		if _, ok := seen[share.ParticipantID]; ok {
			return fmt.Errorf("signature share for participant %d appears more than once", share.ParticipantID)
		}
		seen[share.ParticipantID] = struct{}{}
	}
	return nil
}

func chainSupported(chain string) bool {
	for _, compatible := range chainCompatibility {
		if chain == compatible {
			return true
		}
	}
	return false
}

func participantSet(participants []Participant) map[uint16]struct{} {
	out := make(map[uint16]struct{}, len(participants))
	for _, participant := range participants {
		out[participant.ID] = struct{}{}
	}
	return out
}

func normalizeParticipants(participants []Participant) []Participant {
	out := cloneParticipants(participants)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func normalizeCommitments(commitments []CommitmentTranscript) []CommitmentTranscript {
	out := slices.Clone(commitments)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ParticipantID < out[j].ParticipantID
	})
	return out
}

func normalizeShares(shares []SignatureShareTranscript) []SignatureShareTranscript {
	out := slices.Clone(shares)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ParticipantID < out[j].ParticipantID
	})
	return out
}

func cloneParticipants(participants []Participant) []Participant {
	return slices.Clone(participants)
}
