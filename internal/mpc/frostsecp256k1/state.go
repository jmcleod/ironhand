package frostsecp256k1

import (
	"fmt"
	"slices"
)

type DKGState string

const (
	DKGStateStarted   DKGState = "dkg_started"
	DKGStateFinalized DKGState = "dkg_finalized"
	DKGStateCommitted DKGState = "dkg_committed"
	DKGStateAborted   DKGState = "dkg_aborted"
)

type SigningState string

const (
	SigningStateStarted             SigningState = "signing_started"
	SigningStateCommitmentsReserved SigningState = "commitments_reserved"
	SigningStateSharesProduced      SigningState = "shares_produced"
	SigningStateFinalized           SigningState = "signing_finalized"
	SigningStateAborted             SigningState = "signing_aborted"
)

type DKGStateRecord struct {
	KeyID            string   `json:"key_id"`
	DKGID            string   `json:"dkg_id"`
	State            DKGState `json:"state"`
	TranscriptDigest string   `json:"transcript_digest"`
	UpdatedAtUnix    int64    `json:"updated_at_unix,omitempty"`
}

type SigningStateRecord struct {
	KeyID                 string       `json:"key_id"`
	SessionID             string       `json:"session_id"`
	State                 SigningState `json:"state"`
	TranscriptDigest      string       `json:"transcript_digest"`
	CommitmentIDs         []uint64     `json:"commitment_ids,omitempty"`
	ConsumedCommitmentIDs []uint64     `json:"consumed_commitment_ids,omitempty"`
	ShareParticipantIDs   []uint16     `json:"share_participant_ids,omitempty"`
	UpdatedAtUnix         int64        `json:"updated_at_unix,omitempty"`
}

type DurableState struct {
	DKG      map[string]DKGStateRecord     `json:"dkg,omitempty"`
	Signing  map[string]SigningStateRecord `json:"signing,omitempty"`
	Consumed map[string]string             `json:"consumed_commitments,omitempty"`
}

func NewDurableState() DurableState {
	return DurableState{
		DKG:      make(map[string]DKGStateRecord),
		Signing:  make(map[string]SigningStateRecord),
		Consumed: make(map[string]string),
	}
}

func ReconstructDurableState(dkg []DKGStateRecord, signing []SigningStateRecord) (DurableState, error) {
	state := NewDurableState()
	for _, record := range dkg {
		if record.KeyID == "" || record.DKGID == "" || record.TranscriptDigest == "" {
			return DurableState{}, fmt.Errorf("DKG record missing key ID, DKG ID, or transcript digest")
		}
		if !validDKGState(record.State) {
			return DurableState{}, fmt.Errorf("invalid DKG state %q", record.State)
		}
		key := recordKey(record.KeyID, record.DKGID)
		if existing, ok := state.DKG[key]; ok {
			return DurableState{}, fmt.Errorf("duplicate DKG record for %q/%q in states %s and %s", record.KeyID, record.DKGID, existing.State, record.State)
		}
		state.DKG[key] = record
	}
	for _, record := range signing {
		if record.KeyID == "" || record.SessionID == "" || record.TranscriptDigest == "" {
			return DurableState{}, fmt.Errorf("signing record missing key ID, session ID, or transcript digest")
		}
		if !validSigningState(record.State) {
			return DurableState{}, fmt.Errorf("invalid signing state %q", record.State)
		}
		if err := validateSigningRecordShape(record); err != nil {
			return DurableState{}, err
		}
		record.CommitmentIDs = normalizeU64s(record.CommitmentIDs)
		record.ConsumedCommitmentIDs = normalizeU64s(record.ConsumedCommitmentIDs)
		record.ShareParticipantIDs = normalizeU16s(record.ShareParticipantIDs)
		key := recordKey(record.KeyID, record.SessionID)
		if existing, ok := state.Signing[key]; ok {
			return DurableState{}, fmt.Errorf("duplicate signing record for %q/%q in states %s and %s", record.KeyID, record.SessionID, existing.State, record.State)
		}
		state.Signing[key] = record
		for _, commitmentID := range record.ConsumedCommitmentIDs {
			consumedKey := commitmentUseKey(record.KeyID, commitmentID)
			if prior, ok := state.Consumed[consumedKey]; ok && prior != record.SessionID {
				return DurableState{}, fmt.Errorf("commitment %d for key %q consumed by sessions %q and %q", commitmentID, record.KeyID, prior, record.SessionID)
			}
			state.Consumed[consumedKey] = record.SessionID
		}
	}
	return state, nil
}

func (s *DurableState) StartDKG(record DKGStateRecord) error {
	if err := validateNewDKGRecord(record, DKGStateStarted); err != nil {
		return err
	}
	s.init()
	key := recordKey(record.KeyID, record.DKGID)
	if existing, ok := s.DKG[key]; ok {
		if existing.TranscriptDigest != record.TranscriptDigest {
			return fmt.Errorf("DKG transcript digest mismatch for %q", record.DKGID)
		}
		if existing.State != DKGStateStarted {
			return fmt.Errorf("DKG %q is already %s", record.DKGID, existing.State)
		}
		return nil
	}
	s.DKG[key] = record
	return nil
}

func (s *DurableState) TransitionDKG(record DKGStateRecord) error {
	if err := validateNewDKGRecord(record, record.State); err != nil {
		return err
	}
	s.init()
	key := recordKey(record.KeyID, record.DKGID)
	existing, ok := s.DKG[key]
	if !ok {
		return fmt.Errorf("DKG %q has not started", record.DKGID)
	}
	if existing.TranscriptDigest != record.TranscriptDigest {
		return fmt.Errorf("DKG transcript digest mismatch for %q", record.DKGID)
	}
	if !allowedDKGTransition(existing.State, record.State) {
		return fmt.Errorf("invalid DKG transition %s -> %s", existing.State, record.State)
	}
	s.DKG[key] = record
	return nil
}

func (s *DurableState) StartSigning(record SigningStateRecord) error {
	if err := validateNewSigningRecord(record, SigningStateStarted); err != nil {
		return err
	}
	s.init()
	key := recordKey(record.KeyID, record.SessionID)
	if existing, ok := s.Signing[key]; ok {
		if existing.TranscriptDigest != record.TranscriptDigest {
			return fmt.Errorf("signing transcript digest mismatch for %q", record.SessionID)
		}
		if existing.State != SigningStateStarted {
			return fmt.Errorf("signing session %q is already %s", record.SessionID, existing.State)
		}
		return nil
	}
	s.Signing[key] = record
	return nil
}

func (s *DurableState) TransitionSigning(record SigningStateRecord) error {
	if err := validateNewSigningRecord(record, record.State); err != nil {
		return err
	}
	s.init()
	key := recordKey(record.KeyID, record.SessionID)
	existing, ok := s.Signing[key]
	if !ok {
		return fmt.Errorf("signing session %q has not started", record.SessionID)
	}
	if existing.TranscriptDigest != record.TranscriptDigest {
		return fmt.Errorf("signing transcript digest mismatch for %q", record.SessionID)
	}
	if !allowedSigningTransition(existing.State, record.State) {
		return fmt.Errorf("invalid signing transition %s -> %s", existing.State, record.State)
	}
	record.CommitmentIDs = normalizeU64s(record.CommitmentIDs)
	record.ConsumedCommitmentIDs = normalizeU64s(record.ConsumedCommitmentIDs)
	record.ShareParticipantIDs = normalizeU16s(record.ShareParticipantIDs)
	if err := validateSigningRecordShape(record); err != nil {
		return err
	}
	if err := s.reserveCommitments(record); err != nil {
		return err
	}
	s.Signing[key] = record
	return nil
}

func (s *DurableState) init() {
	if s.DKG == nil {
		s.DKG = make(map[string]DKGStateRecord)
	}
	if s.Signing == nil {
		s.Signing = make(map[string]SigningStateRecord)
	}
	if s.Consumed == nil {
		s.Consumed = make(map[string]string)
	}
}

func (s *DurableState) reserveCommitments(record SigningStateRecord) error {
	if record.State != SigningStateSharesProduced && record.State != SigningStateFinalized {
		return nil
	}
	for _, commitmentID := range record.ConsumedCommitmentIDs {
		consumedKey := commitmentUseKey(record.KeyID, commitmentID)
		if prior, ok := s.Consumed[consumedKey]; ok && prior != record.SessionID {
			return fmt.Errorf("commitment %d for key %q was already consumed by session %q", commitmentID, record.KeyID, prior)
		}
	}
	for _, commitmentID := range record.ConsumedCommitmentIDs {
		s.Consumed[commitmentUseKey(record.KeyID, commitmentID)] = record.SessionID
	}
	return nil
}

func validateNewDKGRecord(record DKGStateRecord, expected DKGState) error {
	if record.KeyID == "" || record.DKGID == "" || record.TranscriptDigest == "" {
		return fmt.Errorf("DKG record missing key ID, DKG ID, or transcript digest")
	}
	if record.State != expected {
		return fmt.Errorf("DKG record state = %q, want %q", record.State, expected)
	}
	if !validDKGState(record.State) {
		return fmt.Errorf("invalid DKG state %q", record.State)
	}
	return nil
}

func validateNewSigningRecord(record SigningStateRecord, expected SigningState) error {
	if record.KeyID == "" || record.SessionID == "" || record.TranscriptDigest == "" {
		return fmt.Errorf("signing record missing key ID, session ID, or transcript digest")
	}
	if record.State != expected {
		return fmt.Errorf("signing record state = %q, want %q", record.State, expected)
	}
	if !validSigningState(record.State) {
		return fmt.Errorf("invalid signing state %q", record.State)
	}
	return nil
}

func validateSigningRecordShape(record SigningStateRecord) error {
	if hasDuplicates(record.CommitmentIDs) {
		return fmt.Errorf("signing session %q has duplicate commitment IDs", record.SessionID)
	}
	if hasDuplicates(record.ConsumedCommitmentIDs) {
		return fmt.Errorf("signing session %q has duplicate consumed commitment IDs", record.SessionID)
	}
	if hasDuplicates(record.ShareParticipantIDs) {
		return fmt.Errorf("signing session %q has duplicate share participant IDs", record.SessionID)
	}
	switch record.State {
	case SigningStateStarted:
		if len(record.CommitmentIDs) != 0 || len(record.ConsumedCommitmentIDs) != 0 || len(record.ShareParticipantIDs) != 0 {
			return fmt.Errorf("signing session %q started state cannot include commitments or shares", record.SessionID)
		}
	case SigningStateCommitmentsReserved:
		if len(record.CommitmentIDs) == 0 {
			return fmt.Errorf("signing session %q must reserve commitments before signing", record.SessionID)
		}
	case SigningStateSharesProduced:
		if len(record.CommitmentIDs) == 0 || len(record.ConsumedCommitmentIDs) == 0 {
			return fmt.Errorf("signing session %q must consume commitments before producing shares", record.SessionID)
		}
		if !subsetU64(record.ConsumedCommitmentIDs, record.CommitmentIDs) {
			return fmt.Errorf("signing session %q consumed commitments were not reserved", record.SessionID)
		}
		if len(record.ShareParticipantIDs) == 0 {
			return fmt.Errorf("signing session %q must include produced shares", record.SessionID)
		}
	case SigningStateFinalized:
		if len(record.ConsumedCommitmentIDs) == 0 || len(record.ShareParticipantIDs) == 0 {
			return fmt.Errorf("signing session %q cannot finalize without consumed commitments and shares", record.SessionID)
		}
		if !subsetU64(record.ConsumedCommitmentIDs, record.CommitmentIDs) {
			return fmt.Errorf("signing session %q consumed commitments were not reserved", record.SessionID)
		}
	case SigningStateAborted:
		if len(record.ShareParticipantIDs) != 0 {
			return fmt.Errorf("signing session %q aborted state cannot include produced shares", record.SessionID)
		}
	}
	return nil
}

func allowedDKGTransition(from, to DKGState) bool {
	switch from {
	case DKGStateStarted:
		return to == DKGStateStarted || to == DKGStateFinalized || to == DKGStateAborted
	case DKGStateFinalized:
		return to == DKGStateFinalized || to == DKGStateCommitted || to == DKGStateAborted
	default:
		return false
	}
}

func allowedSigningTransition(from, to SigningState) bool {
	switch from {
	case SigningStateStarted:
		return to == SigningStateStarted || to == SigningStateCommitmentsReserved || to == SigningStateAborted
	case SigningStateCommitmentsReserved:
		return to == SigningStateCommitmentsReserved || to == SigningStateSharesProduced || to == SigningStateAborted
	case SigningStateSharesProduced:
		return to == SigningStateSharesProduced || to == SigningStateFinalized
	default:
		return false
	}
}

func validDKGState(state DKGState) bool {
	switch state {
	case DKGStateStarted, DKGStateFinalized, DKGStateCommitted, DKGStateAborted:
		return true
	default:
		return false
	}
}

func validSigningState(state SigningState) bool {
	switch state {
	case SigningStateStarted, SigningStateCommitmentsReserved, SigningStateSharesProduced, SigningStateFinalized, SigningStateAborted:
		return true
	default:
		return false
	}
}

func normalizeU64s(values []uint64) []uint64 {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}

func normalizeU16s(values []uint16) []uint16 {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}

func subsetU64(subset, superset []uint64) bool {
	allowed := make(map[uint64]struct{}, len(superset))
	for _, value := range superset {
		allowed[value] = struct{}{}
	}
	for _, value := range subset {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}

func hasDuplicates[T comparable](values []T) bool {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func recordKey(left, right string) string {
	return left + ":" + right
}

func commitmentUseKey(keyID string, commitmentID uint64) string {
	return fmt.Sprintf("%s:%d", keyID, commitmentID)
}
