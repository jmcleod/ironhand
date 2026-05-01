package frostsecp256k1

import "fmt"

var ErrOperationsDisabled = fmt.Errorf("FROST secp256k1 operations are disabled")

type OperationGate struct {
	Enabled bool
}

func DisabledOperationGate() OperationGate {
	return OperationGate{}
}

func InternalSpikeOperationGate() OperationGate {
	return OperationGate{Enabled: true}
}

func (g OperationGate) Check() error {
	if !g.Enabled {
		return ErrOperationsDisabled
	}
	return nil
}

type DKGCoordinator interface {
	StartDKG(StartDKGRequest) (StartDKGResponse, error)
	AcceptDKGShare(AcceptDKGShareRequest) error
	FinalizeDKG(FinalizeDKGRequest) (FinalizeDKGResponse, error)
	AbortDKG(AbortDKGRequest) error
}

type SignerParticipant interface {
	ReserveNonceCommitments(ReserveNonceCommitmentsRequest) (ReserveNonceCommitmentsResponse, error)
	ProduceSignatureShare(ProduceSignatureShareRequest) (ProduceSignatureShareResponse, error)
}

type SigningCoordinator interface {
	StartSigning(StartSigningRequest) (StartSigningResponse, error)
	AcceptSignatureShare(AcceptSignatureShareRequest) error
	AggregateSignature(AggregateSignatureRequest) (AggregateSignatureResponse, error)
	AbortSigning(AbortSigningRequest) error
}

type DurableStateRecorder interface {
	StartDKG(DKGStateRecord) error
	TransitionDKG(DKGStateRecord) error
	StartSigning(SigningStateRecord) error
	TransitionSigning(SigningStateRecord) error
}

type TranscriptBuilder interface {
	DKGTranscript(StartDKGRequest) (DKGTranscript, string, error)
	SigningTranscript(StartSigningRequest) (SigningTranscript, string, error)
}

type StartDKGRequest struct {
	VaultID          string        `json:"vault_id"`
	KeyID            string        `json:"key_id"`
	DKGID            string        `json:"dkg_id"`
	Threshold        uint16        `json:"threshold"`
	Participants     []Participant `json:"participants"`
	TranscriptDigest string        `json:"transcript_digest"`
}

type StartDKGResponse struct {
	TranscriptDigest string   `json:"transcript_digest"`
	State            DKGState `json:"state"`
}

type AcceptDKGShareRequest struct {
	KeyID            string `json:"key_id"`
	DKGID            string `json:"dkg_id"`
	FromParticipant  uint16 `json:"from_participant"`
	ToParticipant    uint16 `json:"to_participant"`
	SharePackage     string `json:"share_package"`
	TranscriptDigest string `json:"transcript_digest"`
}

type FinalizeDKGRequest struct {
	KeyID            string `json:"key_id"`
	DKGID            string `json:"dkg_id"`
	TranscriptDigest string `json:"transcript_digest"`
	PublicKey        string `json:"public_key"`
}

type FinalizeDKGResponse struct {
	TranscriptDigest string   `json:"transcript_digest"`
	State            DKGState `json:"state"`
	PublicKey        string   `json:"public_key"`
}

type AbortDKGRequest struct {
	KeyID            string `json:"key_id"`
	DKGID            string `json:"dkg_id"`
	TranscriptDigest string `json:"transcript_digest"`
	Reason           string `json:"reason,omitempty"`
}

type StartSigningRequest struct {
	VaultID          string        `json:"vault_id"`
	KeyID            string        `json:"key_id"`
	DKGID            string        `json:"dkg_id"`
	SessionID        string        `json:"session_id"`
	Threshold        uint16        `json:"threshold"`
	Participants     []Participant `json:"participants"`
	Chain            string        `json:"chain"`
	MessageDigest    string        `json:"message_digest"`
	TranscriptDigest string        `json:"transcript_digest"`
}

type StartSigningResponse struct {
	TranscriptDigest string       `json:"transcript_digest"`
	State            SigningState `json:"state"`
}

type ReserveNonceCommitmentsRequest struct {
	KeyID            string `json:"key_id"`
	SessionID        string `json:"session_id"`
	ParticipantID    uint16 `json:"participant_id"`
	TranscriptDigest string `json:"transcript_digest"`
}

type ReserveNonceCommitmentsResponse struct {
	ParticipantID          uint16 `json:"participant_id"`
	CommitmentID           uint64 `json:"commitment_id"`
	HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
	BindingNonceCommitment string `json:"binding_nonce_commitment"`
	TranscriptDigest       string `json:"transcript_digest"`
}

type ProduceSignatureShareRequest struct {
	KeyID            string                 `json:"key_id"`
	SessionID        string                 `json:"session_id"`
	ParticipantID    uint16                 `json:"participant_id"`
	MessageDigest    string                 `json:"message_digest"`
	Commitments      []CommitmentTranscript `json:"commitments"`
	TranscriptDigest string                 `json:"transcript_digest"`
}

type ProduceSignatureShareResponse struct {
	ParticipantID    uint16 `json:"participant_id"`
	SignatureShare   string `json:"signature_share"`
	TranscriptDigest string `json:"transcript_digest"`
}

type AcceptSignatureShareRequest struct {
	KeyID            string `json:"key_id"`
	SessionID        string `json:"session_id"`
	ParticipantID    uint16 `json:"participant_id"`
	SignatureShare   string `json:"signature_share"`
	TranscriptDigest string `json:"transcript_digest"`
}

type AggregateSignatureRequest struct {
	KeyID            string                     `json:"key_id"`
	SessionID        string                     `json:"session_id"`
	MessageDigest    string                     `json:"message_digest"`
	Commitments      []CommitmentTranscript     `json:"commitments"`
	Shares           []SignatureShareTranscript `json:"signature_shares"`
	TranscriptDigest string                     `json:"transcript_digest"`
}

type AggregateSignatureResponse struct {
	Signature        string       `json:"signature"`
	TranscriptDigest string       `json:"transcript_digest"`
	State            SigningState `json:"state"`
}

type AbortSigningRequest struct {
	KeyID            string `json:"key_id"`
	SessionID        string `json:"session_id"`
	TranscriptDigest string `json:"transcript_digest"`
	Reason           string `json:"reason,omitempty"`
}

func BuildDKGTranscript(req StartDKGRequest) (DKGTranscript, string, error) {
	transcript := NewDKGTranscript(req.VaultID, req.KeyID, req.DKGID, req.Threshold, req.Participants)
	digest, err := DKGTranscriptDigest(transcript)
	return transcript, digest, err
}

func BuildSigningTranscript(req StartSigningRequest) (SigningTranscript, string, error) {
	transcript := NewSigningTranscript(req.VaultID, req.KeyID, req.DKGID, req.SessionID, req.Threshold, req.Participants, req.Chain, req.MessageDigest)
	digest, err := SigningTranscriptDigest(transcript)
	return transcript, digest, err
}

func ValidateStartDKGRequest(req StartDKGRequest) error {
	_, digest, err := BuildDKGTranscript(req)
	if err != nil {
		return err
	}
	return requireTranscriptDigest("start DKG", req.TranscriptDigest, digest)
}

func ValidateStartSigningRequest(req StartSigningRequest) error {
	_, digest, err := BuildSigningTranscript(req)
	if err != nil {
		return err
	}
	return requireTranscriptDigest("start signing", req.TranscriptDigest, digest)
}

func ValidateAcceptDKGShareRequest(req AcceptDKGShareRequest) error {
	if req.KeyID == "" || req.DKGID == "" {
		return fmt.Errorf("accept DKG share missing key ID or DKG ID")
	}
	if req.FromParticipant == 0 || req.ToParticipant == 0 {
		return fmt.Errorf("accept DKG share participant IDs must be greater than zero")
	}
	if req.SharePackage == "" {
		return fmt.Errorf("accept DKG share missing share package")
	}
	return requireAnyTranscriptDigest("accept DKG share", req.TranscriptDigest)
}

func ValidateFinalizeDKGRequest(req FinalizeDKGRequest) error {
	if req.KeyID == "" || req.DKGID == "" {
		return fmt.Errorf("finalize DKG missing key ID or DKG ID")
	}
	if req.PublicKey == "" {
		return fmt.Errorf("finalize DKG missing public key")
	}
	return requireAnyTranscriptDigest("finalize DKG", req.TranscriptDigest)
}

func ValidateAbortDKGRequest(req AbortDKGRequest) error {
	if req.KeyID == "" || req.DKGID == "" {
		return fmt.Errorf("abort DKG missing key ID or DKG ID")
	}
	return requireAnyTranscriptDigest("abort DKG", req.TranscriptDigest)
}

func ValidateReserveNonceCommitmentsRequest(req ReserveNonceCommitmentsRequest) error {
	if req.KeyID == "" || req.SessionID == "" {
		return fmt.Errorf("reserve nonce commitments missing key ID or session ID")
	}
	if req.ParticipantID == 0 {
		return fmt.Errorf("reserve nonce commitments participant ID must be greater than zero")
	}
	return requireAnyTranscriptDigest("reserve nonce commitments", req.TranscriptDigest)
}

func ValidateProduceSignatureShareRequest(req ProduceSignatureShareRequest) error {
	if req.KeyID == "" || req.SessionID == "" {
		return fmt.Errorf("produce signature share missing key ID or session ID")
	}
	if req.ParticipantID == 0 {
		return fmt.Errorf("produce signature share participant ID must be greater than zero")
	}
	if err := validateMessageDigest(req.MessageDigest); err != nil {
		return err
	}
	if len(req.Commitments) == 0 {
		return fmt.Errorf("produce signature share missing commitments")
	}
	return requireAnyTranscriptDigest("produce signature share", req.TranscriptDigest)
}

func ValidateAcceptSignatureShareRequest(req AcceptSignatureShareRequest) error {
	if req.KeyID == "" || req.SessionID == "" {
		return fmt.Errorf("accept signature share missing key ID or session ID")
	}
	if req.ParticipantID == 0 {
		return fmt.Errorf("accept signature share participant ID must be greater than zero")
	}
	if req.SignatureShare == "" {
		return fmt.Errorf("accept signature share missing signature share")
	}
	return requireAnyTranscriptDigest("accept signature share", req.TranscriptDigest)
}

func ValidateAggregateSignatureRequest(req AggregateSignatureRequest) error {
	if req.KeyID == "" || req.SessionID == "" {
		return fmt.Errorf("aggregate signature missing key ID or session ID")
	}
	if err := validateMessageDigest(req.MessageDigest); err != nil {
		return err
	}
	if len(req.Commitments) == 0 || len(req.Shares) == 0 {
		return fmt.Errorf("aggregate signature missing commitments or signature shares")
	}
	return requireAnyTranscriptDigest("aggregate signature", req.TranscriptDigest)
}

func ValidateAbortSigningRequest(req AbortSigningRequest) error {
	if req.KeyID == "" || req.SessionID == "" {
		return fmt.Errorf("abort signing missing key ID or session ID")
	}
	return requireAnyTranscriptDigest("abort signing", req.TranscriptDigest)
}

func requireTranscriptDigest(operation, got, want string) error {
	if got == "" {
		return fmt.Errorf("%s missing transcript digest", operation)
	}
	if got != want {
		return fmt.Errorf("%s transcript digest mismatch", operation)
	}
	return nil
}

func requireAnyTranscriptDigest(operation, digest string) error {
	if digest == "" {
		return fmt.Errorf("%s missing transcript digest", operation)
	}
	return nil
}
