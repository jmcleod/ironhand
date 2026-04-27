package mpcsigner

import (
	"time"

	"github.com/jmcleod/ironhand/internal/mpc"
)

type Member struct {
	MemberID            string `json:"member_id"`
	PartyID             uint32 `json:"party_id"`
	URL                 string `json:"url"`
	EncryptionPublicKey string `json:"encryption_public_key"`
	ApprovalPublicKey   string `json:"approval_public_key"`
}

type IdentityResponse struct {
	Member mpc.SignerIdentity `json:"member"`
}

type StartDKGRequest struct {
	DKGSessionID string   `json:"dkg_session_id"`
	VaultID      string   `json:"vault_id"`
	KeyID        string   `json:"key_id"`
	Threshold    int      `json:"threshold"`
	Members      []Member `json:"members"`
}

type StartDKGResponse struct {
	PartyID    uint32               `json:"party_id"`
	Commitment mpc.PublicCommitment `json:"commitment"`
}

type DKGShareRequest struct {
	DKGSessionID string               `json:"dkg_session_id"`
	VaultID      string               `json:"vault_id"`
	KeyID        string               `json:"key_id"`
	Threshold    int                  `json:"threshold"`
	Members      []Member             `json:"members"`
	FromPartyID  uint32               `json:"from_party_id"`
	ToPartyID    uint32               `json:"to_party_id"`
	Share        string               `json:"share"`
	Commitment   mpc.PublicCommitment `json:"commitment"`
}

type FinalizeDKGRequest struct {
	DKGSessionID string                 `json:"dkg_session_id"`
	VaultID      string                 `json:"vault_id"`
	KeyID        string                 `json:"key_id"`
	Threshold    int                    `json:"threshold"`
	Members      []Member               `json:"members"`
	Commitments  []mpc.PublicCommitment `json:"commitments"`
}

type FinalizeDKGResponse struct {
	PartyID           uint32                `json:"party_id"`
	PublicKey         mpc.Point             `json:"public_key"`
	EncryptedFragment mpc.EncryptedFragment `json:"encrypted_fragment"`
}

type AbortDKGRequest struct {
	DKGSessionID string `json:"dkg_session_id"`
	KeyID        string `json:"key_id"`
}

type CommitDKGRequest struct {
	DKGSessionID string `json:"dkg_session_id"`
	KeyID        string `json:"key_id"`
}

type ApprovalRequest struct {
	VaultID      string    `json:"vault_id"`
	SessionID    string    `json:"session_id"`
	KeyID        string    `json:"key_id"`
	Threshold    int       `json:"threshold"`
	Participants []int     `json:"participants"`
	MessageHash  string    `json:"message_hash"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type ApprovalRequestStatus string

const (
	ApprovalRequestPending  ApprovalRequestStatus = "pending"
	ApprovalRequestApproved ApprovalRequestStatus = "approved"
	ApprovalRequestRejected ApprovalRequestStatus = "rejected"
	ApprovalRequestExpired  ApprovalRequestStatus = "expired"
)

type ApprovalRequestRecord struct {
	RequestID  string                `json:"request_id"`
	PartyID    uint32                `json:"party_id"`
	Status     ApprovalRequestStatus `json:"status"`
	Request    ApprovalRequest       `json:"request"`
	Approval   *mpc.Approval         `json:"approval,omitempty"`
	Reason     string                `json:"reason,omitempty"`
	CreatedAt  time.Time             `json:"created_at"`
	UpdatedAt  time.Time             `json:"updated_at"`
	ApprovedAt time.Time             `json:"approved_at,omitempty"`
	RejectedAt time.Time             `json:"rejected_at,omitempty"`
}

type CreateApprovalRequestResponse struct {
	Request ApprovalRequestRecord `json:"request"`
}

type ListApprovalRequestsResponse struct {
	Requests []ApprovalRequestRecord `json:"requests"`
}

type RejectApprovalRequest struct {
	Reason string `json:"reason,omitempty"`
}

type NonceCommitRequest struct {
	KeyID       string `json:"key_id"`
	SessionID   string `json:"session_id"`
	MessageHash string `json:"message_hash"`
}

type SignShareRequest struct {
	KeyID        string                `json:"key_id"`
	SessionID    string                `json:"session_id"`
	MessageB64   string                `json:"message_base64"`
	Participants []int                 `json:"participants"`
	AggregateR   mpc.Point             `json:"aggregate_r"`
	Fragment     mpc.EncryptedFragment `json:"fragment"`
	Approval     mpc.Approval          `json:"approval"`
}
