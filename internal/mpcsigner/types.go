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
	KeyID     string   `json:"key_id"`
	Threshold int      `json:"threshold"`
	Members   []Member `json:"members"`
}

type StartDKGResponse struct {
	PartyID    uint32               `json:"party_id"`
	Commitment mpc.PublicCommitment `json:"commitment"`
}

type DKGShareRequest struct {
	KeyID       string               `json:"key_id"`
	Threshold   int                  `json:"threshold"`
	Members     []Member             `json:"members"`
	FromPartyID uint32               `json:"from_party_id"`
	ToPartyID   uint32               `json:"to_party_id"`
	Share       string               `json:"share"`
	Commitment  mpc.PublicCommitment `json:"commitment"`
}

type FinalizeDKGRequest struct {
	KeyID       string                 `json:"key_id"`
	Threshold   int                    `json:"threshold"`
	Members     []Member               `json:"members"`
	Commitments []mpc.PublicCommitment `json:"commitments"`
}

type FinalizeDKGResponse struct {
	PartyID           uint32                `json:"party_id"`
	PublicKey         mpc.Point             `json:"public_key"`
	EncryptedFragment mpc.EncryptedFragment `json:"encrypted_fragment"`
}

type ApprovalRequest struct {
	SessionID   string    `json:"session_id"`
	KeyID       string    `json:"key_id"`
	MessageHash string    `json:"message_hash"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type NonceCommitRequest struct {
	KeyID     string `json:"key_id"`
	SessionID string `json:"session_id"`
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
