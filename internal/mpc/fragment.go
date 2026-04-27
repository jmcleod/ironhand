package mpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const FragmentEnvelope = "ecdh-p256-aes-256-gcm-v1"

type SignerIdentity struct {
	PartyID             int    `json:"party_id"`
	Name                string `json:"name,omitempty"`
	URL                 string `json:"url,omitempty"`
	EncryptionPublicKey string `json:"encryption_public_key"`
	ApprovalPublicKey   string `json:"approval_public_key"`
}

type EncryptedFragment struct {
	KeyID                 string               `json:"key_id"`
	PartyID               int                  `json:"party_id"`
	Algorithm             string               `json:"algorithm"`
	EphemeralPublicKey    string               `json:"ephemeral_public_key"`
	Nonce                 string               `json:"nonce"`
	Ciphertext            string               `json:"ciphertext"`
	PublicShareCommitment Point                `json:"public_share_commitment"`
	Attestation           *FragmentAttestation `json:"attestation,omitempty"`
}

type FragmentAttestation struct {
	VaultID               string    `json:"vault_id"`
	DKGSessionID          string    `json:"dkg_session_id"`
	KeyID                 string    `json:"key_id"`
	PartyID               int       `json:"party_id"`
	PublicShareCommitment Point     `json:"public_share_commitment"`
	CommitmentsHash       string    `json:"commitments_hash"`
	ApprovalPublicKey     string    `json:"approval_public_key"`
	CreatedAt             time.Time `json:"created_at"`
	Signature             string    `json:"signature"`
}

type Approval struct {
	VaultID           string    `json:"vault_id"`
	SessionID         string    `json:"session_id"`
	KeyID             string    `json:"key_id"`
	PartyID           int       `json:"party_id"`
	Threshold         int       `json:"threshold"`
	Participants      []int     `json:"participants"`
	MessageHash       string    `json:"message_hash"`
	MessageType       string    `json:"message_type,omitempty"`
	Chain             string    `json:"chain,omitempty"`
	Network           string    `json:"network,omitempty"`
	TransactionDigest string    `json:"transaction_digest,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
	Signature         string    `json:"signature"`
}

func GenerateSignerIdentity(partyID int, name, url string) (*ecdh.PrivateKey, ed25519.PrivateKey, SignerIdentity, error) {
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, SignerIdentity{}, err
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, SignerIdentity{}, err
	}
	return ecdhPriv, edPriv, SignerIdentity{
		PartyID:             partyID,
		Name:                name,
		URL:                 strings.TrimRight(url, "/"),
		EncryptionPublicKey: base64.StdEncoding.EncodeToString(ecdhPriv.PublicKey().Bytes()),
		ApprovalPublicKey:   base64.StdEncoding.EncodeToString(edPub),
	}, nil
}

func EncryptFragment(keyID string, partyID int, recipientPublicKey string, plaintext []byte, publicShare Point) (EncryptedFragment, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(recipientPublicKey)
	if err != nil {
		return EncryptedFragment{}, fmt.Errorf("decode recipient public key: %w", err)
	}
	pub, err := ecdh.P256().NewPublicKey(pubBytes)
	if err != nil {
		return EncryptedFragment{}, fmt.Errorf("parse recipient public key: %w", err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return EncryptedFragment{}, err
	}
	secret, err := ephemeral.ECDH(pub)
	if err != nil {
		return EncryptedFragment{}, err
	}
	key := deriveFragmentKey(secret, ephemeral.PublicKey().Bytes(), pub.Bytes())
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedFragment{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedFragment{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedFragment{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(fragmentAAD(keyID, partyID)))
	return EncryptedFragment{
		KeyID:                 keyID,
		PartyID:               partyID,
		Algorithm:             FragmentEnvelope,
		EphemeralPublicKey:    base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce:                 base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:            base64.StdEncoding.EncodeToString(ciphertext),
		PublicShareCommitment: publicShare,
	}, nil
}

func DecryptFragment(privateKey *ecdh.PrivateKey, fragment EncryptedFragment) ([]byte, error) {
	if fragment.Algorithm != FragmentEnvelope {
		return nil, fmt.Errorf("unsupported fragment envelope %q", fragment.Algorithm)
	}
	ephemeralBytes, err := base64.StdEncoding.DecodeString(fragment.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral public key: %w", err)
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(fragment.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(fragment.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	secret, err := privateKey.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	key := deriveFragmentKey(secret, ephemeral.Bytes(), privateKey.PublicKey().Bytes())
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, []byte(fragmentAAD(fragment.KeyID, fragment.PartyID)))
}

func SignApproval(privateKey ed25519.PrivateKey, approval Approval) (Approval, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Approval{}, errors.New("invalid ed25519 private key")
	}
	approval.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(ApprovalPayload(approval))))
	return approval, nil
}

func VerifyApproval(publicKey string, approval Approval, now time.Time) bool {
	if approval.ExpiresAt.Before(now) {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(ApprovalPayload(approval)), signature)
}

func CommitmentsHash(commitments []PublicCommitment) (string, error) {
	payload, err := json.Marshal(commitments)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func SignFragmentAttestation(privateKey ed25519.PrivateKey, attestation FragmentAttestation) (FragmentAttestation, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return FragmentAttestation{}, errors.New("invalid ed25519 private key")
	}
	attestation.Signature = ""
	attestation.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(FragmentAttestationPayload(attestation))))
	return attestation, nil
}

func VerifyFragmentAttestation(publicKey string, attestation FragmentAttestation) bool {
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(attestation.Signature)
	if err != nil {
		return false
	}
	unsigned := attestation
	unsigned.Signature = ""
	return ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(FragmentAttestationPayload(unsigned)), signature)
}

func FragmentAttestationPayload(attestation FragmentAttestation) string {
	return strings.Join([]string{
		attestation.VaultID,
		attestation.DKGSessionID,
		attestation.KeyID,
		fmt.Sprintf("%d", attestation.PartyID),
		attestation.PublicShareCommitment.X,
		attestation.PublicShareCommitment.Y,
		attestation.CommitmentsHash,
		attestation.ApprovalPublicKey,
		attestation.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, "\n")
}

func ApprovalPayload(approval Approval) string {
	participants := make([]string, 0, len(approval.Participants))
	for _, partyID := range approval.Participants {
		participants = append(participants, fmt.Sprintf("%d", partyID))
	}
	return strings.Join([]string{
		approval.VaultID,
		approval.SessionID,
		approval.KeyID,
		fmt.Sprintf("%d", approval.PartyID),
		fmt.Sprintf("%d", approval.Threshold),
		strings.Join(participants, ","),
		approval.MessageHash,
		approval.MessageType,
		approval.Chain,
		approval.Network,
		approval.TransactionDigest,
		approval.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "\n")
}

func MessageHash(message []byte) string {
	sum := sha256.Sum256(message)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func deriveFragmentKey(secret, firstPub, secondPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte(FragmentEnvelope))
	h.Write(secret)
	h.Write(firstPub)
	h.Write(secondPub)
	return h.Sum(nil)
}

func fragmentAAD(keyID string, partyID int) string {
	return fmt.Sprintf("%s:%d:%s", keyID, partyID, FragmentEnvelope)
}
