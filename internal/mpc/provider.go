package mpc

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"sort"
)

const (
	AlgorithmExperimentalP256Schnorr = "experimental-p256-schnorr-v1"
	AlgorithmFROSTSecp256k1          = "frost-secp256k1-v1"
)

type ProviderStatus string

const (
	ProviderStatusExperimental ProviderStatus = "experimental"
	ProviderStatusProduction   ProviderStatus = "production"
)

type ProviderInfo struct {
	Algorithm                          string         `json:"algorithm"`
	Curve                              string         `json:"curve"`
	Status                             ProviderStatus `json:"status"`
	Domain                             string         `json:"domain"`
	ProductionReady                    bool           `json:"production_ready"`
	ProductionBlockers                 []string       `json:"production_blockers,omitempty"`
	SupportsKeygen                     bool           `json:"supports_keygen"`
	SupportsSigning                    bool           `json:"supports_signing"`
	SupportsReshare                    bool           `json:"supports_reshare"`
	SupportsRecoveryImportAttestations bool           `json:"supports_recovery_import_attestations"`
	DeterministicTranscriptValidation  bool           `json:"deterministic_transcript_validation"`
	ChainCompatibility                 []string       `json:"chain_compatibility,omitempty"`
}

type Provider interface {
	Info() ProviderInfo
	NewKeyMeta(id string, threshold int, parties []PartyInfo, commitments []PublicCommitment) (*KeyMeta, error)
	AggregateCommitments(commitments []Commitment) (Point, error)
	ChallengeHex(publicKey, r Point, message []byte) (string, error)
	CombineSignatureShares(shares []ShareProof) (string, error)
	Verify(message []byte, publicKey Point, sig *Signature) bool
	ValidateKeyFragments(keyID string, parties []PartyInfo, commitments []PublicCommitment, fragments []EncryptedFragment) error
}

var providers = map[string]Provider{
	AlgorithmExperimentalP256Schnorr: experimentalP256SchnorrProvider{},
	AlgorithmFROSTSecp256k1:          frostSecp256k1Provider{},
}

func GetProvider(algorithm string) (Provider, error) {
	if algorithm == "" {
		algorithm = AlgorithmExperimentalP256Schnorr
	}
	provider, ok := providers[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported MPC algorithm %q", ErrInvalidKey, algorithm)
	}
	return provider, nil
}

func SupportedProviders() []ProviderInfo {
	algorithms := make([]string, 0, len(providers))
	for algorithm := range providers {
		algorithms = append(algorithms, algorithm)
	}
	sort.Strings(algorithms)
	out := make([]ProviderInfo, 0, len(algorithms))
	for _, algorithm := range algorithms {
		out = append(out, providers[algorithm].Info())
	}
	return out
}

type experimentalP256SchnorrProvider struct{}

func (experimentalP256SchnorrProvider) Info() ProviderInfo {
	return ProviderInfo{
		Algorithm:       AlgorithmExperimentalP256Schnorr,
		Curve:           CurveName,
		Status:          ProviderStatusExperimental,
		Domain:          domain,
		ProductionReady: false,
		ProductionBlockers: []string{
			"demo P-256 Schnorr-style provider",
			"not externally reviewed",
			"not chain-compatible for production assets",
			"does not support resharing",
		},
		SupportsKeygen:                     true,
		SupportsSigning:                    true,
		SupportsReshare:                    false,
		SupportsRecoveryImportAttestations: true,
		DeterministicTranscriptValidation:  true,
		ChainCompatibility:                 []string{"development", "p256-demo"},
	}
}

func (experimentalP256SchnorrProvider) NewKeyMeta(id string, threshold int, parties []PartyInfo, commitments []PublicCommitment) (*KeyMeta, error) {
	return NewKeyMeta(id, threshold, parties, commitments)
}

func (experimentalP256SchnorrProvider) AggregateCommitments(commitments []Commitment) (Point, error) {
	return AggregateCommitments(commitments)
}

func (experimentalP256SchnorrProvider) ChallengeHex(publicKey, r Point, message []byte) (string, error) {
	return ChallengeHex(publicKey, r, message)
}

func (experimentalP256SchnorrProvider) CombineSignatureShares(shares []ShareProof) (string, error) {
	return CombineSignatureShares(shares)
}

func (experimentalP256SchnorrProvider) Verify(message []byte, publicKey Point, sig *Signature) bool {
	return Verify(message, publicKey, sig)
}

func (experimentalP256SchnorrProvider) ValidateKeyFragments(keyID string, parties []PartyInfo, commitments []PublicCommitment, fragments []EncryptedFragment) error {
	if len(fragments) != len(parties) {
		return fmt.Errorf("%w: fragment count must match participant count", ErrInvalidKey)
	}
	allowed := make(map[int]struct{}, len(parties))
	for _, party := range parties {
		allowed[party.ID] = struct{}{}
	}
	seen := make(map[int]struct{}, len(fragments))
	for _, fragment := range fragments {
		if fragment.KeyID != keyID {
			return fmt.Errorf("%w: fragment for party %d is bound to key %q, expected %q", ErrInvalidKey, fragment.PartyID, fragment.KeyID, keyID)
		}
		if _, ok := allowed[fragment.PartyID]; !ok {
			return fmt.Errorf("%w: fragment party %d is not selected for this key", ErrInvalidKey, fragment.PartyID)
		}
		if _, ok := seen[fragment.PartyID]; ok {
			return fmt.Errorf("%w: duplicate fragment for party %d", ErrInvalidKey, fragment.PartyID)
		}
		seen[fragment.PartyID] = struct{}{}
		if fragment.Algorithm != FragmentEnvelope {
			return fmt.Errorf("%w: unsupported fragment envelope %q", ErrInvalidKey, fragment.Algorithm)
		}
		if fragment.Nonce == "" || fragment.Ciphertext == "" || fragment.EphemeralPublicKey == "" {
			return fmt.Errorf("%w: fragment for party %d is incomplete", ErrInvalidKey, fragment.PartyID)
		}
		ephemeral, err := base64.StdEncoding.DecodeString(fragment.EphemeralPublicKey)
		if err != nil {
			return fmt.Errorf("%w: fragment for party %d has invalid ephemeral public key: %v", ErrInvalidKey, fragment.PartyID, err)
		}
		if _, err := ecdh.P256().NewPublicKey(ephemeral); err != nil {
			return fmt.Errorf("%w: fragment for party %d has invalid ephemeral public key: %v", ErrInvalidKey, fragment.PartyID, err)
		}
		expected, err := PublicShareCommitment(commitments, fragment.PartyID)
		if err != nil {
			return fmt.Errorf("%w: compute public share commitment for party %d: %v", ErrInvalidKey, fragment.PartyID, err)
		}
		if fragment.PublicShareCommitment != expected {
			return fmt.Errorf("%w: fragment public share commitment for party %d does not match DKG commitments", ErrInvalidKey, fragment.PartyID)
		}
	}
	return nil
}

type frostSecp256k1Provider struct{}

func (frostSecp256k1Provider) Info() ProviderInfo {
	return ProviderInfo{
		Algorithm:       AlgorithmFROSTSecp256k1,
		Curve:           "secp256k1",
		Status:          ProviderStatusExperimental,
		Domain:          "mpc-frost-secp256k1-v1",
		ProductionReady: false,
		ProductionBlockers: []string{
			"provider implementation pending",
			"known-answer vectors pending",
			"crash/restart nonce safety validation pending",
			"external cryptographic review pending",
		},
		SupportsKeygen:                     false,
		SupportsSigning:                    false,
		SupportsReshare:                    false,
		SupportsRecoveryImportAttestations: false,
		DeterministicTranscriptValidation:  false,
		ChainCompatibility:                 []string{"evm-secp256k1", "bitcoin-secp256k1"},
	}
}

func (p frostSecp256k1Provider) NewKeyMeta(string, int, []PartyInfo, []PublicCommitment) (*KeyMeta, error) {
	return nil, unsupportedProviderError(p)
}

func (p frostSecp256k1Provider) AggregateCommitments([]Commitment) (Point, error) {
	return Point{}, unsupportedProviderError(p)
}

func (p frostSecp256k1Provider) ChallengeHex(Point, Point, []byte) (string, error) {
	return "", unsupportedProviderError(p)
}

func (p frostSecp256k1Provider) CombineSignatureShares([]ShareProof) (string, error) {
	return "", unsupportedProviderError(p)
}

func (frostSecp256k1Provider) Verify([]byte, Point, *Signature) bool {
	return false
}

func (p frostSecp256k1Provider) ValidateKeyFragments(string, []PartyInfo, []PublicCommitment, []EncryptedFragment) error {
	return unsupportedProviderError(p)
}

func unsupportedProviderError(provider Provider) error {
	return fmt.Errorf("%w: MPC provider %q is reserved but not implemented", ErrInvalidKey, provider.Info().Algorithm)
}
