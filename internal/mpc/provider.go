package mpc

import (
	"fmt"
	"sort"
)

const AlgorithmExperimentalP256Schnorr = "experimental-p256-schnorr-v1"

type ProviderStatus string

const (
	ProviderStatusExperimental ProviderStatus = "experimental"
	ProviderStatusProduction   ProviderStatus = "production"
)

type ProviderInfo struct {
	Algorithm       string         `json:"algorithm"`
	Curve           string         `json:"curve"`
	Status          ProviderStatus `json:"status"`
	Domain          string         `json:"domain"`
	ProductionReady bool           `json:"production_ready"`
	SupportsKeygen  bool           `json:"supports_keygen"`
	SupportsSigning bool           `json:"supports_signing"`
	SupportsReshare bool           `json:"supports_reshare"`
}

type Provider interface {
	Info() ProviderInfo
	NewKeyMeta(id string, threshold int, parties []PartyInfo, commitments []PublicCommitment) (*KeyMeta, error)
	AggregateCommitments(commitments []Commitment) (Point, error)
	ChallengeHex(publicKey, r Point, message []byte) (string, error)
	CombineSignatureShares(shares []ShareProof) (string, error)
	Verify(message []byte, publicKey Point, sig *Signature) bool
}

var providers = map[string]Provider{
	AlgorithmExperimentalP256Schnorr: experimentalP256SchnorrProvider{},
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
		SupportsKeygen:  true,
		SupportsSigning: true,
		SupportsReshare: false,
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
