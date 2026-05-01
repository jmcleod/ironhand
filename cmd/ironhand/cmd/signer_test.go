package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateSignerDeploymentRequiresProductionControls(t *testing.T) {
	base := signerDeploymentConfig{
		Listen:          "127.0.0.1:8081",
		URL:             "https://signer.internal",
		SharedKey:       "shared",
		StateFile:       "signer.sealed",
		StatePassphrase: "state-passphrase",
		OperatorToken:   "operator",
	}
	require.ErrorContains(t, validateSignerDeployment(base), "tls-cert")

	withTLS := base
	withTLS.TLSCert = "signer.crt"
	withTLS.TLSKey = "signer.key"
	require.ErrorContains(t, validateSignerDeployment(withTLS), "client-ca")

	withClientCA := withTLS
	withClientCA.ClientCA = "ca.pem"
	require.NoError(t, validateSignerDeployment(withClientCA))
}

func TestValidateSignerDeploymentAllowsLoopbackDevOnly(t *testing.T) {
	require.NoError(t, validateSignerDeployment(signerDeploymentConfig{
		Listen:           "127.0.0.1:8081",
		URL:              "http://localhost:8081",
		DevMemory:        true,
		AllowInsecureDev: true,
	}))
	require.ErrorContains(t, validateSignerDeployment(signerDeploymentConfig{
		Listen:           "0.0.0.0:8081",
		URL:              "http://127.0.0.1:8081",
		DevMemory:        true,
		AllowInsecureDev: true,
	}), "loopback")
	require.ErrorContains(t, validateSignerDeployment(signerDeploymentConfig{
		Listen:           "127.0.0.1:8081",
		URL:              "http://signer.internal:8081",
		DevMemory:        true,
		AllowInsecureDev: true,
	}), "loopback")
}

func TestValidateSignerDeploymentRejectsVolatileProductionState(t *testing.T) {
	err := validateSignerDeployment(signerDeploymentConfig{
		Listen:        "127.0.0.1:8081",
		URL:           "https://signer.internal",
		SharedKey:     "shared",
		TLSCert:       "signer.crt",
		TLSKey:        "signer.key",
		ClientCA:      "ca.pem",
		DevMemory:     true,
		OperatorToken: "operator",
	})
	require.ErrorContains(t, err, "dev-in-memory")
}
