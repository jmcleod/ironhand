package api_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jmcleod/ironhand/api"
	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/jmcleod/ironhand/vault"
)

func setupServer(t *testing.T) *httptest.Server {
	t.Helper()
	repo := memory.NewRepository()
	epochCache := vault.NewMemoryEpochCache()
	a := api.New(repo, epochCache)
	r := chi.NewRouter()
	r.Mount("/api/v1", a.Router())
	return httptest.NewServer(r)
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{Jar: jar}
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any) *http.Response {
	t.Helper()
	var reqBody bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&reqBody).Encode(body))
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, &reqBody)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func registerAndLogin(t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()
	passphrase := "test-passphrase"

	resp := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/register", map[string]string{
		"passphrase": passphrase,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var reg api.RegisterResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&reg))
	require.NotEmpty(t, reg.SecretKey)

	// Explicit login flow with passphrase + secret key.
	resp = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/login", map[string]string{
		"passphrase": passphrase,
		"secret_key": reg.SecretKey,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return reg.SecretKey
}

func TestAuthRegisterAndLogin(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	secretKey := registerAndLogin(t, client, srv.URL)
	assert.NotEmpty(t, secretKey)
}

func TestLoginRejectsWrongPassphrase(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/register", map[string]string{
		"passphrase": "correct-passphrase",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var reg api.RegisterResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&reg))
	require.NotEmpty(t, reg.SecretKey)

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/login", map[string]string{
		"passphrase": "wrong-passphrase",
		"secret_key": reg.SecretKey,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRevealSecretKeyEndpointRemoved(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/reveal-secret-key", map[string]string{
		"passphrase": "irrelevant",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestTwoFactorFlow(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	passphrase := "test-passphrase"
	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/register", map[string]string{
		"passphrase": passphrase,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var reg api.RegisterResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&reg))

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/2fa/setup", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var setup api.SetupTwoFactorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&setup))
	require.NotEmpty(t, setup.Secret)
	require.NotEmpty(t, setup.OtpauthURL)

	code := totpCodeAt(t, setup.Secret, time.Now())
	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/2fa/enable", map[string]string{
		"code": code,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var status api.TwoFactorStatusResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&status))
	require.True(t, status.Enabled)

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/logout", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/login", map[string]string{
		"passphrase": passphrase,
		"secret_key": reg.SecretKey,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/login", map[string]string{
		"passphrase": passphrase,
		"secret_key": reg.SecretKey,
		"totp_code":  "000000",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/login", map[string]string{
		"passphrase": passphrase,
		"secret_key": reg.SecretKey,
		"totp_code":  totpCodeAt(t, setup.Secret, time.Now()),
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func totpCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	require.NoError(t, err)

	counter := uint64(at.Unix() / 30)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", binCode%1000000)
}

func TestCreateAndListVaults(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name":        "Personal",
		"description": "Primary vault",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))
	require.NotEmpty(t, create.VaultID)
	assert.NotZero(t, create.Epoch)

	resp = doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/vaults", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list api.ListVaultsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	require.NotEmpty(t, list.Vaults)
	assert.Equal(t, create.VaultID, list.Vaults[0].VaultID)
	assert.Equal(t, "Personal", list.Vaults[0].Name)
}

func TestVaultCRUD(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "Vault",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults/"+create.VaultID+"/items/item-1", map[string]any{
		"fields": map[string]string{"username": "admin", "password": "secret"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp = doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/vaults/"+create.VaultID+"/items/item-1", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var getItem api.GetItemResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getItem))
	assert.Equal(t, "item-1", getItem.ItemID)
	assert.Equal(t, "admin", getItem.Fields["username"])
	assert.Equal(t, "secret", getItem.Fields["password"])
}

func TestDeleteVault(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "ToDelete",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	resp = doJSON(t, client, http.MethodDelete, srv.URL+"/api/v1/vaults/"+create.VaultID, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults/"+create.VaultID+"/open", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestItemHistory(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	// Create vault
	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "HistoryVault",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	base := srv.URL + "/api/v1/vaults/" + create.VaultID

	// Put an item
	resp = doJSON(t, client, http.MethodPost, base+"/items/login-1", map[string]any{
		"fields": map[string]string{"username": "alice", "password": "pass1"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Update the item twice
	resp = doJSON(t, client, http.MethodPut, base+"/items/login-1", map[string]any{
		"fields": map[string]string{"username": "alice", "password": "pass2"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doJSON(t, client, http.MethodPut, base+"/items/login-1", map[string]any{
		"fields": map[string]string{"username": "bob", "password": "pass3"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Get history list
	resp = doJSON(t, client, http.MethodGet, base+"/items/login-1/history", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var histResp api.GetItemHistoryResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&histResp))
	assert.Equal(t, "login-1", histResp.ItemID)
	require.Len(t, histResp.History, 2)
	assert.Equal(t, uint64(2), histResp.History[0].Version) // newest first
	assert.Equal(t, uint64(1), histResp.History[1].Version)

	// Get specific historical version (version 1 = original)
	resp = doJSON(t, client, http.MethodGet, base+"/items/login-1/history/1", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var verResp api.GetHistoryVersionResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&verResp))
	assert.Equal(t, "login-1", verResp.ItemID)
	assert.Equal(t, uint64(1), verResp.Version)
	assert.Equal(t, "alice", verResp.Fields["username"])
	assert.Equal(t, "pass1", verResp.Fields["password"])

	// Get version 2 (first update)
	resp = doJSON(t, client, http.MethodGet, base+"/items/login-1/history/2", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&verResp))
	assert.Equal(t, uint64(2), verResp.Version)
	assert.Equal(t, "alice", verResp.Fields["username"])
	assert.Equal(t, "pass2", verResp.Fields["password"])

	// Current item should be the latest update
	resp = doJSON(t, client, http.MethodGet, base+"/items/login-1", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var getResp api.GetItemResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getResp))
	assert.Equal(t, "bob", getResp.Fields["username"])
	assert.Equal(t, "pass3", getResp.Fields["password"])
}
