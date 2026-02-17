package api_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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

	resp = doJSON(t, client, http.MethodGet, srv.URL+"/api/v1/vaults/"+create.VaultID+"/items", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list api.ListItemsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	require.Len(t, list.Items, 1)
	assert.Equal(t, "item-1", list.Items[0].ItemID)
	assert.Equal(t, "item-1", list.Items[0].Name)
	assert.Equal(t, "custom", list.Items[0].Type)
}

func TestAuditLogTracksItemAccessAndModification(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "AuditVault",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	base := srv.URL + "/api/v1/vaults/" + create.VaultID
	itemID := "login-1"

	resp = doJSON(t, client, http.MethodPost, base+"/items/"+itemID, map[string]any{
		"fields": map[string]string{"username": "alice", "password": "s3cret"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp = doJSON(t, client, http.MethodGet, base+"/items/"+itemID, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doJSON(t, client, http.MethodPut, base+"/items/"+itemID, map[string]any{
		"fields": map[string]string{"username": "alice", "password": "new-pass"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doJSON(t, client, http.MethodDelete, base+"/items/"+itemID, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doJSON(t, client, http.MethodGet, base+"/audit", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var auditResp api.ListAuditLogsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&auditResp))
	require.GreaterOrEqual(t, len(auditResp.Entries), 4)

	actions := make(map[string]bool)
	for _, e := range auditResp.Entries {
		if e.ItemID == itemID {
			actions[e.Action] = true
			assert.NotEmpty(t, e.MemberID)
			assert.NotEmpty(t, e.CreatedAt)
		}
	}
	assert.True(t, actions["item_created"])
	assert.True(t, actions["item_accessed"])
	assert.True(t, actions["item_updated"])
	assert.True(t, actions["item_deleted"])
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

func TestLoginRateLimiting(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	// Register an account first.
	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/register", map[string]string{
		"passphrase": "rate-limit-test-passphrase",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var reg api.RegisterResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&reg))

	// Send maxFailures wrong-passphrase attempts.
	for i := 0; i < 5; i++ {
		resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/login", map[string]string{
			"passphrase": "wrong-passphrase!!!",
			"secret_key": reg.SecretKey,
		})
		resp.Body.Close()
		// These should return 401.
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}

	// The next attempt (even with correct credentials) should be rate-limited.
	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/login", map[string]string{
		"passphrase": "rate-limit-test-passphrase",
		"secret_key": reg.SecretKey,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}

func TestAttachmentRoundTrip(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	// Create vault.
	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "AttVault",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	// Create item with attachment.
	rawContent := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake key content\n-----END OPENSSH PRIVATE KEY-----\n")
	b64Content := base64.StdEncoding.EncodeToString(rawContent)
	metaJSON := `{"content_type":"application/octet-stream","size":` + fmt.Sprint(len(rawContent)) + `}`

	base := srv.URL + "/api/v1/vaults/" + create.VaultID
	resp = doJSON(t, client, http.MethodPost, base+"/items/ssh-key", map[string]any{
		"fields": map[string]string{
			"_name":           "My SSH Key",
			"_type":           "custom",
			"_att.id_rsa":     b64Content,
			"_attmeta.id_rsa": metaJSON,
			"note":            "server key",
		},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Get item back and verify round-trip.
	resp = doJSON(t, client, http.MethodGet, base+"/items/ssh-key", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var getResp api.GetItemResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getResp))

	// Attachment content should round-trip through base64.
	decoded, err := base64.StdEncoding.DecodeString(getResp.Fields["_att.id_rsa"])
	require.NoError(t, err)
	assert.Equal(t, rawContent, decoded)

	// Metadata should be a plain string (not base64-encoded).
	assert.Equal(t, metaJSON, getResp.Fields["_attmeta.id_rsa"])

	// Regular text fields should be unchanged.
	assert.Equal(t, "My SSH Key", getResp.Fields["_name"])
	assert.Equal(t, "server key", getResp.Fields["note"])
}

func TestAttachmentInvalidBase64(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "V",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	// Send invalid base64 in attachment field.
	base := srv.URL + "/api/v1/vaults/" + create.VaultID
	resp = doJSON(t, client, http.MethodPost, base+"/items/bad-att", map[string]any{
		"fields": map[string]string{
			"_att.file.bin": "!!!not-valid-base64!!!",
		},
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAttachmentTooLarge(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "V",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	// Create data that exceeds MaxAttachmentSize (768 KiB).
	oversized := make([]byte, 769*1024)
	b64 := base64.StdEncoding.EncodeToString(oversized)

	base := srv.URL + "/api/v1/vaults/" + create.VaultID
	resp = doJSON(t, client, http.MethodPost, base+"/items/big-att", map[string]any{
		"fields": map[string]string{
			"_att.huge.bin": b64,
		},
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestRegisterRejectsShortPassphrase(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/auth/register", map[string]string{
		"passphrase": "short",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "at least")
}

func TestExportAndImportVault(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)

	registerAndLogin(t, client, srv.URL)

	// Create a vault.
	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name":        "ExportTest",
		"description": "vault for export testing",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	base := srv.URL + "/api/v1/vaults/" + create.VaultID

	// Add a plain item.
	resp = doJSON(t, client, http.MethodPost, base+"/items/item-a", map[string]any{
		"fields": map[string]string{"_name": "Login A", "_type": "login", "username": "alice", "password": "s3cret"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Add an item with attachment.
	rawContent := []byte("ssh-rsa AAAA test-key")
	b64Content := base64.StdEncoding.EncodeToString(rawContent)
	resp = doJSON(t, client, http.MethodPost, base+"/items/item-b", map[string]any{
		"fields": map[string]string{
			"_name":           "With Attachment",
			"_type":           "custom",
			"_att.id_rsa":     b64Content,
			"_attmeta.id_rsa": `{"content_type":"application/octet-stream","size":21}`,
		},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Export the vault.
	exportPassphrase := "export-test-passphrase-long-enough"
	resp = doJSON(t, client, http.MethodPost, base+"/export", map[string]string{
		"passphrase": exportPassphrase,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))

	backupData, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.True(t, len(backupData) > 17) // version + salt + ciphertext

	// Create a second vault to import into.
	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{
		"name": "ImportTarget",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var create2 api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create2))

	// Import into the second vault using multipart form.
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "backup.ironhand-backup")
	require.NoError(t, err)
	_, err = part.Write(backupData)
	require.NoError(t, err)
	require.NoError(t, writer.WriteField("passphrase", exportPassphrase))
	require.NoError(t, writer.Close())

	base2 := srv.URL + "/api/v1/vaults/" + create2.VaultID
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base2+"/import", &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var importResp api.ImportVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&importResp))
	assert.Equal(t, 2, importResp.ImportedCount)

	// Verify items were imported by listing them.
	resp = doJSON(t, client, http.MethodGet, base2+"/items", nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list api.ListItemsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	assert.Len(t, list.Items, 2)

	// Verify attachment data round-trips correctly.
	var attachmentItemID string
	for _, item := range list.Items {
		if item.Name == "With Attachment" {
			attachmentItemID = item.ItemID
		}
	}
	require.NotEmpty(t, attachmentItemID)

	resp = doJSON(t, client, http.MethodGet, base2+"/items/"+attachmentItemID, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var getResp api.GetItemResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getResp))
	decoded, err := base64.StdEncoding.DecodeString(getResp.Fields["_att.id_rsa"])
	require.NoError(t, err)
	assert.Equal(t, rawContent, decoded)
}

func TestExportRequiresPassphrase(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)
	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{"name": "V"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	resp = doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults/"+create.VaultID+"/export", map[string]string{
		"passphrase": "",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestImportWrongPassphraseFails(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()
	client := newClient(t)
	registerAndLogin(t, client, srv.URL)

	resp := doJSON(t, client, http.MethodPost, srv.URL+"/api/v1/vaults", map[string]string{"name": "V"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var create api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&create))

	base := srv.URL + "/api/v1/vaults/" + create.VaultID

	// Add an item and export.
	resp = doJSON(t, client, http.MethodPost, base+"/items/item-1", map[string]any{
		"fields": map[string]string{"_name": "Test", "_type": "note", "content": "hello"},
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp = doJSON(t, client, http.MethodPost, base+"/export", map[string]string{
		"passphrase": "correct-passphrase-long",
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	backupData, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Try to import with wrong passphrase.
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "backup.ironhand-backup")
	require.NoError(t, err)
	_, err = part.Write(backupData)
	require.NoError(t, err)
	require.NoError(t, writer.WriteField("passphrase", "wrong-passphrase-long"))
	require.NoError(t, writer.Close())

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/import", &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
