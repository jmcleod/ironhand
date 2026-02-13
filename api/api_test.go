package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

type testCredentials struct {
	VaultID     string
	MemberID    string
	Credentials string // base64-encoded export blob
	Passphrase  string // export passphrase
	SecretKey   string
}

func createVault(t *testing.T, srv *httptest.Server, vaultID string) testCredentials {
	t.Helper()
	body := map[string]string{
		"vault_id":          vaultID,
		"passphrase":        "test-passphrase",
		"export_passphrase": "export-pass",
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/api/v1/vaults", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var result api.CreateVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Equal(t, vaultID, result.VaultID)
	require.NotEmpty(t, result.MemberID)
	require.NotEmpty(t, result.SecretKey)
	require.NotEmpty(t, result.Credentials)
	require.Equal(t, uint64(1), result.Epoch)

	return testCredentials{
		VaultID:     vaultID,
		MemberID:    result.MemberID,
		Credentials: result.Credentials,
		Passphrase:  "export-pass",
		SecretKey:   result.SecretKey,
	}
}

func authRequest(t *testing.T, method, url string, body any, creds testCredentials) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req, err := http.NewRequest(method, url, &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Credentials", creds.Credentials)
	req.Header.Set("X-Passphrase", creds.Passphrase)
	return req
}

func TestCreateVault(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	creds := createVault(t, srv, "test-vault")
	assert.Equal(t, "test-vault", creds.VaultID)
	assert.NotEmpty(t, creds.MemberID)
}

func TestCreateVault_MissingFields(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	tests := []struct {
		name string
		body map[string]string
	}{
		{"missing vault_id", map[string]string{"passphrase": "p", "export_passphrase": "e"}},
		{"missing passphrase", map[string]string{"vault_id": "v", "export_passphrase": "e"}},
		{"missing export_passphrase", map[string]string{"vault_id": "v", "passphrase": "p"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.body)
			resp, err := http.Post(srv.URL+"/api/v1/vaults", "application/json", bytes.NewReader(b))
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestOpenVault(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	creds := createVault(t, srv, "open-test")
	req := authRequest(t, http.MethodPost, srv.URL+"/api/v1/vaults/open-test/open", nil, creds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result api.OpenVaultResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, "open-test", result.VaultID)
	assert.Equal(t, creds.MemberID, result.MemberID)
	assert.Equal(t, uint64(1), result.Epoch)
}

func TestItemCRUD(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	creds := createVault(t, srv, "crud-vault")
	plaintext := []byte("hello secret world")
	encoded := base64.StdEncoding.EncodeToString(plaintext)

	// PUT item
	putBody := map[string]string{"data": encoded, "content_type": "text/plain"}
	req := authRequest(t, http.MethodPost, srv.URL+"/api/v1/vaults/crud-vault/items/secret-1", putBody, creds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// GET item
	req = authRequest(t, http.MethodGet, srv.URL+"/api/v1/vaults/crud-vault/items/secret-1", nil, creds)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var getResult api.GetItemResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getResult))
	assert.Equal(t, "secret-1", getResult.ItemID)
	decoded, err := base64.StdEncoding.DecodeString(getResult.Data)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decoded)

	// LIST items
	req = authRequest(t, http.MethodGet, srv.URL+"/api/v1/vaults/crud-vault/items", nil, creds)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var listResult api.ListItemsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResult))
	assert.Contains(t, listResult.Items, "secret-1")

	// UPDATE item
	newPlaintext := []byte("updated secret")
	newEncoded := base64.StdEncoding.EncodeToString(newPlaintext)
	updateBody := map[string]string{"data": newEncoded}
	req = authRequest(t, http.MethodPut, srv.URL+"/api/v1/vaults/crud-vault/items/secret-1", updateBody, creds)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// GET updated item
	req = authRequest(t, http.MethodGet, srv.URL+"/api/v1/vaults/crud-vault/items/secret-1", nil, creds)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&getResult))
	decoded, err = base64.StdEncoding.DecodeString(getResult.Data)
	require.NoError(t, err)
	assert.Equal(t, newPlaintext, decoded)

	// DELETE item
	req = authRequest(t, http.MethodDelete, srv.URL+"/api/v1/vaults/crud-vault/items/secret-1", nil, creds)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// GET deleted item - should 404
	req = authRequest(t, http.MethodGet, srv.URL+"/api/v1/vaults/crud-vault/items/secret-1", nil, creds)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestGetItem_NotFound(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	creds := createVault(t, srv, "notfound-vault")
	req := authRequest(t, http.MethodGet, srv.URL+"/api/v1/vaults/notfound-vault/items/nonexistent", nil, creds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAuthFailure_MissingHeaders(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	createVault(t, srv, "auth-vault")

	// No auth headers at all
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/vaults/auth-vault/items", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthFailure_BadCredentials(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	createVault(t, srv, "badcreds-vault")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/vaults/badcreds-vault/items", nil)
	req.Header.Set("X-Credentials", base64.StdEncoding.EncodeToString([]byte("garbage")))
	req.Header.Set("X-Passphrase", "wrong")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestVaultNotFound(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	// Create a vault to get valid credentials, then try to open a different vault
	creds := createVault(t, srv, "existing-vault")
	req := authRequest(t, http.MethodPost, srv.URL+"/api/v1/vaults/nonexistent-vault/open", nil, creds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAddAndRevokeMember(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	ownerCreds := createVault(t, srv, "member-vault")

	// Create credentials for the new member (just need a public key)
	newMemberCreds, err := vault.NewCredentials("member-pass")
	require.NoError(t, err)
	defer newMemberCreds.Destroy()

	pubKey := newMemberCreds.PublicKey()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	// Add member
	addBody := map[string]string{
		"member_id": newMemberCreds.MemberID(),
		"pub_key":   pubKeyB64,
		"role":      "writer",
	}
	req := authRequest(t, http.MethodPost, srv.URL+"/api/v1/vaults/member-vault/members", addBody, ownerCreds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var addResult api.AddMemberResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&addResult))
	assert.Equal(t, uint64(2), addResult.Epoch)

	// Need to re-export owner creds since epoch rotated — the existing export still works
	// because ImportCredentials gives back valid key material; the vault.Open re-derives KEK

	// Revoke member
	req = authRequest(t, http.MethodDelete,
		srv.URL+"/api/v1/vaults/member-vault/members/"+newMemberCreds.MemberID(),
		nil, ownerCreds)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var revokeResult api.AddMemberResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&revokeResult))
	assert.Equal(t, uint64(3), revokeResult.Epoch)
}

func TestAddMember_MissingFields(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	creds := createVault(t, srv, "validate-vault")

	tests := []struct {
		name string
		body map[string]string
	}{
		{"missing member_id", map[string]string{"pub_key": "AAAA", "role": "writer"}},
		{"missing pub_key", map[string]string{"member_id": "bob", "role": "writer"}},
		{"missing role", map[string]string{"member_id": "bob", "pub_key": "AAAA"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := authRequest(t, http.MethodPost, srv.URL+"/api/v1/vaults/validate-vault/members", tt.body, creds)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestPutItem_InvalidBase64(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	creds := createVault(t, srv, "b64-vault")
	putBody := map[string]string{"data": "not-valid-base64!!!"}
	req := authRequest(t, http.MethodPost, srv.URL+"/api/v1/vaults/b64-vault/items/item1", putBody, creds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestListItems_EmptyVault(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	creds := createVault(t, srv, "empty-vault")
	req := authRequest(t, http.MethodGet, srv.URL+"/api/v1/vaults/empty-vault/items", nil, creds)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result api.ListItemsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Empty(t, result.Items)
	// Ensure it's an empty array, not null
	raw, _ := json.Marshal(result)
	assert.Contains(t, string(raw), `"items":[]`)
}

func TestOpenAPI(t *testing.T) {
	srv := setupServer(t)
	defer srv.Close()

	t.Run("OpenAPI YAML", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/api/v1/openapi.yaml")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/yaml", resp.Header.Get("Content-Type"))
	})

	t.Run("Swagger UI", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/api/v1/docs")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Redoc", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/api/v1/redoc")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
