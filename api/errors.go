package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}

// Body size limits (bytes) for JSON request payloads.
// Each limit is set to the smallest reasonable cap for the endpoint's DTO.
const (
	// maxAuthBodySize covers login, register, 2FA, WebAuthn login/register.
	// These bodies contain credentials (passphrase, secret_key, totp_code)
	// and are very small.
	maxAuthBodySize int64 = 4 * 1024 // 4 KiB

	// maxItemBodySize covers put/update item requests whose Fields map
	// may include base64-encoded attachments (up to 768 KiB decoded each).
	maxItemBodySize int64 = 4 * 1024 * 1024 // 4 MiB

	// maxSmallBodySize covers vault create, member add, PKI operations,
	// export passphrase, and other small structured requests.
	maxSmallBodySize int64 = 64 * 1024 // 64 KiB

	// maxWebAuthnBodySize covers WebAuthn protocol messages (assertions,
	// attestations) which are moderately sized due to CBOR payloads.
	maxWebAuthnBodySize int64 = 64 * 1024 // 64 KiB
)

// decodeJSON reads a size-limited JSON request body into a value of type T.
// It enforces http.MaxBytesReader to cap the body size and
// DisallowUnknownFields to reject unexpected keys. Returns false and
// writes a 400 error if decoding fails.
func decodeJSON[T any](w http.ResponseWriter, r *http.Request, maxBytes int64) (T, bool) {
	var v T
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		// Distinguish body-too-large from malformed JSON.
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid request body")
		}
		return v, false
	}
	return v, true
}

// writeInternalError logs the full error detail server-side with a unique
// correlation ID, then returns a generic error message to the client along
// with the correlation ID so operators can match user reports to log entries.
func writeInternalError(w http.ResponseWriter, msg string, err error) {
	corrID := uuid.New()
	slog.Error(msg,
		slog.String("correlation_id", corrID),
		slog.String("error", err.Error()),
	)
	writeJSON(w, http.StatusInternalServerError, ErrorResponse{
		Error:         msg,
		CorrelationID: corrID,
	})
}

func mapError(w http.ResponseWriter, err error) {
	if _, ok := errors.AsType[vault.UnauthorizedError](err); ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, ok := errors.AsType[vault.StaleSessionError](err); ok {
		writeError(w, http.StatusConflict, "stale session")
		return
	}
	if _, ok := errors.AsType[vault.SessionClosedError](err); ok {
		writeInternalError(w, "internal server error", err)
		return
	}
	if _, ok := errors.AsType[vault.RollbackError](err); ok {
		writeError(w, http.StatusConflict, "rollback detected")
		return
	}
	if ve, ok := errors.AsType[vault.ValidationError](err); ok {
		// ValidationError messages describe user-input violations (e.g.
		// "field X is required") and are safe to return to the client.
		writeError(w, http.StatusBadRequest, ve.Error())
		return
	}
	if _, ok := errors.AsType[vault.VaultExistsError](err); ok {
		writeError(w, http.StatusConflict, "vault already exists")
		return
	}

	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, storage.ErrVaultNotFound):
		writeError(w, http.StatusNotFound, "vault not found")
	case errors.Is(err, storage.ErrCASFailed):
		writeError(w, http.StatusConflict, "conflict")
	default:
		writeInternalError(w, "internal server error", err)
	}
}
