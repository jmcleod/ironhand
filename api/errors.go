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
