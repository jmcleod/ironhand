package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

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
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if _, ok := errors.AsType[vault.RollbackError](err); ok {
		writeError(w, http.StatusConflict, "rollback detected")
		return
	}
	if _, ok := errors.AsType[vault.ValidationError](err); ok {
		writeError(w, http.StatusBadRequest, err.Error())
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
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}
