package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}

func mapError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vault.ErrUnauthorized):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, vault.ErrStaleSession):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, vault.ErrSessionClosed):
		writeError(w, http.StatusInternalServerError, err.Error())
	case errors.Is(err, vault.ErrRollbackDetected):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, storage.ErrVaultNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, storage.ErrCASFailed):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
