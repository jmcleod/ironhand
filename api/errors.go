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
	if _, ok := errors.AsType[vault.UnauthorizedError](err); ok {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if _, ok := errors.AsType[vault.StaleSessionError](err); ok {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, ok := errors.AsType[vault.SessionClosedError](err); ok {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, ok := errors.AsType[vault.RollbackError](err); ok {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, ok := errors.AsType[vault.ValidationError](err); ok {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := errors.AsType[vault.VaultExistsError](err); ok {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	switch {
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
