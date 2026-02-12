package web

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
)

//go:embed dist/*
var content embed.FS

func Handler() (http.Handler, error) {
	fsys, err := fs.Sub(content, "dist")
	if err != nil {
		return nil, fmt.Errorf("loading embedded web assets: %w", err)
	}
	return http.FileServer(http.FS(fsys)), nil
}
