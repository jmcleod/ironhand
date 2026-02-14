package web

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist/*
var content embed.FS

func Handler() (http.Handler, error) {
	fsys, err := fs.Sub(content, "dist")
	if err != nil {
		return nil, fmt.Errorf("loading embedded web assets: %w", err)
	}
	static := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFileFS(w, r, fsys, "index.html")
			return
		}

		cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanPath == "." {
			http.ServeFileFS(w, r, fsys, "index.html")
			return
		}

		if _, err := fs.Stat(fsys, cleanPath); err == nil {
			static.ServeHTTP(w, r)
			return
		}

		// BrowserRouter deep-link fallback.
		http.ServeFileFS(w, r, fsys, "index.html")
	}), nil
}
