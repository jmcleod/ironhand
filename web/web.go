package web

import (
	"embed"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist/*
var content embed.FS

// NonceFunc returns the per-request CSP nonce from the request context.
// When nil, no nonce meta tag is injected into the HTML.
type NonceFunc func(r *http.Request) string

// Handler returns an http.Handler that serves the embedded SPA assets.
//
// When nonceFunc is provided, HTML responses have a
// <meta name="csp-nonce" content="..."> tag injected before </head> so that
// client-side code can read the per-request nonce and apply it to dynamically
// created <style> elements.
func Handler(nonceFunc NonceFunc) (http.Handler, error) {
	fsys, err := fs.Sub(content, "dist")
	if err != nil {
		return nil, fmt.Errorf("loading embedded web assets: %w", err)
	}

	// Read index.html once at init for nonce injection.
	indexBytes, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		return nil, fmt.Errorf("reading embedded index.html: %w", err)
	}
	indexTemplate := string(indexBytes)

	static := http.FileServer(http.FS(fsys))

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		if nonceFunc != nil {
			if nonce := nonceFunc(r); nonce != "" {
				nonceTag := `<meta name="csp-nonce" content="` + html.EscapeString(nonce) + `">`
				body := strings.Replace(indexTemplate, "</head>", nonceTag+"\n  </head>", 1)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write([]byte(body))
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexBytes)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			serveIndex(w, r)
			return
		}

		cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanPath == "." {
			serveIndex(w, r)
			return
		}

		if _, err := fs.Stat(fsys, cleanPath); err == nil {
			static.ServeHTTP(w, r)
			return
		}

		// BrowserRouter deep-link fallback.
		serveIndex(w, r)
	}), nil
}
