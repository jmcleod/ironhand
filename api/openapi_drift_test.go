package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// openAPIDoc is the minimal structure we need from the spec.
type openAPIDoc struct {
	Paths map[string]map[string]interface{} `yaml:"paths"`
}

// TestOpenAPIDrift walks the chi router and compares the registered routes
// against the OpenAPI spec embedded in api/openapi.yaml. It fails if any
// routes are undocumented or if the spec contains stale paths.
func TestOpenAPIDrift(t *testing.T) {
	// Parse OpenAPI spec.
	var doc openAPIDoc
	if err := yaml.Unmarshal(openapiSpec, &doc); err != nil {
		t.Fatalf("failed to parse openapi.yaml: %v", err)
	}

	// Collect {METHOD PATH} pairs from the spec.
	specRoutes := make(map[string]bool)
	for path, methods := range doc.Paths {
		for method := range methods {
			method = strings.ToUpper(method)
			// Skip OpenAPI extension keys (x-...) and parameters.
			if strings.HasPrefix(strings.ToLower(method), "x-") || method == "PARAMETERS" {
				continue
			}
			specRoutes[method+" "+path] = true
		}
	}

	// Create a zero-value API and walk its router.
	// Router() only registers routes — it never invokes handlers,
	// so nil dependencies are fine.
	a := &API{}
	router := a.Router()

	chiRoutes := make(map[string]bool)
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// Normalise trailing slashes for consistent comparison.
		route = strings.TrimRight(route, "/")
		if route == "" {
			route = "/"
		}

		// Skip utility/doc routes that aren't part of the API contract.
		if route == "/openapi.yaml" ||
			strings.HasPrefix(route, "/docs") ||
			strings.HasPrefix(route, "/redoc") {
			return nil
		}

		// chi uses {param} which matches OpenAPI's {param} format.
		chiRoutes[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk failed: %v", err)
	}

	// Find undocumented routes (in chi but not in spec).
	var undocumented []string
	for route := range chiRoutes {
		if !specRoutes[route] {
			undocumented = append(undocumented, route)
		}
	}
	sort.Strings(undocumented)

	// Find stale spec entries (in spec but not in chi).
	var stale []string
	for route := range specRoutes {
		if !chiRoutes[route] {
			stale = append(stale, route)
		}
	}
	sort.Strings(stale)

	if len(undocumented) > 0 {
		t.Errorf("routes registered in Router() but missing from openapi.yaml:\n%s",
			formatRouteList(undocumented))
	}

	if len(stale) > 0 {
		t.Errorf("routes in openapi.yaml but not registered in Router():\n%s",
			formatRouteList(stale))
	}

	if len(undocumented) == 0 && len(stale) == 0 {
		t.Logf("✓ OpenAPI spec and chi router are in sync (%d routes)", len(chiRoutes))
	}
}

func formatRouteList(routes []string) string {
	var b strings.Builder
	for _, r := range routes {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	return b.String()
}
