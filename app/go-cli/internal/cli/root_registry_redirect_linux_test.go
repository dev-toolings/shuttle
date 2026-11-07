//go:build linux

package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newRootRegistryRedirectServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.Start()
	return server
}

func setupRootRegistryRedirectSweep(t *testing.T, handler http.Handler) (string, string, string, string) {
	t.Helper()
	server := newRootRegistryRedirectServer(t, handler)
	originalURL := rootRegistryBaseURL
	originalKeep := rootRegistryKeepRead
	originalVolume := rootRegistryVolumeMeasure
	originalSole := rootRegistrySoleOperation
	originalLog := rootRegistryLog
	keep := sweepDigest('a')
	rootRegistryBaseURL = server.URL
	rootRegistryKeepRead = func(string, string, string) (map[string]bool, error) {
		return map[string]bool{keep: true}, nil
	}
	rootRegistryVolumeMeasure = func() (int64, error) { return 0, nil }
	rootRegistrySoleOperation = func(_ string, fn func() error) error { return fn() }
	rootRegistryLog = func(string, ...any) {}
	t.Cleanup(func() {
		server.Close()
		rootRegistryBaseURL = originalURL
		rootRegistryKeepRead = originalKeep
		rootRegistryVolumeMeasure = originalVolume
		rootRegistrySoleOperation = originalSole
		rootRegistryLog = originalLog
	})

	root := t.TempDir()
	current := filepath.Join(root, "app", "current.yml")
	previous := filepath.Join(root, "app", "previous.yml")
	writeStack(t, current, registryImage("app-web", keep))
	return root, current, previous, keep
}

func TestRootRegistryRedirectDeleteIsNeverFollowed(t *testing.T) {
	var redirectedRequests, deleteRequests atomic.Int32
	redirectTarget := newRootRegistryRedirectServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer redirectTarget.Close()
	var keep string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(registryCatalog{Repositories: []string{"app-web"}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tags/list"):
			_ = json.NewEncoder(w).Encode(registryTags{Tags: []string{"release", "old"}})
		case r.Method == http.MethodHead:
			if path.Base(r.URL.Path) == "release" {
				w.Header().Set("Docker-Content-Digest", keep)
			} else {
				w.Header().Set("Docker-Content-Digest", sweepDigest('b'))
			}
		case r.Method == http.MethodDelete:
			deleteRequests.Add(1)
			http.Redirect(w, r, redirectTarget.URL+"/manifest", http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	root, current, previous, retained := setupRootRegistryRedirectSweep(t, handler)
	keep = retained
	collected := false
	err := maintainRootRegistry("app", current, previous, 0, func() error {
		collected = true
		return nil
	}, root, true, "redirect-delete")
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("maintainRootRegistry error = %v, want HTTP 307", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Errorf("redirect target requests = %d, want 0", got)
	}
	if got := deleteRequests.Load(); got != 1 {
		t.Errorf("registry DELETE requests = %d, want 1 superseded manifest", got)
	}
	if collected {
		t.Error("collector ran after the redirected manifest deletion failed")
	}
}

func TestRootRegistryRedirectCatalogIsNeverFollowed(t *testing.T) {
	var redirectedRequests, deleteRequests atomic.Int32
	redirectTarget := newRootRegistryRedirectServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v2/_catalog" {
			http.Redirect(w, r, redirectTarget.URL+"/catalog", http.StatusFound)
			return
		}
		if r.Method == http.MethodDelete {
			deleteRequests.Add(1)
		}
		w.WriteHeader(http.StatusNotFound)
	})
	root, current, previous, _ := setupRootRegistryRedirectSweep(t, handler)
	err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, true, "redirect-catalog")
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("maintainRootRegistry error = %v, want HTTP 302", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Errorf("redirect target requests = %d, want 0", got)
	}
	if got := deleteRequests.Load(); got != 0 {
		t.Errorf("registry DELETE requests = %d, want 0", got)
	}
}

func TestRootRegistryRedirectHeadIsNeverFollowed(t *testing.T) {
	var redirectedRequests, deleteRequests atomic.Int32
	redirectTarget := newRootRegistryRedirectServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		w.Header().Set("Docker-Content-Digest", sweepDigest('b'))
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(registryCatalog{Repositories: []string{"app-web"}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tags/list"):
			_ = json.NewEncoder(w).Encode(registryTags{Tags: []string{"old"}})
		case r.Method == http.MethodHead:
			http.Redirect(w, r, redirectTarget.URL+"/manifest", http.StatusTemporaryRedirect)
		case r.Method == http.MethodDelete:
			deleteRequests.Add(1)
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	root, current, previous, _ := setupRootRegistryRedirectSweep(t, handler)
	err := maintainRootRegistry("app", current, previous, 0, func() error { return nil }, root, true, "redirect-head")
	if err == nil {
		t.Fatal("maintainRootRegistry succeeded after a redirected HEAD response")
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Errorf("redirect target requests = %d, want 0", got)
	}
	if got := deleteRequests.Load(); got != 0 {
		t.Errorf("registry DELETE requests = %d, want 0", got)
	}
}

func TestRootRegistryRedirectHealthProbeIsNeverFollowed(t *testing.T) {
	var redirectedRequests atomic.Int32
	redirectTarget := newRootRegistryRedirectServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/health", http.StatusTemporaryRedirect)
	})
	setupRootRegistryRedirectSweep(t, handler)
	err := probeRootRegistryV2(time.Second)
	if err == nil {
		t.Fatal("probeRootRegistryV2 succeeded after a redirected response")
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Errorf("redirect target requests = %d, want 0", got)
	}
}

func TestRootRegistryHTTPClientsRefuseRedirects(t *testing.T) {
	source, err := os.ReadFile("root_helper_linux.go")
	if err != nil {
		t.Fatalf("read root helper source: %v", err)
	}
	text := string(source)
	if got := strings.Count(text, "&http.Client{"); got != 1 {
		t.Fatalf("http.Client literals = %d, want exactly one shared constructor", got)
	}
	start := strings.Index(text, "func rootLoopbackRegistryClient(")
	if start < 0 {
		t.Fatal("rootLoopbackRegistryClient constructor was not found")
	}
	endOffset := strings.Index(text[start:], "\n}")
	if endOffset < 0 {
		t.Fatal("rootLoopbackRegistryClient function end was not found")
	}
	end := start + endOffset
	constructor := text[start:end]
	literal := strings.Index(text, "&http.Client{")
	if literal < start || literal >= end {
		t.Fatal("the only http.Client literal is outside rootLoopbackRegistryClient")
	}
	if !strings.Contains(constructor, "CheckRedirect:") || !strings.Contains(constructor, "http.ErrUseLastResponse") {
		t.Fatal("rootLoopbackRegistryClient must refuse redirects with http.ErrUseLastResponse")
	}
}
