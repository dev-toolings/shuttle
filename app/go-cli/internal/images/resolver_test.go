package images

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRegistryPaginationSelectsLatestStableAndDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		header := http.Header{}
		body := ""
		status := 200
		switch {
		case r.URL.Host == "auth.docker.io":
			if r.URL.Query().Get("scope") != "repository:oven/bun:pull" {
				t.Errorf("scope=%s", r.URL.RawQuery)
			}
			body = `{"token":"token"}`
		case r.Header.Get("Authorization") != "Bearer token":
			status = 401
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			if r.URL.Query().Get("last") == "first" {
				body = `{"tags":["1.12.0-alpine-rc1","2.0.0-alpine","1.11.0-alpine"]}`
			} else {
				body = `{"tags":["1.9.0-alpine"]}`
				header.Set("Link", `</v2/oven/bun/tags/list?n=1000&last=first>; rel="next"`)
			}
		case r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/manifests/1.11.0-alpine"):
			header.Set("Docker-Content-Digest", digest)
		default:
			status = 404
		}
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	got, err := (Resolver{Client: client}).Resolve(context.Background(), "oven/bun", "1", "-alpine")
	if err != nil || got != "oven/bun:1.11.0-alpine@"+digest {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestGHCRUsesRepositoryTokenAndManifest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	client := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		body := ""
		header := http.Header{}
		status := 200
		switch {
		case r.URL.Host != "ghcr.io":
			status = 404
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:astral-sh/uv:pull" {
				t.Errorf("scope=%s", r.URL.RawQuery)
			}
			body = `{"token":"token"}`
		case r.Header.Get("Authorization") != "Bearer token":
			status = 401
		case r.URL.Path == "/v2/astral-sh/uv/tags/list":
			body = `{"tags":["0.13.0-python3.11-trixie-slim","0.14.0-python3.11-trixie-slim-rc1"]}`
		case r.Method == http.MethodHead && r.URL.Path == "/v2/astral-sh/uv/manifests/0.13.0-python3.11-trixie-slim":
			header.Set("Docker-Content-Digest", digest)
		default:
			status = 404
		}
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	got, err := (Resolver{Client: client}).Resolve(context.Background(), "ghcr.io/astral-sh/uv", "0", "-python3.11-trixie-slim")
	if err != nil || got != "ghcr.io/astral-sh/uv:0.13.0-python3.11-trixie-slim@"+digest {
		t.Fatalf("got %q err %v", got, err)
	}
}
func TestPinnedReferenceRejectsInvalidTag(t *testing.T) {
	if ValidPinned("oven/bun", "oven/bun:$BAD@sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("accepted invalid tag")
	}
}
