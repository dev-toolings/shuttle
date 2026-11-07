// Package images resolves official image releases to immutable registry identities.
package images

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var validTagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var tagPattern = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$`)

// Resolver speaks the registry v2 token, tag listing and manifest APIs.
type Resolver struct{ Client *http.Client }

// Resolve chooses the highest stable numeric release in the requested major and
// variant, then pins its manifest. An empty major permits the latest major.
func (r Resolver) Resolve(ctx context.Context, image, major, suffix string) (string, error) {
	return r.resolve(ctx, image, major, suffix, "")
}

// ResolveTag resolves a declared mutable tag using the same registry client.
func (r Resolver) ResolveTag(ctx context.Context, image, tag string) (string, error) {
	if !validTagPattern.MatchString(tag) {
		return "", fmt.Errorf("invalid image tag")
	}
	reference, err := r.resolve(ctx, image, "", "", tag)
	if err != nil {
		return "", err
	}
	return strings.SplitN(reference, "@", 2)[1], nil
}

func (r Resolver) resolve(ctx context.Context, image, major, suffix, requestedTag string) (string, error) {
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	host, repo := "registry-1.docker.io", image
	if strings.HasPrefix(image, "ghcr.io/") {
		host, repo = "ghcr.io", strings.TrimPrefix(image, "ghcr.io/")
	} else if !strings.Contains(image, "/") {
		repo = "library/" + image
	}
	fail := func(err error) (string, error) { return "", fmt.Errorf("cannot resolve image %s: %w", image, err) }
	tokenURL := "https://auth.docker.io/token?service=registry.docker.io&scope=" + url.QueryEscape("repository:"+repo+":pull")
	if host == "ghcr.io" {
		tokenURL = "https://ghcr.io/token?scope=" + url.QueryEscape("repository:"+repo+":pull")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return fail(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fail(fmt.Errorf("token request returned %s", resp.Status))
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token)
	resp.Body.Close()
	if err != nil {
		return fail(err)
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" {
		return fail(fmt.Errorf("registry returned an empty token"))
	}
	base := "https://" + host + "/v2/" + repo
	get := func(method, address string) (*http.Response, error) {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.Host != host || !strings.HasPrefix(u.Path, "/v2/"+repo+"/") {
			return nil, fmt.Errorf("invalid registry pagination URL")
		}
		req, err := http.NewRequestWithContext(ctx, method, address, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("registry returned %s", resp.Status)
		}
		return resp, nil
	}
	next := base + "/tags/list?n=1000"
	best := requestedTag
	if requestedTag != "" {
		next = ""
	}
	bestVersion := [3]uint64{}
	seen := map[string]bool{}
	for next != "" {
		if seen[next] {
			return fail(fmt.Errorf("registry repeated a tag page"))
		}
		seen[next] = true
		resp, err := get(http.MethodGet, next)
		if err != nil {
			return fail(err)
		}
		var page struct {
			Tags []string `json:"tags"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&page)
		link := resp.Header.Get("Link")
		resp.Body.Close()
		if err != nil {
			return fail(err)
		}
		for _, tag := range page.Tags {
			m := tagPattern.FindStringSubmatch(tag)
			if m == nil || m[4] != suffix || (major != "" && m[1] != major) {
				continue
			}
			var v [3]uint64
			valid := true
			for i := 0; i < 3; i++ {
				v[i], err = strconv.ParseUint(m[i+1], 10, 64)
				if err != nil {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			if best == "" || v[0] > bestVersion[0] || (v[0] == bestVersion[0] && (v[1] > bestVersion[1] || (v[1] == bestVersion[1] && v[2] > bestVersion[2]))) {
				best, bestVersion = tag, v
			}
		}
		next = ""
		if link != "" {
			left := strings.Index(link, "<")
			right := strings.Index(link, ">")
			if left < 0 || right <= left || !strings.Contains(link[right+1:], `rel="next"`) {
				return fail(fmt.Errorf("invalid registry pagination link"))
			}
			ref, err := url.Parse(link[left+1 : right])
			if err != nil {
				return fail(err)
			}
			origin, _ := url.Parse(base + "/tags/list")
			next = origin.ResolveReference(ref).String()
		}
	}
	if best == "" {
		return fail(fmt.Errorf("no stable release for major %s and variant %q", major, suffix))
	}
	resp, err = get(http.MethodHead, base+"/manifests/"+url.PathEscape(best))
	if err != nil {
		return fail(err)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	resp.Body.Close()
	if !digestPattern.MatchString(digest) {
		return fail(fmt.Errorf("registry returned an invalid digest"))
	}
	return image + ":" + best + "@" + digest, nil
}

// ValidPinned confirms the exact immutable reference, including its repository.
func ValidPinned(image, reference string) bool {
	prefix := image + ":"
	if !strings.HasPrefix(reference, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(reference, prefix), "@")
	return len(parts) == 2 && validTagPattern.MatchString(parts[0]) && digestPattern.MatchString(parts[1])
}
