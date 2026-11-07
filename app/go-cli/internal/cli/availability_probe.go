package cli

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

type availabilityProbeResult struct {
	Samples      int
	Failures     int
	FirstFailure string
}

type availabilityProbe struct {
	url      string
	gated    bool
	interval time.Duration
	client   *http.Client
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	result   availabilityProbeResult
}

func startAvailabilityProbe(url string, intervalMS int, gated bool) *availabilityProbe {
	if url == "" {
		return nil
	}
	probe := newAvailabilityProbe(url, intervalMS, gated)
	go probe.run()
	return probe
}

func newAvailabilityProbe(url string, intervalMS int, gated bool) *availabilityProbe {
	if intervalMS <= 0 {
		intervalMS = 250
	}
	return &availabilityProbe{
		url:      url,
		gated:    gated,
		interval: time.Duration(intervalMS) * time.Millisecond,
		client:   &http.Client{Timeout: 2 * time.Second},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (probe *availabilityProbe) run() {
	defer close(probe.done)
	probe.sample()
	ticker := time.NewTicker(probe.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			probe.sample()
		case <-probe.stop:
			return
		}
	}
}

func (probe *availabilityProbe) sample() string {
	response, err := probe.client.Get(probe.url)
	failure := ""
	if err != nil {
		failure = err.Error()
	} else {
		response.Body.Close()
		if (response.StatusCode < 200 || response.StatusCode >= 300) &&
			!(probe.gated && response.StatusCode == http.StatusUnauthorized && basicChallenge(response)) {
			failure = response.Status
		}
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()
	probe.result.Samples++
	if failure != "" {
		probe.result.Failures++
		if probe.result.FirstFailure == "" {
			probe.result.FirstFailure = failure
		}
	}
	return failure
}

// availabilityURLIsGated reports whether the public URL is served by a site
// on which this configuration renders caddy.basic_auth. A bare 401 is never
// enough: sample also requires Caddy's Basic challenge before accepting it.
func availabilityURLIsGated(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Caddy.BasicAuth.Users) == 0 {
		return false
	}
	target, err := url.Parse(strings.TrimSpace(cfg.Deploy.AvailabilityURL))
	if err != nil || target.Hostname() == "" {
		return false
	}
	hostname := strings.TrimSuffix(strings.TrimSpace(target.Hostname()), ".")
	domain, _ := cfg.Domain.(string)
	if strings.EqualFold(hostname, strings.TrimSuffix(strings.TrimSpace(domain), ".")) {
		return cfg.DomainBasicAuthEnabled()
	}
	for _, route := range cfg.Caddy.HostRoutes {
		if route.BasicAuth && strings.EqualFold(hostname, strings.TrimSuffix(strings.TrimSpace(route.Host), ".")) {
			return true
		}
	}
	return false
}

func (probe *availabilityProbe) CheckNow() error {
	if probe == nil {
		return nil
	}
	if failure := probe.sample(); failure != "" {
		return fmt.Errorf("availability check failed: %s", failure)
	}
	return nil
}

func (probe *availabilityProbe) Stop() availabilityProbeResult {
	if probe == nil {
		return availabilityProbeResult{}
	}
	probe.once.Do(func() {
		close(probe.stop)
		<-probe.done
	})
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.result
}
