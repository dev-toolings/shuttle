package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAvailabilityProbeRecordsContinuousSuccess(t *testing.T) {
	requests := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case requests <- struct{}{}:
		default:
		}
	}))
	defer server.Close()

	probe := startAvailabilityProbe(server.URL, 10, false)
	defer probe.Stop()
	// Wait for actual requests, not an assumed scheduler/HTTP latency. Stop
	// joins the sampler, including the response for the second observed request.
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for range 2 {
		select {
		case <-requests:
		case <-timeout.C:
			t.Fatal("availability probe did not issue two requests")
		}
	}
	result := probe.Stop()
	if result.Samples < 2 || result.Failures != 0 {
		t.Fatalf("unexpected probe result: %+v", result)
	}
}

func TestAvailabilityProbeRecordsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	probe := startAvailabilityProbe(server.URL, 10, false)
	// The probe takes its first sample before checking stop; Stop waits for it.
	result := probe.Stop()
	if result.Failures == 0 || result.FirstFailure != "502 Bad Gateway" {
		t.Fatalf("expected HTTP failure, got %+v", result)
	}
}

func TestAvailabilityProbeCheckNowReturnsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not ready", http.StatusBadGateway)
	}))
	defer server.Close()

	probe := newAvailabilityProbe(server.URL, 250, false)
	if err := probe.CheckNow(); err == nil {
		t.Fatal("expected synchronous availability failure")
	}
	probe.mu.Lock()
	result := probe.result
	probe.mu.Unlock()
	if result.Samples != 1 || result.Failures != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestAvailabilityProbeAcceptsBasicChallengeForGatedSite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	probe := newAvailabilityProbe(server.URL, 250, true)
	if err := probe.CheckNow(); err != nil {
		t.Fatalf("a configured Basic Auth gate is an available site: %v", err)
	}
	if probe.result.Samples != 1 || probe.result.Failures != 0 {
		t.Fatalf("unexpected result: %#v", probe.result)
	}
}

func TestAvailabilityProbeRejectsUnexplainedUnauthorizedResponse(t *testing.T) {
	tests := map[string]struct {
		gated     bool
		challenge string
	}{
		"ungated site":        {gated: false, challenge: `Basic realm="restricted"`},
		"missing challenge":   {gated: true},
		"non-Basic challenge": {gated: true, challenge: "Bearer"},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if testCase.challenge != "" {
					w.Header().Set("WWW-Authenticate", testCase.challenge)
				}
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()

			probe := newAvailabilityProbe(server.URL, 250, testCase.gated)
			if err := probe.CheckNow(); err == nil {
				t.Fatal("an unexplained application 401 must remain a failure")
			}
		})
	}
}
