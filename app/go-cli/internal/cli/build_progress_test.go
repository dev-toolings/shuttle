package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func allCachedBuildLog() string {
	return `#1 [internal] load build definition from Dockerfile
#2 [internal] load metadata for docker.io/library/alpine:3.21
#3 [web 1/4] FROM docker.io/library/alpine:3.21
#3 CACHED
#4 [web 2/4] WORKDIR /app
#4 CACHED
#5 [web 3/4] COPY go.mod go.sum ./
#5 CACHED
#6 [web 4/4] RUN go build ./...
#6 CACHED
`
}

func fullRebuildBuildLog() string {
	return `#1 [full 1/4] FROM python:3.12-slim-bookworm
#1 DONE 1.2s
#2 [full 2/4] RUN playwright install chromium
#2 DONE 3m12s
#3 [full 3/4] COPY app/ /app/
#3 DONE 4.5s
`
}

// oneChangedLayerBuildLog is shaped on the real plain progress of the
// demo-agent deploy of 2026-10-28 (768586e): step #22 printed CACHED, then
// extracted its parent layers and printed DONE 14.1s.
func oneChangedLayerBuildLog() string {
	var log strings.Builder
	for index := 1; index <= 16; index++ {
		label := fmt.Sprintf("[full %d/16] RUN cached-step-%d", index, index)
		if index == 3 {
			label = "[full 3/4] COPY --chown=agent:agent models/ /app/models/"
		}
		fmt.Fprintf(&log, "#%d %s\n", index, label)
		switch index {
		case 3:
			fmt.Fprintf(&log, "#%d CACHED\n\n", index)
			fmt.Fprintf(&log, "#%d %s\n", index, label)
			fmt.Fprintf(&log, "#%d extracting sha256:2483e80441b67476e27615c516ecbfe8ad8d4a357f566f436dfb5d6de95882c0\n", index)
			fmt.Fprintf(&log, "#%d extracting sha256:2483e80441b67476e27615c516ecbfe8ad8d4a357f566f436dfb5d6de95882c0 13.8s done\n", index)
			fmt.Fprintf(&log, "#%d DONE 14.1s\n", index)
		case 16:
			fmt.Fprintf(&log, "#%d DONE 1.2s\n", index)
		default:
			fmt.Fprintf(&log, "#%d CACHED\n", index)
		}
	}
	return log.String()
}

func TestParseBuildKitProgressAllCached(t *testing.T) {
	log := strings.NewReader(allCachedBuildLog())
	summary := parseBuildKitProgress(log)
	if summary.Steps != 4 || summary.Cached != 4 || summary.Executed != 0 || summary.RebuiltStage != "" {
		t.Fatalf("all-cached progress summary = %+v", summary)
	}
}

func TestParseBuildKitProgressFullRebuildOfTheBaseStage(t *testing.T) {
	log := strings.NewReader(fullRebuildBuildLog())
	summary := parseBuildKitProgress(log)
	if summary.RebuiltStage != "full" || summary.Steps != 3 || summary.Executed != 3 {
		t.Fatalf("full-rebuild progress summary = %+v", summary)
	}
	if summary.SlowestLabel != "[full 2/4] RUN playwright install chromium" || summary.Slowest != 3*time.Minute+12*time.Second {
		t.Fatalf("slowest step = %q at %s", summary.SlowestLabel, summary.Slowest)
	}
}

func TestParseBuildKitProgressOneChangedLayerFromRealOutput(t *testing.T) {
	summary := parseBuildKitProgress(strings.NewReader(oneChangedLayerBuildLog()))
	if summary.Steps != 16 || summary.Cached != 15 || summary.Executed != 1 || summary.RebuiltStage != "" {
		t.Fatalf("one-changed-layer progress summary = %+v", summary)
	}
	wantLabel := "[full 3/4] COPY --chown=agent:agent models/ /app/models/"
	if summary.SlowestLabel != wantLabel || summary.Slowest != 14100*time.Millisecond {
		t.Fatalf("slowest step = %q at %s", summary.SlowestLabel, summary.Slowest)
	}
}

func TestParseBuildKitProgressIgnoresInternalMalformedAndUnknownLines(t *testing.T) {
	log := strings.NewReader(`#1 [internal] load build definition from Dockerfile
#2 [internal] load metadata for python:3.12-slim
#3 [metadata 1/1] load metadata for python:3.12-slim
#4 [web 1/2] FROM python:3.12-slim
#4 CACHED
#5 [web ?/2] RUN malformed-position
#broken [web 2/2] RUN malformed-id
not a BuildKit progress line
#6 SOME-NEW-STATUS
`)
	summary := parseBuildKitProgress(log)
	if summary.Steps != 1 || summary.Cached != 1 || summary.Executed != 0 {
		t.Fatalf("ignored-line progress summary = %+v", summary)
	}
}

func TestBuildProgressDetailStrings(t *testing.T) {
	allCached := parseBuildKitProgress(strings.NewReader(allCachedBuildLog()))
	fullRebuild := parseBuildKitProgress(strings.NewReader(fullRebuildBuildLog()))
	changedLayer := parseBuildKitProgress(strings.NewReader(oneChangedLayerBuildLog()))
	cases := []struct {
		name    string
		summary buildProgressSummary
		want    string
	}{
		{name: "all cached", summary: allCached, want: "Build detail.web: 4/4 steps cached"},
		{name: "full rebuild", summary: fullRebuild, want: "Build detail.web: 0/3 steps cached, stage full rebuilt from its base: base image changed or build cache was cold (full rebuild); slowest: [full 2/4] RUN playwright install chromium 3m12s"},
		{name: "changed layer", summary: changedLayer, want: "Build detail.web: 15/16 steps cached; slowest: [full 3/4] COPY --chown=agent:agent models/ /app/models/ 14.1s"},
		{name: "empty", summary: buildProgressSummary{}, want: ""},
	}
	for _, test := range cases {
		if got := test.summary.Detail("web"); got != test.want {
			t.Errorf("%s detail = %q, want %q", test.name, got, test.want)
		}
	}
	long := buildProgressSummary{Steps: 1, SlowestLabel: "[web 1/1] " + strings.Repeat("very-long-instruction ", 8), Slowest: time.Second}.Detail("web")
	if got := len([]rune(strings.SplitN(long, "; slowest: ", 2)[1])); got < 100 {
		t.Fatalf("truncated label unexpectedly short: %q", long)
	}
	label := strings.SplitN(strings.SplitN(long, "; slowest: ", 2)[1], " 1s", 2)[0]
	if got := len([]rune(label)); got != 100 {
		t.Fatalf("truncated label has %d runes, want 100: %q", got, label)
	}
}

func TestBuildProgressTeePreservesTerminalBytesAndKeepsNoTranscript(t *testing.T) {
	terminal := &bytes.Buffer{}
	capture := newBuildProgressCapture()
	tee := buildProgressTee{terminal: terminal, capture: capture}
	var want bytes.Buffer
	want.WriteString(oneChangedLayerBuildLog())
	want.Write(bytes.Repeat([]byte("x"), 3*maxBuildProgressLineBytes))
	want.WriteString("\n")
	for index := 0; index < 20000; index++ {
		want.WriteString("#999 noise line that is not a step\n")
	}
	n, err := tee.Write(want.Bytes())
	if err != nil || n != want.Len() {
		t.Fatalf("tee write returned %d, %v", n, err)
	}
	if !bytes.Equal(terminal.Bytes(), want.Bytes()) {
		t.Fatal("terminal writer did not receive the exact build output")
	}
	capture.mu.Lock()
	retained := cap(capture.partial)
	capture.mu.Unlock()
	if retained > maxBuildProgressLineBytes {
		t.Fatalf("capture retained a %d byte buffer, want at most one line (%d)", retained, maxBuildProgressLineBytes)
	}
	if summary := capture.Summary(); summary.Steps != 16 || summary.Slowest != 14100*time.Millisecond {
		t.Fatalf("streamed summary = %+v", summary)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("terminal closed") }

func TestBuildProgressTerminalFailureLeavesTheExitStatusUnchanged(t *testing.T) {
	script := "printf '#1 [web 1/1] RUN true\\n#1 DONE 1.0s\\n'; printf 'warning\\n' >&2; exit %d"
	for _, code := range []int{0, 3} {
		capture := newBuildProgressCapture()
		err := runWithBuildProgress(exec.Command("sh", "-c", fmt.Sprintf(script, code)), failingWriter{}, failingWriter{}, capture)
		if code == 0 && err != nil {
			t.Fatalf("a failing terminal must not fail a successful build: %v", err)
		}
		var exitErr *exec.ExitError
		if code == 3 && (!errors.As(err, &exitErr) || exitErr.ExitCode() != 3) {
			t.Fatalf("the build's own exit status must be returned unchanged, got %v", err)
		}
		if summary := capture.Summary(); summary.Steps != 1 {
			t.Fatalf("progress still parsed with a failing terminal: %+v", summary)
		}
	}
}

// A later stage restarting from its FROM while the first stage stays cached is
// named for what it is; it is not a full rebuild.
func TestBuildProgressNamesTheRebuiltStageNotTheFirstOne(t *testing.T) {
	log := strings.NewReader(`#1 [deps 1/2] FROM python:3.12-slim
#1 CACHED

#2 [deps 2/2] RUN pip install -r requirements.txt
#2 CACHED

#3 [runtime 1/2] FROM debian:13-slim
#3 DONE 4.0s

#4 [runtime 2/2] RUN apt-get install -y --no-install-recommends libpq5
#4 DONE 2.0s
`)
	summary := parseBuildKitProgress(log)
	if summary.RebuiltStage != "runtime" {
		t.Fatalf("rebuilt stage = %q, want runtime", summary.RebuiltStage)
	}
	if got, want := summary.RebuildCause(), "stage runtime rebuilt from its base: base image changed or build cache was cold"; got != want {
		t.Fatalf("cause = %q, want %q", got, want)
	}
}

// On a warm build BuildKit prints DONE for the FROM step itself while every
// later step is CACHED; that is no rebuild from the base. A COPY rerun at step
// 2 (changed context) is no evidence of a base change either.
func TestBuildProgressClaimsNoBaseRebuildWithoutAnExecutedStepAfterFrom(t *testing.T) {
	warm := parseBuildKitProgress(strings.NewReader(`#3 [web 1/3] FROM docker.io/library/alpine:3.21@sha256:aaaa
#3 resolve docker.io/library/alpine:3.21@sha256:aaaa 0.0s done
#3 DONE 0.0s
#4 [web 2/3] RUN apk add --no-cache ca-certificates
#4 CACHED
#5 [web 3/3] COPY . /app
#5 CACHED
`))
	if warm.RebuiltStage != "" || warm.RebuildCause() != "" {
		t.Fatalf("warm build claimed a base rebuild: %+v", warm)
	}
	contextChange := parseBuildKitProgress(strings.NewReader(`#3 [web 1/3] FROM docker.io/library/alpine:3.21
#3 DONE 0.0s
#4 [web 2/3] COPY . /app
#4 DONE 0.4s
#5 [web 3/3] RUN make
#5 DONE 9.0s
`))
	if contextChange.RebuiltStage != "" {
		t.Fatalf("context change claimed a base rebuild: %+v", contextChange)
	}
}

// BuildKit's direct push runs inside the build, so its measured push phases
// are reported apart instead of reading as build time.
func TestBuildProgressReportsTheDirectRegistryPush(t *testing.T) {
	summary := parseBuildKitProgress(strings.NewReader(allCachedBuildLog() + `#7 exporting to image
#7 exporting layers 0.3s done
#7 pushing layers
#7 pushing layers 41.3s done
#7 pushing manifest for 127.0.0.1:5000/app/web:abc@sha256:bbbb
#7 pushing manifest for 127.0.0.1:5000/app/web:abc@sha256:bbbb 0.2s done
#7 DONE 41.9s
`))
	if summary.Push != 41500*time.Millisecond || summary.Steps != 4 {
		t.Fatalf("push summary = %+v", summary)
	}
	if got, want := summary.Detail("web"), "Build detail.web: 4/4 steps cached; registry push 41.5s of it"; got != want {
		t.Fatalf("detail = %q, want %q", got, want)
	}
}
