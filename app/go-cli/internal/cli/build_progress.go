package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The capture keeps no transcript: lines are parsed as they arrive and only
// the step table stays in memory. A line longer than maxBuildProgressLineBytes
// is dropped (BuildKit step lines are short), and the table stops growing at
// maxBuildProgressSteps, so memory stays bounded per build and therefore per
// deploy even when several builds run in parallel.
const (
	maxBuildProgressLineBytes = 64 << 10
	maxBuildProgressSteps     = 4096
)

var (
	buildProgressStepLine = regexp.MustCompile(`^\s*#(\d+)\s+\[([^]]+)\]\s+(.+?)\s*$`)
	buildProgressPosition = regexp.MustCompile(`(?:^|\s)(\d+)/(\d+)\s*$`)
	buildProgressStatus   = regexp.MustCompile(`^\s*#(\d+)\s+(CACHED|DONE(?:\s+\S+)?|ERROR\b.*)\s*$`)
	// BuildKit's direct registry push reports its own phases inside the
	// "exporting to image" vertex: "#12 pushing layers 41.3s done" and
	// "#12 pushing manifest for <ref>@sha256:... 0.1s done".
	buildProgressPushDone = regexp.MustCompile(`^\s*#\d+\s+pushing (?:layers|manifest for \S+)\s+(\S+)\s+done\s*$`)
)

type buildProgressSummary struct {
	Steps        int
	Cached       int
	Executed     int
	SlowestLabel string
	Slowest      time.Duration
	// RebuiltStage names a stage whose first instruction after FROM (step 2/n)
	// executed: the cache chain broke at the base. The FROM step itself is no
	// evidence: on a warm build BuildKit prints "FROM ... DONE 0.0s" for it
	// while every later step is CACHED, so a FROM-based rule labelled warm builds
	// as rebuilt from their base. A COPY or ADD at step 2 is no evidence either:
	// a changed context or a rebuilt source stage reruns it with the same base.
	// Plain progress cannot tell a moved base image from a cold or lost build
	// cache, so the wording never claims which one it was, and it names the
	// stage instead of assuming it is the Dockerfile's first one.
	RebuiltStage string
	// Push is the registry push time BuildKit measured inside this build when
	// it pushes directly (--push). That time is part of the build's wall clock,
	// so without it a slow upload reads as a slow build.
	Push time.Duration
}

type buildProgressStep struct {
	id       int
	position int
	label    string
	cached   bool
	finished bool
	duration time.Duration
}

// parseBuildKitProgress reads the bounded plain-progress transcript after the
// build finishes. In October 2026, demo-agent spent 6m07 of a 7m57 deploy
// rebuilding a 3.36 GB Playwright and Camoufox layer after python:3.12-slim-bookworm
// moved upstream. The SLO warning could only suggest growing the budget, so the
// operator had to compare node image layers by hand. A later cached COPY took
// 14.1 s while fetching parent layers, which is also useful evidence even though
// BuildKit called that instruction CACHED. Parsing is deliberately tolerant:
// it is diagnostic data, so unknown or malformed lines never affect a build.
func parseBuildKitProgress(r io.Reader) buildProgressSummary {
	parser := newBuildProgressParser()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), maxBuildProgressLineBytes)
	for scanner.Scan() {
		parser.feedLine(scanner.Text())
	}
	return parser.summary()
}

// buildProgressParser holds only the step table built from plain progress
// lines. A step can carry both CACHED and a later DONE with a duration: on
// 2026-10-28 the demo-agent build printed `#22 CACHED`, then
// `#22 extracting sha256:2483e804... 13.8s done` and `#22 DONE 14.1s` for
// `COPY models/`, the parent layers being unpacked so the changed layer could
// be applied on top. That duration is real and is reported as the slowest step.
type buildProgressParser struct {
	steps map[int]*buildProgressStep
	push  time.Duration
}

func newBuildProgressParser() *buildProgressParser {
	return &buildProgressParser{steps: make(map[int]*buildProgressStep)}
}

func (p *buildProgressParser) step(id int) *buildProgressStep {
	step := p.steps[id]
	if step == nil {
		if len(p.steps) >= maxBuildProgressSteps {
			return nil
		}
		step = &buildProgressStep{id: id}
		p.steps[id] = step
	}
	return step
}

func (p *buildProgressParser) feedLine(line string) {
	if match := buildProgressStepLine.FindStringSubmatch(line); match != nil {
		stage := strings.TrimSpace(match[2])
		instruction := strings.TrimSpace(match[3])
		lowerInstruction := strings.ToLower(instruction)
		if strings.EqualFold(stage, "internal") || strings.HasPrefix(lowerInstruction, "load metadata") || strings.HasPrefix(lowerInstruction, "load build definition") {
			return
		}
		position := buildProgressPosition.FindStringSubmatch(stage)
		if position == nil {
			return
		}
		id, idErr := strconv.Atoi(match[1])
		index, indexErr := strconv.Atoi(position[1])
		if idErr != nil || indexErr != nil {
			return
		}
		if step := p.step(id); step != nil {
			step.position = index
			step.label = "[" + stage + "] " + instruction
		}
		return
	}
	if push := buildProgressPushDone.FindStringSubmatch(line); push != nil {
		if duration, err := time.ParseDuration(push[1]); err == nil {
			p.push += duration
		}
		return
	}
	match := buildProgressStatus.FindStringSubmatch(line)
	if match == nil {
		return
	}
	id, err := strconv.Atoi(match[1])
	if err != nil {
		return
	}
	step := p.step(id)
	if step == nil {
		return
	}
	status := strings.Fields(match[2])
	switch status[0] {
	case "CACHED":
		step.cached = true
	case "DONE":
		step.finished = true
		if len(status) > 1 {
			if duration, err := time.ParseDuration(status[len(status)-1]); err == nil {
				step.duration = duration
			}
		}
	case "ERROR":
		step.finished = true
	}
}

func (p *buildProgressParser) summary() buildProgressSummary {
	summary := buildProgressSummary{Push: p.push}
	var rebuiltFromBase *buildProgressStep
	for _, step := range p.steps {
		if step.label == "" {
			continue
		}
		summary.Steps++
		if step.cached {
			summary.Cached++
		} else if step.finished {
			summary.Executed++
			if step.position == 2 && !buildStepCopiesFiles(step.label) && (rebuiltFromBase == nil || step.id < rebuiltFromBase.id) {
				rebuiltFromBase = step
			}
		}
		if step.duration > summary.Slowest {
			summary.Slowest = step.duration
			summary.SlowestLabel = step.label
		}
	}
	if rebuiltFromBase != nil {
		summary.RebuiltStage = buildStepStageName(rebuiltFromBase.label)
	}
	return summary
}

// buildStepCopiesFiles reports whether a "[stage n/m] INSTRUCTION ..." label
// is a COPY or ADD, whose rerun can come from the context or another stage.
func buildStepCopiesFiles(label string) bool {
	instruction := label
	if end := strings.Index(label, "] "); end >= 0 {
		instruction = label[end+2:]
	}
	fields := strings.Fields(instruction)
	return len(fields) > 0 && (strings.EqualFold(fields[0], "COPY") || strings.EqualFold(fields[0], "ADD"))
}

// buildStepStageName returns the stage of a "[stage n/m] ..." label, or
// "build" for a single-stage label "[n/m] ...".
func buildStepStageName(label string) string {
	inner := strings.TrimPrefix(label, "[")
	if end := strings.Index(inner, "]"); end >= 0 {
		inner = inner[:end]
	}
	fields := strings.Fields(inner)
	if len(fields) >= 2 {
		return strings.Join(fields[:len(fields)-1], " ")
	}
	return "build"
}

// RebuildCause is the measured statement about a rebuild from a base, or "".
func (s buildProgressSummary) RebuildCause() string {
	if s.RebuiltStage == "" {
		return ""
	}
	cause := "stage " + s.RebuiltStage + " rebuilt from its base: base image changed or build cache was cold"
	if s.Cached == 0 {
		cause += " (full rebuild)"
	}
	return cause
}

// Detail is labeled with the service so parallel builds stay attributable,
// like the "Timing build.<service>" line it follows.
func (s buildProgressSummary) Detail(service string) string {
	if s.Steps == 0 {
		return ""
	}
	detail := fmt.Sprintf("Build detail.%s: %d/%d steps cached", service, s.Cached, s.Steps)
	if cause := s.RebuildCause(); cause != "" {
		detail += ", " + cause
	}
	if s.SlowestLabel != "" {
		detail += fmt.Sprintf("; slowest: %s %s", truncateBuildStepLabel(s.SlowestLabel, 100), formatDeployDuration(s.Slowest))
	}
	if s.Push > 0 {
		detail += "; registry push " + formatDeployDuration(s.Push) + " of it"
	}
	return detail
}

func truncateBuildStepLabel(label string, limit int) string {
	if limit < 4 {
		return ""
	}
	runes := []rune(label)
	if len(runes) <= limit {
		return label
	}
	return string(runes[:limit-3]) + "..."
}

type buildProgressCapture struct {
	mu       sync.Mutex
	parser   *buildProgressParser
	partial  []byte
	skipping bool
}

func newBuildProgressCapture() *buildProgressCapture {
	return &buildProgressCapture{parser: newBuildProgressParser()}
}

// Write parses complete lines as they arrive and keeps only the unfinished
// tail of the current line. It never fails: progress parsing is diagnostic.
func (c *buildProgressCapture) Write(p []byte) (int, error) {
	if c == nil {
		return len(p), nil
	}
	written := len(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(p) > 0 {
		newline := bytes.IndexByte(p, '\n')
		chunk := p
		if newline >= 0 {
			chunk = p[:newline]
		}
		if !c.skipping {
			if len(c.partial)+len(chunk) > maxBuildProgressLineBytes {
				c.partial = c.partial[:0]
				c.skipping = true
			} else {
				c.partial = append(c.partial, chunk...)
			}
		}
		if newline < 0 {
			break
		}
		if !c.skipping {
			c.parser.feedLine(string(c.partial))
		}
		c.partial = c.partial[:0]
		c.skipping = false
		p = p[newline+1:]
	}
	return written, nil
}

func (c *buildProgressCapture) Summary() buildProgressSummary {
	if c == nil {
		return buildProgressSummary{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.partial) > 0 && !c.skipping {
		c.parser.feedLine(string(c.partial))
		c.partial = c.partial[:0]
	}
	return c.parser.summary()
}

// buildProgressTee shows the build output on the terminal and feeds the
// parser. It always reports the whole write as accepted: with a Go writer as
// cmd.Stdout, a returned error would end the copy and turn a display problem
// (a closed terminal, a full pipe) into a failed build. The build's result is
// its exit status, nothing else.
type buildProgressTee struct {
	terminal io.Writer
	capture  *buildProgressCapture
}

func (w buildProgressTee) Write(p []byte) (int, error) {
	if w.terminal != nil {
		_, _ = w.terminal.Write(p)
	}
	_, _ = w.capture.Write(p)
	return len(p), nil
}

type buildProgressReport struct {
	Service  string
	Duration time.Duration
	Summary  buildProgressSummary
}

type buildProgressResults struct {
	mu      sync.Mutex
	reports []buildProgressReport
}

func (r *buildProgressResults) add(report buildProgressReport) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.reports = append(r.reports, report)
	r.mu.Unlock()
}

func (r *buildProgressResults) snapshot() []buildProgressReport {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]buildProgressReport(nil), r.reports...)
}
