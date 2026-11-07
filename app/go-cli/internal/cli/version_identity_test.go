package cli

import (
	"errors"
	"regexp"
	"testing"
	"time"
)

func TestTimestampVersionIsUniqueAtSubsecondResolutionAndTagSafe(t *testing.T) {
	first := timestampVersion(time.Date(2026, 8, 13, 1, 2, 3, 4, time.UTC))
	second := timestampVersion(time.Date(2026, 8, 13, 1, 2, 3, 5, time.UTC))
	if first == second {
		t.Fatalf("distinct dirty builds must not share a version: %q", first)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(first) {
		t.Fatalf("version must be a valid Docker tag component: %q", first)
	}
}

func TestDirtyGitStateNeverReusesCleanImmutableTag(t *testing.T) {
	now := time.Date(2026, 8, 13, 1, 2, 3, 4, time.UTC)
	if got := versionForGitState("abc1234", "", nil, now); got != "abc1234" {
		t.Fatalf("clean checkout version = %q", got)
	}
	for name, got := range map[string]string{
		"modified":     versionForGitState("abc1234", " M Dockerfile\n", nil, now),
		"untracked":    versionForGitState("abc1234", "?? app.go\n", nil, now),
		"status error": versionForGitState("abc1234", "", errors.New("git failed"), now),
	} {
		if got == "abc1234" || !regexp.MustCompile(`^abc1234-dirty-[0-9]+T[0-9]+$`).MatchString(got) {
			t.Fatalf("%s checkout reused or produced invalid immutable tag %q", name, got)
		}
	}
}
