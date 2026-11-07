package cli

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func detectVersion() string {
	now := time.Now().UTC()
	shaOut, shaErr := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if shaErr != nil {
		return timestampVersion(now)
	}
	sha := strings.TrimSpace(string(shaOut))
	if sha == "" {
		return timestampVersion(now)
	}
	statusOut, statusErr := exec.Command("git", "status", "--porcelain", "--untracked-files=normal").Output()
	return versionForGitState(sha, string(statusOut), statusErr, now)
}

func timestampVersion(now time.Time) string {
	return fmt.Sprintf("%s%09d", now.Format("20060102T150405"), now.Nanosecond())
}

func versionForGitState(sha, status string, statusErr error, now time.Time) string {
	if statusErr != nil || len(strings.TrimSpace(status)) > 0 {
		return sha + "-dirty-" + timestampVersion(now)
	}
	return sha
}
