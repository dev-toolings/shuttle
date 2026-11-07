package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/version"
)

const updateCheckInterval = 24 * time.Hour

func checkForUpdateAsync() {
	// Without a release origin there is nothing to ask; do not start a network
	// call that can only fail.
	if siteBaseURL() == "" {
		return
	}
	go func() {
		if shouldSkipCheck() {
			return
		}
		latest, err := fetchLatestVersionQuiet()
		if err != nil {
			return
		}
		current := version.Version
		if current == latest || "v"+current == latest || current == "v"+latest {
			return
		}
		if strings.Contains(current, "dev") {
			return
		}
		fmt.Fprintf(os.Stderr, "\n  A new version of shuttle is available: %s → %s\n", current, latest)
		fmt.Fprintf(os.Stderr, "  Run: shuttle update\n\n")
		touchCheckFile()
	}()
}

func shouldSkipCheck() bool {
	path := checkFilePath()
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < updateCheckInterval
}

func touchCheckFile() {
	path := checkFilePath()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(time.Now().Format(time.RFC3339)), 0o644)
}

func checkFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".shuttle", "last_update_check")
}

func fetchLatestVersionQuiet() (string, error) {
	base := siteBaseURL()
	if base == "" {
		return "", errNoDistributionChannel
	}
	if err := assertTrustedDownloadURL(manifestURL()); err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: updateHTTPClient.CheckRedirect}
	url := manifestURL()
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return "", err
	}
	return manifest.Version, nil
}
