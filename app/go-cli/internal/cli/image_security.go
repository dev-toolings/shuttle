package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"gopkg.in/yaml.v3"
)

var infrastructureSecurityCheck = func(*config.Config, bool) error { return nil }

func scanInfrastructureImages(cfg *config.Config, sharedEdge bool) error {
	return scanImageReferences(infrastructureImages(cfg, sharedEdge))
}

// infrastructureImages selects the images covered by this optional diagnostic.
// Setup and adoption include the shared edge and registry. A Swarm deploy also
// converges the registry from its signed digest, but this scan selection covers
// only its application Redis and RabbitMQ services, not shared infrastructure.
func infrastructureImages(cfg *config.Config, sharedEdge bool) []string {
	images := []string{}
	if sharedEdge {
		images = append(images, caddyImage(cfg.Caddy), rootRegistryImageForSecurity)
	}
	if cfg.Production.Redis {
		images = append(images, redisImageForConfig(cfg))
	}
	if cfg.Production.RabbitMQ {
		image := cfg.Production.RabbitMQImage
		if image == "" {
			image = rabbitImage
		}
		images = append(images, image)
	}
	return images
}

// Also defined on non-Linux clients, where the SSH bootstrap still needs to
// assess the registry that the Linux helper will install.
const rootRegistryImageForSecurity = "registry:3"

type imageScanSelection struct {
	Reference string
	Scope     string
}

// Retained stack identities can differ from the local configuration. A missing
// audit entry is local selection, not evidence of what is running on the VPS.
func selectDoctorImageScans(cfg *config.Config, retained map[string]string) []imageScanSelection {
	local := infrastructureImages(cfg, true)
	repos := []string{"caddy", "registry"}
	if cfg.Production.Redis {
		repos = append(repos, "redis")
	}
	if cfg.Production.RabbitMQ {
		repos = append(repos, "rabbitmq")
	}
	scans := make([]imageScanSelection, 0, len(local))
	for i, image := range local {
		scope := "local-selection"
		if retained[repos[i]] != "" {
			image, scope = retained[repos[i]], "vps-retained"
		}
		scans = append(scans, imageScanSelection{image, scope})
	}
	// A retained service may still exist after its local flag was disabled.
	for _, repo := range []string{"redis", "rabbitmq"} {
		if retained[repo] != "" && !((repo == "redis" && cfg.Production.Redis) || (repo == "rabbitmq" && cfg.Production.RabbitMQ)) {
			scans = append(scans, imageScanSelection{retained[repo], "vps-retained"})
		}
	}
	return scans
}

func scanDoctorImages(cfg *config.Config, audit func(*config.Config) (map[string]string, error)) error {
	var retained map[string]string
	var err error
	if !cfg.UsesCompose() {
		retained, err = audit(cfg)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "VPS image audit unavailable: %v; using local-selection where needed\n", err)
	}
	return scanSelectedImages(selectDoctorImageScans(cfg, retained))
}

func scanImageReferences(images []string) error {
	selections := make([]imageScanSelection, 0, len(images))
	for _, image := range images {
		selections = append(selections, imageScanSelection{image, "local-selection"})
	}
	return scanSelectedImages(selections)
}

func scanSelectedImages(selections []imageScanSelection) error {
	// No selected infrastructure image means nothing is installed that a scan
	// could vouch for, so there is no evidence to require.
	if len(selections) == 0 {
		return nil
	}
	for _, selection := range selections {
		fmt.Printf("CVE scan scope=%s image=%s\n", selection.Scope, selection.Reference)
	}
	scanner, err := exec.LookPath("trivy")
	if err != nil {
		return errors.New("optional image vulnerability diagnostic requires Trivy on PATH; no scan result is available")
	}
	dir := filepath.Join(".shuttle", "security")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	control, err := os.CreateTemp(dir, ".trivy-config-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(control.Name())
	if _, err = control.WriteString("{}\n"); err != nil {
		control.Close()
		return err
	}
	control.Close()
	ignored, err := os.CreateTemp(dir, ".trivy-ignore-*")
	if err != nil {
		return err
	}
	ignored.Close()
	defer os.Remove(ignored.Name())
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TRIVY_") {
			env = append(env, value)
		}
	}
	sort.Slice(selections, func(i, j int) bool { return selections[i].Reference < selections[j].Reference })
	seen := map[string]bool{}
	var findings []error
	for _, selection := range selections {
		image := selection.Reference
		if seen[image] {
			continue
		}
		seen[image] = true
		sum := sha256.Sum256([]byte(image))
		base := hex.EncodeToString(sum[:12]) + "-" + time.Now().UTC().Format("20060102T150405")
		report := filepath.Join(dir, base+".json")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		command := exec.CommandContext(ctx, scanner, "--config", control.Name(), "image", "--scanners", "vuln", "--format", "json", "--output", report, "--no-progress", "--ignorefile", ignored.Name(), "--ignore-unfixed=false", "--skip-db-update=false", image)
		command.Env = env
		var diagnostic bytes.Buffer
		command.Stderr = &diagnostic
		err = command.Run()
		cancel()
		if err != nil {
			os.Remove(report)
			return fmt.Errorf("CVE scan failed for %s: %w; no clean result was recorded", image, err)
		}
		body, err := os.ReadFile(report)
		if err != nil {
			return err
		}
		// Embed provenance in the report itself, preserving Trivy's fields.
		// A tag alone cannot establish the digest that Trivy actually scanned.
		var reportData map[string]any
		if err = json.Unmarshal(body, &reportData); err != nil || reportData == nil {
			os.Remove(report)
			return errors.New("invalid CVE report; no clean result was recorded")
		}
		if reportData["ArtifactName"] != image || reportData["ArtifactType"] != "container_image" {
			os.Remove(report)
			return errors.New("CVE report does not identify the selected image; no clean result was recorded")
		}
		imageMetadata, _ := reportData["Metadata"].(map[string]any)
		digest := ""
		if at := strings.Index(image, "@sha256:"); at >= 0 {
			digest = image[at+1:]
		}
		if digest == "" {
			if digests, ok := imageMetadata["RepoDigests"].([]any); ok && len(digests) > 0 {
				if ref, ok := digests[0].(string); ok {
					if at := strings.Index(ref, "@sha256:"); at >= 0 {
						digest = ref[at+1:]
					}
				}
			}
		}
		if digest == "" {
			os.Remove(report)
			return fmt.Errorf("CVE report for %s has no scanned repository digest; no clean result was recorded", image)
		}
		reportData["ShuttleScan"] = map[string]any{"scope": selection.Scope, "reference": image, "digest": digest, "from_vps": selection.Scope == "vps-retained"}
		body, err = json.MarshalIndent(reportData, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(report, body, 0600); err != nil {
			return err
		}
		metadata := exec.Command(scanner, "--version", "--format", "json")
		metadata.Env = env
		version, err := metadata.Output()
		if err != nil {
			return fmt.Errorf("cannot attest scanner database freshness: %w", err)
		}
		if err = os.WriteFile(filepath.Join(dir, base+".scanner.json"), version, 0600); err != nil {
			return err
		}
		// Findings on one image must not hide the next: the first real scan on
		// 2026-11-07 stopped on Caddy and never reached the registry.
		if err = evaluateImageSecurity(image, body, version, time.Now()); err != nil {
			findings = append(findings, fmt.Errorf("%w (report: %s)", err, report))
		}
	}
	return errors.Join(findings...)
}

func evaluateImageSecurity(image string, body, scanner []byte, now time.Time) error {
	var metadata struct {
		Version         string
		VulnerabilityDB struct{ UpdatedAt time.Time }
	}
	if err := json.Unmarshal(scanner, &metadata); err != nil {
		return errors.New("invalid scanner metadata")
	}
	updated := metadata.VulnerabilityDB.UpdatedAt
	if metadata.Version == "" || updated.IsZero() || now.Sub(updated) > 24*time.Hour || updated.After(now.Add(10*time.Minute)) {
		return errors.New("CVE database freshness cannot be established within 24 hours")
	}
	var report struct {
		ArtifactName string
		ArtifactType string
		Metadata     struct{ ImageID string }
		Results      []struct {
			Vulnerabilities []struct {
				VulnerabilityID string
				Severity        string
			}
		}
	}
	if err := json.Unmarshal(body, &report); err != nil {
		return errors.New("invalid CVE report")
	}
	if report.ArtifactName != image || report.ArtifactType != "container_image" || report.Metadata.ImageID == "" || len(report.Results) == 0 {
		return errors.New("CVE report does not identify the selected image or contains no analysis")
	}
	ids := map[string]bool{}
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			if v.Severity == "HIGH" || v.Severity == "CRITICAL" {
				ids[v.VulnerabilityID] = true
			}
		}
	}
	if len(ids) > 0 {
		return fmt.Errorf("image %s has %d critical/high CVEs; this diagnostic does not gate installation or deployment", image, len(ids))
	}
	return nil
}

// Updating the shipped defaults must not silently migrate an existing Redis or
// RabbitMQ data volume. Such migrations need their own tested recovery path.
func rejectImplicitInfrastructureMajorChange(previous, next []byte) error {
	decode := func(body []byte) (map[string]any, error) {
		var doc map[string]any
		err := yaml.Unmarshal(body, &doc)
		return doc, err
	}
	before, err := decode(previous)
	if err != nil {
		return err
	}
	after, err := decode(next)
	if err != nil {
		return err
	}
	oldServices, _ := before["services"].(map[string]any)
	newServices, _ := after["services"].(map[string]any)
	for _, name := range []string{"redis", "rabbitmq"} {
		old, _ := oldServices[name].(map[string]any)
		next, _ := newServices[name].(map[string]any)
		if old == nil || next == nil {
			continue
		}
		major := func(v any) string {
			reference := fmt.Sprint(v)
			tagged := strings.SplitN(reference, "@", 2)[0]
			colon := strings.LastIndex(tagged, ":")
			if colon < 0 {
				return ""
			}
			return leadingMajor(tagged[colon+1:])
		}
		a, b := major(old["image"]), major(next["image"])
		if a != "" && b != "" && a != b {
			return fmt.Errorf("%s major change %s -> %s requires an explicit data migration; existing volume was not changed", name, a, b)
		}
	}
	return nil
}
