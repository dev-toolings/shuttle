package cli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestDoctorImageScanRemainsAnExplicitDiagnostic(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	command := newDoctorCommand()
	command.SetArgs([]string{"--config", "../config/testdata/valid-config.json", "--scan-images"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "optional image vulnerability diagnostic requires Trivy") {
		t.Fatalf("explicit scan must attempt the diagnostic, not just validate versions: %v", err)
	}
}

func TestInfrastructureScanCoversOnlyWhatTheCommandInstalls(t *testing.T) {
	cfg := &config.Config{}
	if got := infrastructureImages(cfg, false); len(got) != 0 {
		t.Fatalf("an application deploy selected infrastructure it does not install: %v", got)
	}
	t.Setenv("PATH", "")
	if err := scanImageReferences(nil); err != nil {
		t.Fatalf("an empty selection demanded scanner evidence: %v", err)
	}
	if scanImageReferences([]string{redisImage}) == nil {
		t.Fatal("a selected image passed without a scanner")
	}
	if got := infrastructureImages(cfg, true); len(got) != 2 || got[0] != caddyImage(cfg.Caddy) || got[1] != rootRegistryImageForSecurity {
		t.Fatalf("setup must scan the edge and the registry, got %v", got)
	}
	cfg.Production.Redis = true
	if got := infrastructureImages(cfg, false); len(got) != 1 || got[0] != redisImage {
		t.Fatalf("a deploy enabling Redis must scan it, got %v", got)
	}
}

func TestImageSecurityNeedsFreshBoundEvidence(t *testing.T) {
	now := time.Now().UTC()
	image := "redis@sha256:" + strings.Repeat("a", 64)
	report := map[string]any{"ArtifactName": image, "ArtifactType": "container_image", "Metadata": map[string]string{"ImageID": "sha256:test"}, "Results": []any{map[string]any{"Vulnerabilities": []any{}}}}
	scanner := func(at time.Time) []byte {
		b, _ := json.Marshal(map[string]any{"Version": "test", "VulnerabilityDB": map[string]any{"UpdatedAt": at}})
		return b
	}
	body, _ := json.Marshal(report)
	if err := evaluateImageSecurity(image, body, scanner(now), now); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-25 * time.Hour), now.Add(time.Hour), {}} {
		if evaluateImageSecurity(image, body, scanner(at), now) == nil {
			t.Fatal("untrusted database age accepted")
		}
	}
	if evaluateImageSecurity("different-image", body, scanner(now), now) == nil {
		t.Fatal("report for another image accepted")
	}
	report["Results"] = []any{map[string]any{"Vulnerabilities": []any{map[string]string{"Severity": "HIGH", "VulnerabilityID": "CVE-test"}}}}
	body, _ = json.Marshal(report)
	if evaluateImageSecurity(image, body, scanner(now), now) == nil {
		t.Fatal("high risk accepted")
	}
	if evaluateImageSecurity(image, []byte(`{}`), scanner(now), now) == nil {
		t.Fatal("missing evidence accepted")
	}
}

func TestInfrastructureMajorCannotChangeImplicitly(t *testing.T) {
	previous := []byte("services:\n  redis:\n    image: redis:7.4.5-alpine@sha256:old\n")
	next := []byte("services:\n  redis:\n    image: redis:8.10.1-alpine@sha256:new\n")
	if rejectImplicitInfrastructureMajorChange(previous, next) == nil {
		t.Fatal("implicit Redis data migration accepted")
	}
	if err := rejectImplicitInfrastructureMajorChange(previous, []byte(strings.ReplaceAll(string(previous), "7.4.5", "7.4.6"))); err != nil {
		t.Fatal(err)
	}
	if err := rejectImplicitInfrastructureMajorChange(nil, next); err != nil {
		t.Fatal(err)
	}
}

func TestInfrastructureScanRespectsConfiguredRabbitMQImage(t *testing.T) {
	cfg := &config.Config{}
	cfg.Production.RabbitMQ = true
	cfg.Production.RabbitMQImage = "rabbitmq:4.1-alpine@sha256:" + strings.Repeat("a", 64)
	images := infrastructureImages(cfg, false)
	if len(images) != 1 || images[0] != cfg.Production.RabbitMQImage {
		t.Fatalf("configured RabbitMQ image not selected: %v", images)
	}
}

func TestDoctorImageScansUseRetainedDigests(t *testing.T) {
	cfg := &config.Config{}
	cfg.Production.Redis = true
	digest := "redis:8-alpine@sha256:" + strings.Repeat("b", 64)
	scans := selectDoctorImageScans(cfg, map[string]string{"redis": digest})
	for _, scan := range scans {
		if scan.Reference == digest && scan.Scope == "vps-retained" {
			return
		}
	}
	t.Fatalf("retained digest was not selected: %v", scans)
}

func TestDoctorImageScansFallbackHasLocalScope(t *testing.T) {
	scans := selectDoctorImageScans(&config.Config{}, nil)
	for _, scan := range scans {
		if scan.Scope != "local-selection" {
			t.Fatalf("missing audit reported as VPS: %v", scans)
		}
	}
	if len(scans) == 0 {
		t.Fatal("no local selection")
	}
}

func TestFailedImageScanDoesNotLeaveCleanReport(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n if [ \"$1\" = --output ]; then shift; printf '{}' > \"$1\"; fi\n shift\ndone\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	err = scanImageReferences([]string{"redis:8-alpine"})
	if err == nil || !strings.Contains(err.Error(), "no clean result") {
		t.Fatalf("failed scan accepted: %v", err)
	}
	reports, err := filepath.Glob(filepath.Join(dir, ".shuttle", "security", "*.json"))
	if err != nil || len(reports) != 0 {
		t.Fatalf("failed scan left reports: %v, %v", reports, err)
	}
}

func TestDoctorScansRetainedDigestAndRecordsProvenance(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
 printf '{"Version":"test","VulnerabilityDB":{"UpdatedAt":"%s"}}' "` + time.Now().UTC().Format(time.RFC3339) + `"
 exit 0
fi
while [ "$#" -gt 0 ]; do
 if [ "$1" = "--output" ]; then shift; output="$1"; fi
 image="$1"
 shift
done
printf '{"ArtifactName":"%s","ArtifactType":"container_image","Metadata":{"ImageID":"sha256:test"},"Results":[{}]}' "$image" > "$output"
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	digest := "sha256:" + strings.Repeat("b", 64)
	reference := "redis:8-alpine@" + digest
	cfg := &config.Config{}
	cfg.Production.Redis = true
	scans := selectDoctorImageScans(cfg, map[string]string{"redis": reference})
	if err := scanSelectedImages(scans[2:]); err != nil {
		t.Fatal(err)
	}
	reports, err := filepath.Glob(filepath.Join(dir, ".shuttle", "security", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range reports {
		if strings.HasSuffix(path, ".scanner.json") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			ShuttleScan struct {
				Reference, Digest, Scope string
				FromVPS                  bool `json:"from_vps"`
			}
		}
		if err := json.Unmarshal(body, &report); err != nil {
			t.Fatal(err)
		}
		if report.ShuttleScan.Reference != reference || report.ShuttleScan.Digest != digest || report.ShuttleScan.Scope != "vps-retained" || !report.ShuttleScan.FromVPS {
			t.Fatalf("wrong scan provenance: %+v", report.ShuttleScan)
		}
		return
	}
	t.Fatal("missing scan report")
}

func TestDoctorUnreachableAuditReportsLocalSelection(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = write
	t.Cleanup(func() { os.Stdout = previous; _ = read.Close(); _ = write.Close() })
	err = scanDoctorImages(&config.Config{}, func(*config.Config) (map[string]string, error) { return nil, errors.New("unreachable") })
	_ = write.Close()
	output, readErr := io.ReadAll(read)
	if readErr != nil || err == nil || !strings.Contains(string(output), "scope=local-selection") {
		t.Fatalf("fallback not reported: output=%s error=%v read=%v", output, err, readErr)
	}
}

func TestDoctorScanContinuesAfterAnImageWithFindings(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
 printf '{"Version":"test","VulnerabilityDB":{"UpdatedAt":"%s"}}' "` + time.Now().UTC().Format(time.RFC3339) + `"
 exit 0
fi
while [ "$#" -gt 0 ]; do
 if [ "$1" = "--output" ]; then shift; output="$1"; fi
 image="$1"
 shift
done
printf '{"ArtifactName":"%s","ArtifactType":"container_image","Metadata":{"ImageID":"sha256:test"},"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH"}]}]}' "$image" > "$output"
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	first := "caddy:2@sha256:" + strings.Repeat("a", 64)
	second := "registry:3@sha256:" + strings.Repeat("b", 64)
	err = scanSelectedImages([]imageScanSelection{{first, "vps-retained"}, {second, "vps-retained"}})
	if err == nil || !strings.Contains(err.Error(), first) || !strings.Contains(err.Error(), second) {
		t.Fatalf("both images must be reported, got %v", err)
	}
}
