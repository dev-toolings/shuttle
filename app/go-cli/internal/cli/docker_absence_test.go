package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDockerObjectAbsentAcceptsBothDockerGenerations(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		object string
		text   string
	}{
		{name: "Docker 29 volume", kind: "volume", object: "e2ec_redis_data", text: "Error response from daemon: volume e2ec_redis_data not found"},
		{name: "Docker 29 secret", kind: "secret", object: "e2ec_rabbitmq_password_v1", text: "secret e2ec_rabbitmq_password_v1 not found"},
		{name: "Docker 29 network", kind: "network", object: "X", text: "network X not found"},
		{name: "Docker 29 service", kind: "service", object: "e2ec_web", text: "service e2ec_web not found"},
		{name: "Docker 29 command output newline", kind: "volume", object: "e2ec_redis_data", text: "Error response from daemon: volume e2ec_redis_data not found\n"},
		{name: "legacy volume", kind: "volume", object: "x", text: "Error: No such volume: x"},
		{name: "legacy secret", kind: "secret", object: "x", text: "Error response from daemon: No such secret: x"},
		{name: "legacy container without name", kind: "container", object: "", text: "Error: No such container: x"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !dockerObjectAbsent(test.kind, test.object, test.text) {
				t.Fatalf("dockerObjectAbsent(%q, %q, %q) = false, want true", test.kind, test.object, test.text)
			}
		})
	}
	if !dockerObjectAbsentAny("service", []string{"a_web", "a_worker"}, "service a_worker not found") {
		t.Fatal("one of several addressed services reported absent must count")
	}
}

// The 30-10-2026 review found that a loose "<kind> ... not found" match would
// read these errors as an absent object, so a deletion could be skipped.
func TestDockerObjectAbsentRejectsUnrelatedNotFound(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		object string
		text   string
	}{
		{name: "executable", kind: "container", object: "c1", text: "executable file not found in $PATH"},
		{name: "context", kind: "volume", object: "v", text: "context \"x\" not found"},
		{name: "kind mismatch", kind: "volume", object: "x", text: "secret x not found"},
		{name: "image registry", kind: "volume", object: "v", text: "image not found in registry"},
		{name: "permission denied", kind: "secret", object: "s", text: "permission denied"},
		{name: "empty", kind: "network", object: "n", text: ""},
		{name: "driver not found", kind: "volume", object: "app_data", text: "Error response from daemon: volume driver not found"},
		{name: "kind inside another message", kind: "volume", object: "app_data", text: "secret volume not found"},
		{name: "name suffix", kind: "volume", object: "volume", text: "network my-volume not found"},
		{name: "other volume", kind: "volume", object: "app_data", text: "volume app_data_old not found"},
		{name: "Docker 29 form without name", kind: "volume", object: "", text: "volume app_data not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if dockerObjectAbsent(test.kind, test.object, test.text) {
				t.Fatalf("dockerObjectAbsent(%q, %q, %q) = true, want false", test.kind, test.object, test.text)
			}
		})
	}
}

func TestNoRawDockerAbsenceMatching(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source file")
	}
	packageDir := filepath.Dir(source)
	forbidden := []string{
		"no such volume",
		"no such secret",
		"no such service",
		"no such container",
		"no such network",
	}
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "docker_absence.go" {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(packageDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for lineNumber, line := range strings.Split(string(contents), "\n") {
			if name == "root_helper_linux.go" && strings.Contains(line, "[]byte(") && strings.Contains(line, "Error: No such volume") {
				continue
			}
			for _, phrase := range forbidden {
				if strings.Contains(line, phrase) {
					t.Errorf("%s:%d contains raw Docker absence matching %q", name, lineNumber+1, phrase)
				}
			}
		}
	}
}
