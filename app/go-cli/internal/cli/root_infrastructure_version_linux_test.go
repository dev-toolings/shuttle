//go:build linux

package cli

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRecoveryRedisVersionWithoutImageEnvironment(t *testing.T) {
	image := "redis:8.0.0-alpine@sha256:" + strings.Repeat("a", 64)
	lookup := recoveryInfrastructureInspectReference(image)
	calls := 0
	read := func(ctx context.Context, args ...string) (string, error) {
		calls++
		if calls == 1 {
			return `["PATH=/usr/local/bin","REDIS_DOWNLOAD_URL=https://example.invalid/redis.tar.gz","REDIS_DOWNLOAD_SHA=unused"]`, nil
		}
		want := []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--user", "999:1000", "--entrypoint", "redis-server", lookup, "--version"}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("unsafe version command: %q", args)
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Minute {
			t.Fatal("version probe has no bounded deadline")
		}
		return "Redis server v=8.0.0 sha=00000000:1 malloc=jemalloc-5.3.0 bits=64 build=95994a37e6522b40\n", nil
	}
	version, err := readRecoveryInfrastructureVersion(context.Background(), read, infrastructureRuntimeFor("redis"), "retained", image)
	if err != nil || version != "8.0.0" || calls != 2 {
		t.Fatalf("version=%q calls=%d err=%v", version, calls, err)
	}
}

func TestInfrastructureImageVersionProof(t *testing.T) {
	image := "redis:99-alpine@sha256:" + strings.Repeat("b", 64)
	for _, tt := range []struct {
		name, env, output, versionEnv, want string
		wantRun                             bool
	}{
		{"binary proves version despite tag", `[]`, "Redis server v=8.0.0", "REDIS_VERSION", "8.0.0", true},
		{"metadata takes precedence", `["REDIS_VERSION=7.4.11"]`, "", "REDIS_VERSION", "7.4.11", false},
		{"malformed metadata refuses fallback", `["REDIS_VERSION=invalid"]`, "", "REDIS_VERSION", "invalid", false},
		{"rabbit metadata", `["RABBITMQ_VERSION=4.1.0"]`, "", "RABBITMQ_VERSION", "4.1.0", false},
		{"rabbit missing metadata", `[]`, "", "RABBITMQ_VERSION", "", false},
		{"unrelated output", `[]`, "8.0.0", "REDIS_VERSION", "", true},
		{"prerelease", `[]`, "Redis server v=8.0.0-rc1", "REDIS_VERSION", "", true},
		{"extra line", `[]`, "Redis server v=8.0.0\nRedis server v=9.0.0", "REDIS_VERSION", "", true},
		{"leading zero", `[]`, "Redis server v=08.0.0", "REDIS_VERSION", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ran := false
			read := func(_ context.Context, args ...string) (string, error) {
				if args[0] == "image" {
					return tt.env, nil
				}
				ran = true
				return tt.output, nil
			}
			version, err := readInfrastructureImageVersion(context.Background(), read, image, tt.versionEnv)
			if version != tt.want || ran != tt.wantRun {
				t.Fatalf("version=%q ran=%v err=%v", version, ran, err)
			}
			if tt.want == "" && (err == nil || !strings.Contains(err.Error(), image)) {
				t.Fatalf("refusal must name image: %v", err)
			}
			if tt.want != "" && err != nil {
				t.Fatal(err)
			}
		})
	}
}
