package cli

import (
	"strings"
	"testing"
)

// Linux only: infrastructureImageNeedsVersionCheck is root helper code.
func TestRootHelperAcceptsOfficialResolvedInfraDigests(t *testing.T) {
	runtime := infrastructureRuntimeFor("redis")
	valid := "redis:8-alpine@sha256:" + strings.Repeat("a", 64)
	if needs, err := infrastructureImageNeedsVersionCheck(runtime, "", valid); err != nil || needs {
		t.Fatalf("fresh official digest rejected: needs=%v err=%v", needs, err)
	}
	for _, image := range []string{
		"unofficial/redis:8-alpine@sha256:" + strings.Repeat("a", 64),
		"redis:8-alpine",
	} {
		if _, err := infrastructureImageNeedsVersionCheck(runtime, "", image); err == nil {
			t.Errorf("unsafe image accepted: %s", image)
		}
	}
	old := "redis:7-alpine@sha256:" + strings.Repeat("b", 64)
	if _, err := infrastructureImageNeedsVersionCheck(runtime, old, "redis:6-alpine@sha256:"+strings.Repeat("c", 64)); err == nil {
		t.Fatal("an image tag older than the running major was accepted")
	}
}
