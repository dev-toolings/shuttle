package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestMonitoringPlansAreTypedAndSigned(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	digest := "sha256:" + strings.Repeat("b", 64)
	install, err := NewMonitoringInstall("demo", digest, fingerprint, fingerprint, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	install, err = Sign(install, privateKey)
	if err != nil || Verify(install, publicKey, now) != nil {
		t.Fatalf("signed monitoring install failed: %v", err)
	}
	plans := []Plan{}
	for _, constructor := range []func() (Plan, error){
		func() (Plan, error) { return NewMonitoringRemove("demo", fingerprint, fingerprint, now, time.Minute) },
		func() (Plan, error) { return NewMonitoringRun("demo", fingerprint, fingerprint, now, time.Minute) },
		func() (Plan, error) {
			return NewMonitoringMaintenance("demo", now.Add(time.Hour), fingerprint, fingerprint, now, time.Minute)
		},
	} {
		plan, err := constructor()
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, plan)
	}
	for _, plan := range plans {
		if _, err := Sign(plan, privateKey); err != nil {
			t.Fatalf("monitoring plan could not be signed: %v", err)
		}
	}
}

func mustMonitoringPlan(t *testing.T, plan Plan, err error) Plan {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestMonitoringPlansRejectUnsafeCoordinates(t *testing.T) {
	now := time.Now().UTC()
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	if _, err := NewMonitoringInstall("../demo", "sha256:"+strings.Repeat("a", 64), fingerprint, fingerprint, now, time.Minute); err == nil {
		t.Fatal("unsafe monitoring application accepted")
	}
	if _, err := NewMonitoringMaintenance("demo", now.Add(8*24*time.Hour), fingerprint, fingerprint, now, time.Minute); err == nil {
		t.Fatal("unbounded maintenance accepted")
	}
	plan, err := NewMonitoringRun("demo", fingerprint, fingerprint, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	plan.Monitoring.PayloadSHA256 = "sha256:" + strings.Repeat("a", 64)
	if _, err := Sign(plan, mustPrivateKey(t)); err == nil {
		t.Fatal("monitor-run carrying a payload digest was accepted")
	}
}

func mustPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}
