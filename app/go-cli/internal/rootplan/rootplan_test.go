package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestPlansAreTypedSignedAndExpiring(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	operator := "SHA256:" + strings.Repeat("A", 43)
	host := "SHA256:" + strings.Repeat("B", 43)
	plan, err := NewStackAction("stack-apply", "demo", "sha256:"+strings.Repeat("a", 64), 30, 0, operator, host, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = Sign(plan, privateKey)
	if err != nil || Verify(plan, publicKey, now) != nil {
		t.Fatalf("signed plan failed: %v", err)
	}
	if err := Verify(plan, publicKey, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired plan accepted")
	}
	tampered := plan
	tampered.Stack = &StackOperation{App: "other", PayloadSHA256: plan.Stack.PayloadSHA256}
	if err := Verify(tampered, publicKey, now); err == nil {
		t.Fatal("tampered plan accepted")
	}
}

func TestPlanRejectsShellAndUnsafeApp(t *testing.T) {
	now := time.Now().UTC()
	fp := "SHA256:" + strings.Repeat("A", 43)
	if _, err := NewStackAction("shell", "demo", "sha256:"+strings.Repeat("a", 64), 30, 0, fp, fp, now, time.Minute); err == nil {
		t.Fatal("shell action accepted")
	}
	if _, err := NewStackAction("stack-apply", "../demo", "sha256:"+strings.Repeat("a", 64), 30, 0, fp, fp, now, time.Minute); err == nil {
		t.Fatal("unsafe app name accepted")
	}
}

func TestRollbackAndRemovalAreTypedWithoutPayloads(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fp := "SHA256:" + strings.Repeat("A", 43)
	rollback, err := NewStackAction("stack-rollback", "demo", "", 30, 0, fp, fp, now, time.Minute)
	if err != nil || rollback.Stack == nil || rollback.Stack.Remove {
		t.Fatalf("invalid rollback plan: %#v %v", rollback, err)
	}
	remove, err := NewStackRemove("demo", fp, fp, now, time.Minute)
	if err != nil || remove.Stack == nil || !remove.Stack.Remove {
		t.Fatalf("invalid remove plan: %#v %v", remove, err)
	}
}

func TestBaselineRecoveryOperationsAreTypedAndSigned(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	fp := "SHA256:" + strings.Repeat("A", 43)
	for _, construct := range []func(string, string, time.Time, time.Duration) (Plan, error){NewBaselineRollback, NewBaselineCommit} {
		plan, err := construct(fp, fp, now, time.Minute)
		if err == nil {
			plan, err = Sign(plan, privateKey)
		}
		if err != nil || Verify(plan, publicKey, now) != nil || plan.Stack != nil || plan.Audit != nil {
			t.Fatalf("invalid signed baseline recovery operation: %#v %v", plan, err)
		}
	}
}

func TestReadinessAuditRejectsUnsafeParameters(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fp := "SHA256:" + strings.Repeat("A", 43)
	if _, err := NewReadinessAudit("demo", "demo.example.com", "/health", "node", 22, true, fp, fp, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		domain, path, runtime string
		port                  int
	}{
		{"https://evil.example", "/health", "node", 22},
		{"demo.example.com", "health", "node", 22},
		{"demo.example.com", "/health", "shell", 22},
		{"demo.example.com", "/health", "node", 0},
	} {
		if _, err := NewReadinessAudit("demo", test.domain, test.path, test.runtime, test.port, false, fp, fp, now, time.Minute); err == nil {
			t.Fatalf("unsafe readiness audit accepted: %#v", test)
		}
	}
}

func TestReadinessAuditAllowsInternalAndStillValidatesPublicDomain(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fp := "SHA256:" + strings.Repeat("A", 43)
	if _, err := NewReadinessAudit("demo", "", "", "", 22, false, fp, fp, now, time.Minute); err != nil {
		t.Fatalf("internal readiness audit rejected: %v", err)
	}
	if _, err := NewReadinessAudit("demo", "https://invalid.example", "/health", "", 22, false, fp, fp, now, time.Minute); err == nil {
		t.Fatal("invalid non-empty domain was accepted")
	}
	if _, err := NewReadinessAudit("demo", "demo.example.com", "", "", 22, false, fp, fp, now, time.Minute); err == nil {
		t.Fatal("public readiness audit without a health path was accepted")
	}
}

// The promotion budget travels inside the signed plan because the root helper
// derives its privileged waits from it. Signing does not make a value safe, so
// the contract range-checks it: a plan is refused outright rather than allowed
// to stretch a privileged wait past what an operator can recover from.
func TestStackPlanBoundsTheTransportedPromotionBudget(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("C", 43)
	digest := "sha256:" + strings.Repeat("a", 64)
	now := time.Now().UTC()
	for _, seconds := range []int{-1, MinPromotionSLOSeconds - 1, MaxPromotionSLOSeconds + 1, 86400} {
		if _, err := NewStackAction("stack-apply", "demo", digest, seconds, 0, fp, fp, now, time.Minute); err == nil {
			t.Errorf("a %d s promotion budget must be refused", seconds)
		}
	}
	for _, seconds := range []int{0, MinPromotionSLOSeconds, 45, MaxPromotionSLOSeconds} {
		if _, err := NewStackAction("stack-apply", "demo", digest, seconds, 0, fp, fp, now, time.Minute); err != nil {
			t.Errorf("a %d s promotion budget must be accepted: %v", seconds, err)
		}
	}
}

// retention.registry_cache reaches the VPS through this field, and the helper
// deletes registry content on the strength of it, so the contract bounds it the
// same way it bounds the promotion budget. A budget below the floor would make
// the helper evict the build cache after every single deploy, turning every
// build cold — the exact cost the registry cache exists to avoid.
func TestStackPlanBoundsTheTransportedRegistryCacheBudget(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("C", 43)
	digest := "sha256:" + strings.Repeat("a", 64)
	now := time.Now().UTC()
	for _, budget := range []int64{-1, MinRegistryCacheBytes - 1, MaxRegistryCacheBytes + 1} {
		if _, err := NewStackAction("stack-apply", "demo", digest, 30, budget, fp, fp, now, time.Minute); err == nil {
			t.Errorf("a %d byte registry cache budget must be refused", budget)
		}
	}
	for _, budget := range []int64{0, MinRegistryCacheBytes, 5 << 30, MaxRegistryCacheBytes} {
		plan, err := NewStackAction("stack-apply", "demo", digest, 30, budget, fp, fp, now, time.Minute)
		if err != nil {
			t.Fatalf("a %d byte registry cache budget must be accepted: %v", budget, err)
		}
		if plan.Stack.RegistryCacheBudgetBytes != budget {
			t.Errorf("the budget must reach the helper unchanged, got %d for %d", plan.Stack.RegistryCacheBudgetBytes, budget)
		}
	}
	// Only a promotion performs registry maintenance, so no other signed action
	// may carry an authorisation to delete registry content.
	if _, err := NewStackAction("stack-rollback", "demo", "", 30, 5<<30, fp, fp, now, time.Minute); err == nil {
		t.Error("a rollback must not carry a registry cache budget")
	}
}

func TestStackPlanCarriesOnlyAnOfficialResolvedRegistryImage(t *testing.T) {
	now := time.Now().UTC()
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	image := "registry:3@sha256:" + strings.Repeat("b", 64)
	plan, err := NewStackAction("stack-apply", "demo", "sha256:"+strings.Repeat("c", 64), 30, 0, fingerprint, fingerprint, now, time.Minute, image)
	if err != nil || plan.Stack.RegistryImage != image {
		t.Fatalf("registry image not carried: plan=%+v err=%v", plan.Stack, err)
	}
	for _, invalid := range []string{
		"registry:3",
		"evil/registry:3@sha256:" + strings.Repeat("b", 64),
		"registry:3@sha256:" + strings.Repeat("B", 64),
		"registry@sha256:" + strings.Repeat("b", 64),
	} {
		plan.Stack.RegistryImage = invalid
		if err := validate(plan, false); err == nil {
			t.Errorf("stack-apply accepted invalid registry image: %q", invalid)
		}
	}
	plan.Stack.RegistryImage = image
	plan.Action = "stack-rollback"
	if err := validate(plan, false); err == nil {
		t.Fatal("stack-rollback accepted a registry image intended only for promotion")
	}
}

func TestRetainedInfrastructureAuditIsAppScopedAndReadOnly(t *testing.T) {
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	plan, err := NewStackAudit("infra-images", "demo", "", 0, fingerprint, fingerprint, time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "audit" || plan.Audit == nil || plan.Audit.Mode != "infra-images" {
		t.Fatalf("unexpected retained infrastructure audit plan: %+v", plan.Audit)
	}
}

// A reclaim names an application and nothing more. Every other field of a
// stack operation authorises something a reclaim never does, so each one is
// refused rather than ignored: the action must not be able to grow into a
// second way to promote, remove or wait on a stack.
func TestStackReclaimCarriesOnlyAnApplicationName(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	fp := "SHA256:" + strings.Repeat("A", 43)
	plan, err := NewStackReclaim("demo", fp, fp, now, time.Minute)
	if err != nil || plan.Action != "stack-reclaim" || plan.Stack == nil || plan.Stack.App != "demo" {
		t.Fatalf("invalid reclaim plan: %#v %v", plan, err)
	}
	signed, err := Sign(plan, privateKey)
	if err != nil || Verify(signed, publicKey, now) != nil {
		t.Fatalf("signed reclaim failed: %v", err)
	}
	if _, err := NewStackReclaim("../demo", fp, fp, now, time.Minute); err == nil {
		t.Fatal("unsafe app name accepted")
	}
	for name, mutate := range map[string]func(*Plan){
		"payload digest":  func(p *Plan) { p.Stack.PayloadSHA256 = "sha256:" + strings.Repeat("a", 64) },
		"removal":         func(p *Plan) { p.Stack.Remove = true },
		"promotion wait":  func(p *Plan) { p.Stack.PromotionSLOSeconds = 30 },
		"registry budget": func(p *Plan) { p.Stack.RegistryCacheBudgetBytes = 5 << 30 },
		"run block":       func(p *Plan) { p.Run = &RunOperation{App: "demo", Operation: "migrate"} },
		"audit block":     func(p *Plan) { p.Audit = &AuditOperation{Mode: "baseline"} },
		"baseline block":  func(p *Plan) { p.Baseline = &BaselineOperation{AllowedSSHUsers: []string{"deploy"}} },
	} {
		tampered := signed
		stack := *signed.Stack
		tampered.Stack = &stack
		mutate(&tampered)
		if err := Verify(tampered, publicKey, now); err == nil {
			t.Fatalf("a reclaim carrying a %s was accepted", name)
		}
		if widened, err := Sign(tampered, privateKey); err == nil {
			t.Fatalf("a reclaim carrying a %s could be signed: %#v", name, widened)
		}
	}
}
