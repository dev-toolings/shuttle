package rootplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestOperationReservationAndBoundPhaseCarrySignedIdentity(t *testing.T) {
	operator, host := testOperatorKey, testHostKey
	id := strings.Repeat("a", 32)
	plan, err := NewOperationReserve(id, "deploy", "demo", operator, host, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if plan.OperationID != id || plan.OperationKind != "deploy" || plan.OperationApp != "demo" {
		t.Fatalf("reservation lost its binding: %+v", plan)
	}
	bound, err := WithOperationID(Plan{Schema: Schema, Action: "stack-rollback", GeneratedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: operator, RequiredHostFingerprint: host, Stack: &StackOperation{App: "demo"}}, id, "rollback", "demo")
	if err != nil {
		t.Fatal(err)
	}
	if bound.OperationID != id || bound.OperationKind != "rollback" || bound.OperationApp != "demo" {
		t.Fatalf("bound plan lost its identity: %+v", bound)
	}
	if bound.Digest == "" {
		t.Fatal("binding must reseal the plan")
	}
}

func TestOperationBindingCannotBeReusedForAnotherAction(t *testing.T) {
	plan := Plan{Schema: Schema, Action: "stack-rollback", GeneratedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339), OperatorUser: "deploy", OperatorKeyFingerprint: testOperatorKey, RequiredHostFingerprint: testHostKey, OperationID: strings.Repeat("b", 32), OperationKind: "helper-update", OperationApp: "demo", Stack: &StackOperation{App: "demo"}}
	if err := validate(plan, false); err == nil {
		t.Fatal("a helper-update reservation must not authorize a rollback")
	}
}

func TestRemoteOperationsUseTypedSignedActions(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	id := strings.Repeat("c", 32)
	status, err := NewOperationsStatus(testOperatorKey, testHostKey, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	recoveryPlan, err := NewRecoveryPlan(id, testOperatorKey, testHostKey, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	recoveryApply, err := NewRecoveryApply(id, "sha256:"+strings.Repeat("d", 64), testOperatorKey, testHostKey, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range []Plan{status, recoveryPlan, recoveryApply} {
		signed, err := Sign(plan, privateKey)
		if err != nil || Verify(signed, publicKey, now) != nil {
			t.Fatalf("remote operation was not signable and verifiable: %#v %v", plan, err)
		}
	}
	if _, err := NewRecoveryApply(id, "sha256:wrong", testOperatorKey, testHostKey, now, time.Minute); err == nil {
		t.Fatal("malformed recovery confirmation was accepted")
	}
}
