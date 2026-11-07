package ssh

import (
	"strings"
	"testing"
	"time"
)

func TestConcurrentRunnerCloseWaitsForTheFirstFence(t *testing.T) {
	for _, code := range []int{0, 17} {
		t.Run(map[int]string{0: "success", 17: "failure"}[code], func(t *testing.T) {
			gate := make(chan struct{})
			managed := &ManagedCommand{closeDone: gate, result: Result{Code: code, Stderr: "fixture"}, resultSet: true}
			r := &BuildRunner{Config: BuildRunnerConfig{Host: "192.0.2.1", User: "build"}, transportDir: t.TempDir(), lease: &runnerLease{token: "run-token", app: "demo", supervisor: managed, done: make(chan struct{}), stop: make(chan struct{}), admission: "open"}, remoteRun: func(string) Result {
				return Result{Stdout: "state=fenced\nproof_hash=" + strings.Repeat("a", 64) + "\nboot_id=boot\n"}
			}}
			first := make(chan error, 1)
			second := make(chan error, 1)
			go func() { first <- r.Close() }()
			deadline := time.Now().Add(time.Second)
			for {
				r.mu.Lock()
				started := r.closed
				r.mu.Unlock()
				if started {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("first Close did not start")
				}
				time.Sleep(time.Millisecond)
			}
			go func() { second <- r.Close() }()
			select {
			case err := <-second:
				t.Fatalf("concurrent Close returned before fence: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(gate)
			a, b := <-first, <-second
			if code == 0 && (a != nil || b != nil) {
				t.Fatalf("closure failed: %v / %v", a, b)
			}
			if code != 0 && (a == nil || b == nil || a.Error() != b.Error()) {
				t.Fatalf("closure failure not shared: %v / %v", a, b)
			}
		})
	}
}
