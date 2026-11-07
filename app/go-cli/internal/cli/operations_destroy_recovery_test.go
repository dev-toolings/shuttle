package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	coord "github.com/dev-toolings/deploy-shuttle/go-cli/internal/operations"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
)

func TestDestroyRecoveryNegotiatesSafetyBeforePlanAndApply(t *testing.T) {
	for _, action := range []string{"recovery-plan", "recovery-apply"} {
		for _, kind := range []string{"destroy", "deploy"} {
			for _, capable := range []bool{false, true} {
				t.Run(action+"/"+kind+"/"+map[bool]string{false: "old", true: "current"}[capable], func(t *testing.T) {
					id := strings.Repeat("a", 32)
					var mu sync.Mutex
					var sent []string
					client, identity, key := reservationTestClient(t, func(_, _ string, stdin []byte) shuttlessh.Result {
						p, _, err := decodeRootHelperEnvelope(bytes.NewReader(stdin))
						if err != nil {
							return shuttlessh.Result{Code: 1, Stderr: err.Error()}
						}
						mu.Lock()
						sent = append(sent, p.Action)
						mu.Unlock()
						var value any = map[string]string{"ok": "true"}
						if p.Action == "operations-status" {
							value = []coord.Record{{ID: id, Kind: kind}}
						}
						if p.Action == "audit" {
							report := currentRootHelperCapabilities()
							if !capable {
								features := []string{}
								for _, feature := range report.Features {
									if feature != capabilityDestroySafeOptions {
										features = append(features, feature)
									}
								}
								report.Features = features
							}
							value = report
						}
						body, _ := json.Marshal(value)
						return shuttlessh.Result{Stdout: string(body)}
					})
					_, err := runRemoteOperationsOn(client, identity, key, action, id, "sha256:"+strings.Repeat("b", 64))
					mu.Lock()
					defer mu.Unlock()
					issued := false
					for _, a := range sent {
						if a == action {
							issued = true
						}
					}
					if kind == "destroy" && !capable {
						if err == nil || !strings.Contains(err.Error(), "shuttle helper update") || issued {
							t.Fatalf("unsafe recovery sent: %v err=%v", sent, err)
						}
					} else if err != nil || !issued {
						t.Fatalf("safe recovery refused: %v %v", sent, err)
					}
				})
			}
		}
	}
}
