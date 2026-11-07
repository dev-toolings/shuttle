package monitoring

import (
	"context"
	"strings"
	"testing"
)

func TestApplicationInventoryReadIsBoundedAndEmptyEvidenceUnavailable(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":     nil,
		"oversized": []byte(strings.Repeat("x", maxCurrentStackBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			engine := collectorEngine("demo_web\t1/1\n", "", "")
			engine.Adapters.Read = func(string) ([]byte, error) { return body, nil }
			state, _, _ := engine.application(context.Background())
			if state != StateUnavailable {
				t.Fatalf("inventory body should be unavailable, got %s", state)
			}
		})
	}
}
