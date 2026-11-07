package cli

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func parseComposeString(t *testing.T, body string) *composeFile {
	t.Helper()
	var parsed composeFile
	if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(body), &parsed.Raw); err != nil {
		t.Fatal(err)
	}
	return &parsed
}

func generatedService(t *testing.T, document map[string]any, name string) map[string]any {
	t.Helper()
	services, ok := document["services"].(map[string]any)
	if !ok {
		t.Fatalf("generated document has no services map: %#v", document)
	}
	service, ok := services[name].(map[string]any)
	if !ok {
		t.Fatalf("generated document has no service %q: %#v", name, services)
	}
	return service
}
