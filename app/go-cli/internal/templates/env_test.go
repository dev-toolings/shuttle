package templates

import (
	"strings"
	"testing"
)

func TestEnvExampleLaravel(t *testing.T) {
	out := EnvExample("laravel")
	for _, key := range []string{"APP_NAME", "APP_KEY", "DB_CONNECTION", "DB_HOST", "QUEUE_CONNECTION", "MAIL_MAILER"} {
		if !strings.Contains(out, key) {
			t.Errorf("laravel env missing %s", key)
		}
	}
}

func TestEnvExampleSymfony(t *testing.T) {
	out := EnvExample("symfony")
	for _, key := range []string{"APP_ENV", "APP_SECRET", "DATABASE_URL", "MESSENGER_TRANSPORT_DSN", "MAILER_DSN"} {
		if !strings.Contains(out, key) {
			t.Errorf("symfony env missing %s", key)
		}
	}
}

func TestEnvExampleNextjs(t *testing.T) {
	out := EnvExample("nextjs")
	if !strings.Contains(out, "NODE_ENV") {
		t.Error("nextjs env missing NODE_ENV")
	}
	if !strings.Contains(out, "NEXT_PUBLIC_API_URL") {
		t.Error("nextjs env missing NEXT_PUBLIC_API_URL")
	}
}

func TestEnvExampleNodeAPI(t *testing.T) {
	out := EnvExample("node-api")
	if !strings.Contains(out, "PORT=3000") {
		t.Error("node-api env missing PORT=3000")
	}
}

func TestEnvExampleUnknownPreset(t *testing.T) {
	out := EnvExample("unknown")
	if out == "" {
		t.Error("unknown preset should still return a default")
	}
}

func TestEnvExampleDoesNotAskToCopyProductionValues(t *testing.T) {
	out := EnvExample("laravel")
	if !strings.Contains(out, "secrets.host.env_file") {
		t.Fatal("the example must name the VPS file, not a local copy")
	}
	if strings.Contains(out, "Copy to .env") {
		t.Fatal("the example must not tell anyone to copy production values onto a workstation")
	}
}
