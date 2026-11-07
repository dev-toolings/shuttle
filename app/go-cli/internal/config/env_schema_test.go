package config

import (
	"os"
	"testing"
)

func TestValidateEnvSchema(t *testing.T) {
	t.Run("invalid type", func(t *testing.T) {
		schema := EnvSchema{
			"FOO": {Type: "not-a-type"},
		}
		if err := schema.ValidateEnvSchema(); err == nil {
			t.Fatal("expected an invalid type error")
		}
	})

	t.Run("valid schema", func(t *testing.T) {
		schema := EnvSchema{
			"FOO": {Type: "int", Required: true},
			"BAR": {Type: "bool", Default: "true"},
			"BAZ": {Type: "string", Pattern: `^[a-z]+$`, Allowed: []string{"alpha", "beta"}},
		}
		if err := schema.ValidateEnvSchema(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestValidateEnv(t *testing.T) {
	_ = os.Unsetenv("FOO")
	_ = os.Unsetenv("BAR")
	_ = os.Unsetenv("BAZ")

	schema := EnvSchema{
		"FOO": {Type: "int", Required: true},
		"BAR": {Type: "bool", Default: "true"},
		"BAZ": {Type: "string", Pattern: `^[a-z]+$`, Allowed: []string{"alpha"}},
	}

	t.Run("required missing", func(t *testing.T) {
		if err := schema.ValidateEnv(); err == nil {
			t.Fatal("expected missing required environment variable error")
		}
	})

	t.Run("valid provided", func(t *testing.T) {
		t.Setenv("FOO", "12")
		t.Setenv("BAZ", "alpha")
		if err := schema.ValidateEnv(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid value", func(t *testing.T) {
		t.Setenv("FOO", "not-int")
		t.Setenv("BAZ", "gamma")
		if err := schema.ValidateEnv(); err == nil {
			t.Fatal("expected invalid value error")
		}
	})
}
