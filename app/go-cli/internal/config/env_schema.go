package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ValidateEnvSchema validates only the schema itself (types, regex syntax, allowed
// values). It does not inspect the current process environment.
func (schema EnvSchema) ValidateEnvSchema() error {
	if len(schema) == 0 {
		return nil
	}

	var errs []string
	for _, key := range sortedEnvKeys(schema) {
		spec := schema[key]
		if strings.TrimSpace(key) == "" {
			errs = append(errs, "env_schema: variable name cannot be empty")
			continue
		}
		if len(strings.TrimSpace(spec.Type)) > 0 {
			switch strings.ToLower(strings.TrimSpace(spec.Type)) {
			case "string", "int", "integer", "float", "bool", "boolean":
			case "":
			default:
				errs = append(errs, fmt.Sprintf("env_schema[%s].type: unsupported value %q", key, spec.Type))
			}
		}
		if len(spec.Pattern) > 0 {
			if _, err := regexp.Compile(spec.Pattern); err != nil {
				errs = append(errs, fmt.Sprintf("env_schema[%s].pattern: invalid regex %q", key, err))
			}
		}
		if len(spec.Allowed) > 0 {
			for _, item := range spec.Allowed {
				if item == "" {
					errs = append(errs, fmt.Sprintf("env_schema[%s].allowed: empty value is not allowed", key))
					break
				}
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid env schema:\n - %s", strings.Join(errs, "\n - "))
}

// ValidateEnv checks all required variables and their configured types against
// the current process environment. Variables with Default values are considered
// present and validated against their type/constraints.
func (schema EnvSchema) ValidateEnv() error {
	if len(schema) == 0 {
		return nil
	}

	var errs []string
	for _, name := range sortedEnvKeys(schema) {
		spec := schema[name]
		value, exists := os.LookupEnv(name)
		if strings.TrimSpace(value) == "" {
			if exists {
				value = ""
			}
			if strings.TrimSpace(spec.Default) != "" {
				value = spec.Default
			}
		}

		if strings.TrimSpace(value) == "" && spec.Required {
			errs = append(errs, fmt.Sprintf("required environment variable %q is not set", name))
			continue
		}
		if strings.TrimSpace(value) == "" {
			continue
		}

		if err := validateEnvValue(name, value, spec); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("environment validation failed:\n - %s", strings.Join(errs, "\n - "))
}

func sortedEnvKeys(schema EnvSchema) []string {
	keys := make([]string, 0, len(schema))
	for key := range schema {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validateEnvValue(name, value string, spec EnvVarSchema) error {
	switch strings.ToLower(strings.TrimSpace(spec.Type)) {
	case "", "string":
		// strings are always accepted.
	case "int", "integer":
		if _, err := strconv.Atoi(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("env_schema[%s]: %q is not a valid integer", name, value)
		}
	case "float":
		if _, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err != nil {
			return fmt.Errorf("env_schema[%s]: %q is not a valid float", name, value)
		}
	case "bool", "boolean":
		if _, err := strconv.ParseBool(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("env_schema[%s]: %q is not a valid boolean", name, value)
		}
	default:
		return fmt.Errorf("env_schema[%s].type: unsupported value %q", name, spec.Type)
	}

	if len(spec.Pattern) > 0 {
		if !regexp.MustCompile(spec.Pattern).MatchString(value) {
			return fmt.Errorf("env_schema[%s]: %q does not match pattern", name, value)
		}
	}

	if len(spec.Allowed) > 0 {
		match := false
		for _, allowed := range spec.Allowed {
			if value == allowed {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("env_schema[%s]: %q is not one of [%s]", name, value, strings.Join(spec.Allowed, ", "))
		}
	}

	return nil
}
