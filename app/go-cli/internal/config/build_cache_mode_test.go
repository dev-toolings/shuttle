package config

import (
	"strings"
	"testing"
)

func TestValidateBuildCacheModeAcceptsEmptyMaxAndMin(t *testing.T) {
	for _, mode := range []string{"", BuildCacheModeMax, BuildCacheModeMin} {
		if err := validateBuildCacheMode(mode); err != nil {
			t.Fatalf("build_cache_mode %q must be accepted, got %v", mode, err)
		}
	}
}

func TestValidateBuildCacheModeRejectsAnUnknownValue(t *testing.T) {
	for _, mode := range []string{"full", "MAX", "off", " min"} {
		err := validateBuildCacheMode(mode)
		if err == nil || !strings.Contains(err.Error(), "deploy.build_cache_mode") {
			t.Fatalf("build_cache_mode %q must be refused, got %v", mode, err)
		}
	}
}
