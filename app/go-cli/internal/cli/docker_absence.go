package cli

import (
	"regexp"
	"strings"
)

// dockerObjectAbsent reports whether Docker said that the named object does not
// exist, in either message generation.
//
// The 30-10-2026 e2e on VM 246 with Docker 29.9.2 showed destroy and recovery
// failing on objects that were never created, because Docker changed
// "No such volume: x" to "volume x not found". A cross-family review then
// showed that matching "<kind> ... not found" loosely is worse: "volume driver
// not found" or "network my-volume not found" would read as an absent volume,
// and these callers skip a deletion or settle a journal entry on absence. So
// the Docker 29 form only counts with the exact object name, as a whole token.
// The legacy "no such <kind>" form keeps the exact meaning it had before.
//
// name may be empty when the caller cannot know it; then only the legacy form
// is recognized.
func dockerObjectAbsent(kind, name string, texts ...string) bool {
	switch kind {
	case "volume", "secret", "service", "container", "network", "image", "config":
	default:
		return false
	}
	legacy := "no such " + kind
	var named *regexp.Regexp
	if name = strings.TrimSpace(name); name != "" {
		named = regexp.MustCompile(`(?i)(^|[\s:])` + kind + `\s+` + regexp.QuoteMeta(name) + `\s+not found($|[\s.:,;)"'])`)
	}
	for _, text := range texts {
		if strings.Contains(strings.ToLower(text), legacy) {
			return true
		}
		if named != nil && named.MatchString(text) {
			return true
		}
	}
	return false
}

// dockerObjectAbsentAny is dockerObjectAbsent for a command that addressed
// several objects at once (`docker service rm a b`): the error names the one
// Docker could not find.
func dockerObjectAbsentAny(kind string, names []string, texts ...string) bool {
	if dockerObjectAbsent(kind, "", texts...) {
		return true
	}
	for _, name := range names {
		if dockerObjectAbsent(kind, name, texts...) {
			return true
		}
	}
	return false
}
