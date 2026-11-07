package monitoring

import (
	"errors"
	"os/exec"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	commandURLPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://\S+`)
	// Keys may be quoted (JSON stderr such as {"password":"x"}) or carry a
	// prefix (db_password, X-Auth-Token); values may hold escaped quotes.
	commandAuthorizationPattern = regexp.MustCompile(`(?im)(["']?\bauthorization["']?\s*[=:]\s*)[^\r\n]*`)
	commandSecretPattern        = regexp.MustCompile(`(?i)(["']?[A-Za-z0-9_-]*(?:password|passwd|secret|token|api_key|apikey)[A-Za-z0-9_-]*["']?\s*[=:]\s*)(?:"(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?|[^\s,;}]+)`)
)

// commandFailureDetail keeps the command's actual cause for incidents, where
// command.Output previously hid ExitError.Stderr and left only an exit status.
func commandFailureDetail(err error) string {
	if err == nil {
		return ""
	}

	text := err.Error()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && strings.TrimSpace(string(exitErr.Stderr)) != "" {
		text = string(exitErr.Stderr)
	}

	text = commandURLPattern.ReplaceAllString(text, "<url>")
	text = commandAuthorizationPattern.ReplaceAllString(text, "${1}<redacted>")
	text = commandSecretPattern.ReplaceAllString(text, "${1}<redacted>")
	text = strings.ToValidUTF8(text, "�")

	var cleaned strings.Builder
	cleaned.Grow(len(text))
	for _, char := range text {
		if unicode.Is(unicode.C, char) {
			cleaned.WriteByte(' ')
			continue
		}
		cleaned.WriteRune(char)
	}
	text = strings.Join(strings.Fields(cleaned.String()), " ")
	if len(text) > 240 {
		cut := len(text) - (240 - len("... "))
		for cut < len(text) && !utf8.RuneStart(text[cut]) {
			cut++
		}
		text = "... " + text[cut:]
	}
	return text
}

func commandFailureSummary(summary string, err error) string {
	if detail := commandFailureDetail(err); detail != "" {
		return summary + ": " + detail
	}
	return summary
}

func withCommandError(evidence map[string]any, err error) map[string]any {
	if evidence == nil {
		evidence = map[string]any{}
	}
	if detail := commandFailureDetail(err); detail != "" {
		evidence["command_error"] = detail
	}
	return evidence
}
