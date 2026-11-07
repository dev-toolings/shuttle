package output

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// colorEnabled reports whether ANSI color should be emitted on stdout.
// Honors NO_COLOR (https://no-color.org) and FORCE_COLOR, otherwise falls
// back to a TTY check so piped/CI output stays plain.
var colorEnabled = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}()

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func paint(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

// Step prints a primary deploy action line with a cyan arrow.
func Step(format string, args ...any) {
	fmt.Println(paint(ansiCyan, "→ ") + fmt.Sprintf(format, args...))
}

// Detail prints an indented sub-status line, dimmed.
func Detail(format string, args ...any) {
	fmt.Println(paint(ansiDim, "   "+fmt.Sprintf(format, args...)))
}

// OK prints a success line with a green check.
func OK(format string, args ...any) {
	fmt.Println(paint(ansiGreen, "✓ ") + fmt.Sprintf(format, args...))
}

// Attn prints a warning line (yellow) to stderr.
func Attn(format string, args ...any) {
	fmt.Fprintln(os.Stderr, paint(ansiYellow, "⚠ ")+fmt.Sprintf(format, args...))
}

// Header prints a bold heading line.
func Header(format string, args ...any) {
	fmt.Println(paint(ansiBold, fmt.Sprintf(format, args...)))
}
