package cli

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backup"
)

// The live VPS refused every operation ID because the program read the base64
// request emitted by backup.PythonCommand as if it were the raw identifier.
func TestReadWriterRecoveryProgramDecodesPythonCommandRequest(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	run := func(id string) string {
		command, err := backup.PythonCommand(readWriterRecoveryProgram, []string{id})
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(command)
		payload := strings.Trim(fields[len(fields)-1], "'")
		output, _ := exec.Command(python, "-c", readWriterRecoveryProgram, payload).CombinedOutput()
		return string(output)
	}
	valid := run("f32567fa-5241-580c-2204-b37f009ea1e7")
	if strings.Contains(valid, "invalid identifier") || strings.Contains(valid, "invalid request") {
		t.Fatalf("a canonical operation ID was refused: %s", valid)
	}
	if !strings.Contains(valid, "/var/lib/shuttle/operations/f32567fa-5241-580c-2204-b37f009ea1e7.json") && !strings.Contains(valid, "unsafe operation inventory") {
		t.Fatalf("program did not reach the bound journal path: %s", valid)
	}
	if out := run("../etc/passwd"); !strings.Contains(out, "invalid identifier") {
		t.Fatalf("path traversal was not refused: %s", out)
	}
}
