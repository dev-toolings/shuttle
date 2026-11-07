package backup

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"strings"
)

//go:embed source.py
var SourceScript string

//go:embed restore.py
var RestoreScript string

// PythonCommand keeps both the program and its JSON request separate from
// shell syntax. It executes only through the root-equivalent operator account.
func PythonCommand(program string, request any) (string, error) {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	command := "sudo -n python3 -c " + quote(program)
	if request != nil {
		body, err := json.Marshal(request)
		if err != nil {
			return "", err
		}
		command += " " + quote(base64.StdEncoding.EncodeToString(body))
	}
	return command, nil
}
