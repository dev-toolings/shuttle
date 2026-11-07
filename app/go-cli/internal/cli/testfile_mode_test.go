package cli

import "os"

// writeTestFile creates a fixture with exactly mode: os.WriteFile applies the
// process umask, so a 0755 fixture became 0700 on a workstation with umask 077
// and permission checks failed for reasons unrelated to the code under test.
func writeTestFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
