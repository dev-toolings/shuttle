// release-keyring-check validates the keyring embedded into release clients.
package main

import (
	"fmt"
	"os"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/release"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: release-keyring-check <trusted-keys> <signing-key-id> <signing-public-key>")
		os.Exit(2)
	}
	if err := release.ValidateTrustedKeys(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, "release-keyring-check:", err)
		os.Exit(1)
	}
}
