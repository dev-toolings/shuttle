//go:build linux

package cli

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// rootEdgeCertificateReader reads the certificates the running shared edge holds.
// A variable so tests exercise the mode decision without a Docker daemon.
var rootEdgeCertificateReader = readRootEdgeCertificates

const (
	// rootEdgeCertificateReadBudget bounds the two docker reads that locate the
	// edge's /data mount. The promotion has not started yet, and a daemon that
	// does not answer in this time is one the promotion would not get far on.
	rootEdgeCertificateReadBudget = 10 * time.Second
	// A certificate chain is a few kilobytes; anything near this is not one.
	rootEdgeCertificateFileLimit = 1 << 20
	// A store with more certificates than this is not one Shuttle manages (16
	// hostnames per application), and walking it is bounded for the same reason.
	rootEdgeCertificateFileMax = 4096
)

// readRootEdgeCertificates returns the leaf certificate of every file in the
// store of the running shuttle-edge_caddy container.
func readRootEdgeCertificates() ([]*x509.Certificate, error) {
	data, err := rootEdgeDataDirectory()
	if err != nil {
		return nil, err
	}
	return readCaddyCertificateStore(filepath.Join(data, "caddy", "certificates"))
}

// rootEdgeDataDirectory is the host path behind the running edge's /data mount.
// The helper reads the store from the host instead of through `docker exec`: the
// edge runs read-only with every capability dropped and carries no tools to
// list a directory with.
func rootEdgeDataDirectory() (string, error) {
	deadline := time.Now().Add(rootEdgeCertificateReadBudget)
	container, err := runFixedOutput(rootEdgeCertificateReadBudget, "/usr/bin/docker", "ps", "-q",
		"--filter", "label=com.docker.swarm.service.name=shuttle-edge_caddy")
	if err != nil {
		return "", fmt.Errorf("inspect shared Caddy: %w", err)
	}
	id, _, _ := strings.Cut(strings.TrimSpace(container), "\n")
	if id == "" {
		return "", errors.New("the shared Caddy container is not running")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return "", errors.New("locating the shared Caddy certificate store timed out")
	}
	source, err := runFixedOutput(remaining, "/usr/bin/docker", "inspect", "--format",
		`{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}`, id)
	if err != nil {
		return "", fmt.Errorf("inspect shared Caddy mounts: %w", err)
	}
	source = strings.TrimSpace(source)
	if !filepath.IsAbs(source) {
		return "", errors.New("the shared Caddy container has no /data mount on the host")
	}
	return source, nil
}

// readCaddyCertificateStore reads <root>/<issuer>/<subject>/<subject>.crt, the
// layout CertMagic stores issued certificates in. A missing root is an empty
// store (an edge that has issued nothing yet); a directory that cannot be listed
// is an error, so that the decision falls back to the legacy mode instead of
// reading "nothing there" out of "could not look".
//
// The store belongs to the edge's account, not to root: symbolic links are not
// followed (listing reports them as links, and the files are opened with
// O_NOFOLLOW), so nothing the edge writes there can make the helper read a file
// outside it.
func readCaddyCertificateStore(root string) ([]*x509.Certificate, error) {
	issuers, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var certificates []*x509.Certificate
	files := 0
	for _, issuer := range issuers {
		if !issuer.IsDir() {
			continue
		}
		subjects, err := os.ReadDir(filepath.Join(root, issuer.Name()))
		if err != nil {
			return nil, err
		}
		for _, subject := range subjects {
			if !subject.IsDir() {
				continue
			}
			directory := filepath.Join(root, issuer.Name(), subject.Name())
			entries, err := os.ReadDir(directory)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".crt") {
					continue
				}
				if files++; files > rootEdgeCertificateFileMax {
					return nil, errors.New("the shared Caddy certificate store is larger than Shuttle manages")
				}
				certificate, err := readCaddyCertificateFile(filepath.Join(directory, entry.Name()))
				if err != nil {
					// One unreadable file leaves its hostname uncovered, which
					// selects the legacy mode: the safe direction.
					continue
				}
				certificates = append(certificates, certificate)
			}
		}
	}
	return certificates, nil
}

// readCaddyCertificateFile parses the first certificate of a PEM file, which in
// Caddy's store is the leaf; the issuing chain follows it.
func readCaddyCertificateFile(path string) (*x509.Certificate, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, rootEdgeCertificateFileLimit))
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, body = pem.Decode(body)
		if block == nil {
			return nil, fmt.Errorf("%s holds no certificate", filepath.Base(path))
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}
