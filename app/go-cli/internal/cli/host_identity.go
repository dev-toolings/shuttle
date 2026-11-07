package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type trustedHostIdentity struct {
	Version                int    `json:"version"`
	Host                   string `json:"host"`
	Port                   int    `json:"port"`
	HostKeyFingerprint     string `json:"host_key_fingerprint"`
	OperatorKeyFingerprint string `json:"operator_key_fingerprint,omitempty"`
	// AllowedSSHUsers records the policy actually committed on this host. It is
	// needed when a fresh operator was supplied through flags rather than kept
	// in config.json, and when adoption preserved its first-contact account.
	AllowedSSHUsers []string `json:"allowed_ssh_users,omitempty"`
	// Mode says which strategy trusted this host. Empty is the historical
	// record, written by setup for the swarm strategy: it carries the
	// root-operation key fingerprint every signed plan is checked against.
	// "compose" is written by the first compose deploy and carries the host
	// key alone: there is no helper, no signing identity, nothing else to
	// record. The two are kept apart so that a host somebody deploys to as an
	// existing account can never be mistaken for one Shuttle set up, and the
	// other way round.
	Mode string `json:"mode,omitempty"`
}

// hostIdentityModeCompose marks a record the compose strategy wrote.
const hostIdentityModeCompose = "compose"

func (value trustedHostIdentity) compose() bool { return value.Mode == hostIdentityModeCompose }

func trustedHostIdentityPath(host string, port int) (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", host, port)))
	return filepath.Join(root, "shuttle", "v2", "hosts", hex.EncodeToString(digest[:16])+".json"), nil
}

func saveTrustedHostIdentity(value trustedHostIdentity) error {
	path, err := trustedHostIdentityPath(value.Host, value.Port)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("trusted VPS identity path is not a regular file")
	}
	// A record is never silently converted from one strategy to the other.
	// setup writing over a compose record is exactly the host modification the
	// compose strategy was chosen to avoid; a compose deploy writing over a
	// setup record would erase the signing identity every signed operation
	// on that host depends on.
	if existing, err := readTrustedHostIdentity(path); err == nil && existing.compose() != value.compose() {
		if existing.compose() {
			return fmt.Errorf("%s:%d is trusted for deploy.strategy: compose, a host Shuttle must not set up; remove the record under %s first if that is really intended", value.Host, value.Port, filepath.Dir(path))
		}
		return fmt.Errorf("%s:%d was set up by Shuttle and carries a signing identity; deploy it with deploy.strategy: swarm, or remove the record under %s to abandon that setup", value.Host, value.Port, filepath.Dir(path))
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".host-identity-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(body, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// readTrustedHostIdentity decodes a record without deciding what it is for.
func readTrustedHostIdentity(path string) (trustedHostIdentity, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return trustedHostIdentity{}, err
	}
	var value trustedHostIdentity
	if err := json.Unmarshal(body, &value); err != nil {
		return trustedHostIdentity{}, err
	}
	return value, nil
}

// loadTrustedHostIdentity is what every signed operation reads: the record
// setup wrote, with the signing identity. A compose record is refused here
// with one message for all of them, because none of setup, doctor, helper,
// debug, rollback or destroy through the helper applies to such a host.
func loadTrustedHostIdentity(host string, port int) (trustedHostIdentity, error) {
	path, err := trustedHostIdentityPath(host, port)
	if err != nil {
		return trustedHostIdentity{}, err
	}
	value, err := readTrustedHostIdentity(path)
	if err != nil {
		return trustedHostIdentity{}, fmt.Errorf("trusted VPS identity is missing; complete shuttle setup first: %w", err)
	}
	if value.Version != 2 || value.Host != host || value.Port != port || value.HostKeyFingerprint == "" {
		return trustedHostIdentity{}, errors.New("trusted VPS identity record is invalid")
	}
	if value.compose() {
		return trustedHostIdentity{}, fmt.Errorf("%s:%d is trusted for deploy.strategy: compose, which installs no root helper: setup, doctor's host audit, helper, debug and the signed operations do not apply to it", host, port)
	}
	if value.OperatorKeyFingerprint == "" {
		return trustedHostIdentity{}, errors.New("trusted VPS identity record is invalid")
	}
	return value, nil
}

// loadComposeHostIdentity reads the record a compose deploy wrote, reporting
// its absence as a plain false rather than an error: the first deploy is
// what writes it. A setup record found in its place is refused, since a host
// Shuttle set up is deployed through the helper it installed.
func loadComposeHostIdentity(host string, port int) (trustedHostIdentity, bool, error) {
	path, err := trustedHostIdentityPath(host, port)
	if err != nil {
		return trustedHostIdentity{}, false, err
	}
	value, err := readTrustedHostIdentity(path)
	if errors.Is(err, os.ErrNotExist) {
		return trustedHostIdentity{}, false, nil
	}
	if err != nil {
		return trustedHostIdentity{}, false, fmt.Errorf("trusted VPS identity record is unreadable: %w", err)
	}
	if value.Version != 2 || value.Host != host || value.Port != port || value.HostKeyFingerprint == "" {
		return trustedHostIdentity{}, false, errors.New("trusted VPS identity record is invalid")
	}
	if !value.compose() {
		return trustedHostIdentity{}, false, fmt.Errorf("%s:%d was set up by Shuttle and carries a signing identity; deploy it with deploy.strategy: swarm, or remove the record under %s to abandon that setup", host, port, filepath.Dir(path))
	}
	return value, true, nil
}
