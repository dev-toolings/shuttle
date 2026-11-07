package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type Store struct {
	Path       string
	Passphrase string
}

// Secret is a value and its immutable version identifier. Version is empty only
// when reading a legacy v1 store before its next write migrates it to v2.
type Secret struct {
	Value   string `json:"value"`
	Version string `json:"version"`
}

type envelope struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memoryKiB"`
	Threads    uint8  `json:"threads"`
	Cipher     string `json:"cipher"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type v2Payload struct {
	Entries map[string]Secret `json:"entries"`
}

const (
	defaultPath     = ".shuttle/secrets.enc"
	envelopeVersion = 2
	legacyVersion   = 1
	kdfName         = "argon2id"
	cipherName      = "xchacha20-poly1305"
	argonTime       = uint32(3)
	argonMemoryKiB  = uint32(64 * 1024)
	argonThreads    = uint8(4)

	saltSize           = 32
	versionIDSize      = 16
	maxEnvelopeSize    = 2 * 1024 * 1024
	maxCiphertextSize  = 1024*1024 + chacha20poly1305.Overhead
	maxPlaintextSize   = 1024 * 1024
	maxSecretCount     = 256
	maxSecretKeySize   = 256
	maxSecretValueSize = 64 * 1024
)

func (s Store) path() string {
	if s.Path == "" {
		return defaultPath
	}
	return s.Path
}

func (s Store) passphrase() ([]byte, error) {
	if s.Passphrase != "" {
		return []byte(s.Passphrase), nil
	}
	if value := os.Getenv("SHUTTLE_SECRETS_PASSPHRASE"); value != "" {
		return []byte(value), nil
	}
	return nil, errors.New(MissingPassphraseMessage)
}

// MissingPassphraseMessage names every way to supply the passphrase, because an
// error that names one environment variable is what makes each operator invent
// their own storage for the key protecting all of their secrets.
const MissingPassphraseMessage = "missing secrets passphrase; write it to ~/.config/shuttle/<app>.passphrase (mode 0600), or set SHUTTLE_SECRETS_PASSPHRASE_FILE or SHUTTLE_SECRETS_PASSPHRASE"

func deriveKey(passphrase []byte, salt []byte, time uint32, memoryKiB uint32, threads uint8) []byte {
	return argon2.IDKey(passphrase, salt, time, memoryKiB, threads, chacha20poly1305.KeySize)
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return nil, err
	}
	return value, nil
}

func newVersionID() (string, error) {
	value, err := randomBytes(versionIDSize)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func encryptValues(values map[string]Secret, passphrase []byte) ([]byte, error) {
	if err := validateEntries(values, true); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(v2Payload{Entries: values})
	if err != nil {
		return nil, err
	}
	defer zero(plaintext)
	if len(plaintext) > maxPlaintextSize {
		return nil, fmt.Errorf("secrets store plaintext exceeds maximum size")
	}
	salt, err := randomBytes(saltSize)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	payload := envelope{
		Version:   envelopeVersion,
		KDF:       kdfName,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Time:      argonTime,
		MemoryKiB: argonMemoryKiB,
		Threads:   argonThreads,
		Cipher:    cipherName,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
	}
	key := deriveKey(passphrase, salt, argonTime, argonMemoryKiB, argonThreads)
	defer zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	aad, err := envelopeAAD(payload)
	if err != nil {
		return nil, err
	}
	payload.Ciphertext = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, aad))
	return json.MarshalIndent(payload, "", "  ")
}

func decryptValues(raw []byte, passphrase []byte) (map[string]Secret, error) {
	if len(raw) > maxEnvelopeSize {
		return nil, fmt.Errorf("secrets envelope exceeds maximum size")
	}
	payload, err := decodeEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if payload.Version != envelopeVersion && payload.Version != legacyVersion {
		return nil, fmt.Errorf("unsupported secrets envelope version %d", payload.Version)
	}
	if payload.KDF != kdfName {
		return nil, fmt.Errorf("unsupported secrets kdf %q", payload.KDF)
	}
	if payload.Cipher != cipherName {
		return nil, fmt.Errorf("unsupported secrets cipher %q", payload.Cipher)
	}
	if payload.Time != argonTime || payload.MemoryKiB != argonMemoryKiB || payload.Threads != argonThreads {
		return nil, fmt.Errorf("unsupported secrets kdf parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(payload.Salt)
	if err != nil || len(salt) != saltSize {
		return nil, fmt.Errorf("invalid secrets salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid secrets nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil || len(ciphertext) < chacha20poly1305.Overhead || len(ciphertext) > maxCiphertextSize {
		return nil, fmt.Errorf("invalid secrets ciphertext")
	}
	key := deriveKey(passphrase, salt, payload.Time, payload.MemoryKiB, payload.Threads)
	defer zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	var aad []byte
	if payload.Version == envelopeVersion {
		aad, err = envelopeAAD(payload)
		if err != nil {
			return nil, err
		}
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secrets: wrong passphrase or corrupted store")
	}
	defer zero(plaintext)
	if len(plaintext) > maxPlaintextSize {
		return nil, fmt.Errorf("secrets store plaintext exceeds maximum size")
	}
	if payload.Version == legacyVersion {
		var legacy map[string]string
		if err := json.Unmarshal(plaintext, &legacy); err != nil {
			return nil, fmt.Errorf("invalid legacy secrets payload")
		}
		entries := make(map[string]Secret, len(legacy))
		for key, value := range legacy {
			entries[key] = Secret{Value: value}
		}
		if err := validateEntries(entries, false); err != nil {
			return nil, err
		}
		return entries, nil
	}
	var decoded v2Payload
	if err := json.Unmarshal(plaintext, &decoded); err != nil {
		return nil, fmt.Errorf("invalid secrets payload")
	}
	if decoded.Entries == nil {
		return nil, fmt.Errorf("invalid secrets payload")
	}
	if err := validateEntries(decoded.Entries, true); err != nil {
		return nil, err
	}
	return decoded.Entries, nil
}

func decodeEnvelope(raw []byte) (envelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload envelope
	if err := decoder.Decode(&payload); err != nil {
		return envelope{}, fmt.Errorf("invalid secrets envelope")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return envelope{}, fmt.Errorf("invalid secrets envelope")
	}
	return payload, nil
}

func envelopeAAD(payload envelope) ([]byte, error) {
	return json.Marshal(struct {
		Version   int    `json:"version"`
		KDF       string `json:"kdf"`
		Salt      string `json:"salt"`
		Time      uint32 `json:"time"`
		MemoryKiB uint32 `json:"memoryKiB"`
		Threads   uint8  `json:"threads"`
		Cipher    string `json:"cipher"`
		Nonce     string `json:"nonce"`
	}{payload.Version, payload.KDF, payload.Salt, payload.Time, payload.MemoryKiB, payload.Threads, payload.Cipher, payload.Nonce})
}

func validateEntries(entries map[string]Secret, requireVersion bool) error {
	if len(entries) > maxSecretCount {
		return fmt.Errorf("secrets store contains too many entries")
	}
	for key, entry := range entries {
		if key == "" || len(key) > maxSecretKeySize {
			return fmt.Errorf("invalid secrets key")
		}
		if len(entry.Value) > maxSecretValueSize {
			return fmt.Errorf("secrets value exceeds maximum size")
		}
		if requireVersion && !validVersionID(entry.Version) {
			return fmt.Errorf("invalid secrets version identifier")
		}
	}
	return nil
}

func validVersionID(version string) bool {
	value, err := base64.RawURLEncoding.DecodeString(version)
	return err == nil && len(value) == versionIDSize
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func (s Store) loadEntries() (map[string]Secret, error) {
	raw, err := readStoreFile(s.path())
	if os.IsNotExist(err) {
		return map[string]Secret{}, nil
	}
	if err != nil {
		return nil, err
	}
	passphrase, err := s.passphrase()
	if err != nil {
		return nil, err
	}
	defer zero(passphrase)
	return decryptValues(raw, passphrase)
}

func readStoreFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxEnvelopeSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxEnvelopeSize {
		return nil, fmt.Errorf("secrets envelope exceeds maximum size")
	}
	return raw, nil
}

func (s Store) saveEntries(entries map[string]Secret) error {
	for key, entry := range entries {
		if entry.Version != "" {
			continue
		}
		version, err := newVersionID()
		if err != nil {
			return err
		}
		entry.Version = version
		entries[key] = entry
	}
	path := s.path()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	passphrase, err := s.passphrase()
	if err != nil {
		return err
	}
	defer zero(passphrase)
	raw, err := encryptValues(entries, passphrase)
	if err != nil {
		return err
	}
	return writeStoreFile(path, raw)
}

func writeStoreFile(path string, raw []byte) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".secrets-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s Store) Set(key string, value string) error {
	entries, err := s.loadEntries()
	if err != nil {
		return err
	}
	if current, ok := entries[key]; ok && current.Value == value && current.Version != "" {
		return s.saveEntries(entries)
	}
	version, err := newVersionID()
	if err != nil {
		return err
	}
	entries[key] = Secret{Value: value, Version: version}
	return s.saveEntries(entries)
}

// Get returns one stored secret and its version. The value is returned exactly
// as it was stored, newlines included: a PEM private key that comes back
// trimmed is a PEM private key that no longer parses.
func (s Store) Get(key string) (Secret, bool, error) {
	entries, err := s.loadEntries()
	if err != nil {
		return Secret{}, false, err
	}
	entry, ok := entries[key]
	return entry, ok, nil
}

func (s Store) List() ([]string, error) {
	entries, err := s.loadEntries()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	return keys, nil
}

func (s Store) Remove(key string) error {
	entries, err := s.loadEntries()
	if err != nil {
		return err
	}
	delete(entries, key)
	return s.saveEntries(entries)
}
