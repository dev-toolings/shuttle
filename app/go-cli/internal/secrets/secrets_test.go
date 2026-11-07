package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testGet(store Store, key string) (string, bool, error) {
	entry, ok, err := testGetWithMetadata(store, key)
	return entry.Value, ok, err
}

func testGetWithMetadata(store Store, key string) (Secret, bool, error) {
	entries, err := store.loadEntries()
	if err != nil {
		return Secret{}, false, err
	}
	entry, ok := entries[key]
	return entry, ok, nil
}

func TestStoreEncryptsAndReadsSecrets(t *testing.T) {
	dir := t.TempDir()
	store := Store{
		Path:       filepath.Join(dir, "secrets.enc"),
		Passphrase: "correct horse battery staple",
	}

	if err := store.Set("API_KEY", "test-value"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	value, ok, err := testGet(store, "API_KEY")
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if !ok {
		t.Fatal("expected API_KEY to exist")
	}
	if value != "test-value" {
		t.Fatalf("expected test-value, got %q", value)
	}

	raw, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatalf("read encrypted store: %v", err)
	}
	if strings.Contains(string(raw), "test-value") {
		t.Fatal("encrypted store contains plaintext secret value")
	}
	var payload envelope
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("encrypted store should be a JSON envelope: %v", err)
	}
	if payload.KDF != kdfName {
		t.Fatalf("expected kdf %q, got %q", kdfName, payload.KDF)
	}
	if payload.Cipher != cipherName {
		t.Fatalf("expected cipher %q, got %q", cipherName, payload.Cipher)
	}
	if _, err := base64.StdEncoding.DecodeString(payload.Ciphertext); err != nil {
		t.Fatalf("ciphertext should be base64 encoded: %v", err)
	}
	if payload.Version != envelopeVersion {
		t.Fatalf("expected envelope version %d, got %d", envelopeVersion, payload.Version)
	}
	info, ok, err := testGetWithMetadata(store, "API_KEY")
	if err != nil || !ok {
		t.Fatalf("get secret metadata: ok=%v err=%v", ok, err)
	}
	if info.Value != "test-value" || info.Version == "" {
		t.Fatalf("unexpected secret metadata: %#v", info)
	}
	mode, err := os.Stat(store.Path)
	if err != nil {
		t.Fatalf("stat encrypted store: %v", err)
	}
	if mode.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 encrypted store, got %04o", mode.Mode().Perm())
	}
}

func TestStoreRejectsWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.enc")
	store := Store{Path: path, Passphrase: "right-passphrase"}
	if err := store.Set("API_KEY", "test-value"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	wrong := Store{Path: path, Passphrase: "wrong-passphrase"}
	if _, _, err := testGet(wrong, "API_KEY"); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}

func TestStorePreservesVersionForUnchangedValueAndRotatesChangedValue(t *testing.T) {
	dir := t.TempDir()
	store := Store{Path: filepath.Join(dir, "secrets.enc"), Passphrase: "passphrase"}
	if err := store.Set("API_KEY", "first"); err != nil {
		t.Fatalf("set initial secret: %v", err)
	}
	first, ok, err := testGetWithMetadata(store, "API_KEY")
	if err != nil || !ok {
		t.Fatalf("get initial secret: ok=%v err=%v", ok, err)
	}
	if err := store.Set("API_KEY", "first"); err != nil {
		t.Fatalf("set unchanged secret: %v", err)
	}
	unchanged, ok, err := testGetWithMetadata(store, "API_KEY")
	if err != nil || !ok {
		t.Fatalf("get unchanged secret: ok=%v err=%v", ok, err)
	}
	if unchanged.Version != first.Version {
		t.Fatalf("unchanged value rotated version: %q != %q", unchanged.Version, first.Version)
	}
	if err := store.Set("API_KEY", "second"); err != nil {
		t.Fatalf("set changed secret: %v", err)
	}
	changed, ok, err := testGetWithMetadata(store, "API_KEY")
	if err != nil || !ok {
		t.Fatalf("get changed secret: ok=%v err=%v", ok, err)
	}
	if changed.Version == first.Version || changed.Value != "second" {
		t.Fatalf("changed secret did not rotate version: %#v", changed)
	}
}

func TestStoreLoadsV1AndMigratesOnWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.enc")
	passphrase := []byte("passphrase")
	legacy, err := encryptV1Values(map[string]string{"LEGACY": "value"}, passphrase)
	if err != nil {
		t.Fatalf("encrypt legacy values: %v", err)
	}
	if err := os.WriteFile(path, legacy, 0o644); err != nil {
		t.Fatalf("write legacy store: %v", err)
	}
	store := Store{Path: path, Passphrase: string(passphrase)}
	value, ok, err := testGet(store, "LEGACY")
	if err != nil || !ok || value != "value" {
		t.Fatalf("read legacy secret: value=%q ok=%v err=%v", value, ok, err)
	}
	if err := store.Set("NEW", "value"); err != nil {
		t.Fatalf("write migrated secret: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated store: %v", err)
	}
	var payload envelope
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode migrated store: %v", err)
	}
	if payload.Version != envelopeVersion {
		t.Fatalf("expected v%d after write, got v%d", envelopeVersion, payload.Version)
	}
	all, err := store.loadEntries()
	if err != nil {
		t.Fatalf("load migrated metadata: %v", err)
	}
	if all["LEGACY"].Version == "" || all["NEW"].Version == "" {
		t.Fatalf("migrated entries need versions: %#v", all)
	}
	mode, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat migrated store: %v", err)
	}
	if mode.Mode().Perm() != 0o600 {
		t.Fatalf("expected migrated store to be 0600, got %04o", mode.Mode().Perm())
	}
}

func encryptV1Values(values map[string]string, passphrase []byte) ([]byte, error) {
	plaintext, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt, argonTime, argonMemoryKiB, argonThreads)
	defer zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	payload := envelope{
		Version:    legacyVersion,
		KDF:        kdfName,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Time:       argonTime,
		MemoryKiB:  argonMemoryKiB,
		Threads:    argonThreads,
		Cipher:     cipherName,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, nil)),
	}
	return json.Marshal(payload)
}

func TestStoreRejectsTamperedMetadataAndUnsafeEnvelopeParameters(t *testing.T) {
	dir := t.TempDir()
	store := Store{Path: filepath.Join(dir, "secrets.enc"), Passphrase: "passphrase"}
	if err := store.Set("API_KEY", "value"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	raw, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var payload envelope
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	payload.Time++
	tampered, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal tampered envelope: %v", err)
	}
	if err := os.WriteFile(store.Path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered envelope: %v", err)
	}
	if _, _, err := testGet(store, "API_KEY"); err == nil {
		t.Fatal("expected tampered metadata to fail")
	}

	payload.Time = argonTime
	payload.MemoryKiB = argonMemoryKiB * 1024
	unsafe, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal unsafe envelope: %v", err)
	}
	if err := os.WriteFile(store.Path, unsafe, 0o600); err != nil {
		t.Fatalf("write unsafe envelope: %v", err)
	}
	if _, _, err := testGet(store, "API_KEY"); err == nil {
		t.Fatal("expected unsafe kdf parameters to fail before derivation")
	}
}

func TestStoreRejectsV2CiphertextWithoutAuthenticatedMetadata(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "secrets.enc"), Passphrase: "passphrase"}
	version, err := newVersionID()
	if err != nil {
		t.Fatalf("create version: %v", err)
	}
	plaintext, err := json.Marshal(v2Payload{Entries: map[string]Secret{"API_KEY": {Value: "value", Version: version}}})
	if err != nil {
		t.Fatalf("marshal v2 payload: %v", err)
	}
	salt := make([]byte, saltSize)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		t.Fatalf("random salt: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("random nonce: %v", err)
	}
	key := deriveKey([]byte(store.Passphrase), salt, argonTime, argonMemoryKiB, argonThreads)
	defer zero(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("create aead: %v", err)
	}
	payload := envelope{
		Version:    envelopeVersion,
		KDF:        kdfName,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Time:       argonTime,
		MemoryKiB:  argonMemoryKiB,
		Threads:    argonThreads,
		Cipher:     cipherName,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, nil)),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal unsigned envelope: %v", err)
	}
	if err := os.WriteFile(store.Path, raw, 0o600); err != nil {
		t.Fatalf("write unsigned envelope: %v", err)
	}
	if _, _, err := testGet(store, "API_KEY"); err == nil {
		t.Fatal("expected v2 ciphertext without authenticated metadata to fail")
	}
}

func TestStoreRejectsMalformedEnvelopeWithoutPanic(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "secrets.enc"), Passphrase: "passphrase"}
	malformed := [][]byte{
		[]byte(`{"version":2,"kdf":"argon2id","salt":"x","time":3,"memoryKiB":65536,"threads":4,"cipher":"xchacha20-poly1305","nonce":"x","ciphertext":"x"}`),
		[]byte(strings.Repeat("x", maxEnvelopeSize+1)),
	}
	for _, raw := range malformed {
		if err := os.WriteFile(store.Path, raw, 0o600); err != nil {
			t.Fatalf("write malformed store: %v", err)
		}
		if _, _, err := testGet(store, "KEY"); err == nil {
			t.Fatal("expected malformed envelope to fail")
		}
	}
}
