package backup

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"filippo.io/age"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleArchive(t *testing.T, extra *tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	contents := []byte(`{"app":"demo"}`)
	sum := sha256.Sum256(contents)
	if err := tw.WriteHeader(&tar.Header{Name: "config.json", Size: int64(len(contents)), Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	tw.Write(contents)
	m := Manifest{Schema: Schema, App: "demo", Postgres: 17, Files: []File{{Path: "config.json", Size: int64(len(contents)), SHA256: hex.EncodeToString(sum[:])}}}
	if extra != nil {
		if err := tw.WriteHeader(extra); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := json.Marshal(m)
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(body))})
	tw.Write(body)
	tw.Close()
	return out.Bytes()
}
func TestArchiveRejectsTraversalLinksAndDuplicateFiles(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg},
		{Name: "state/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"},
		{Name: "config.json", Typeflag: tar.TypeReg},
		{Name: "state/device", Typeflag: tar.TypeChar},
	} {
		t.Run(header.Name, func(t *testing.T) {
			if _, err := VerifyArchive(bytes.NewReader(sampleArchive(t, header))); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	if _, err := VerifyArchive(bytes.NewReader(sampleArchive(t, nil))); err != nil {
		t.Fatal(err)
	}
}
func TestSignedEncryptedBackupRoundTripAndTampering(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	identity, _ := age.GenerateX25519Identity()
	filename := filepath.Join(t.TempDir(), "snapshot.age")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := age.Encrypt(f, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	writer.Write(sampleArchive(t, nil))
	writer.Close()
	f.Close()
	ciphertext, _ := os.ReadFile(filename)
	sum := sha256.Sum256(ciphertext)
	r := Receipt{Schema: Schema, App: "demo", CreatedAt: time.Now().UTC().Format(time.RFC3339), Bytes: int64(len(ciphertext)), SHA256: hex.EncodeToString(sum[:])}
	r.Sign(private)
	input, _ := os.Open(filename)
	defer input.Close()
	plaintext, m, err := DecryptVerified(input, r, public, identity)
	if err != nil {
		t.Fatal(err)
	}
	if m.App != "demo" {
		t.Fatal("wrong app")
	}
	plaintext.Close()
	os.Remove(plaintext.Name())
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if r.Verify(wrong) == nil {
		t.Fatal("untrusted signer accepted")
	}
	r.App = "other"
	if r.Verify(public) == nil {
		t.Fatal("modified receipt accepted")
	}
	r.App = "demo"
	ciphertext[len(ciphertext)-1] ^= 1
	os.WriteFile(filename, ciphertext, 0600)
	if _, _, err = DecryptVerified(input, r, public, identity); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestArchiveHashesFileContents(t *testing.T) {
	body := sampleArchive(t, nil)
	body = bytes.Replace(body, []byte(`{"app":"demo"}`), []byte(`{"app":"evil"}`), 1)
	if _, err := VerifyArchive(bytes.NewReader(body)); err == nil {
		t.Fatal("changed archive content accepted")
	}
}
func TestArchiveRejectsTruncation(t *testing.T) {
	body := sampleArchive(t, nil)
	if _, err := VerifyArchive(io.LimitReader(bytes.NewReader(body), 600)); err == nil {
		t.Fatal("truncated archive accepted")
	}
}
