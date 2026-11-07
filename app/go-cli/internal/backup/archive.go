// Package backup implements the encrypted, signed application recovery format.
package backup

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"filippo.io/age"
)

const Schema = "shuttle.application-backup/v1"

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Schema    string   `json:"schema"`
	App       string   `json:"app"`
	CreatedAt string   `json:"created_at"`
	Postgres  int      `json:"postgres"`
	Databases []string `json:"databases"`
	Volumes   []string `json:"volumes"`
	Files     []File   `json:"files"`
}

type Receipt struct {
	Schema    string `json:"schema"`
	App       string `json:"app"`
	Host      string `json:"host"`
	HostKey   string `json:"host_key"`
	CreatedAt string `json:"created_at"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

func (r Receipt) signingBytes() ([]byte, error) { r.Signature = ""; return json.Marshal(r) }
func (r *Receipt) Sign(key ed25519.PrivateKey) error {
	body, err := r.signingBytes()
	if err != nil {
		return err
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))
	return nil
}
func (r Receipt) Verify(key ed25519.PublicKey) error {
	if r.Schema != Schema || r.Bytes <= 0 || len(r.SHA256) != 64 || r.App == "" {
		return errors.New("invalid backup receipt")
	}
	if _, err := hex.DecodeString(r.SHA256); err != nil {
		return errors.New("invalid backup digest")
	}
	if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		return errors.New("invalid backup timestamp")
	}
	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return errors.New("invalid backup signature")
	}
	body, err := r.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, body, signature) {
		return errors.New("backup signature does not match the trusted verification key")
	}
	return nil
}

func ReadReceipt(filename string, key ed25519.PublicKey) (Receipt, error) {
	var r Receipt
	f, err := os.Open(filename)
	if err != nil {
		return r, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 64<<10))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return r, errors.New("receipt must contain one JSON document")
	}
	return r, r.Verify(key)
}

func VerifyCiphertext(file *os.File, r Receipt) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, file)
	if err != nil {
		return err
	}
	if n != r.Bytes || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		return errors.New("encrypted backup is truncated or its digest differs from the signed receipt")
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

// DecryptVerified authenticates the complete ciphertext before a restore can
// contact its target. The returned private temporary archive belongs to the
// caller, which must close and remove it even when later validation fails.
func DecryptVerified(cipher *os.File, r Receipt, key ed25519.PublicKey, identity age.Identity) (*os.File, Manifest, error) {
	var m Manifest
	if err := r.Verify(key); err != nil {
		return nil, m, err
	}
	if err := VerifyCiphertext(cipher, r); err != nil {
		return nil, m, err
	}
	reader, err := age.Decrypt(cipher, identity)
	if err != nil {
		return nil, m, err
	}
	tmp, err := os.CreateTemp("", "shuttle-restore-*.tar")
	if err != nil {
		return nil, m, err
	}
	good := false
	defer func() {
		if !good {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err = io.Copy(tmp, reader); err != nil {
		return nil, m, err
	}
	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return nil, m, err
	}
	m, err = VerifyArchive(tmp)
	if err != nil {
		return nil, m, err
	}
	if m.App != r.App {
		return nil, m, errors.New("archive application differs from signed receipt")
	}
	_, err = tmp.Seek(0, io.SeekStart)
	if err != nil {
		return nil, m, err
	}
	good = true
	return tmp, m, nil
}

func SafePath(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00\r\n") || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	if name == ".." || strings.HasPrefix(name, "../") {
		return false
	}
	for _, prefix := range []string{"postgres/", "volumes/", "state/", "images/"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return name == "config.json" || name == "manifest.json"
}

// VerifyArchive hashes every regular file, forbids links and special entries,
// and requires an exact manifest inventory. Nothing is extracted locally.
func VerifyArchive(input io.Reader) (Manifest, error) {
	var manifest Manifest
	files := map[string]File{}
	seen := map[string]bool{}
	tr := tar.NewReader(input)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest, err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !SafePath(name) || seen[name] {
			return manifest, fmt.Errorf("unsafe or duplicate archive entry %q", h.Name)
		}
		seen[name] = true
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return manifest, fmt.Errorf("archive links and special entries are forbidden: %q", name)
		}
		if h.Name == "manifest.json" {
			if h.Size > 4<<20 {
				return manifest, errors.New("backup manifest exceeds 4 MiB")
			}
			d := json.NewDecoder(tr)
			if err = d.Decode(&manifest); err != nil {
				return manifest, err
			}
			continue
		}
		sum := sha256.New()
		n, err := io.Copy(sum, tr)
		if err != nil {
			return manifest, err
		}
		files[name] = File{Path: name, Size: n, SHA256: hex.EncodeToString(sum.Sum(nil))}
		if len(files) > 100000 {
			return manifest, errors.New("backup exceeds 100000 files")
		}
	}
	if manifest.Schema != Schema || manifest.App == "" || (manifest.Postgres != 16 && manifest.Postgres != 17 && manifest.Postgres != 18) {
		return manifest, errors.New("invalid backup manifest")
	}
	if len(files) != len(manifest.Files) || len(files) == 0 {
		return manifest, errors.New("archive inventory differs from manifest")
	}
	for _, f := range manifest.Files {
		got, ok := files[f.Path]
		if !ok || got != f {
			return manifest, fmt.Errorf("archive content differs from manifest: %q", f.Path)
		}
		delete(files, f.Path)
	}
	return manifest, nil
}
