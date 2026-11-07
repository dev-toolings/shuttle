package backup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestCloudOptionalAndRejectsInsecureEndpoints(t *testing.T) {
	if err := UploadCloud(context.Background(), CloudOptions{}, "does-not-exist"); err != nil {
		t.Fatal(err)
	}
	for _, o := range []CloudOptions{{Endpoint: "https://example.test"}, {Bucket: "b", Endpoint: "http://example.test"}, {Bucket: "b", Endpoint: "https://secret@example.test"}, {Bucket: "b", Prefix: "../other"}} {
		if o.Validate() == nil {
			t.Fatalf("invalid cloud options accepted: %+v", o)
		}
	}
}

func TestCloudCommitFollowsVerifiedReadBack(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			var mu sync.Mutex
			var events []string
			var object []byte
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if strings.HasSuffix(r.URL.Path, ".receipt.json") {
					events = append(events, "receipt")
					if r.Header.Get("If-None-Match") != "*" {
						t.Error("receipt may overwrite an existing commit")
					}
					w.WriteHeader(200)
					return
				}
				switch r.Method {
				case "PUT":
					object, _ = io.ReadAll(r.Body)
					events = append(events, "upload")
					w.Header().Set("ETag", `"test"`)
					w.WriteHeader(200)
				case "GET":
					events = append(events, "download")
					if corrupt {
						w.Write([]byte("corrupt"))
					} else {
						w.Write(object)
					}
				default:
					t.Errorf("unexpected cloud request: %s", r.Method)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			client := s3.NewFromConfig(aws.Config{Region: "auto", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired, ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}, func(o *s3.Options) { o.BaseEndpoint = aws.String(server.URL); o.UsePathStyle = true })
			file := filepath.Join(t.TempDir(), "backup.tar.age")
			body := []byte("encrypted fixture")
			os.WriteFile(file, body, 0600)
			sum := sha256.Sum256(body)
			receipt, _ := json.Marshal(Receipt{Bytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
			os.WriteFile(file+".receipt.json", receipt, 0600)
			err := uploadCloudWithClient(context.Background(), client, CloudOptions{Bucket: "backups", Prefix: "owned"}, file)
			if corrupt && err == nil {
				t.Fatal("corrupt cloud object was committed")
			}
			if !corrupt && err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			got := strings.Join(events, ",")
			want := "upload,download,receipt"
			if corrupt {
				want = "upload,download"
			}
			if got != want {
				t.Fatalf("got %s; want %s", got, want)
			}
		})
	}
}

func TestCloudFetchRequiresTrustedReceiptBeforeDownloadingData(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("ciphertext fixture")
	sum := sha256.Sum256(body)
	receipt := Receipt{Schema: Schema, App: "demo", CreatedAt: time.Now().UTC().Format(time.RFC3339), Bytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	receipt.Sign(private)
	for _, trusted := range []bool{true, false} {
		var downloads atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".receipt.json") {
				json.NewEncoder(w).Encode(receipt)
				return
			}
			downloads.Add(1)
			w.Write(body)
		}))
		client := s3.NewFromConfig(aws.Config{Region: "auto", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired}, func(o *s3.Options) { o.BaseEndpoint = aws.String(server.URL); o.UsePathStyle = true })
		key := public
		if !trusted {
			key, _, _ = ed25519.GenerateKey(rand.Reader)
		}
		dir := filepath.Join(t.TempDir(), "fetched")
		target, err := fetchCloudWithClient(context.Background(), client, CloudOptions{Bucket: "backups"}, "owned/fixture.tar.age", dir, key)
		if trusted {
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadReceipt(target+".receipt.json", key); err != nil {
				t.Fatal(err)
			}
		} else {
			if err == nil || downloads.Load() != 0 {
				t.Fatal("untrusted receipt allowed a download")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("untrusted receipt created recovery files")
			}
		}
		server.Close()
	}
}
