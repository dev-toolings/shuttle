package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type CloudOptions struct{ Bucket, Endpoint, Region, Prefix string }

func (o CloudOptions) Validate() error {
	if o.Bucket == "" {
		if o.Endpoint != "" || o.Region != "" {
			return errors.New("cloud endpoint/region require --bucket")
		}
		return nil
	}
	if strings.ContainsAny(o.Bucket, "/\\\r\n") || strings.Contains(o.Prefix, "..") || strings.HasPrefix(o.Prefix, "/") || strings.ContainsAny(o.Prefix, "\\\r\n") {
		return errors.New("invalid backup bucket or object prefix")
	}
	if o.Endpoint != "" {
		u, err := url.Parse(o.Endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("cloud endpoint must be an HTTPS URL without embedded credentials")
		}
	}
	return nil
}

// UploadCloud is optional. A receipt is published only after the encrypted
// object has been read back and verified. Failed multipart uploads are aborted.
func UploadCloud(ctx context.Context, o CloudOptions, filename string) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if o.Bucket == "" {
		return nil
	}
	client, err := cloudClient(ctx, o)
	if err != nil {
		return err
	}
	return uploadCloudWithClient(ctx, client, o, filename)
}

func cloudClient(ctx context.Context, o CloudOptions) (*s3.Client, error) {
	options := []func(*awsconfig.LoadOptions) error{}
	region := o.Region
	if region == "" && strings.Contains(o.Endpoint, ".r2.cloudflarestorage.com") {
		region = "auto"
	}
	if region != "" {
		options = append(options, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, err
	}
	cfg.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	cfg.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	client := s3.NewFromConfig(cfg, func(s *s3.Options) {
		if o.Endpoint != "" {
			s.BaseEndpoint = aws.String(o.Endpoint)
			s.UsePathStyle = true
		}
	})
	return client, nil
}

func uploadCloudWithClient(ctx context.Context, client *s3.Client, o CloudOptions, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	receiptBody, err := os.ReadFile(filename + ".receipt.json")
	if err != nil {
		return err
	}
	var receipt Receipt
	if err = json.Unmarshal(receiptBody, &receipt); err != nil {
		return err
	}
	if err = VerifyCiphertext(file, receipt); err != nil {
		return err
	}
	// A retry owns a fresh namespace. This operation never selects an existing
	// backup for overwrite or deletion.
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	key := path.Join(o.Prefix, hex.EncodeToString(nonce), filepath.Base(filename))
	uploader := manager.NewUploader(client, func(u *manager.Uploader) { u.Concurrency = 2; u.PartSize = 16 << 20 })
	if _, err = uploader.Upload(ctx, &s3.PutObjectInput{Bucket: aws.String(o.Bucket), Key: aws.String(key), Body: file, ContentType: aws.String("application/octet-stream")}); err != nil {
		return err
	}
	downloaded, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(o.Bucket), Key: aws.String(key)})
	if err != nil {
		return err
	}
	sum := sha256.New()
	n, copyErr := io.Copy(sum, downloaded.Body)
	closeErr := downloaded.Body.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != receipt.Bytes || hex.EncodeToString(sum.Sum(nil)) != receipt.SHA256 {
		return errors.New("cloud object read-back differs from the signed backup; no receipt published")
	}
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(o.Bucket), Key: aws.String(key + ".receipt.json"), Body: bytes.NewReader(receiptBody), ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*")})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Cloud backup: s3://%s/%s\n", o.Bucket, key)
	return nil
}

// FetchCloud trusts an independently retained verification key, never a key
// supplied alongside the remote object. Incomplete uploads have no valid receipt.
func FetchCloud(ctx context.Context, o CloudOptions, object, output string, key ed25519.PublicKey) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	if o.Bucket == "" || object == "" || !strings.HasSuffix(object, ".tar.age") || strings.Contains(object, "..") {
		return "", errors.New("fetch requires --bucket and an exact .tar.age object key")
	}
	client, err := cloudClient(ctx, o)
	if err != nil {
		return "", err
	}
	return fetchCloudWithClient(ctx, client, o, object, output, key)
}

func fetchCloudWithClient(ctx context.Context, client *s3.Client, o CloudOptions, object, output string, key ed25519.PublicKey) (string, error) {
	remote, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(o.Bucket), Key: aws.String(object + ".receipt.json")})
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(remote.Body, (64<<10)+1))
	remote.Body.Close()
	if err != nil {
		return "", err
	}
	if len(body) > 64<<10 {
		return "", errors.New("cloud receipt exceeds size limit")
	}
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&receipt); err != nil {
		return "", err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", errors.New("cloud receipt must contain one JSON document")
	}
	if err = receipt.Verify(key); err != nil {
		return "", err
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(output, ".shuttle-fetch-*.partial")
	if err != nil {
		return "", err
	}
	defer func() { temp.Close(); os.Remove(temp.Name()) }()
	data, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(o.Bucket), Key: aws.String(object)})
	if err != nil {
		return "", err
	}
	_, err = io.Copy(temp, io.LimitReader(data.Body, receipt.Bytes+1))
	data.Body.Close()
	if err != nil {
		return "", err
	}
	if err = VerifyCiphertext(temp, receipt); err != nil {
		return "", err
	}
	if err = temp.Sync(); err != nil {
		return "", err
	}
	target := filepath.Join(output, path.Base(object))
	if err = os.Link(temp.Name(), target); err != nil {
		return "", err
	}
	committed, err := os.OpenFile(target+".receipt.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		os.Remove(target)
		return "", err
	}
	_, err = committed.Write(body)
	if err == nil {
		err = committed.Sync()
	}
	closeErr := committed.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(target)
		os.Remove(target + ".receipt.json")
		return "", err
	}
	return target, nil
}
