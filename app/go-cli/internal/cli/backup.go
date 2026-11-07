package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backup"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/backuplifecycle"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/rootplan"
	shuttlessh "github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"github.com/spf13/cobra"
)

func newBackupCommand() *cobra.Command {
	root := &cobra.Command{Use: "backup", Short: "Create encrypted application backups and verify isolated native PostgreSQL restores"}
	root.AddCommand(newBackupFetchCommand(), newBackupKeygenCommand(), newBackupCreateCommand(), newBackupVerifyCommand(false), newBackupVerifyCommand(true))
	return root
}

func newBackupKeygenCommand() *cobra.Command {
	var output string
	c := &cobra.Command{Use: "keygen", Short: "Create a local age recovery identity without overwriting an existing file", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if output == "" {
			return errors.New("--output is required; the private identity must be kept outside the VPS")
		}
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		if err = writeBackupExclusive(output, []byte(identity.String()+"\n")); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Recovery identity written to %s (0600). Public recipient: %s\n", output, identity.Recipient())
		return nil
	}}
	c.Flags().StringVar(&output, "output", "", "local private recovery identity file")
	return c
}

func writeBackupExclusive(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(body); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	good = true
	return f.Close()
}

type backupLifecycleStatus = backuplifecycle.Status

const backupLifecycleSchema = backuplifecycle.Schema

func saveBackupLifecycle(path string, status backupLifecycleStatus) error {
	body, err := backuplifecycle.Marshal(status)
	if err != nil {
		return err
	}
	return backuplifecycle.WriteStatusFile(path, append(body, '\n'))
}

func writeBackupFailure(path, app string, now time.Time) error {
	stamp := now.UTC().Format(time.RFC3339Nano)
	return saveBackupLifecycle(path, backupLifecycleStatus{Schema: backupLifecycleSchema, App: app, CreatedAt: stamp, UpdatedAt: stamp, State: backuplifecycle.StateFailed, SourceCapture: backuplifecycle.StageFailed, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: backuplifecycle.StageNotStarted, AttemptID: "backup-failure", Phase: backuplifecycle.PhaseFailed, Host: "local", HostKey: "SHA256:" + strings.Repeat("A", 43)})
}

func publishBackupLifecycle(cfg *config.Config, client *shuttlessh.Client, host, hostKey string, status backupLifecycleStatus) error {
	if client == nil {
		return errors.New("backup lifecycle requires an authenticated root helper client")
	}
	body, err := backuplifecycle.Marshal(status)
	if err != nil {
		return err
	}
	privatePath, _, err := ensureRootOperationKeyPair()
	if err != nil {
		return err
	}
	key, err := rootplan.ReadPrivateKey(privatePath)
	if err != nil {
		return err
	}
	identity, err := loadTrustedHostIdentity(host, mustServerPort(cfg))
	if err != nil {
		return err
	}
	plan, err := rootplan.NewBackupStatus(cfg.App, status.AttemptID, rootplan.PayloadDigest(body), identity.OperatorKeyFingerprint, hostKey, time.Now().UTC(), 5*time.Minute)
	if err != nil {
		return err
	}
	plan, err = rootplan.Sign(plan, key)
	if err != nil {
		return err
	}
	envelope, err := encodeRootHelperEnvelope(plan, body)
	if err != nil {
		return err
	}
	result := client.RunWithStdin("sudo -n /usr/local/libexec/shuttle-root apply", envelope)
	if result.Code != 0 {
		return errors.New("root helper rejected backup lifecycle status")
	}
	return nil
}

func mustServerPort(cfg *config.Config) int {
	group, _, err := singleVPS(cfg)
	if err != nil {
		return 0
	}
	return group.Port
}

func backupAdministrator(cfg *config.Config) (*shuttlessh.Client, string, string, error) {
	group, host, err := singleVPS(cfg)
	if err != nil {
		return nil, "", "", err
	}
	if cfg.Deploy.Strategy != "swarm" {
		return nil, "", "", errors.New("application backup currently requires the managed Swarm strategy")
	}
	operator := cfg.Setup.OperatorUser
	if operator == "" || operator == "deploy" || operator == "root" {
		return nil, "", "", errors.New("backup requires setup.operator_user naming the separate SSH administrator")
	}
	identity, err := loadTrustedHostIdentity(host, group.Port)
	if err != nil {
		return nil, "", "", err
	}
	client, err := shuttlessh.NewClientExactWithFingerprint(host, operator, group.Port, identity.HostKeyFingerprint)
	if err == nil {
		client.SetOperationTimeout(35 * time.Minute)
	}
	return client, host, identity.HostKeyFingerprint, err
}

func newBackupCreateCommand() *cobra.Command {
	var flags configFlags
	var output, recipient string
	var volumes []string
	var yes, dryRun bool
	var cloud backup.CloudOptions
	c := &cobra.Command{Use: "create", Short: "Quiesce the application and export an encrypted backup outside its VPS", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) (backupErr error) {
		var finishLifecycle func(error) error
		// Registered first, so lifecycle completion observes renewal, local
		// cleanup and operation-finalization errors from every later defer.
		defer func() {
			if finishLifecycle != nil {
				backupErr = finishLifecycle(backupErr)
			}
		}()

		cfg, err := loadWithFlags(flags)
		if err != nil {
			return err
		}
		if !cfg.Database.Managed() {
			return errors.New("backup requires a declared native PostgreSQL 16, 17 or 18 cluster")
		}
		parsedRecipient, err := age.ParseX25519Recipient(recipient)
		if err != nil {
			return fmt.Errorf("--recipient must be an age public recipient: %w", err)
		}
		if output == "" {
			return errors.New("--output is required (directory outside the source VPS)")
		}
		if err = cloud.Validate(); err != nil {
			return err
		}
		client, host, pin, err := backupAdministrator(cfg)
		if err != nil {
			return err
		}
		databases := []string{}
		for _, d := range cfg.Database.Databases {
			databases = append(databases, d.Name)
		}
		if len(databases) == 0 {
			databases = []string{config.DerivedDatabaseIdentifier(cfg.App)}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Backup %s from %s: native PostgreSQL %d, databases %v, explicit volumes %v.\nThe application's services are stopped during the snapshot, then restored to their original replica counts.\n", cfg.App, host, cfg.Database.Version, databases, volumes)
		if dryRun {
			request := map[string]any{"app": cfg.App, "postgres": cfg.Database.Version, "databases": databases, "volumes": volumes, "dry_run": true}
			body, err := json.Marshal(request)
			if err != nil {
				return err
			}
			command, err := backup.PythonCommand(backup.SourceScript, nil)
			if err != nil {
				return err
			}
			result := client.RunWithStreams(command, bytes.NewReader(body), cmd.OutOrStdout())
			if result.Code != 0 {
				return fmt.Errorf("backup preflight failed: %s", strings.TrimSpace(result.Stderr))
			}
			return nil
		}
		if !yes {
			return errors.New("backup create requires --yes to authorize the snapshot's application downtime; use --dry-run first")
		}
		privatePath, _, err := ensureRootOperationKeyPair()
		if err != nil {
			return err
		}
		signingKey, err := rootplan.ReadPrivateKey(privatePath)
		if err != nil {
			return err
		}
		group, _, err := singleVPS(cfg)
		if err != nil {
			return err
		}
		identity, err := loadTrustedHostIdentity(host, group.Port)
		if err != nil {
			return err
		}
		controlClient, err := connectSSH(group, host)
		if err != nil {
			return err
		}
		operation, err := beginRemoteOperation(controlClient, identity, signingKey, "backup", cfg.App)
		if err != nil {
			return err
		}
		// finish follows backupErr. Completing on a published flag while
		// directory sync, requested cloud verification or keepAlive had failed
		// reported "all requested changes verified" for an incomplete backup.
		// Local archive and receipt stay on disk when a later step fails.
		defer operation.finish(&backupErr)
		configBody, err := recoveryConfiguration(cfg)
		if err != nil {
			return err
		}
		var document any
		if err = json.Unmarshal(configBody, &document); err != nil {
			return err
		}
		request := map[string]any{"app": cfg.App, "postgres": cfg.Database.Version, "databases": databases, "volumes": volumes, "config": document, "operation": map[string]string{"id": operation.id, "principal": identity.OperatorKeyFingerprint, "owner_key_fingerprint": identity.OperatorKeyFingerprint, "host": identity.HostKeyFingerprint}}
		command, err := backup.PythonCommand(backup.SourceScript, nil)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(output, 0o700); err != nil {
			return err
		}
		remoteLifecycle, err := negotiateBackupLifecycle(cfg, client, host)
		if err != nil {
			return err
		}
		if !remoteLifecycle {
			fmt.Fprintln(cmd.OutOrStdout(), "Backup lifecycle is local-only: the installed root helper cannot publish remote status.")
		}
		startedAt := time.Now().UTC()
		attemptID := backupLifecycleAttemptID(operation.id)
		cloudState := backuplifecycle.CloudNotConfigured
		if cloud.Bucket != "" {
			cloudState = backuplifecycle.StageNotStarted
		}
		lifecycle := backupLifecycleStatus{Schema: backupLifecycleSchema, App: cfg.App, CreatedAt: lifecycleTimestamp(startedAt), UpdatedAt: lifecycleTimestamp(startedAt), State: backuplifecycle.StatePending, SourceCapture: backuplifecycle.StageNotStarted, Encryption: backuplifecycle.StageNotStarted, Receipt: backuplifecycle.StageNotStarted, Cloud: cloudState, AttemptID: attemptID, Phase: backuplifecycle.PhaseSource, Host: host, HostKey: pin}
		lifecyclePath := filepath.Join(output, cfg.App+"-"+attemptID+".status.json")
		publish := func(status backupLifecycleStatus) error {
			if !remoteLifecycle {
				return nil
			}
			return publishBackupLifecycle(cfg, client, host, pin, status)
		}
		if err := persistLocalLifecycle(lifecyclePath, lifecycle); err != nil {
			return err
		}
		fail := func(cause error) error {
			markLifecycleFailure(&lifecycle, time.Now())
			localErr := persistLocalLifecycle(lifecyclePath, lifecycle)
			remoteErr := publish(lifecycle)
			return lifecycleFailure(cause, localErr, remoteErr)
		}
		if err := publish(lifecycle); err != nil {
			return fail(fmt.Errorf("could not publish backup lifecycle start: %w", err))
		}
		finishLifecycle = func(finalErr error) error {
			if finalErr != nil && lifecycle.State == backuplifecycle.StateFailed {
				return finalErr
			}
			if finalErr != nil {
				markLifecycleFailure(&lifecycle, time.Now())
			} else {
				lifecycle.State = backuplifecycle.StateComplete
				lifecycle.Phase = backuplifecycle.PhaseComplete
				lifecycle.UpdatedAt = lifecycleTimestamp(time.Now())
			}
			return lifecycleFailure(finalErr, persistLocalLifecycle(lifecyclePath, lifecycle), publish(lifecycle))
		}
		temp, err := os.CreateTemp(output, ".shuttle-backup-*.partial")
		if err != nil {
			return fail(err)
		}
		defer func() { backupErr = errors.Join(backupErr, temp.Close(), os.Remove(temp.Name())) }()
		hash := sha256.New()
		encrypted, err := age.Encrypt(io.MultiWriter(temp, hash), parsedRecipient)
		if err != nil {
			return fail(err)
		}
		requestBody, err := json.Marshal(request)
		if err != nil {
			return fail(err)
		}
		// Renew before the source dump, not after it. Capture can run for most
		// of the 35-minute lease; starting keepAlive only once Python returned
		// left the reservation looking abandoned mid-quiesce.
		stopRenewal := operation.keepAlive(func() error { return nil })
		defer func() { backupErr = errors.Join(backupErr, stopRenewal()) }()
		result := client.RunWithStreams(command, bytes.NewReader(requestBody), encrypted)
		if result.Code != 0 {
			return fail(fmt.Errorf("backup source failed: %s", strings.TrimSpace(result.Stderr)))
		}
		markSourceCaptureComplete(&lifecycle, time.Now())
		if err := persistLocalLifecycle(lifecyclePath, lifecycle); err != nil {
			return fail(err)
		}
		if err := publish(lifecycle); err != nil {
			return fail(fmt.Errorf("could not publish completed source capture: %w", err))
		}
		if err = encrypted.Close(); err != nil {
			return fail(err)
		}
		if err = temp.Sync(); err != nil {
			return fail(err)
		}
		markEncryptionComplete(&lifecycle, time.Now())
		if err := persistLocalLifecycle(lifecyclePath, lifecycle); err != nil {
			return fail(err)
		}
		if err := publish(lifecycle); err != nil {
			return fail(fmt.Errorf("could not publish completed encryption: %w", err))
		}
		info, err := temp.Stat()
		if err != nil {
			return fail(err)
		}
		now := time.Now().UTC()
		receipt := backup.Receipt{Schema: backup.Schema, App: cfg.App, Host: host, HostKey: pin, CreatedAt: now.Format(time.RFC3339), Bytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))}
		if err = receipt.Sign(signingKey); err != nil {
			return fail(err)
		}
		target := filepath.Join(output, cfg.App+"-"+now.Format("20060102T150405")+"-"+strings.TrimSuffix(strings.TrimPrefix(filepath.Base(temp.Name()), ".shuttle-backup-"), ".partial")+".tar.age")
		if err = os.Link(temp.Name(), target); err != nil {
			return fail(err)
		}
		body, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			return fail(err)
		}
		if err = writeBackupExclusive(target+".receipt.json", append(body, '\n')); err != nil {
			os.Remove(target)
			return fail(err)
		}
		directory, err := os.Open(output)
		if err != nil {
			return fail(err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if err := errors.Join(syncErr, closeErr); err != nil {
			return fail(fmt.Errorf("persist encrypted archive and receipt directory: %w", err))
		}
		lifecyclePath = target + ".status.json"
		lifecycle.Receipt = backuplifecycle.StageComplete
		lifecycle.ArchiveSHA256 = hex.EncodeToString(hash.Sum(nil))
		lifecycle.Phase = backuplifecycle.PhaseReceipt
		lifecycle.UpdatedAt = lifecycleTimestamp(time.Now())
		if err := persistLocalLifecycle(lifecyclePath, lifecycle); err != nil {
			return fail(err)
		}
		if err := publish(lifecycle); err != nil {
			return fail(fmt.Errorf("could not publish verified receipt: %w", err))
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Encrypted backup committed: %s\nSignature receipt: %s.receipt.json\n", target, target)
		if cloud.Bucket != "" {
			if err = backup.UploadCloud(cmd.Context(), cloud, target); err != nil {
				lifecycle.Cloud = backuplifecycle.CloudFailed
				lifecycle.State = backuplifecycle.StateFailed
				lifecycle.Phase = backuplifecycle.PhaseCloudFailed
				lifecycle.Error = "optional cloud upload failed"
				lifecycle.UpdatedAt = lifecycleTimestamp(time.Now())
				localErr := persistLocalLifecycle(lifecyclePath, lifecycle)
				remoteErr := publish(lifecycle)
				return lifecycleFailure(fmt.Errorf("local backup preserved; optional cloud upload failed: %w", err), localErr, remoteErr)
			}
			lifecycle.Cloud = backuplifecycle.CloudComplete
			lifecycle.Phase = backuplifecycle.PhaseCloud
			lifecycle.UpdatedAt = lifecycleTimestamp(time.Now())
			if err := persistLocalLifecycle(lifecyclePath, lifecycle); err != nil {
				return fail(err)
			}
			if err := publish(lifecycle); err != nil {
				return fail(fmt.Errorf("could not publish completed cloud receipt: %w", err))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Cloud copy downloaded and verified; signed receipt published last.")
		}
		return nil
	}}
	addConfigFlags(c, &flags)
	c.Flags().StringVar(&output, "output", "", "local directory for encrypted archives and signed receipts")
	c.Flags().StringVar(&recipient, "recipient", "", "age public recipient; the private identity never goes to the VPS")
	c.Flags().StringSliceVar(&volumes, "volume", nil, "explicit Docker volume names; must cover all application volumes")
	c.Flags().BoolVar(&yes, "yes", false, "authorize application downtime for a consistent snapshot")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "describe the backup without changing the VPS")
	c.Flags().StringVar(&cloud.Bucket, "bucket", "", "optional AWS S3 or Cloudflare R2 bucket")
	c.Flags().StringVar(&cloud.Endpoint, "endpoint", "", "optional HTTPS S3 endpoint, including the R2 account endpoint")
	c.Flags().StringVar(&cloud.Region, "region", "", "AWS region; use auto for Cloudflare R2")
	c.Flags().StringVar(&cloud.Prefix, "prefix", "shuttle-backups", "object prefix inside the optional bucket")
	return c
}

func newBackupVerifyCommand(restore bool) *cobra.Command {
	var identityFile, verifyKeyFile, target, hostKey string
	var port int
	var yes, dryRun bool
	name, description := "verify", "Verify the signed ciphertext, decrypt it and check every archived file"
	if restore {
		name, description = "restore", "Restore into a fresh, isolated native PostgreSQL cluster and new Docker volumes"
	}
	c := &cobra.Command{Use: name + " <archive.tar.age>", Short: description, Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if identityFile == "" || verifyKeyFile == "" {
			return errors.New("--identity and --verify-key are required; use independently retained local keys")
		}
		info, err := os.Stat(identityFile)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("private recovery identity must have mode 0600")
		}
		body, err := os.ReadFile(identityFile)
		if err != nil {
			return err
		}
		identity, err := age.ParseX25519Identity(strings.TrimSpace(string(body)))
		if err != nil {
			return err
		}
		key, err := rootplan.ReadTrustedKey(verifyKeyFile)
		if err != nil {
			return err
		}
		receipt, err := backup.ReadReceipt(args[0]+".receipt.json", key)
		if err != nil {
			return err
		}
		file, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer file.Close()
		archive, manifest, err := backup.DecryptVerified(file, receipt, key, identity)
		if err != nil {
			return err
		}
		defer func() { archive.Close(); os.Remove(archive.Name()) }()
		fmt.Fprintf(cmd.OutOrStdout(), "Verified signed backup: %s, native PostgreSQL %d, %d files.\n", manifest.App, manifest.Postgres, len(manifest.Files))
		if !restore {
			return nil
		}
		if target == "" || hostKey == "" {
			return errors.New("restore requires --target operator@host and --host-key for the isolated target")
		}
		parts := strings.Split(target, "@")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[0] == "deploy" {
			return errors.New("--target must name an SSH administrator, not deploy")
		}
		if dryRun {
			fmt.Fprintln(cmd.OutOrStdout(), "Would restore into a newly named native cluster with no TCP listener, and fresh volumes; no live application is switched.")
			return nil
		}
		if !yes {
			return errors.New("restore requires --yes after verifying its isolated target")
		}
		client, err := shuttlessh.NewClientExactWithFingerprint(parts[1], parts[0], port, hostKey)
		if err != nil {
			return err
		}
		client.SetOperationTimeout(35 * time.Minute)
		command, err := backup.PythonCommand(backup.RestoreScript, map[string]string{"app": manifest.App})
		if err != nil {
			return err
		}
		result := client.RunWithReader(command, archive)
		if result.Stdout != "" {
			fmt.Fprintln(cmd.OutOrStdout(), result.Stdout)
		}
		if result.Code != 0 {
			return fmt.Errorf("isolated restore failed: %s", strings.TrimSpace(result.Stderr))
		}
		return nil
	}}
	c.Flags().StringVar(&identityFile, "identity", "", "local age private recovery identity")
	c.Flags().StringVar(&verifyKeyFile, "verify-key", "", "trusted Ed25519 verification key PEM retained independently of the backup")
	if restore {
		c.Flags().StringVar(&target, "target", "", "SSH administrator on the isolated restore target")
		c.Flags().StringVar(&hostKey, "host-key", "", "independently verified target ED25519 host fingerprint")
		c.Flags().IntVar(&port, "port", 22, "target SSH port")
		c.Flags().BoolVar(&yes, "yes", false, "create isolated recovery resources")
		c.Flags().BoolVar(&dryRun, "dry-run", false, "verify the archive and describe the isolated restore")
	}
	return c
}

func newBackupFetchCommand() *cobra.Command {
	var cloud backup.CloudOptions
	var object, output, verifyKey string
	c := &cobra.Command{Use: "fetch", Short: "Download a committed S3 or R2 backup and verify its signature and ciphertext", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if output == "" || verifyKey == "" {
			return errors.New("fetch requires --output and an independently retained --verify-key")
		}
		key, err := rootplan.ReadTrustedKey(verifyKey)
		if err != nil {
			return err
		}
		target, err := backup.FetchCloud(cmd.Context(), cloud, object, output, key)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Verified cloud backup downloaded: %s\n", target)
		return nil
	}}
	c.Flags().StringVar(&cloud.Bucket, "bucket", "", "AWS S3 or Cloudflare R2 bucket")
	c.Flags().StringVar(&cloud.Endpoint, "endpoint", "", "HTTPS S3 endpoint for Cloudflare R2")
	c.Flags().StringVar(&cloud.Region, "region", "", "AWS region, or auto for R2")
	c.Flags().StringVar(&object, "key", "", "exact encrypted object key printed by backup create")
	c.Flags().StringVar(&output, "output", "", "destination directory")
	c.Flags().StringVar(&verifyKey, "verify-key", "", "trusted Ed25519 verification key PEM")
	return c
}

// Config.Load materializes legacy server groups internally for SSH callers.
// They must not be serialized into a recovery config: the public v2 loader
// correctly rejects a nonempty legacy servers block.
func recoveryConfiguration(cfg *config.Config) ([]byte, error) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var document map[string]json.RawMessage
	if err = json.Unmarshal(body, &document); err != nil {
		return nil, err
	}
	delete(document, "servers")
	return json.Marshal(document)
}
