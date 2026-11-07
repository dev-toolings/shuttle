package cli

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

func TestPostgresBackupPublishesOnlyCompletePrivateArchives(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the VPS backup script requires Linux flock and GNU find/xargs")
	}
	gzipPath, err := exec.LookPath("gzip")
	if err != nil {
		t.Skip("gzip is required for the backup shell regression")
	}
	for _, failure := range []string{"", "dump", "compression"} {
		t.Run("failure="+failure, func(t *testing.T) {
			dir, bin := t.TempDir(), t.TempDir()
			old := filepath.Join(dir, "previous-valid.sql.gz")
			var previous bytes.Buffer
			writer := gzip.NewWriter(&previous)
			_, _ = writer.Write([]byte("previous valid backup"))
			_ = writer.Close()
			if err := os.WriteFile(old, previous.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			scripts := map[string]string{
				"runuser": `#!/bin/sh
printf '%s\n' 'synthetic SQL with private data'
if [ "$SHUTTLE_BACKUP_FAILURE" = dump ]; then exit 42; fi
`,
				"gzip": fmt.Sprintf(`#!/bin/sh
if [ "$SHUTTLE_BACKUP_FAILURE" = compression ] && [ "$1" = -9 ]; then
 cat >/dev/null
 printf 'incomplete archive'
 exit 43
fi
exec %q "$@"
`, gzipPath),
				"date": "#!/bin/sh\nprintf '20260904T120000Z\\n'\n",
			}
			for name, body := range scripts {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.Replace(postgresBackupScript, "dir=/var/backups/shuttle-postgres", "dir="+fmt.Sprintf("%q", dir), 1)
			script = strings.Replace(script, "retention_dir=/etc/shuttle/postgres-backup.d", "retention_dir="+fmt.Sprintf("%q", filepath.Join(t.TempDir(), "retention")), 1)
			runs := 1
			if failure == "" {
				runs = 2
			} // Same timestamp must not overwrite a valid archive.
			for i := 0; i < runs; i++ {
				cmd := exec.Command("bash", "-c", script)
				cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "SHUTTLE_BACKUP_FAILURE="+failure)
				output, err := cmd.CombinedOutput()
				if (err != nil) != (failure != "") {
					t.Fatalf("failure=%s err=%v output=%s", failure, err, output)
				}
			}
			original, err := os.ReadFile(old)
			if err != nil || !bytes.Equal(original, previous.Bytes()) {
				t.Fatal("previous valid archive changed")
			}
			partial, _ := filepath.Glob(filepath.Join(dir, ".backup-*"))
			if len(partial) != 0 {
				t.Fatalf("partial archives leaked: %v", partial)
			}
			archives, _ := filepath.Glob(filepath.Join(dir, "*.sql.gz"))
			want := 1
			if failure == "" {
				want = 3
			}
			if len(archives) != want {
				t.Fatalf("got %d archives, want %d", len(archives), want)
			}
			for _, path := range archives {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0600 {
					t.Fatalf("archive permissions: %v", info.Mode())
				}
				if path == old {
					continue
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				reader, err := gzip.NewReader(file)
				if err != nil {
					file.Close()
					t.Fatal(err)
				}
				decoded, err := io.ReadAll(reader)
				reader.Close()
				file.Close()
				if err != nil || string(decoded) != "synthetic SQL with private data\n" {
					t.Fatalf("incomplete dump: %q %v", decoded, err)
				}
			}
		})
	}
}

func TestPostgresBackupRetentionUsesLargestValidHostConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the VPS backup script requires Linux flock and GNU find/xargs")
	}
	if _, err := exec.LookPath("gzip"); err != nil {
		t.Skip("gzip is required for the backup shell regression")
	}
	tests := []struct {
		name        string
		configs     map[string]string
		want        int
		wantWarning bool
		dirAbsent   bool
	}{
		{"one", map[string]string{"demo.conf": "keep=1\n"}, 1, false, false},
		{"largest of apps", map[string]string{"small.conf": "keep=2\n", "large.conf": "keep=7\n"}, 7, false, false},
		{"empty config defaults to seven", nil, 7, false, false},
		{"absent config directory defaults to seven", nil, 7, false, true},
		{"malformed ignored", map[string]string{"demo.conf": "keep=2\n", "broken.conf": "keep=bogus\n"}, 2, true, false},
		{"only malformed defaults to seven", map[string]string{"broken.conf": "keep=8\n"}, 7, true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			backupDir := filepath.Join(root, "backups")
			retentionDir := filepath.Join(root, "retention")
			bin := filepath.Join(root, "bin")
			dirs := []string{backupDir, bin}
			if !test.dirAbsent {
				dirs = append(dirs, retentionDir)
			}
			for _, dir := range dirs {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for name, body := range test.configs {
				if err := os.WriteFile(filepath.Join(retentionDir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 10; i++ {
				path := filepath.Join(backupDir, fmt.Sprintf("dump-%02d.sql.gz", i))
				if err := os.WriteFile(path, []byte("old archive"), 0600); err != nil {
					t.Fatal(err)
				}
				mtime := time.Unix(int64(i+1), 0)
				if err := os.Chtimes(path, mtime, mtime); err != nil {
					t.Fatal(err)
				}
			}
			for name, body := range map[string]string{
				"runuser": "#!/bin/sh\nprintf 'synthetic SQL\\n'\n",
				"date":    "#!/bin/sh\nprintf '20261030T120000Z\\n'\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for name := range map[string]string{"notes.txt": "keep", "not-a-dump.sql.gz.tmp": "keep", "dump.sql": "keep"} {
				if err := os.WriteFile(filepath.Join(backupDir, name), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			script := strings.Replace(postgresBackupScript, "dir=/var/backups/shuttle-postgres", "dir="+fmt.Sprintf("%q", backupDir), 1)
			script = strings.Replace(script, "retention_dir=/etc/shuttle/postgres-backup.d", "retention_dir="+fmt.Sprintf("%q", retentionDir), 1)
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("backup failed: %v\n%s", err, output)
			}
			if gotWarning := strings.Contains(string(output), "ignoring malformed PostgreSQL backup retention config:"); gotWarning != test.wantWarning {
				t.Fatalf("malformed warning=%t, want %t; output=%s", gotWarning, test.wantWarning, output)
			}

			archives, err := filepath.Glob(filepath.Join(backupDir, "*.sql.gz"))
			if err != nil {
				t.Fatal(err)
			}
			if len(archives) != test.want {
				t.Fatalf("kept %d archives, want %d: %v", len(archives), test.want, archives)
			}
			kept := make(map[string]bool, len(archives))
			newestKept := false
			for _, archive := range archives {
				name := filepath.Base(archive)
				kept[name] = true
				if strings.HasPrefix(name, "20261030T120000Z-") {
					newestKept = true
				}
			}
			if !newestKept {
				t.Fatalf("newest archive was not retained: %v", archives)
			}
			for i := 9; i >= 10-test.want+1; i-- {
				name := fmt.Sprintf("dump-%02d.sql.gz", i)
				if !kept[name] {
					t.Fatalf("newest older archive %s was not retained: %v", name, archives)
				}
			}
			for _, name := range []string{"notes.txt", "not-a-dump.sql.gz.tmp", "dump.sql"} {
				if _, err := os.Stat(filepath.Join(backupDir, name)); err != nil {
					t.Fatalf("unrelated file %s was deleted: %v", name, err)
				}
			}
		})
	}
}

func TestPostgresBackupMigrationResumesWithoutReconfiguringDatabase(t *testing.T) {
	for _, state := range []string{"legacy", "shipped", "current", "customized", "missing", "symlink"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			sbin := filepath.Join(dir, "sbin")
			checkpoints := filepath.Join(dir, "checkpoints")
			retentionDir := filepath.Join(dir, "retention")
			for _, path := range []string{sbin, checkpoints, retentionDir} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			// A host that already converged: every checkpoint, including the
			// old one-shot 31-postgres-backup, is marked done. The policy and
			// its retention must still be applied.
			for _, marker := range []string{"30-postgres", "31-postgres-backup", "32-postgres-boot-order"} {
				if err := os.WriteFile(filepath.Join(checkpoints, marker), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			policy := filepath.Join(sbin, "shuttle-postgres-backup")
			before := legacyPostgresBackupScript
			if state == "shipped" {
				before = previousPostgresBackupScript
			}
			if state == "current" {
				before = postgresBackupScript
			}
			if state == "customized" {
				before = previousPostgresBackupScript
				before += "# operator customization\n"
			}
			if state == "symlink" {
				target := filepath.Join(dir, "operator-script")
				if err := os.WriteFile(target, []byte(before), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, policy); err != nil {
					t.Fatal(err)
				}
			} else if state != "missing" {
				if err := os.WriteFile(policy, []byte(before), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.Config{
				App:      "demo",
				Database: config.DatabaseConfig{Version: 17},
				Retention: config.RetentionConfig{
					Backups: 3,
				},
			}
			postgresCommand := postgresStage(t, cfg)
			script := strings.ReplaceAll(postgresCommand, "/usr/local/sbin", sbin)
			script = strings.ReplaceAll(script, "/etc/shuttle/setup.d", checkpoints)
			script = strings.ReplaceAll(script, "install -d -o root -g root -m 0700 /etc/shuttle/postgres-backup.d", "install -d -m 0700 "+retentionDir)
			script = strings.ReplaceAll(script, "retention_file='/etc/shuttle/postgres-backup.d/demo.conf'", "retention_file='"+filepath.Join(retentionDir, "demo.conf")+"'")
			script = strings.ReplaceAll(script, "install -o root -g root -m 0600 /dev/null", "install -m 0600 /dev/null")
			script = strings.ReplaceAll(script, "chown root:root \"$retention_file\"", ":")
			cmd := exec.Command("sh", "-c", script)
			output, err := cmd.CombinedOutput()
			success := state == "legacy" || state == "shipped" || state == "current"
			if (err == nil) != success {
				t.Fatalf("state=%s err=%v output=%s", state, err, output)
			}
			if state == "customized" && !strings.Contains(string(output), "differs from the known policy; refusing automatic migration") {
				t.Fatalf("modified shipped policy was not refused: %s", output)
			}
			retentionFile := filepath.Join(retentionDir, "demo.conf")
			if success {
				body, err := os.ReadFile(retentionFile)
				if err != nil || string(body) != "keep=3\n" {
					t.Fatalf("retention config=%q err=%v, want keep=3", body, err)
				}
				info, err := os.Stat(retentionFile)
				if err != nil {
					t.Fatalf("stat retention config: %v", err)
				}
				if info.Mode().Perm() != 0600 {
					t.Fatalf("retention config mode=%v, want 0600", info.Mode())
				}
			}
			if state != "missing" {
				after, err := os.ReadFile(policy)
				if err != nil {
					t.Fatal(err)
				}
				want := before
				if success {
					want = postgresBackupScript
				}
				if string(after) != want {
					t.Fatal("unexpected backup policy change")
				}
			}
			leftovers, _ := filepath.Glob(filepath.Join(sbin, ".shuttle-postgres-backup.*"))
			if len(leftovers) != 0 {
				t.Fatalf("migration leaked work files: %v", leftovers)
			}
		})
	}
}
