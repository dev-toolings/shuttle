package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAdoptionRetentionSurvivesInterruptedWrite(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/demo.conf"
	if err := os.WriteFile(path, []byte("keep=7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := adoptionApplyConfig(t)
	cfg.Retention.Backups = 3
	var program string
	for _, stage := range adoptionSetupStages(cfg, 22, adoptionPrerequisiteFixture(t)) {
		if stage.name == "31-postgres-backup-script" {
			program = stage.command
		}
	}
	program = strings.NewReplacer("/etc/shuttle/postgres-backup.d", dir, "/usr/local/sbin/shuttle-postgres-backup", dir+"/backup", "/var/backups/shuttle-postgres", dir+"/backups").Replace(program)
	bin := dir + "/bin"
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"install": "#!/bin/sh\nlast=\nfor arg do last=$arg; done\ncase \"$1\" in -d) mkdir -p \"$last\" ;; *) cp /dev/null \"$last\"; exit 71 ;; esac\n", "chown": "#!/bin/sh\nexit 0\n", "chmod": "#!/bin/sh\nexit 0\n", "mv": "#!/bin/sh\nexit 71\n"} {
		if err := os.WriteFile(bin+"/"+name, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", program)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected interruption: %s", out)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "keep=7\n" {
		t.Fatalf("interruption damaged existing retention: %q, %v", value, err)
	}
}
