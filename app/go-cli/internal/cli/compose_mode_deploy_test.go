package cli

import (
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/ssh"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposeDockerSSHUsesConfiguredEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, host     string
		port           int
		account, known string
	}{
		{"default", "example.test", 22, "bob@example.test", "example.test"},
		{"custom", "example.test", 2222, "bob@example.test:2222", "[example.test]:2222"},
		{"ipv6", "2001:db8::1", 2222, "bob@[2001:db8::1]:2222", "[2001:db8::1]:2222"},
		{"ipv6-default", "2001:db8::1", 22, "bob@[2001:db8::1]", "2001:db8::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := composeTestConfig(t)
			for name, group := range cfg.Servers {
				group.Hosts = []string{tc.host}
				group.Port = tc.port
				cfg.Servers[name] = group
			}
			if got := "ssh://" + composeAccount(cfg); got != "ssh://"+tc.account {
				t.Errorf("Docker URI = %s, want ssh://%s", got, tc.account)
			}
			dir := t.TempDir()
			args := filepath.Join(dir, "args")
			t.Setenv("SSH_TEST_ARGS", args)
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SSH_TEST_ARGS\"\nprintf '%s\\n' 'host ED25519 " + (composeHost{cfg: cfg}).cfgHostKey() + "'\n"
			if err := os.WriteFile(filepath.Join(dir, "ssh-keygen"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			if err := (composeHost{cfg: cfg, address: tc.host}).verifyDockerSSHTransport(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(args)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(got)) != "-lF\n"+tc.known {
				t.Errorf("ssh-keygen arguments = %q, want -lF %s", got, tc.known)
			}
		})
	}
}

func TestComposePrepareReleaseNeverReusesCurrent(t *testing.T) {
	root := t.TempDir()
	release := filepath.Join(root, "abc123")
	if err := os.Mkdir(release, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("abc123", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{release, filepath.Join(root, "current")} {
		if out, err := exec.Command("sh", "-c", composePrepareReleaseCommand(target)).CombinedOutput(); err == nil {
			t.Errorf("accepted existing release %s: %s", target, out)
		}
	}
	fresh := filepath.Join(root, "abc123-attempt")
	if out, err := exec.Command("sh", "-c", composePrepareReleaseCommand(fresh)).CombinedOutput(); err != nil {
		t.Fatalf("new release: %v: %s", err, out)
	}
}

func TestComposeRecoveryRestoresIntactRelease(t *testing.T) {
	for _, tc := range []struct{ name, current, previous, failed, want string }{
		{"before-up", "abc123", "older", "abc123-attempt", "abc123"},
		{"after-up", "abc123", "older", "abc123-attempt", "abc123"},
		{"first-deploy", "", "", "abc123-attempt", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := composeTestConfig(t)
			h := composeHost{cfg: cfg, home: t.TempDir(), client: &ssh.Client{}}
			root := h.releaseRoot()
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			for link, version := range map[string]string{"current": tc.current, "previous": tc.previous} {
				if version == "" {
					continue
				}
				release := h.releaseDir(version)
				if err := os.MkdirAll(release, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(h.composeFile(release), []byte("intact-"+version), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(version, filepath.Join(root, link)); err != nil {
					t.Fatal(err)
				}
			}
			// Model the project already replaced by up, or still healthy before up.
			running := tc.failed
			if tc.name == "before-up" {
				running = tc.current
			}
			original := composeRemoteRunner
			t.Cleanup(func() { composeRemoteRunner = original })
			composeRemoteRunner = func(_ *ssh.Client, command string) ssh.Result {
				if strings.Contains(command, "docker compose") {
					if strings.Contains(command, " down") {
						running = ""
						return ssh.Result{}
					}
					wanted := h.composeFile(h.releaseDir(tc.want))
					if tc.want == "" || !strings.Contains(command, wanted) {
						t.Errorf("unexpected recovery command %s", command)
					}
					content, err := os.ReadFile(wanted)
					if err != nil || string(content) != "intact-"+tc.want {
						t.Errorf("release changed: %s, %v", content, err)
					}
					running = tc.want
					return ssh.Result{}
				}
				out, err := exec.Command("sh", "-c", command).CombinedOutput()
				if err != nil {
					return ssh.Result{Code: 1, Stderr: string(out)}
				}
				return ssh.Result{Stdout: string(out)}
			}
			result := h.recover()
			link, linkErr := os.Readlink(filepath.Join(root, "current"))
			if tc.want == "" {
				if !os.IsNotExist(linkErr) {
					t.Errorf("failed first deploy published current: %q %v", link, linkErr)
				}
			} else if linkErr != nil || link != tc.want {
				t.Errorf("current=%q, want %q: %v", link, tc.want, linkErr)
			}

			if running != tc.want {
				t.Errorf("running %q, want %q: %s", running, tc.want, result)
			}
		})
	}
}

func TestComposeSameSourceKeepsRollbackTarget(t *testing.T) {
	root := t.TempDir()
	stub := t.TempDir()
	log := filepath.Join(stub, "removed")
	t.Setenv("REMOVED", log)
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte("#!/bin/sh\nif [ \"$1\" = images ]; then printf '%s\\n' shuttle/web:W shuttle/web:X; elif [ \"$1 $2\" = 'image rm' ]; then echo \"$3\" >> \"$REMOVED\"; fi\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", stub+":/usr/bin:/bin")
	for _, release := range []string{"W-t1", "X-t1", "X-t2"} {
		if err := os.Mkdir(filepath.Join(root, release), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, release, "docker-compose.yml"), []byte("services:\n  web:\n    image: shuttle/web:"+strings.Split(release, "-")[0]+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		command := composeRotateCommand(root, release, strings.Split(release, "-")[0]) + composeRetainCommand(root, "test")
		if out, err := exec.Command("sh", "-c", command).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	if got, err := os.Readlink(filepath.Join(root, "previous")); err != nil || got != "W-t1" {
		t.Errorf("previous=%q: %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "W-t1")); err != nil {
		t.Error(err)
	}
	removed, _ := os.ReadFile(log)
	if strings.Contains(string(removed), "shuttle/web:W") {
		t.Errorf("removed rollback image: %s", removed)
	}
}

func TestComposeAttemptImagesDoNotFollowSourceRetag(t *testing.T) {
	planned := map[string]string{"web": "shuttle/web:X"}
	first := composeAttemptImages(planned, "X-t1")
	second := composeAttemptImages(planned, "X-t2")
	if first["web"] != "shuttle/web:X-t1" || second["web"] != "shuttle/web:X-t2" {
		t.Fatalf("attempts share mutable source tags: %v %v", first, second)
	}
	// Model Docker's references: tag adds another name for an existing ID,
	// while loading a rebuilt source moves only the source alias.
	store := map[string]string{"shuttle/web:X": "sha256:old"}
	original := composeRemoteRunner
	t.Cleanup(func() { composeRemoteRunner = original })
	composeRemoteRunner = func(_ *ssh.Client, command string) ssh.Result {
		fields := strings.Fields(command)
		if len(fields) != 4 || fields[0] != "docker" || fields[1] != "tag" {
			t.Fatalf("unexpected image operation: %s", command)
		}
		store[strings.Trim(fields[3], "'")] = strings.Trim(fields[2], "'")
		return ssh.Result{}
	}
	h := composeHost{}
	if err := h.tagAttemptImages(planned, first, map[string]string{"shuttle/web:X": store["shuttle/web:X"]}); err != nil {
		t.Fatal(err)
	}
	store["shuttle/web:X"] = "sha256:failed"
	if err := h.tagAttemptImages(planned, second, map[string]string{"shuttle/web:X": store["shuttle/web:X"]}); err != nil {
		t.Fatal(err)
	}
	if store[first["web"]] != "sha256:old" || store[second["web"]] != "sha256:failed" {
		t.Fatalf("old attempt follows retag: %v", store)
	}
	third := composeAttemptImages(planned, "X-t3")
	if err := h.tagAttemptImages(planned, third, map[string]string{"shuttle/web:X": "sha256:failed"}); err != nil {
		t.Fatal(err)
	}
	if store[third["web"]] != store[second["web"]] {
		t.Fatal("equal images must share one ID and layers")
	}
	root := t.TempDir()
	for _, version := range []string{"X-t1", "X-t2", "X-t3"} {
		if err := os.Mkdir(filepath.Join(root, version), 0700); err != nil {
			t.Fatal(err)
		}
		manifest := "services:\n  web:\n    image: shuttle/web:" + version + "\n# shuttle-source-image: shuttle/web:X\n"
		if err := os.WriteFile(filepath.Join(root, version, "docker-compose.yml"), []byte(manifest), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for link, version := range map[string]string{"current": "X-t3", "previous": "X-t1"} {
		if err := os.Symlink(version, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	stub := t.TempDir()
	removed := filepath.Join(stub, "removed")
	t.Setenv("REMOVED", removed)
	script := "#!/bin/sh\nif [ \"$1\" = images ]; then printf '%s\\n' shuttle/web:X shuttle/web:X-t1 shuttle/web:X-t2 shuttle/web:X-t3; elif [ \"$1 $2\" = 'image rm' ]; then echo \"$3\" >> \"$REMOVED\"; fi\n"
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", stub+":/usr/bin:/bin")
	if out, err := exec.Command("sh", "-c", composeRetainCommand(root, "test")).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got, err := os.ReadFile(removed)
	if err != nil || strings.TrimSpace(string(got)) != "shuttle/web:X-t2" {
		t.Fatalf("removed %q: %v", got, err)
	}

}

func TestComposeSecretValidationDoesNotWarnAboutSwarmEntrypoints(t *testing.T) {
	cfg := composeTestConfig(t)
	parsed := &composeFile{Services: map[string]composeService{"api": {}, "crm-poller": {}}}
	warning := captureStderr(t, func() {
		if err := validateConfiguredSecretServices(parsed, cfg); err != nil {
			t.Fatal(err)
		}
	})
	if warning != "" {
		t.Fatalf("Compose env_file needs no Swarm entrypoint: %s", warning)
	}
}

func TestComposeDryRunUsesAttemptIdentityForDirectoryAndManifest(t *testing.T) {
	cfg := composeTestConfig(t)
	cfg.Secrets.Items = nil
	dir := t.TempDir()
	cfg.Deploy.EnvFile = filepath.Join(dir, "absent-env")
	cfg.Deploy.ComposeFiles = []string{filepath.Join(dir, "compose.yml")}
	if err := os.WriteFile(cfg.Deploy.ComposeFiles[0], []byte("services:\n  web:\n    build: .\n    ports: [\"80:80\"]\n    healthcheck:\n      test: [CMD, true]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\nif [ \"$1\" = rev-parse ]; then echo abc123; fi\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	oldConnector, oldRunner := composeHostConnector, composeRemoteRunner
	t.Cleanup(func() { composeHostConnector = oldConnector; composeRemoteRunner = oldRunner })
	composeHostConnector = func(c *config.Config) (composeHost, error) {
		return composeHost{cfg: c, home: dir, platform: localPlatform()}, nil
	}
	composeRemoteRunner = func(_ *ssh.Client, command string) ssh.Result { return ssh.Result{} }
	var previous string
	for i := 0; i < 2; i++ {
		out := captureStdout(t, func() {
			if err := deployCompose(cfg, true, true); err != nil {
				t.Fatal(err)
			}
		})
		var release string
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "[dry-run] Release directory: ") {
				release = filepath.Base(strings.TrimPrefix(line, "[dry-run] Release directory: "))
			}
		}
		if !strings.HasPrefix(release, "abc123-") || release == previous {
			t.Fatalf("release=%q previous=%q", release, previous)
		}
		if !strings.Contains(out, "image: shuttle/demo-web:"+release) {
			t.Fatalf("manifest lacks attempt image: %s", out)
		}
		previous = release
	}
}

func TestComposeReuseRequiresImmutableAttemptReference(t *testing.T) {
	attempt := "shuttle/web:X-20261105T120000000000002"
	oldAttempt := "shuttle/web:X-20261105T120000000000001"
	for _, tc := range []struct{ name, reference, id, want string }{
		{"unchanged", oldAttempt, "sha256:same", oldAttempt},
		{"changed", oldAttempt, "sha256:old", attempt},
		{"source-alias", "shuttle/web:X", "sha256:same", attempt},
		{"dirty-source-alias", "shuttle/web:X-dirty-20261105T120000000000001", "sha256:same", attempt},
		{"timestamp-source-alias", "shuttle/web:20261105T120000000000001", "sha256:same", attempt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			images, _ := reuseRunningImages(map[string]string{"web": attempt}, map[string]string{attempt: "sha256:same"}, []composeContainerImage{{Service: "web", Reference: tc.reference, ImageID: tc.id, ReferenceID: tc.id}})
			if images["web"] != tc.want {
				t.Fatalf("reference=%s want %s", images["web"], tc.want)
			}
		})
	}
}

func TestComposeRetentionKeepsReusedOlderAttemptTag(t *testing.T) {
	root, stub := t.TempDir(), t.TempDir()
	old := "X-20261105T120000000000001"
	current := "X-20261105T120000000000002"
	for release, image := range map[string]string{"W": "W", old: old, current: old} {
		if err := os.Mkdir(filepath.Join(root, release), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, release, "docker-compose.yml"), []byte("services:\n  web:\n    image: shuttle/web:"+image+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"current": current, "previous": "W"} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	removed := filepath.Join(stub, "removed")
	t.Setenv("REMOVED", removed)
	script := "#!/bin/sh\nif [ \"$1\" = images ]; then printf '%s\\n' shuttle/web:W shuttle/web:" + old + " shuttle/web:" + current + "; elif [ \"$1 $2\" = 'image rm' ]; then echo \"$3\" >> \"$REMOVED\"; fi\n"
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", stub+":/usr/bin:/bin")
	if out, err := exec.Command("sh", "-c", composeRetainCommand(root, "test")).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, old)); !os.IsNotExist(err) {
		t.Fatalf("obsolete directory still exists: %v", err)
	}
	got, err := os.ReadFile(removed)
	if err != nil || strings.TrimSpace(string(got)) != "shuttle/web:"+current {
		t.Fatalf("removed %q: %v", got, err)
	}
}

func TestComposeHostBuildLocalRefusalReleasesLock(t *testing.T) {
	contextDir := gitContext(t, "private.key\n", "", "private.key")
	dir := t.TempDir()
	cfg := composeTestConfig(t)
	cfg.Secrets.Items = nil
	cfg.Deploy.Compose = &config.ComposeDeploy{Build: config.ComposeBuildHost}
	cfg.Deploy.EnvFile = filepath.Join(dir, "absent")
	cfg.Deploy.ComposeFiles = []string{filepath.Join(dir, "compose.yml")}
	if err := os.WriteFile(cfg.Deploy.ComposeFiles[0], []byte("services:\n  web:\n    build: "+contextDir+"\n    ports: [\"80:80\"]\n    healthcheck:\n      test: [CMD, true]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key := (composeHost{cfg: cfg}).cfgHostKey()
	if err := os.WriteFile(filepath.Join(dir, "ssh-keygen"), []byte("#!/bin/sh\nprintf '%s\\n' 'host ED25519 "+key+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	host := composeHost{cfg: cfg, home: dir, user: "operator", address: "example.test", platform: localPlatform(), client: &ssh.Client{}}
	oldConnector, oldRunner := composeHostConnector, composeRemoteRunner
	t.Cleanup(func() { composeHostConnector, composeRemoteRunner = oldConnector, oldRunner })
	composeHostConnector = func(*config.Config) (composeHost, error) { return host, nil }
	composeRemoteRunner = func(_ *ssh.Client, command string) ssh.Result {
		cmd := exec.Command("sh", "-c", command)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return ssh.Result{Code: 1, Stderr: string(out)}
		}
		return ssh.Result{Stdout: string(out)}
	}
	err := deployCompose(cfg, false, false)
	if err == nil || !strings.Contains(err.Error(), "private.key") {
		t.Fatalf("expected local secret refusal: %v", err)
	}
	if _, err := os.Stat(composeLockDir(host.releaseRoot())); !os.IsNotExist(err) {
		t.Fatalf("local refusal left lock: %v", err)
	}
}
