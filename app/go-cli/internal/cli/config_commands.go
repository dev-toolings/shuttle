package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/detect"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/skills"
	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/templates"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type configFlags struct {
	path string
	env  string
}

func addConfigFlags(cmd *cobra.Command, flags *configFlags) {
	cmd.Flags().StringVar(&flags.path, "config", "", "path to config.json (legacy shuttle.yml is accepted)")
	cmd.Flags().StringVarP(&flags.env, "env", "e", "", "environment overlay")
}

func loadWithFlags(flags configFlags) (*config.Config, error) {
	return config.Load(flags.path, flags.env)
}

// servicePortForPreset returns the default container port for a given preset.
func servicePortForPreset(preset string) string {
	switch preset {
	case "laravel":
		return "8000"
	case "symfony":
		return "8080"
	case "nextjs", "node-api", "hono", "fastify", "tanstack-start":
		return "3000"
	case "fastapi":
		return "8000"
	default:
		return "8080"
	}
}

// dockerfileForPreset returns the Dockerfile content for the detected preset.
func dockerfileForPreset(preset string, mode string, hasPackageJSON bool) (string, string) {
	suffix := " (" + mode + ")"
	switch preset {
	case "laravel":
		return templates.DockerfileLaravel(mode), "FrankenPHP + Laravel" + suffix
	case "symfony":
		return templates.DockerfileSymfony(mode, hasPackageJSON), "FrankenPHP + Symfony" + suffix
	case "nextjs", "hono", "fastify", "fastapi", "tanstack-start":
		prod, _, ok := templates.FrameworkDockerfiles(preset)
		if !ok {
			return "", ""
		}
		return prod, preset + " production runtime"
	default:
		return "", ""
	}
}

// renderConfigYAML builds an intermediate typed-key document before the public
// config.json is encoded. YAML keeps this generator compact while JSON remains
// the only file emitted by init.
func renderConfigYAML(app, domain, host string, port int, email, servicePort, preset string, nativePostgres, redis, rabbitMQ bool, expose string) string {
	if port == 0 {
		port = 22
	}
	var b strings.Builder
	b.WriteString("version: 2\n")
	fmt.Fprintf(&b, "app: %s\n", app)
	if expose == config.ExposeInternal {
		b.WriteString("expose: internal\n")
	} else {
		fmt.Fprintf(&b, "domain: %s\n", domain)
	}
	b.WriteString("\n")
	b.WriteString("server:\n")
	fmt.Fprintf(&b, "  host: %s\n", host)
	b.WriteString("  user: deploy\n")
	fmt.Fprintf(&b, "  port: %d\n", port)
	b.WriteString("  access:\n")
	b.WriteString("    allowed_public_tcp_ports: [80, 443]\n")
	b.WriteString("\n")
	// setup.slo_seconds is the budget `shuttle setup` measures itself against
	// and reports; it is not a gate, and a converged host succeeds whatever the
	// clock says. 600 s covers a full first convergence (base packages, Docker,
	// PostgreSQL, reboot) on a normal provider mirror.
	b.WriteString("setup:\n  slo_seconds: 600\n\n")
	b.WriteString("deploy:\n")
	b.WriteString("  strategy: swarm\n")
	b.WriteString("  timeout: 30\n")
	// The generated budget follows the preset because the frameworks do not
	// deploy at the same speed: a Hono release is source-to-production in 8 s,
	// a FrankenPHP one spends most of its promotion waiting for the PHP runtime
	// to answer. Writing one figure for both guaranteed a wrong number for one.
	deploySLO := config.DefaultDeploySLOSeconds(preset)
	fmt.Fprintf(&b, "  promotion_slo_seconds: %d\n", deploySLO)
	fmt.Fprintf(&b, "  total_slo_seconds: %d\n", deploySLO)
	if expose == config.ExposeInternal {
		b.WriteString("  primary_service: web\n")
	} else {
		fmt.Fprintf(&b, "  availability_url: https://%s%s\n", domain, healthPathForPreset(preset))
	}
	b.WriteString("  availability_interval_ms: 250\n")
	b.WriteString("  retain: 2\n")
	b.WriteString("  compose_files:\n")
	b.WriteString("    - docker-compose.yml\n")
	b.WriteString("  prune_build_cache: capped\n")
	b.WriteString("  build_cache_keep: 5GB\n")
	b.WriteString("  prune_local_images: true\n")
	b.WriteString("\nservices:\n  web:\n")
	fmt.Fprintf(&b, "    port: %s\n", servicePort)
	b.WriteString("    healthcheck:\n      type: http\n")
	fmt.Fprintf(&b, "      path: %s\n", healthPathForPreset(preset))
	// retention.registry_cache caps the on-VPS registry volume and is enforced
	// by the root helper after every promotion. 5GB holds one `mode=max` build
	// cache — 1 to 2 GB for a PHP image — plus the two release manifests
	// deploy.retain keeps, with room to spare before the cache is dropped once
	// and rebuilt.
	b.WriteString("\nretention:\n  registry_cache: 5GB\n  postgres_backups: 7\n  min_free_percent: 20\n")
	b.WriteString("\nproduction:\n")
	fmt.Fprintf(&b, "  redis: %t\n  rabbitmq: %t\n", redis, rabbitMQ)
	// The framework secret a preset cannot run without is declared here, so a
	// deploy that lacks it stops at resolution instead of shipping a broken
	// application. Laravel refuses to serve a single route without APP_KEY:
	// every request raises MissingAppKeyException and returns 500, while its
	// /up healthcheck answers 200, so the deployment reports success while the
	// application is dead. Symfony boots without APP_SECRET, which is worse:
	// CSRF tokens, signed URLs, remember-me and login throttling fail later,
	// on the first request that needs them. FrankenDeploy checks the same
	// framework secrets before deploying (internal/deploy/envcheck.go there).
	// Application secrets use the host backend: the value lives in a file on
	// the VPS, never on the workstation that runs init. Infrastructure
	// passwords (Redis, RabbitMQ) stay generated on the host even when they
	// appear next to the framework secret in items.
	frameworkSecret := frameworkSecretForPreset(preset)
	if redis || rabbitMQ || frameworkSecret != "" {
		b.WriteString("\nsecrets:\n")
		if frameworkSecret != "" {
			b.WriteString("  backend: host\n")
			fmt.Fprintf(&b, "  host:\n    env_file: %s\n", hostEnvFileForApp(app))
		} else {
			b.WriteString("  backend: swarm\n")
		}
		b.WriteString("  items:\n")
		if frameworkSecret != "" {
			fmt.Fprintf(&b, "    %s:\n      services: [web]\n      expose: env\n", frameworkSecret)
		}
		if redis {
			b.WriteString("    REDIS_PASSWORD:\n      services: [redis]\n      expose: file\n")
		}
		if rabbitMQ {
			b.WriteString("    RABBITMQ_PASSWORD:\n      services: [rabbitmq]\n      expose: file\n")
		}
	}
	if nativePostgres {
		databaseIdentifier := postgresIdentifierForApp(app)
		// The default major, not a literal: `init` and the version `setup`
		// installs on a bare host are the same promise, and they are kept in
		// one place so they cannot drift apart. 17 is equally supported, but a
		// generated configuration is not the place to move an operator onto a
		// major they did not ask for.
		fmt.Fprintf(&b, "\ndatabase:\n  version: %d\n  backup:\n    mode: local\n    retention: 7\n  roles:\n", config.DefaultDatabaseVersion)
		fmt.Fprintf(&b, "    - name: %s\n  databases:\n    - name: %s\n      owner: %s\n", databaseIdentifier, databaseIdentifier, databaseIdentifier)
	}
	b.WriteString("\nreadiness:\n")
	fmt.Fprintf(&b, "  preset: %s\n  healthcheck_path: %s\n", preset, healthPathForPreset(preset))
	b.WriteString("\n")
	b.WriteString("caddy:\n")
	b.WriteString("  conf_dir: /opt/shuttle/caddy/conf.d\n")
	if email != "" {
		fmt.Fprintf(&b, "  email: %s\n", email)
	}
	if expose != config.ExposeInternal {
		b.WriteString("  routes:\n")
		fmt.Fprintf(&b, "    \"%s\": \"web:%s\"\n", domain, servicePort)
	}
	return b.String()
}

func initConfigJSON(app, domain, host string, port int, email, servicePort, preset string, nativePostgres, redis, rabbitMQ bool) (string, error) {
	return initConfigJSONWithExpose(app, domain, host, port, email, servicePort, preset, nativePostgres, redis, rabbitMQ, config.ExposePublic)
}

func initConfigJSONWithExpose(app, domain, host string, port int, email, servicePort, preset string, nativePostgres, redis, rabbitMQ bool, expose string) (string, error) {
	var document any
	if err := yaml.Unmarshal([]byte(renderConfigYAML(app, domain, host, port, email, servicePort, preset, nativePostgres, redis, rabbitMQ, expose)), &document); err != nil {
		return "", fmt.Errorf("generate config.json: %w", err)
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", fmt.Errorf("generate config.json: %w", err)
	}
	return string(body) + "\n", nil
}

// frameworkSecretForPreset names the secret a preset's framework needs in its
// environment to serve correctly, or "" when the preset has none.
func frameworkSecretForPreset(preset string) string {
	switch preset {
	case "laravel":
		return "APP_KEY"
	case "symfony":
		return "APP_SECRET"
	}
	return ""
}

func hostEnvFileForApp(app string) string {
	return "/opt/" + app + "/.env"
}

func ensureGitignoreKeepsEnvLocal(dir string) error {
	path := filepath.Join(dir, ".gitignore")
	needed := []string{".env", ".env.*", "!.env.example"}
	existing := map[string]bool{}
	body, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		for _, line := range strings.Split(string(body), "\n") {
			existing[strings.TrimSpace(line)] = true
		}
	}
	var missing []string
	for _, line := range needed {
		if !existing[line] {
			missing = append(missing, line)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	var b strings.Builder
	if len(body) > 0 && !strings.HasSuffix(string(body), "\n") {
		b.WriteByte('\n')
	}
	for _, line := range missing {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(b.String()); err != nil {
		return err
	}
	fmt.Println("✓ .gitignore keeps .env out of Git")
	return nil
}

// initComposeConfigJSON writes the configuration of the compose strategy: no
// setup block, no caddy routes, the account and host key in the server block,
// and the local cleanup the strategy defaults to.
func initComposeConfigJSON(app, domain, host string, port int, user, hostKey, servicePort, preset string) (string, error) {
	document := map[string]any{
		"version": 2,
		"app":     app,
		"domain":  domain,
		"server":  map[string]any{"host": host, "user": user, "port": port, "host_key": hostKey},
		"deploy": map[string]any{
			"strategy":              config.StrategyCompose,
			"compose_files":         []string{"docker-compose.yml"},
			"retain":                2,
			"total_slo_seconds":     config.DefaultDeploySLOSeconds(preset),
			"promotion_slo_seconds": config.DefaultDeploySLOSeconds(preset),
			"prune_build_cache":     "capped",
			"build_cache_keep":      "5GB",
		},
		"services": map[string]any{
			"web": map[string]any{"port": mustAtoi(servicePort), "healthcheck": map[string]any{"type": "http", "path": healthPathForPreset(preset)}},
		},
		"readiness": map[string]any{"preset": presetOrDefault(preset), "healthcheck_path": healthPathForPreset(preset)},
	}
	if secret := frameworkSecretForPreset(preset); secret != "" {
		// Same host-backed framework secret as the swarm generator: compose
		// has no local encrypted store, and copying the key onto the laptop
		// would be the only reason it ever left the server.
		document["secrets"] = map[string]any{
			"backend": "host",
			"host":    map[string]any{"env_file": hostEnvFileForApp(app)},
			"items":   map[string]any{secret: map[string]any{"services": []string{"web"}, "expose": "env"}},
		}
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", fmt.Errorf("generate config.json: %w", err)
	}
	return string(body) + "\n", nil
}

func mustAtoi(value string) int {
	number, err := strconv.Atoi(value)
	if err != nil {
		return 3000
	}
	return number
}

func presetOrDefault(preset string) string {
	if preset == "" {
		return "node-api"
	}
	return preset
}

func healthPathForPreset(preset string) string {
	switch preset {
	case "laravel":
		return "/up"
	case "nextjs", "symfony", "tanstack-start":
		return "/"
	default:
		return "/health"
	}
}

// postgresIdentifierForApp maps the public application slug to an unquoted
// PostgreSQL identifier. Application names allow hyphens and a leading digit,
// while PostgreSQL resources deliberately use the stricter portable subset
// validated by config.DatabaseConfig.
func postgresIdentifierForApp(app string) string {
	identifier := strings.ReplaceAll(strings.TrimSpace(app), "-", "_")
	if identifier == "" {
		return "app"
	}
	if identifier[0] >= '0' && identifier[0] <= '9' {
		identifier = "app_" + identifier
	}
	if len(identifier) > 63 {
		identifier = identifier[:63]
	}
	return identifier
}

func newInitCommand() *cobra.Command {
	var force bool
	var declaredImages []string
	var app string
	var domain string
	var host string
	var port int
	var preset string
	var mode string
	var email string
	var skipDetect bool
	var withDB string
	var withRedis bool
	var withRabbitMQ bool
	var strategy string
	var user string
	var hostKey string
	var expose string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Detect your stack and generate configuration",
		Long: "Analyze the current project to detect the technology stack, then generate:\n" +
			"  - config.json (deploy config)\n" +
			"  - Dockerfile (if a preset matches)\n" +
			"  - docker-compose.yml\n" +
			"  - .dockerignore\n\n" +
			"Run without flags for interactive mode. Use flags to skip prompts (for CI/scripting).\n" +
			"Supported presets: " +
			strings.Join(templates.ReadinessPresets, ", ") + ".",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, _ := os.Getwd()
			if preset == "tanstack/start" || preset == "tanstack_start" {
				preset = "tanstack-start"
			}
			if expose == "" {
				expose = config.ExposePublic
			}
			if expose != config.ExposePublic && expose != config.ExposeInternal {
				return fmt.Errorf("invalid --expose %q; expected public or internal", expose)
			}
			if expose == config.ExposeInternal && cmd.Flags().Changed("domain") {
				return errors.New("--expose internal cannot be combined with --domain")
			}

			// --- Stack detection ---
			var stack detect.Stack
			if !templates.IsMode(mode) {
				return fmt.Errorf("unknown mode %q; supported: %s, %s", mode, templates.ModeAPI, templates.ModeMonolith)
			}
			if preset != "" {
				if !templates.IsReadinessPreset(preset) {
					return fmt.Errorf("unknown preset %q; supported: %s", preset, strings.Join(templates.ReadinessPresets, ", "))
				}
				stack = detect.Stack{Preset: preset, Framework: preset}
			} else if !skipDetect {
				fmt.Println("\nDetecting stack...")
				stack = detect.Analyze(dir)
				if stack.Preset != "" {
					fmt.Printf("  ✓ %s detected", stack.Framework)
					if len(stack.Signals) > 0 {
						fmt.Printf(" (%s)", stack.Signals[0])
					}
					fmt.Println()
				} else {
					fmt.Println("  Could not auto-detect stack. Using generic config.")
					fmt.Println("  Tip: use --preset to specify manually.")
				}
				fmt.Println()
			}
			if (stack.Preset == "laravel" || stack.Preset == "symfony") && !cmd.Flags().Changed("mode") {
				if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
					mode = templates.ModeMonolith
				}
			}
			if (stack.Preset == "laravel" || stack.Preset == "symfony") && mode == templates.ModeMonolith {
				if _, err := os.Stat(filepath.Join(dir, "package.json")); err != nil {
					return fmt.Errorf("%s monolith mode requires package.json; use --mode api for a headless application", stack.Preset)
				}
				if _, err := os.Stat(filepath.Join(dir, "bun.lock")); err != nil {
					return fmt.Errorf("%s monolith mode requires a committed bun.lock; run bun install, commit bun.lock, then retry", stack.Preset)
				}
			}

			// --- Compute defaults ---
			defaultApp := filepath.Base(dir)
			defaultDomain := defaultApp + ".example.com"
			defaultPort := 22

			// --- Interactive prompts (skip if flag is provided) ---
			// app
			if !cmd.Flags().Changed("app") {
				app = promptString("App name", defaultApp)
			}
			if app == "" {
				app = defaultApp
			}

			// domain
			if expose == config.ExposeInternal {
				domain = ""
			} else if !cmd.Flags().Changed("domain") {
				defaultDomain = app + ".example.com"
				domain = promptString("Domain", defaultDomain)
			}
			if domain == "" {
				domain = defaultDomain
			}

			// host
			if !cmd.Flags().Changed("host") {
				host = promptString("Server host", "")
			}
			if host == "" {
				host = "203.0.113.10"
			}

			// port
			if !cmd.Flags().Changed("port") {
				port = promptInt("SSH port", defaultPort)
			}
			if port == 0 {
				port = defaultPort
			}

			// email
			if !cmd.Flags().Changed("email") {
				email = promptString("Email (for Let's Encrypt)", "")
			}

			fmt.Println()

			if withDB != "" && withDB != "postgres" {
				return errors.New("Shuttle supports PostgreSQL 16, 17 or 18 natively; --with-db must be postgres")
			}

			// --- Determine service port ---
			servicePort := servicePortForPreset(stack.Preset)

			// Resolve before writing anything, and only when the Dockerfile will be generated.
			dockerfileContent, dockerfileLabel := "", ""
			if stack.Preset != "" {
				if _, statErr := os.Stat("Dockerfile"); statErr == nil && !force {
					fmt.Println("Dockerfile already exists (use --force to overwrite)")
				} else if statErr != nil && !os.IsNotExist(statErr) {
					return statErr
				} else {
					_, packageJSONErr := os.Stat(filepath.Join(dir, "package.json"))
					dockerfileContent, dockerfileLabel = dockerfileForPreset(stack.Preset, mode, packageJSONErr == nil)
					if dockerfileContent != "" {
						var err error
						dockerfileContent, err = resolveDockerfileImages(cmd.Context(), dockerfileContent, declaredImages)
						if err != nil {
							return err
						}
					}
				}
			}

			// --- config.json ---
			if _, err := os.Stat("config.json"); err == nil && !force {
				fmt.Println("config.json already exists (use --force to overwrite)")
			} else {
				if err := os.MkdirAll(".shuttle", 0o755); err != nil {
					return err
				}
				_ = os.WriteFile(filepath.Join(".shuttle", ".gitkeep"), []byte{}, 0o644)
				var content string
				var err error
				switch strategy {
				case "", config.StrategySwarm:
					if user != "" || hostKey != "" {
						return errors.New("--user and --host-key only apply to --strategy compose; the swarm strategy deploys as the deploy account setup creates and records the host key itself")
					}
					content, err = initConfigJSONWithExpose(app, domain, host, port, email, servicePort, stack.Preset, withDB == "postgres", withRedis, withRabbitMQ, expose)
				case config.StrategyCompose:
					if withDB != "" || withRedis || withRabbitMQ {
						return errors.New("--with-db, --with-redis and --with-rabbitmq do not apply to --strategy compose: nothing is installed on the host, declare the services in the compose file")
					}
					if user == "" || hostKey == "" {
						return errors.New("--strategy compose requires --user (an existing account of the host that may run docker) and --host-key (its ED25519 SHA256 fingerprint, obtained out of band)")
					}
					content, err = initComposeConfigJSON(app, domain, host, port, user, hostKey, servicePort, stack.Preset)
					if expose == config.ExposeInternal && err == nil {
						var document map[string]any
						err = json.Unmarshal([]byte(content), &document)
						if err == nil {
							document["expose"] = config.ExposeInternal
							deploy, ok := document["deploy"].(map[string]any)
							if !ok {
								deploy = map[string]any{}
								document["deploy"] = deploy
							}
							deploy["primary_service"] = "web"
							delete(document, "domain")
							var encoded []byte
							encoded, err = json.MarshalIndent(document, "", "  ")
							content = string(encoded) + "\n"
						}
					}
				default:
					return fmt.Errorf("unknown strategy %q; supported: swarm, compose", strategy)
				}
				if err != nil {
					return err
				}
				if err := os.WriteFile("config.json", []byte(content), 0o644); err != nil {
					return err
				}
				fmt.Println("✓ config.json created")
			}

			// --- Dockerfile ---
			if dockerfileContent != "" {
				if err := os.WriteFile("Dockerfile", []byte(dockerfileContent), 0o644); err != nil {
					return err
				}
				fmt.Printf("✓ Dockerfile created (%s)\n", dockerfileLabel)
			}

			// --- Framework config files ---
			if stack.Preset == "laravel" {
				os.MkdirAll("docker", 0o755)
				if err := os.WriteFile("docker/opcache.ini", []byte(templates.LaravelOpcacheIni()), 0o644); err != nil {
					return err
				}
				fmt.Println("✓ docker/opcache.ini created (OPcache production tuning)")
			}
			if stack.Preset == "symfony" {
				os.MkdirAll("docker/conf.d", 0o755)
				if err := os.WriteFile("docker/Caddyfile", []byte(templates.SymfonyCaddyfile()), 0o644); err != nil {
					return err
				}
				if err := os.WriteFile("docker/conf.d/10-app.ini", []byte(templates.SymfonyBaseIni()), 0o644); err != nil {
					return err
				}
				if err := os.WriteFile("docker/conf.d/20-app.prod.ini", []byte(templates.SymfonyProdIni()), 0o644); err != nil {
					return err
				}
				fmt.Println("✓ docker/Caddyfile created (FrankenPHP PHP handler)")
				fmt.Println("✓ docker/conf.d/*.ini created (OPcache + PHP production tuning)")
			}

			// --- docker-compose.yml ---
			composeContent := templates.ComposeTemplate(app, stack.Preset, servicePort)
			if composeContent != "" {
				if _, err := os.Stat("docker-compose.yml"); err == nil && !force {
					fmt.Println("docker-compose.yml already exists (use --force to overwrite)")
				} else {
					if err := os.WriteFile("docker-compose.yml", []byte(composeContent), 0o644); err != nil {
						return err
					}
					fmt.Println("✓ docker-compose.yml created")
				}
			}

			// --- .dockerignore ---
			ignoreContent := templates.Dockerignore(stack.Preset)
			if ignoreContent != "" {
				if _, err := os.Stat(".dockerignore"); err == nil && !force {
					fmt.Println(".dockerignore already exists (use --force to overwrite)")
				} else {
					if err := os.WriteFile(".dockerignore", []byte(ignoreContent), 0o644); err != nil {
						return err
					}
					fmt.Println("✓ .dockerignore created")
				}
			}

			// --- .env.example ---
			envContent := templates.EnvExample(stack.Preset)
			if envContent != "" {
				if _, err := os.Stat(".env.example"); err == nil && !force {
					fmt.Println(".env.example already exists (use --force to overwrite)")
				} else {
					if err := os.WriteFile(".env.example", []byte(envContent), 0o644); err != nil {
						return err
					}
					fmt.Println("✓ .env.example created")
				}
			}

			if err := ensureGitignoreKeepsEnvLocal(dir); err != nil {
				return err
			}
			if err := installProjectHostEnvSkill(dir); err != nil {
				return fmt.Errorf("install %s skill: %w", skills.HostEnvName, err)
			}
			fmt.Printf("✓ agent skill %s installed in this project\n", skills.HostEnvName)

			// --- Summary ---
			fmt.Println("\nNext steps:")
			if secret := frameworkSecretForPreset(stack.Preset); secret != "" {
				fmt.Printf("  1. On the VPS, create %s (mode 0600) with %s. Do not copy a workstation .env.\n", hostEnvFileForApp(app), secret)
				fmt.Println("  2. shuttle setup        (configure and harden your VPS)")
				fmt.Println("  3. shuttle deploy       (build and ship)")
			} else {
				fmt.Println("  1. shuttle setup        (configure and harden your VPS)")
				fmt.Println("  2. shuttle deploy       (build and ship)")
			}
			fmt.Println("  Once per workstation: shuttle --install skills")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	cmd.Flags().StringArrayVar(&declaredImages, "image", nil, "use a digest-pinned template image (repeatable)")
	cmd.Flags().StringVar(&app, "app", "", "application name (default: directory name)")
	cmd.Flags().StringVar(&domain, "domain", "", "application domain")
	cmd.Flags().StringVar(&expose, "expose", config.ExposePublic, "application exposure: public or internal")
	cmd.Flags().StringVar(&host, "host", "", "server host")
	cmd.Flags().IntVar(&port, "port", 22, "server SSH port")
	cmd.Flags().StringVar(&email, "email", "", "email for Let's Encrypt")
	cmd.Flags().StringVar(&preset, "preset", "", "override auto-detection with a specific preset ("+strings.Join(templates.ReadinessPresets, "|")+")")
	cmd.Flags().StringVar(&mode, "mode", templates.ModeAPI, "build mode: api (headless, no frontend toolchain) or monolith (builds and ships Vite/Encore assets)")
	cmd.Flags().BoolVar(&skipDetect, "no-detect", false, "skip stack detection")
	cmd.Flags().StringVar(&withDB, "with-db", "", "configure native PostgreSQL 16, 17 or 18 (postgres)")
	cmd.Flags().BoolVar(&withRedis, "with-redis", false, "add a private per-application Redis service")
	cmd.Flags().BoolVar(&withRabbitMQ, "with-rabbitmq", false, "add a private RabbitMQ service in production")
	cmd.Flags().StringVar(&strategy, "strategy", "", "deploy strategy: swarm (default, hardened host set up by shuttle) or compose (existing host, existing account, no setup)")
	cmd.Flags().StringVar(&user, "user", "", "with --strategy compose, the existing account that runs docker compose on the host")
	cmd.Flags().StringVar(&hostKey, "host-key", "", "with --strategy compose, the host's ED25519 key fingerprint (SHA256:...) from the provider console")
	return cmd
}
