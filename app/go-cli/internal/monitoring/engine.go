// Package monitoring implements bounded, read-only operational checks and the
// durable incident state that drives their notifications. It deliberately does
// not import readiness scoring: a doctor score is not evidence that an image
// has no CVE, and it is not a freshness guarantee.
package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

const (
	Schema             = "shuttle.monitoring/v1"
	InstalledSchema    = "shuttle.monitoring-installed/v1"
	ScopeLocal         = "local"
	ScopeExternal      = "external"
	Fresh              = "fresh"
	Stale              = "stale"
	StateHealthy       = "healthy"
	StateDegraded      = "degraded"
	StateUnavailable   = "unavailable"
	StateNotApplicable = "not_applicable"
	maxMonitoringCycle = 2 * time.Minute
	minPersistReserve  = time.Second
)

type Result struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Category   string         `json:"category"`
	Scope      string         `json:"scope"`
	State      string         `json:"state"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details,omitempty"`
	CheckedAt  string         `json:"checked_at"`
	FreshUntil string         `json:"fresh_until"`
	Freshness  string         `json:"freshness"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

type Report struct {
	Schema     string   `json:"schema"`
	App        string   `json:"app"`
	Scope      string   `json:"scope"`
	State      string   `json:"state"`
	CheckedAt  string   `json:"checked_at"`
	FreshUntil string   `json:"fresh_until"`
	Freshness  string   `json:"freshness"`
	Checks     []Result `json:"checks"`
}

type InstalledConfig struct {
	Schema             string                  `json:"schema"`
	App                string                  `json:"app"`
	Monitoring         config.MonitoringConfig `json:"monitoring"`
	RedisConfigured    bool                    `json:"redis_configured,omitempty"`
	RabbitMQConfigured bool                    `json:"rabbitmq_configured,omitempty"`
	PostgresVersion    int                     `json:"postgres_version,omitempty"`
	PostgresCluster    string                  `json:"postgres_cluster,omitempty"`
	SSHPort            int                     `json:"ssh_port,omitempty"`
	DeployStrategy     string                  `json:"deploy_strategy,omitempty"`
}

type DiskStats struct {
	Blocks uint64
	Bavail uint64
	Files  uint64
	Ffree  uint64
}

type CommandRunner func(context.Context, ...string) ([]byte, error)
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type FileReader func(string) ([]byte, error)
type DirectoryReader func(string) ([]os.DirEntry, error)
type FileStat func(string) (os.FileInfo, error)
type StatfsReader func(string) (DiskStats, error)
type Clock func() time.Time

type Adapters struct {
	Run     CommandRunner
	HTTP    HTTPDoer
	Read    FileReader
	ReadDir DirectoryReader
	Stat    FileStat
	Statfs  StatfsReader
	Now     Clock
}

func defaultAdapters() Adapters {
	return Adapters{
		Run: func(ctx context.Context, args ...string) ([]byte, error) {
			if len(args) == 0 {
				return nil, errors.New("empty command")
			}
			command := exec.CommandContext(ctx, args[0], args[1:]...)
			command.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, os.Environ()...)
			return command.Output()
		},
		HTTP: &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		Read: func(path string) ([]byte, error) {
			return readCollectorPath(path, maxRuntimeReadBytes)
		},
		ReadDir: os.ReadDir,
		Stat:    os.Stat,
		Statfs: func(path string) (DiskStats, error) {
			var stat syscall.Statfs_t
			if err := syscall.Statfs(path, &stat); err != nil {
				return DiskStats{}, err
			}
			return DiskStats{Blocks: stat.Blocks, Bavail: stat.Bavail, Files: stat.Files, Ffree: stat.Ffree}, nil
		},
		Now: time.Now,
	}
}

type Engine struct {
	App                string
	Config             config.MonitoringConfig
	Adapters           Adapters
	RedisConfigured    bool
	RabbitMQConfigured bool
	PostgresVersion    int
	PostgresCluster    string
	SSHPort            int
	DeployStrategy     string
}

func New(app string, cfg config.MonitoringConfig, adapters Adapters) Engine {
	cfg.NormalizeMonitoring()
	defaults := defaultAdapters()
	if adapters.Run == nil {
		adapters.Run = defaults.Run
	}
	if adapters.HTTP == nil {
		adapters.HTTP = defaults.HTTP
	}
	if adapters.Read == nil {
		adapters.Read = defaults.Read
	}
	if adapters.ReadDir == nil {
		adapters.ReadDir = defaults.ReadDir
	}
	if adapters.Stat == nil {
		adapters.Stat = defaults.Stat
	}
	if adapters.Statfs == nil {
		adapters.Statfs = defaults.Statfs
	}
	if adapters.Now == nil {
		adapters.Now = defaults.Now
	}
	return Engine{App: app, Config: cfg, Adapters: adapters}
}

func MarshalReport(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func JSON(report Report) string {
	body, err := MarshalReport(report)
	if err != nil {
		return `{"schema":"shuttle.monitoring/v1","state":"unavailable","error":"encode report"}`
	}
	return string(body)
}

func MarshalInstalledConfig(app string, cfg config.MonitoringConfig) ([]byte, error) {
	return MarshalInstalledConfigWithServices(app, cfg, false, false)
}

func MarshalInstalledConfigWithServices(app string, cfg config.MonitoringConfig, redis, rabbitmq bool) ([]byte, error) {
	return MarshalInstalledConfigWithInventory(app, cfg, redis, rabbitmq, 0, "", 0)
}

// MarshalInstalledConfigWithInventory includes only declared host inventory.
// Unconfigured dependencies remain not applicable during a run.
func MarshalInstalledConfigWithInventory(app string, cfg config.MonitoringConfig, redis, rabbitmq bool, postgresVersion int, postgresCluster string, sshPort int) ([]byte, error) {
	cfg.NormalizeMonitoringForApp(app)
	if err := cfg.ValidateMonitoringForApp(app); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, errors.New("monitoring.enabled must be true for installation")
	}
	if !validApp(app) {
		return nil, errors.New("invalid monitoring application")
	}
	return json.MarshalIndent(InstalledConfig{Schema: InstalledSchema, App: app, Monitoring: cfg, RedisConfigured: redis, RabbitMQConfigured: rabbitmq, PostgresVersion: postgresVersion, PostgresCluster: postgresCluster, SSHPort: sshPort}, "", "  ")
}

func DecodeInstalledConfig(body []byte) (InstalledConfig, error) {
	var installed InstalledConfig
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&installed); err != nil {
		return installed, errors.New("decode installed monitoring configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return installed, errors.New("installed monitoring configuration must contain one JSON document")
	}
	if installed.Schema != InstalledSchema || !validApp(installed.App) {
		return installed, errors.New("invalid installed monitoring configuration")
	}
	installed.Monitoring.NormalizeMonitoringForApp(installed.App)
	if err := installed.Monitoring.ValidateMonitoringForApp(installed.App); err != nil {
		return installed, err
	}
	return installed, nil
}

func validApp(app string) bool {
	if len(app) == 0 || len(app) > 63 || app[0] < 'a' || app[0] > 'z' {
		return false
	}
	for _, character := range app {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return !strings.HasSuffix(app, "-")
}

func (e Engine) Run(ctx context.Context) Report {
	now := e.Adapters.Now().UTC()
	if !e.Config.Enabled {
		return Report{Schema: Schema, App: e.App, Scope: ScopeLocal, State: StateNotApplicable, CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: now.Format(time.RFC3339Nano), Freshness: Fresh, Checks: []Result{e.result(now, "monitoring.disabled", "Monitoring", "monitoring", StateNotApplicable, "Monitoring is not enabled", "Set monitoring.enabled: true to install periodic checks", nil)}}
	}
	collectionCtx, cancel := context.WithTimeout(ctx, monitoringCollectionBudget(e.Config))
	defer cancel()
	ctx = collectionCtx
	checks := make([]Result, 0, 20)
	checks = append(checks, e.runCheck(ctx, "services.application", "Application services", "services", func(ctx context.Context) (string, string, map[string]any) { return e.application(ctx) }))
	checks = append(checks, e.runCheck(ctx, "services.docker", "Docker daemon", "services", func(ctx context.Context) (string, string, map[string]any) { return e.docker(ctx) }))
	checks = append(checks, e.runCheck(ctx, "services.caddy", "Caddy edge", "services", func(ctx context.Context) (string, string, map[string]any) { return e.caddy(ctx) }))
	checks = append(checks, e.runCheck(ctx, "services.registry", "Loopback registry", "services", func(ctx context.Context) (string, string, map[string]any) { return e.registry(ctx) }))
	checks = append(checks, e.runCheck(ctx, "services.postgresql", "Native PostgreSQL", "services", func(ctx context.Context) (string, string, map[string]any) { return e.postgres(ctx) }))
	if e.App == "" {
		checks = append(checks, e.result(now, "services.redis", "Redis", "services", StateNotApplicable, "Redis is not configured", "No application name was supplied", nil))
		checks = append(checks, e.result(now, "services.rabbitmq", "RabbitMQ", "services", StateNotApplicable, "RabbitMQ is not configured", "No application name was supplied", nil))
	} else {
		checks = append(checks, e.runCheck(ctx, "services.redis", "Redis", "services", func(ctx context.Context) (string, string, map[string]any) {
			return e.optionalService(ctx, "redis", e.RedisConfigured)
		}))
		checks = append(checks, e.runCheck(ctx, "services.rabbitmq", "RabbitMQ", "services", func(ctx context.Context) (string, string, map[string]any) {
			return e.optionalService(ctx, "rabbitmq", e.RabbitMQConfigured)
		}))
	}
	checks = append(checks, e.diskChecks(ctx)...)
	checks = append(checks, e.runCheck(ctx, "backup.freshness", "Backup freshness", "backups", func(ctx context.Context) (string, string, map[string]any) { return e.backup(ctx) }))
	checks = append(checks, e.runCheck(ctx, "tls.https", "HTTPS availability", "tls", func(ctx context.Context) (string, string, map[string]any) { return e.https(ctx) }))
	checks = append(checks, e.runCheck(ctx, "tls.expiry", "TLS certificate expiry", "tls", func(ctx context.Context) (string, string, map[string]any) { return e.tlsExpiry(ctx) }))
	checks = append(checks, e.securityChecks(ctx)...)
	checks = append(checks, e.runCheck(ctx, "operations.recovery_required", "Interrupted operations", "operations", func(ctx context.Context) (string, string, map[string]any) { return e.operations(ctx) }))
	checks = append(checks, e.result(now, "external.https", "Independent HTTPS probe", "external", StateNotApplicable, "External probing is independent", "Run the configured external probe on another host; local evidence is never external evidence", nil))
	sort.Slice(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	return e.report(now, ScopeLocal, checks)
}

func (e Engine) RunExternal(ctx context.Context) Report {
	now := e.Adapters.Now().UTC()
	if e.Config.External.URL == "" {
		return e.report(now, ScopeExternal, []Result{e.result(now, "external.https", "Independent HTTPS probe", "external", StateNotApplicable, "External probe is not configured", "Set monitoring.external.url and schedule this command on another host", nil)})
	}
	external := e
	if e.Config.External.TimeoutSeconds > 0 {
		external.Config.TimeoutSeconds = e.Config.External.TimeoutSeconds
	}
	collectionCtx, cancel := context.WithTimeout(ctx, monitoringCollectionBudget(external.Config))
	defer cancel()
	ctx = collectionCtx
	check := external.runCheck(ctx, "external.https", "Independent HTTPS probe", "external", func(ctx context.Context) (string, string, map[string]any) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.Config.External.URL, nil)
		if err != nil {
			return StateUnavailable, "External HTTPS request could not be created", nil
		}
		response, err := e.Adapters.HTTP.Do(request)
		if err != nil {
			return StateUnavailable, "External HTTPS endpoint is unavailable", nil
		}
		defer response.Body.Close()
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return StateDegraded, "External HTTPS endpoint redirected instead of proving the configured URL", map[string]any{"status": response.StatusCode}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return StateDegraded, "External HTTPS endpoint returned an unhealthy status", map[string]any{"status": response.StatusCode}
		}
		return StateHealthy, "External HTTPS endpoint is reachable", map[string]any{"status": response.StatusCode, "url": e.Config.External.URL}
	})
	check.Scope = ScopeExternal
	return e.report(now, ScopeExternal, []Result{check})
}

func (e Engine) report(now time.Time, scope string, checks []Result) Report {
	state := StateHealthy
	applicable := 0
	for _, check := range checks {
		if check.State == StateNotApplicable {
			continue
		}
		applicable++
		if check.State == StateUnavailable {
			state = StateUnavailable
		} else if check.State == StateDegraded && state == StateHealthy {
			state = StateDegraded
		}
	}
	if applicable == 0 {
		state = StateNotApplicable
	}
	freshUntil := now.Add(time.Duration(e.Config.StaleAfterSeconds) * time.Second)
	return Report{Schema: Schema, App: e.App, Scope: scope, State: state, CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: freshUntil.Format(time.RFC3339Nano), Freshness: Fresh, Checks: checks}
}

func monitoringCycleBudget(cfg config.MonitoringConfig) time.Duration {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultMonitoringTimeout) * time.Second
	}
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = time.Duration(config.DefaultMonitoringInterval) * time.Second
	}
	budget := 2 * timeout
	if interval > budget {
		budget = interval
	}
	if budget < 2*minPersistReserve {
		budget = 2 * minPersistReserve
	}
	if budget > maxMonitoringCycle {
		budget = maxMonitoringCycle
	}
	return budget
}

func monitoringCollectionBudget(cfg config.MonitoringConfig) time.Duration {
	cycle := monitoringCycleBudget(cfg)
	reserve := cycle / 5
	if reserve < minPersistReserve {
		reserve = minPersistReserve
	}
	if cycle <= reserve {
		return cycle / 2
	}
	return cycle - reserve
}

func (e Engine) runCheck(ctx context.Context, id, title, category string, fn func(context.Context) (string, string, map[string]any)) Result {
	now := e.Adapters.Now().UTC()
	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(e.Config.TimeoutSeconds)*time.Second)
	defer cancel()
	type outcome struct {
		state    string
		summary  string
		evidence map[string]any
	}
	outcomes := make(chan outcome, 1)
	go func() {
		state, summary, evidence := fn(checkCtx)
		outcomes <- outcome{state: state, summary: summary, evidence: evidence}
	}()
	var result outcome
	select {
	case result = <-outcomes:
	case <-checkCtx.Done():
		result.state = StateUnavailable
		result.summary = "Check timed out before producing evidence"
	}
	if checkCtx.Err() != nil {
		result.state, result.summary = StateUnavailable, "Check timed out before producing evidence"
		result.evidence = nil
	}
	if result.state == "" {
		result.state = StateUnavailable
	}
	return e.result(now, id, title, category, result.state, result.summary, "", result.evidence)
}

func (e Engine) result(now time.Time, id, title, category, state, summary, details string, evidence map[string]any) Result {
	freshUntil := now.Add(time.Duration(e.Config.StaleAfterSeconds) * time.Second)
	return Result{ID: id, Title: title, Category: category, Scope: ScopeLocal, State: state, Summary: summary, Details: details, CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: freshUntil.Format(time.RFC3339Nano), Freshness: Fresh, Evidence: evidence}
}

func (r Result) IsHealthyAt(now time.Time) bool {
	if r.State != StateHealthy {
		return false
	}
	deadline, err := time.Parse(time.RFC3339Nano, r.FreshUntil)
	return err == nil && now.Before(deadline)
}

func (r Result) WithFreshness(now time.Time) Result {
	deadline, err := time.Parse(time.RFC3339Nano, r.FreshUntil)
	if err != nil || !now.Before(deadline) {
		r.Freshness = Stale
		if r.State == StateHealthy {
			r.State = StateUnavailable
			r.Summary = "Check result is stale and cannot be treated as healthy"
		}
		return r
	}
	r.Freshness = Fresh
	return r
}

func ReadInstalledConfig(path string, read FileReader) (InstalledConfig, error) {
	if read == nil {
		read = os.ReadFile
	}
	body, err := read(path)
	if err != nil {
		return InstalledConfig{}, err
	}
	return DecodeInstalledConfig(body)
}

func statePath(cfg config.MonitoringConfig) string {
	return filepath.Join(cfg.StateDir, "incidents.json")
}

// ReadLatest reads the durable report without invoking any collector or
// notifier. It is the implementation used by status.
func ReadLatest(installed InstalledConfig, read FileReader, now time.Time) (Report, error) {
	installed.Monitoring.NormalizeMonitoringForApp(installed.App)
	if !installed.Monitoring.Enabled {
		return New(installed.App, installed.Monitoring, Adapters{Read: read, Now: func() time.Time { return now }}).Run(context.Background()), nil
	}
	store := FileStore{Path: statePath(installed.Monitoring)}
	var state IncidentState
	var err error
	if read != nil {
		body, readErr := read(store.Path)
		if readErr != nil {
			err = readErr
		} else {
			state, err = decodeIncidentState(body)
		}
	} else {
		state, err = store.Load(context.Background())
	}
	if err != nil {
		return unavailableLatest(installed.App, "Persisted monitoring evidence could not be read"), err
	}
	if state.LastReport == nil {
		return unavailableLatest(installed.App, "No persisted monitoring report exists"), nil
	}
	report := *state.LastReport
	report = reportWithFreshness(report, now.UTC())
	return report, nil
}

func reportWithFreshness(report Report, now time.Time) Report {
	if deadline, err := time.Parse(time.RFC3339Nano, report.FreshUntil); err != nil || !now.Before(deadline) {
		report.Freshness = Stale
		if report.State == StateHealthy {
			report.State = StateUnavailable
		}
	} else {
		report.Freshness = Fresh
	}
	for i := range report.Checks {
		report.Checks[i] = report.Checks[i].WithFreshness(now)
	}
	return report
}

func unavailableLatest(app, summary string) Report {
	return unavailableReport(app, "monitoring.last_report", "Persisted monitoring report", summary)
}

// UnavailableReport is the JSON document emitted when a helper path fails
// before producing a monitoring document. Timeout or empty stdout must not
// look like a healthy status.
func UnavailableReport(app, summary string) Report {
	return unavailableReport(app, "monitoring.helper", "Monitoring helper", summary)
}

func unavailableReport(app, id, title, summary string) Report {
	now := time.Now().UTC()
	return Report{Schema: Schema, App: app, Scope: ScopeLocal, State: StateUnavailable, CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: now.Format(time.RFC3339Nano), Freshness: Stale, Checks: []Result{{ID: id, Title: title, Category: "monitoring", Scope: ScopeLocal, State: StateUnavailable, Summary: summary, CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: now.Format(time.RFC3339Nano), Freshness: Stale}}}
}
