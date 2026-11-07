package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MonitoringConfig is deliberately opt-in. A normal deploy does not start a
// scheduler, open a notification channel or claim that a host was checked.
// Every value is bounded here because the same document is later copied into
// a root-owned monitoring installation.
type MonitoringConfig struct {
	Enabled            bool                     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	IntervalSeconds    int                      `yaml:"interval_seconds,omitempty" json:"interval_seconds,omitempty"`
	TimeoutSeconds     int                      `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	StaleAfterSeconds  int                      `yaml:"stale_after_seconds,omitempty" json:"stale_after_seconds,omitempty"`
	StateDir           string                   `yaml:"state_dir,omitempty" json:"state_dir,omitempty"`
	Disk               MonitoringDiskConfig     `yaml:"disk,omitempty" json:"disk,omitempty"`
	Backup             MonitoringBackupConfig   `yaml:"backup,omitempty" json:"backup,omitempty"`
	TLS                MonitoringTLSConfig      `yaml:"tls,omitempty" json:"tls,omitempty"`
	Security           MonitoringSecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`
	External           MonitoringExternalConfig `yaml:"external,omitempty" json:"external,omitempty"`
	Notifications      MonitoringNotifications  `yaml:"notifications,omitempty" json:"notifications,omitempty"`
	OperationsStateDir string                   `yaml:"operations_state_dir,omitempty" json:"operations_state_dir,omitempty"`
}

type MonitoringDiskConfig struct {
	Data           MonitoringDiskTarget `yaml:"data,omitempty" json:"data,omitempty"`
	ImagesRegistry MonitoringDiskTarget `yaml:"images_registry,omitempty" json:"images_registry,omitempty"`
	Cache          MonitoringDiskTarget `yaml:"cache,omitempty" json:"cache,omitempty"`
	Backups        MonitoringDiskTarget `yaml:"backups,omitempty" json:"backups,omitempty"`
}

type MonitoringDiskTarget struct {
	Path                 string `yaml:"path,omitempty" json:"path,omitempty"`
	MinFreePercent       int    `yaml:"min_free_percent,omitempty" json:"min_free_percent,omitempty"`
	MinFreeInodesPercent int    `yaml:"min_free_inodes_percent,omitempty" json:"min_free_inodes_percent,omitempty"`
}

type MonitoringBackupConfig struct {
	Expected      bool   `yaml:"expected,omitempty" json:"expected,omitempty"`
	Path          string `yaml:"path,omitempty" json:"path,omitempty"`
	MaxAgeSeconds int    `yaml:"max_age_seconds,omitempty" json:"max_age_seconds,omitempty"`
	CloudEnabled  bool   `yaml:"cloud_enabled,omitempty" json:"cloud_enabled,omitempty"`
	CloudRequired bool   `yaml:"cloud_required,omitempty" json:"cloud_required,omitempty"`
}

type MonitoringTLSConfig struct {
	URL     string `yaml:"url,omitempty" json:"url,omitempty"`
	MinDays int    `yaml:"min_days,omitempty" json:"min_days,omitempty"`
}

type MonitoringSecurityConfig struct {
	CheckSSH          bool     `yaml:"check_ssh,omitempty" json:"check_ssh,omitempty"`
	CheckUFW          bool     `yaml:"check_ufw,omitempty" json:"check_ufw,omitempty"`
	CheckDockerUser   bool     `yaml:"check_docker_user,omitempty" json:"check_docker_user,omitempty"`
	CheckFail2ban     bool     `yaml:"check_fail2ban,omitempty" json:"check_fail2ban,omitempty"`
	ExpectedSSHUsers  []string `yaml:"expected_ssh_users,omitempty" json:"expected_ssh_users,omitempty"`
	PrivateInterface  string   `yaml:"private_interface,omitempty" json:"private_interface,omitempty"`
	AllowedTCPPorts   []string `yaml:"allowed_tcp_ports,omitempty" json:"allowed_tcp_ports,omitempty"`
	RequireSSHKeyOnly bool     `yaml:"require_ssh_key_only,omitempty" json:"require_ssh_key_only,omitempty"`
	RequireUFW        bool     `yaml:"require_ufw,omitempty" json:"require_ufw,omitempty"`
	RequireDockerUser bool     `yaml:"require_docker_user,omitempty" json:"require_docker_user,omitempty"`
	RequireFail2ban   bool     `yaml:"require_fail2ban,omitempty" json:"require_fail2ban,omitempty"`
	ExpectedSSHPort   int      `yaml:"expected_ssh_port,omitempty" json:"expected_ssh_port,omitempty"`
	// SSHListenAddress is the local sshd address from trusted host inventory.
	// It is never invented as loopback. SSHPeerAddress and SSHPeerHost are the
	// connecting client identity; they stay empty unless the caller observed them.
	SSHListenAddress string `yaml:"ssh_listen_address,omitempty" json:"ssh_listen_address,omitempty"`
	SSHPeerAddress   string `yaml:"ssh_peer_address,omitempty" json:"ssh_peer_address,omitempty"`
	SSHPeerHost      string `yaml:"ssh_peer_host,omitempty" json:"ssh_peer_host,omitempty"`
}

// MonitoringAccessDefaults is the trusted project and host-group baseline used
// to materialize installed monitoring policy. Empty fields on the monitoring
// document keep these values; explicit settings override them.
type MonitoringAccessDefaults struct {
	Users            []string
	AllowedTCPPorts  []string
	SSHPort          int
	ListenAddress    string
	PeerAddress      string
	PeerHost         string
	PrivateInterface string
}

type MonitoringExternalConfig struct {
	URL               string `yaml:"url,omitempty" json:"url,omitempty"`
	IntervalSeconds   int    `yaml:"interval_seconds,omitempty" json:"interval_seconds,omitempty"`
	TimeoutSeconds    int    `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	StateDir          string `yaml:"state_dir,omitempty" json:"state_dir,omitempty"`
	WebhookEnv        string `yaml:"webhook_env,omitempty" json:"webhook_env,omitempty"`
	WebhookSecretFile string `yaml:"webhook_secret_file,omitempty" json:"webhook_secret_file,omitempty"`
}

type MonitoringNotifications struct {
	WebhookEnv        string `yaml:"webhook_env,omitempty" json:"webhook_env,omitempty"`
	WebhookSecretFile string `yaml:"webhook_secret_file,omitempty" json:"webhook_secret_file,omitempty"`
	Retries           int    `yaml:"retries,omitempty" json:"retries,omitempty"`
	RetryDelaySeconds int    `yaml:"retry_delay_seconds,omitempty" json:"retry_delay_seconds,omitempty"`
	DebounceSeconds   int    `yaml:"debounce_seconds,omitempty" json:"debounce_seconds,omitempty"`
	FailureLog        string `yaml:"failure_log,omitempty" json:"failure_log,omitempty"`
}

const (
	MinMonitoringIntervalSeconds = 10
	MaxMonitoringIntervalSeconds = 24 * 60 * 60
	MinMonitoringTimeoutSeconds  = 1
	MaxMonitoringTimeoutSeconds  = 120
	MinMonitoringStaleSeconds    = 10
	MaxMonitoringStaleSeconds    = 7 * 24 * 60 * 60
	DefaultMonitoringInterval    = 60
	DefaultMonitoringTimeout     = 10
	DefaultMonitoringStaleAfter  = 5 * 60
	DefaultMonitoringBackupAge   = 24 * 60 * 60
	DefaultMonitoringMinFree     = 20
	DefaultMonitoringMinInodes   = 20
	DefaultMonitoringRetries     = 3
	DefaultMonitoringRetryDelay  = 2
	DefaultMonitoringDebounce    = 30
	DefaultMonitoringDataPath    = "/var/lib/shuttle"
	DefaultMonitoringImagesPath  = "/var/lib/docker"
	DefaultMonitoringBackupPath  = "/var/backups/shuttle-postgres"
	HostCachePathNotInVPSScope   = "/var/cache"
)

var monitoringEnvName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

// NormalizeMonitoring applies production-safe defaults only after explicit
// opt-in. An empty monitoring block remains inert and therefore compatible
// with configurations created before monitoring existed.
func (m *MonitoringConfig) NormalizeMonitoring() {
	if m == nil || !m.Enabled {
		return
	}
	if m.IntervalSeconds == 0 {
		m.IntervalSeconds = DefaultMonitoringInterval
	}
	if m.TimeoutSeconds == 0 {
		m.TimeoutSeconds = DefaultMonitoringTimeout
	}
	if m.StaleAfterSeconds == 0 {
		m.StaleAfterSeconds = DefaultMonitoringStaleAfter
	}
	if m.StateDir == "" {
		m.StateDir = "/var/lib/shuttle/monitoring"
	}
	if m.OperationsStateDir == "" {
		m.OperationsStateDir = "/var/lib/shuttle/operations"
	}
	for path, target := range map[string]*MonitoringDiskTarget{
		"data":            &m.Disk.Data,
		"images_registry": &m.Disk.ImagesRegistry,
		"cache":           &m.Disk.Cache,
		"backups":         &m.Disk.Backups,
	} {
		if target.Path == "" {
			switch path {
			case "data":
				target.Path = DefaultMonitoringDataPath
			case "images_registry":
				target.Path = DefaultMonitoringImagesPath
			case "backups":
				target.Path = DefaultMonitoringBackupPath
			}
		}
		if target.MinFreePercent == 0 {
			target.MinFreePercent = DefaultMonitoringMinFree
		}
		if target.MinFreeInodesPercent == 0 {
			target.MinFreeInodesPercent = DefaultMonitoringMinInodes
		}
	}
	if m.Backup.Expected {
		if m.Backup.Path == "" {
			m.Backup.Path = DefaultMonitoringBackupPath
		}
		if m.Backup.MaxAgeSeconds == 0 {
			m.Backup.MaxAgeSeconds = DefaultMonitoringBackupAge
		}
	}
	if m.TLS.URL != "" && m.TLS.MinDays == 0 {
		m.TLS.MinDays = 14
	}
	if m.Notifications.Retries == 0 {
		m.Notifications.Retries = DefaultMonitoringRetries
	}
	if m.Notifications.RetryDelaySeconds == 0 {
		m.Notifications.RetryDelaySeconds = DefaultMonitoringRetryDelay
	}
	if m.Notifications.DebounceSeconds == 0 {
		m.Notifications.DebounceSeconds = DefaultMonitoringDebounce
	}
	// A required policy is also an explicit request to collect the matching
	// evidence. Previously a config that set only require_ufw, for example,
	// silently left the UFW collector disabled.
	if m.Security.RequireSSHKeyOnly {
		m.Security.CheckSSH = true
	}
	if m.Security.RequireUFW {
		m.Security.CheckUFW = true
	}
	if m.Security.RequireDockerUser {
		m.Security.CheckDockerUser = true
	}
	if m.Security.RequireFail2ban {
		m.Security.CheckFail2ban = true
	}
	if !m.Security.CheckSSH && !m.Security.CheckUFW && !m.Security.CheckDockerUser && !m.Security.CheckFail2ban && !m.Security.RequireSSHKeyOnly && !m.Security.RequireUFW && !m.Security.RequireDockerUser && !m.Security.RequireFail2ban {
		m.Security.CheckSSH = true
		m.Security.CheckUFW = true
		m.Security.CheckDockerUser = true
		m.Security.CheckFail2ban = true
	}
	if m.Security.CheckSSH && !m.Security.RequireSSHKeyOnly {
		m.Security.RequireSSHKeyOnly = true
	}
	if m.Security.CheckUFW && !m.Security.RequireUFW {
		m.Security.RequireUFW = true
	}
	if m.Security.CheckDockerUser && !m.Security.RequireDockerUser {
		m.Security.RequireDockerUser = true
	}
	if m.Security.CheckFail2ban && !m.Security.RequireFail2ban {
		m.Security.RequireFail2ban = true
	}
	if m.External.URL != "" {
		if m.External.IntervalSeconds == 0 {
			m.External.IntervalSeconds = m.IntervalSeconds
		}
		if m.External.TimeoutSeconds == 0 {
			m.External.TimeoutSeconds = m.TimeoutSeconds
		}
		if m.External.StateDir == "" {
			m.External.StateDir = "/var/lib/shuttle/monitoring-external"
		}
	}
}

// NormalizeMonitoringForApp materializes destinations below the one
// application-owned monitoring root. The generic normalizer remains useful
// for read-only local checks, where the application name is not available.
func (m *MonitoringConfig) NormalizeMonitoringForApp(app string) {
	m.NormalizeMonitoring()
	if m == nil || !m.Enabled || !validMonitoringApp(app) {
		return
	}
	if m.StateDir == "/var/lib/shuttle/monitoring" {
		m.StateDir = filepath.Join("/var/lib/shuttle/monitoring", app)
	}
	if m.External.StateDir == "/var/lib/shuttle/monitoring-external" {
		m.External.StateDir = filepath.Join("/var/lib/shuttle/monitoring-external", app)
	}
}

func validMonitoringApp(app string) bool {
	if app == "" || len(app) > 63 {
		return false
	}
	return regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`).MatchString(app)
}

func monitoringPath(field, value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s must be an absolute path without control characters", field)
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || strings.ContainsRune(";|&$<>`'\"()[]{}!", r)
	}) >= 0 {
		return fmt.Errorf("%s contains whitespace or a systemd metacharacter", field)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || part == "." {
			return fmt.Errorf("%s must not traverse directories", field)
		}
	}
	return nil
}

func monitoringPathBelow(field, value, root string) error {
	if err := monitoringPath(field, value); err != nil {
		return err
	}
	rel, err := filepath.Rel(root, value)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s must remain below %s", field, root)
	}
	return nil
}

func monitoringURL(field, value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s must be an HTTPS URL without embedded credentials or control characters", field)
	}
	return nil
}

func monitoringEnv(field, value string) error {
	if value != "" && !monitoringEnvName.MatchString(value) {
		return fmt.Errorf("%s must be an uppercase environment variable name", field)
	}
	return nil
}

func validateMonitoringDisk(field string, value MonitoringDiskTarget) error {
	if err := monitoringPath(field+".path", value.Path); err != nil {
		return err
	}
	for name, threshold := range map[string]int{"min_free_percent": value.MinFreePercent, "min_free_inodes_percent": value.MinFreeInodesPercent} {
		if threshold < 1 || threshold > 99 {
			return fmt.Errorf("%s.%s must be between 1 and 99", field, name)
		}
	}
	return nil
}

// ValidateMonitoring validates the complete installed monitoring contract.
func (m *MonitoringConfig) ValidateMonitoring() error {
	return m.validateMonitoring("")
}

// ValidateMonitoringForApp applies the stronger installed configuration
// contract. State and delivery files are root-owned outputs, so they may only
// live below the app-specific monitoring root.
func (m *MonitoringConfig) ValidateMonitoringForApp(app string) error {
	if !validMonitoringApp(app) {
		return errors.New("monitoring application must be a lowercase app name")
	}
	m.NormalizeMonitoringForApp(app)
	if err := m.validateMonitoring(app); err != nil {
		return err
	}
	root := filepath.Join("/var/lib/shuttle/monitoring", app)
	if err := monitoringPathBelow("monitoring.state_dir", m.StateDir, root); err != nil {
		return err
	}
	if m.Notifications.FailureLog != "" {
		if err := monitoringPathBelow("monitoring.notifications.failure_log", m.Notifications.FailureLog, root); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{"monitoring.notifications.webhook_secret_file": m.Notifications.WebhookSecretFile, "monitoring.external.webhook_secret_file": m.External.WebhookSecretFile} {
		if value == "" {
			continue
		}
		allowed := false
		for _, root := range []string{"/etc/shuttle", root, filepath.Join("/var/lib/shuttle/monitoring-external", app)} {
			rel, relErr := filepath.Rel(root, value)
			if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%s must remain below an approved root-owned secret root", field)
		}
	}
	if m.External.URL != "" {
		externalRoot := filepath.Join("/var/lib/shuttle/monitoring-external", app)
		if err := monitoringPathBelow("monitoring.external.state_dir", m.External.StateDir, externalRoot); err != nil {
			return err
		}
	}
	return nil
}

func (m *MonitoringConfig) validateMonitoring(app string) error {
	if m == nil || !m.Enabled {
		if m != nil && (m.IntervalSeconds != 0 || m.TimeoutSeconds != 0 || m.StaleAfterSeconds != 0 || m.Backup.Expected || m.TLS.URL != "" || m.External.URL != "" || len(m.Notifications.WebhookEnv) > 0 || len(m.Notifications.WebhookSecretFile) > 0) {
			return errors.New("monitoring settings require monitoring.enabled: true")
		}
		return nil
	}
	m.NormalizeMonitoring()
	if m.IntervalSeconds < MinMonitoringIntervalSeconds || m.IntervalSeconds > MaxMonitoringIntervalSeconds {
		return fmt.Errorf("monitoring.interval_seconds must be between %d and %d", MinMonitoringIntervalSeconds, MaxMonitoringIntervalSeconds)
	}
	if m.TimeoutSeconds < MinMonitoringTimeoutSeconds || m.TimeoutSeconds > MaxMonitoringTimeoutSeconds {
		return fmt.Errorf("monitoring.timeout_seconds must be between %d and %d", MinMonitoringTimeoutSeconds, MaxMonitoringTimeoutSeconds)
	}
	if m.StaleAfterSeconds < m.IntervalSeconds || m.StaleAfterSeconds < MinMonitoringStaleSeconds || m.StaleAfterSeconds > MaxMonitoringStaleSeconds {
		return fmt.Errorf("monitoring.stale_after_seconds must be at least interval_seconds and at most %d", MaxMonitoringStaleSeconds)
	}
	if err := monitoringPath("monitoring.state_dir", m.StateDir); err != nil {
		return err
	}
	if err := monitoringPathBelow("monitoring.state_dir", m.StateDir, "/var/lib/shuttle/monitoring"); err != nil {
		return err
	}
	if err := monitoringPath("monitoring.operations_state_dir", m.OperationsStateDir); err != nil {
		return err
	}
	for field, target := range map[string]MonitoringDiskTarget{
		"monitoring.disk.data":            m.Disk.Data,
		"monitoring.disk.images_registry": m.Disk.ImagesRegistry,
		"monitoring.disk.backups":         m.Disk.Backups,
	} {
		if err := validateMonitoringDisk(field, target); err != nil {
			return err
		}
	}
	if m.Disk.Cache.Path != "" {
		if err := validateMonitoringDisk("monitoring.disk.cache", m.Disk.Cache); err != nil {
			return err
		}
	}
	if m.Backup.Expected {
		if err := monitoringPath("monitoring.backup.path", m.Backup.Path); err != nil {
			return err
		}
		if m.Backup.MaxAgeSeconds < 60 || m.Backup.MaxAgeSeconds > 30*24*60*60 {
			return errors.New("monitoring.backup.max_age_seconds must be between 60 and 2592000")
		}
		if m.Backup.CloudRequired && !m.Backup.CloudEnabled {
			return errors.New("monitoring.backup.cloud_required requires backup.cloud_enabled")
		}
	} else if m.Backup.CloudRequired || m.Backup.CloudEnabled {
		return errors.New("monitoring.backup cloud export settings require backup.expected: true")
	}
	if err := monitoringURL("monitoring.tls.url", m.TLS.URL); err != nil {
		return err
	}
	if m.TLS.URL != "" && (m.TLS.MinDays < 1 || m.TLS.MinDays > 365) {
		return errors.New("monitoring.tls.min_days must be between 1 and 365")
	}
	if m.Security.ExpectedSSHPort != 0 && (m.Security.ExpectedSSHPort < 1 || m.Security.ExpectedSSHPort > 65535) {
		return errors.New("monitoring.security.expected_ssh_port must be between 1 and 65535")
	}
	if err := validateMonitoringIP("monitoring.security.ssh_listen_address", m.Security.SSHListenAddress); err != nil {
		return err
	}
	if err := validateMonitoringIP("monitoring.security.ssh_peer_address", m.Security.SSHPeerAddress); err != nil {
		return err
	}
	if m.Security.SSHPeerHost != "" {
		if len(m.Security.SSHPeerHost) > 253 || strings.ContainsAny(m.Security.SSHPeerHost, " \t\r\n\x00,=") {
			return errors.New("monitoring.security.ssh_peer_host is not a valid sshd host criterion")
		}
	}
	if m.Security.PrivateInterface != "" {
		if len(m.Security.PrivateInterface) > 15 || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(m.Security.PrivateInterface) {
			return errors.New("monitoring.security.private_interface is not a valid interface name")
		}
	}
	if len(m.Security.AllowedTCPPorts) > 64 {
		return errors.New("monitoring.security.allowed_tcp_ports is limited to 64 ports")
	}
	for _, port := range m.Security.AllowedTCPPorts {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || port != strconv.Itoa(value) {
			return fmt.Errorf("monitoring.security.allowed_tcp_ports contains invalid port %q", port)
		}
	}
	if len(m.Security.ExpectedSSHUsers) > MaxAllowedSSHUsers {
		return fmt.Errorf("monitoring.security.expected_ssh_users is limited to %d accounts", MaxAllowedSSHUsers)
	}
	for _, user := range m.Security.ExpectedSSHUsers {
		if user != strings.TrimSpace(user) || !setupOperatorUserPattern.MatchString(user) || user == "root" {
			return fmt.Errorf("monitoring.security.expected_ssh_users contains invalid account %q", user)
		}
	}
	if err := monitoringURL("monitoring.external.url", m.External.URL); err != nil {
		return err
	}
	if err := monitoringEnv("monitoring.external.webhook_env", m.External.WebhookEnv); err != nil {
		return err
	}
	if m.External.WebhookSecretFile != "" {
		if err := monitoringPath("monitoring.external.webhook_secret_file", m.External.WebhookSecretFile); err != nil {
			return err
		}
	}
	if m.External.WebhookEnv != "" && m.External.WebhookSecretFile != "" {
		return errors.New("monitoring.external must use either webhook_env or webhook_secret_file")
	}
	if m.External.URL != "" {
		if m.External.IntervalSeconds < MinMonitoringIntervalSeconds || m.External.IntervalSeconds > MaxMonitoringIntervalSeconds {
			return errors.New("monitoring.external.interval_seconds is outside the monitoring bounds")
		}
		if m.External.TimeoutSeconds < MinMonitoringTimeoutSeconds || m.External.TimeoutSeconds > MaxMonitoringTimeoutSeconds {
			return errors.New("monitoring.external.timeout_seconds is outside the monitoring bounds")
		}
		if err := monitoringPath("monitoring.external.state_dir", m.External.StateDir); err != nil {
			return err
		}
		if err := monitoringPathBelow("monitoring.external.state_dir", m.External.StateDir, "/var/lib/shuttle/monitoring-external"); err != nil {
			return err
		}
	}
	if err := monitoringEnv("monitoring.notifications.webhook_env", m.Notifications.WebhookEnv); err != nil {
		return err
	}
	if m.Notifications.WebhookEnv != "" && m.Notifications.WebhookSecretFile != "" {
		return errors.New("monitoring.notifications must use either webhook_env or webhook_secret_file")
	}
	if m.Notifications.WebhookSecretFile != "" {
		if err := monitoringPath("monitoring.notifications.webhook_secret_file", m.Notifications.WebhookSecretFile); err != nil {
			return err
		}
	}
	if m.Notifications.Retries < 1 || m.Notifications.Retries > 5 {
		return errors.New("monitoring.notifications.retries must be between 1 and 5")
	}
	if m.Notifications.RetryDelaySeconds < 1 || m.Notifications.RetryDelaySeconds > 60 {
		return errors.New("monitoring.notifications.retry_delay_seconds must be between 1 and 60")
	}
	if m.Notifications.DebounceSeconds < 0 || m.Notifications.DebounceSeconds > 3600 {
		return errors.New("monitoring.notifications.debounce_seconds must be between 0 and 3600")
	}
	if m.Notifications.FailureLog != "" {
		if err := monitoringPath("monitoring.notifications.failure_log", m.Notifications.FailureLog); err != nil {
			return err
		}
		if err := monitoringPathBelow("monitoring.notifications.failure_log", m.Notifications.FailureLog, "/var/lib/shuttle/monitoring"); err != nil {
			return err
		}
	}
	if m.Notifications.WebhookEnv == "" && m.Notifications.WebhookSecretFile == "" && m.External.WebhookEnv == "" && m.External.WebhookSecretFile == "" {
		return errors.New("enabled monitoring requires an explicit notification webhook environment variable or root secret file")
	}
	return nil
}

// MonitoringSecurityUsers returns a deterministic expected AllowUsers policy.
func (m MonitoringSecurityConfig) MonitoringSecurityUsers() []string {
	users := append([]string(nil), m.ExpectedSSHUsers...)
	sort.Strings(users)
	return users
}

// ApplyTrustedAccessDefaults copies host-group and project access inventory
// into empty monitoring security fields. Explicit monitoring values win.
func (m *MonitoringConfig) ApplyTrustedAccessDefaults(defaults MonitoringAccessDefaults) {
	if m == nil || !m.Enabled {
		return
	}
	if len(m.Security.ExpectedSSHUsers) == 0 && len(defaults.Users) > 0 {
		m.Security.ExpectedSSHUsers = append([]string(nil), defaults.Users...)
	}
	if len(m.Security.AllowedTCPPorts) == 0 && len(defaults.AllowedTCPPorts) > 0 {
		m.Security.AllowedTCPPorts = append([]string(nil), defaults.AllowedTCPPorts...)
	}
	if m.Security.ExpectedSSHPort == 0 && defaults.SSHPort > 0 {
		m.Security.ExpectedSSHPort = defaults.SSHPort
	}
	if m.Security.PrivateInterface == "" && defaults.PrivateInterface != "" {
		m.Security.PrivateInterface = defaults.PrivateInterface
	}
	if m.Security.SSHListenAddress == "" {
		m.Security.SSHListenAddress = MonitoringSSHListenAddress(defaults.ListenAddress)
	}
	if m.Security.SSHPeerAddress == "" {
		m.Security.SSHPeerAddress = MonitoringSSHListenAddress(defaults.PeerAddress)
	}
	if m.Security.SSHPeerHost == "" && defaults.PeerHost != "" && !strings.ContainsAny(defaults.PeerHost, " \t\r\n\x00,=") {
		m.Security.SSHPeerHost = defaults.PeerHost
	}
}

// MonitoringSSHListenAddress accepts an observed IP address. Hostnames and
// empty values are omitted rather than rewritten as loopback.
func MonitoringSSHListenAddress(host string) string {
	value := strings.TrimSpace(host)
	if value == "" || net.ParseIP(value) == nil {
		return ""
	}
	return value
}

func validateMonitoringIP(field, value string) error {
	if value == "" {
		return nil
	}
	if net.ParseIP(value) == nil || strings.ContainsAny(value, " \t\r\n\x00,=") {
		return fmt.Errorf("%s must be an IP address without sshd metacharacters", field)
	}
	return nil
}

// DiskCachePathInVPSScope reports whether a cache path is an explicit VPS
// filesystem to monitor. The host /var/cache tree is not BuildKit.
func DiskCachePathInVPSScope(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	return filepath.Clean(path) != HostCachePathNotInVPSScope
}
