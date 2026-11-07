package monitoring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

const incidentSchema = "shuttle.monitoring-incidents/v1"

type Incident struct {
	CheckID            string `json:"check_id"`
	EpisodeID          string `json:"episode_id"`
	State              string `json:"state"`
	FirstSeen          string `json:"first_seen"`
	LastSeen           string `json:"last_seen"`
	LastFailureState   string `json:"last_failure_state,omitempty"`
	LastFailureSummary string `json:"last_failure_summary,omitempty"`
	PendingSince       string `json:"pending_since,omitempty"`
	RecoverySince      string `json:"recovery_since,omitempty"`
	IncidentSent       bool   `json:"incident_sent"`
	RecoveryPending    bool   `json:"recovery_pending"`
	RecoverySent       bool   `json:"recovery_sent"`
}

type AlertEvent struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	CheckID   string `json:"check_id"`
	EpisodeID string `json:"episode_id"`
	App       string `json:"app"`
	State     string `json:"state"`
	Summary   string `json:"summary"`
	CreatedAt string `json:"created_at"`
}

type IncidentState struct {
	Schema           string              `json:"schema"`
	UpdatedAt        string              `json:"updated_at"`
	Incidents        map[string]Incident `json:"incidents"`
	Episodes         map[string]Incident `json:"episodes,omitempty"`
	Pending          []AlertEvent        `json:"pending"`
	MaintenanceUntil string              `json:"maintenance_until,omitempty"`
	LastReport       *Report             `json:"last_report,omitempty"`
}

type Store interface {
	Load(context.Context) (IncidentState, error)
	Save(context.Context, IncidentState) error
}

type processLock interface {
	Lock(context.Context) (func(), error)
}

type FileStore struct {
	Path string
	Mu   *sync.Mutex
}

func (s FileStore) Lock(ctx context.Context) (func(), error) {
	session, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	return func() { _ = session.Close() }, nil
}

func (s FileStore) Load(ctx context.Context) (IncidentState, error) {
	if err := ctx.Err(); err != nil {
		return IncidentState{}, err
	}
	if err := validateStatePath(s.Path); err != nil {
		return IncidentState{}, err
	}
	directory, err := openRuntimeDirectory(filepath.Dir(s.Path), true)
	if err != nil {
		return IncidentState{}, err
	}
	defer directory.Close()
	file, err := openRuntimeFile(directory, filepath.Base(s.Path), os.O_RDONLY, runtimeFileMode, runtimeUID(), false)
	if os.IsNotExist(err) {
		return emptyIncidentState(), nil
	}
	if err != nil {
		return IncidentState{}, err
	}
	defer file.Close()
	body, err := readBoundedFile(file, maxIncidentStateBytes)
	if err != nil {
		return IncidentState{}, err
	}
	return decodeIncidentState(body)
}

func decodeIncidentState(body []byte) (IncidentState, error) {
	var state IncidentState
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return IncidentState{}, errors.New("decode monitoring incident state")
	}
	if state.Schema != incidentSchema || state.Incidents == nil {
		return IncidentState{}, errors.New("invalid monitoring incident state")
	}
	if state.Pending == nil {
		state.Pending = []AlertEvent{}
	}
	return state, nil
}

func (s FileStore) Save(ctx context.Context, state IncidentState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateStatePath(s.Path); err != nil {
		return err
	}
	session, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer session.Close()
	return session.Save(ctx, state)
}

func validateStatePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("monitoring incident state path must be an absolute clean path")
	}
	if filepath.Base(path) != "incidents.json" {
		return errors.New("monitoring incident state path must name incidents.json")
	}
	return validateExistingPath(path, false)
}

type MemoryStore struct {
	Mu    sync.Mutex
	State IncidentState
}

func (s *MemoryStore) Load(context.Context) (IncidentState, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.State.Schema == "" {
		s.State = emptyIncidentState()
	}
	return cloneIncidentState(s.State), nil
}

func (s *MemoryStore) Save(_ context.Context, state IncidentState) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.State = cloneIncidentState(state)
	return nil
}

func emptyIncidentState() IncidentState {
	return IncidentState{Schema: incidentSchema, Incidents: map[string]Incident{}, Episodes: map[string]Incident{}, Pending: []AlertEvent{}}
}

func cloneIncidentState(state IncidentState) IncidentState {
	copyState := state
	copyState.Incidents = map[string]Incident{}
	for key, incident := range state.Incidents {
		copyState.Incidents[key] = incident
	}
	copyState.Episodes = map[string]Incident{}
	for key, incident := range state.Episodes {
		copyState.Episodes[key] = incident
	}
	copyState.Pending = append([]AlertEvent(nil), state.Pending...)
	if state.LastReport != nil {
		report := cloneReport(*state.LastReport)
		copyState.LastReport = &report
	}
	return copyState
}

func cloneReport(report Report) Report {
	copyReport := report
	copyReport.Checks = append([]Result(nil), report.Checks...)
	for index := range copyReport.Checks {
		if copyReport.Checks[index].Evidence == nil {
			continue
		}
		evidence := make(map[string]any, len(copyReport.Checks[index].Evidence))
		for key, value := range copyReport.Checks[index].Evidence {
			evidence[key] = value
		}
		copyReport.Checks[index].Evidence = evidence
	}
	return copyReport
}

type Notification struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	App       string `json:"app"`
	CheckID   string `json:"check_id"`
	EpisodeID string `json:"episode_id"`
	State     string `json:"state"`
	Summary   string `json:"summary"`
	// CreatedAt is when the event was queued (RFC 3339). It dates the chat
	// message, so a retried delivery still says when the change happened.
	CreatedAt string `json:"created_at,omitempty"`
}

// webhookPayload is the body POSTed to the notification webhook. It keeps every
// Notification field for a generic receiver and adds one human line as
// `content` (Discord) and `text` (Slack, Mattermost). The bare Notification had
// neither, so a Discord webhook rejected every alert (HTTP 400, "cannot send an
// empty message") and the only trace was the delivery-failure log: a disk
// filling up on demo prod (2026-10-27) would have alerted no one.
//
// Discord gets an embed instead of `content`: on 2026-10-28 the operator read
// "[shuttle] api services.application degraded: Service task health does
// not match the retained expected replicas" in a critical channel, one line
// of identifiers with no severity colour and no time. The embed answers what
// an on-call reader needs first: which app, what broke, how bad, since when.
// The colour carries the state and nothing else. `content` stays empty so the
// headline is not printed twice; Discord accepts a message with embeds only.
type webhookPayload struct {
	Notification
	Content string         `json:"content,omitempty"`
	Text    string         `json:"text"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
	Footer      *discordFooter `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

// chatMessageLimit stays under Discord's 2000-character message limit; the
// embed description limit (4096) is larger, so one bound serves both.
const (
	chatMessageLimit = 1900
	embedTitleLimit  = 256
)

const (
	colorRecovered = 0x3BA55C
	colorDegraded  = 0xE8A317
	colorDown      = 0xD64045
)

// checkLabels names checks the way an operator says them. An unknown or new
// check falls back to its identifier, which is still exact.
var checkLabels = map[string]string{
	"services.application":        "application service",
	"services.caddy":              "Caddy",
	"services.docker":             "Docker",
	"services.postgresql":         "PostgreSQL",
	"services.rabbitmq":           "RabbitMQ",
	"services.redis":              "Redis",
	"services.registry":           "image registry",
	"disk.backups":                "backup disk",
	"disk.cache":                  "build cache disk",
	"disk.data":                   "data disk",
	"disk.data.postgresql":        "PostgreSQL disk",
	"disk.images_registry":        "image disk",
	"disk.images_registry.volume": "registry volume",
	"security.docker_user":        "Docker user isolation",
	"security.ssh":                "SSH hardening",
	"security.ufw":                "firewall",
	"tls.expiry":                  "TLS certificate",
	"tls.https":                   "HTTPS",
	"external.https":              "public HTTPS",
	"notifications.channel":       "notification channel",
}

func checkLabel(id string) string {
	if label := checkLabels[id]; label != "" {
		return label
	}
	if id == "" {
		return "check"
	}
	return id
}

func notificationHeadline(notification Notification) string {
	state := notification.State
	if notification.Kind == "recovery" {
		state = "recovered"
	}
	headline := checkLabel(notification.CheckID) + " " + state
	if notification.App != "" {
		headline = notification.App + ": " + headline
	}
	return truncateRunes(headline, embedTitleLimit)
}

func truncateRunes(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	return string([]rune(value)[:limit])
}

// chatLine is the plain-text form (Slack, Mattermost, any `text` reader).
func chatLine(notification Notification) string {
	return truncateRunes(notificationHeadline(notification)+". "+notification.Summary, chatMessageLimit)
}

func notificationColor(notification Notification) int {
	switch {
	case notification.Kind == "recovery" || notification.State == StateHealthy:
		return colorRecovered
	case notification.State == StateDegraded:
		return colorDegraded
	default:
		return colorDown
	}
}

func notificationEmbed(notification Notification) discordEmbed {
	embed := discordEmbed{Title: notificationHeadline(notification), Color: notificationColor(notification), Footer: &discordFooter{Text: "Shuttle monitoring"}}
	started, startedErr := time.Parse(time.RFC3339Nano, notification.EpisodeID)
	at, atErr := time.Parse(time.RFC3339Nano, notification.CreatedAt)
	if atErr == nil {
		embed.Timestamp = at.UTC().Format(time.RFC3339)
	}
	description := notification.Summary
	if notification.Kind == "recovery" && startedErr == nil && atErr == nil && !at.Before(started) {
		description = "Healthy again after " + formatEpisodeDuration(at.Sub(started)) + "."
	}
	embed.Description = truncateRunes(description, chatMessageLimit)
	embed.Fields = append(embed.Fields, discordField{Name: "App", Value: fieldValue(notification.App), Inline: true})
	embed.Fields = append(embed.Fields, discordField{Name: "Check", Value: "`" + fieldValue(notification.CheckID) + "`", Inline: true})
	if startedErr == nil {
		// Discord renders <t:unix:R> as a relative time in the reader's locale.
		embed.Fields = append(embed.Fields, discordField{Name: "Started", Value: fmt.Sprintf("<t:%d:R>", started.Unix()), Inline: true})
	}
	return embed
}

func fieldValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return truncateRunes(value, 200)
}

func formatEpisodeDuration(duration time.Duration) string {
	duration = duration.Round(time.Second)
	if duration < time.Minute {
		return fmt.Sprintf("%ds", int(duration.Seconds()))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(duration.Minutes()), int(duration.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(duration.Hours()), int(duration.Minutes())%60)
}

type Notifier interface {
	Notify(context.Context, Notification) error
}

type WebhookNotifier struct {
	URL    string
	Client HTTPDoer
}

func (n WebhookNotifier) Notify(ctx context.Context, notification Notification) error {
	if n.URL == "" || !strings.HasPrefix(strings.ToLower(n.URL), "https://") {
		return errors.New("notification webhook is not an HTTPS URL")
	}
	body, err := json.Marshal(webhookPayload{Notification: notification, Text: chatLine(notification), Embeds: []discordEmbed{notificationEmbed(notification)}})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("create notification request")
	}
	request.Header.Set("Content-Type", "application/json")
	client := n.Client
	if client == nil {
		client = &http.Client{}
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("notification delivery failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("notification endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

type AlertManager struct {
	Store              Store
	Notifier           Notifier
	NotifierFactory    func() (Notifier, error)
	FailureLog         string
	Retries            int
	RetryDelay         time.Duration
	Debounce           time.Duration
	MaintenanceUntil   string
	MaintenanceUnknown bool
	NotifyTimeout      time.Duration
	NotifierErr        error
	Now                func() time.Time
}

const (
	maxIncidentStateBytes = 1 << 20
	maxSecretBytes        = 4096
	maxLockWait           = 30 * time.Second
)

var (
	ErrTransactionTimeout     = errors.New("transaction_timeout")
	ErrPersistenceUnconfirmed = errors.New("persistence_unconfirmed")
	errMaintenanceUnreadable  = errors.New("monitoring maintenance state is unreadable")
)

type transactionSlot struct {
	done     chan struct{}
	progress *saveProgress
}

var (
	transactionMu        sync.Mutex
	inflightTransactions = map[string]*transactionSlot{}
)

type processOutcome struct {
	state IncidentState
	err   error
}

func startTransaction(path string, allowNew bool) (*transactionSlot, bool) {
	transactionMu.Lock()
	defer transactionMu.Unlock()
	if slot, ok := inflightTransactions[path]; ok {
		return slot, false
	}
	if !allowNew {
		return nil, false
	}
	slot := &transactionSlot{done: make(chan struct{}), progress: &saveProgress{}}
	inflightTransactions[path] = slot
	return slot, true
}

func finishTransaction(path string, slot *transactionSlot) {
	transactionMu.Lock()
	if current, ok := inflightTransactions[path]; ok && current == slot {
		delete(inflightTransactions, path)
	}
	transactionMu.Unlock()
	close(slot.done)
}

func (m AlertManager) Process(ctx context.Context, report Report) (IncidentState, error) {
	isolated := cloneReport(report)
	if m.Store == nil {
		return reportOnlyState(isolated), errors.New("monitoring incident store is required")
	}
	if fileStore, ok := fileStoreFrom(m.Store); ok {
		return m.processFileStore(ctx, fileStore, isolated)
	}
	if locker, ok := m.Store.(processLock); ok {
		unlock, lockErr := locker.Lock(ctx)
		if lockErr != nil {
			return reportOnlyState(isolated), lockErr
		}
		defer unlock()
	}
	return m.processLocked(ctx, ctx, m.Store, isolated)
}

func (m AlertManager) processFileStore(ctx context.Context, store FileStore, report Report) (IncidentState, error) {
	path := filepath.Clean(store.Path)
	for {
		// An exhausted collection deadline must still be able to start a
		// persist-only worker. Reusing an inflight slot stays exclusive so
		// repeated expired callers cannot spawn extra writers.
		expiredAtStart := ctx.Err() != nil
		slot, owned := startTransaction(path, true)
		if !owned {
			if slot == nil {
				return reportOnlyState(cloneReport(report)), ErrTransactionTimeout
			}
			select {
			case <-slot.done:
				continue
			case <-ctx.Done():
				return reportOnlyState(cloneReport(report)), slot.progress.timeoutError()
			}
		}
		results := make(chan processOutcome, 1)
		workerReport := cloneReport(report)
		deliveryCtx := ctx
		go func() {
			defer finishTransaction(path, slot)
			// Persistence is always budgeted. Background() used to let a
			// blocked fsync keep the lock after both cycle and finalization
			// deadlines had expired.
			persistCtx, cancelPersist := boundedPersistContext(ctx)
			if expiredAtStart {
				cancelPersist()
				persistCtx, cancelPersist = persistFinalizeContext()
			}
			defer cancelPersist()
			session, err := store.begin(persistCtx)
			if err != nil {
				results <- processOutcome{state: reportOnlyState(cloneReport(workerReport)), err: err}
				return
			}
			session.progress = slot.progress
			defer session.Close()
			state, processErr := m.processLocked(persistCtx, deliveryCtx, session, workerReport)
			results <- processOutcome{state: cloneIncidentState(state), err: processErr}
		}()
		if expiredAtStart {
			persistWait, cancelWait := persistFinalizeContext()
			select {
			case out := <-results:
				cancelWait()
				return out.state, errors.Join(ctx.Err(), out.err)
			case <-persistWait.Done():
				cancelWait()
				return reportOnlyState(cloneReport(report)), errors.Join(ctx.Err(), slot.progress.timeoutError())
			}
		}
		select {
		case out := <-results:
			return out.state, out.err
		case <-ctx.Done():
			return reportOnlyState(cloneReport(report)), slot.progress.timeoutError()
		}
	}
}

func fileStoreFrom(store Store) (FileStore, bool) {
	switch value := store.(type) {
	case FileStore:
		return value, true
	case *FileStore:
		if value != nil {
			return *value, true
		}
	}
	return FileStore{}, false
}

func reportOnlyState(report Report) IncidentState {
	state := emptyIncidentState()
	copyReport := report
	state.LastReport = &copyReport
	return state
}

func (m AlertManager) processLocked(persistCtx, deliveryCtx context.Context, store Store, report Report) (IncidentState, error) {
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	if m.NotifierFactory != nil && m.Notifier == nil && m.NotifierErr == nil && deliveryCtx.Err() == nil {
		m.Notifier, m.NotifierErr = m.NotifierFactory()
	}
	if m.NotifierErr != nil {
		report = reportWithDeliveryError(report)
	}
	state, err := store.Load(persistCtx)
	if err != nil {
		return reportOnlyState(report), err
	}
	if state.Schema == "" {
		state = emptyIncidentState()
	}
	normalizeIncidentState(&state)
	dropAcknowledgedPending(&state)
	if state.LastReport != nil && report.CheckedAt != "" && state.LastReport.CheckedAt != "" {
		prev, prevErr := time.Parse(time.RFC3339Nano, state.LastReport.CheckedAt)
		next, nextErr := time.Parse(time.RFC3339Nano, report.CheckedAt)
		if prevErr == nil && nextErr == nil && next.Before(prev) {
			return state, nil
		}
	}
	if !m.MaintenanceUnknown {
		// The maintenance file is the source of truth for this cycle. Clearing
		// it must clear the persisted window as well, otherwise a recovery can
		// remain suppressed until an old timestamp expires.
		state.MaintenanceUntil = m.MaintenanceUntil
	}
	if m.Retries < 1 {
		m.Retries = 1
	}
	if m.Retries > 5 {
		m.Retries = 5
	}
	if m.Debounce < 0 {
		m.Debounce = 0
	}
	if m.NotifyTimeout <= 0 {
		m.NotifyTimeout = 15 * time.Second
	}
	maintenance := false
	if m.MaintenanceUnknown {
		// Unreadable maintenance is not a cleared window. Notifications stay
		// suppressed so a corrupt file cannot both hide history and page.
		maintenance = true
	} else if state.MaintenanceUntil != "" {
		until, parseErr := time.Parse(time.RFC3339Nano, state.MaintenanceUntil)
		maintenance = parseErr == nil && now.Before(until)
		if !maintenance {
			state.MaintenanceUntil = ""
		}
	}
	flushHistoricalEpisodes(&state, report.App, now, maintenance, m.Debounce)
	for _, raw := range report.Checks {
		check := raw.WithFreshness(now)
		if check.State == StateNotApplicable || check.ID == "notifications.delivery" {
			continue
		}
		incident, exists := state.Incidents[check.ID]
		bad := check.State != StateHealthy
		if !exists {
			incident = newIncident(check.ID, now)
		}
		if incident.EpisodeID == "" {
			incident.EpisodeID = incident.FirstSeen
		}
		// While an incident is active, the previous sample saw the failure,
		// so LastSeen before this sample is where the observed failure ends.
		// The debounce compares that observed span, never the gap to the next
		// healthy sample: with a 60 s interval and a 30 s debounce, that gap
		// made every single bad sample an incident. On 2026-10-28 one sample
		// taken mid-rollout on demo prod (a new api_worker-high task
		// still starting) paged the critical channel. Using LastSeen keeps the
		// state file on its v1 shape, which a previous binary still reads.
		failureSeenUntil := now
		if incident.State == StateActive {
			failureSeenUntil = parseStamp(incident.LastSeen, now)
		}
		incident.LastSeen = now.Format(time.RFC3339Nano)
		if bad {
			if incident.State == StateRecovered || incident.RecoveryPending || incident.RecoverySent {
				preserveEpisode(&state, incident)
				queueEpisodeEvents(&state, incident, report.App, now, maintenance, m.Debounce)
				incident = newIncident(check.ID, now)
			}
			if incident.State != StateActive {
				if incident.State == StateHealthy {
					// The record was a healthy baseline, possibly created days
					// earlier: the episode starts now, not when it was created.
					incident.EpisodeID = now.Format(time.RFC3339Nano)
					incident.FirstSeen = incident.EpisodeID
				}
				incident.State = StateActive
				incident.PendingSince = now.Format(time.RFC3339Nano)
				incident.RecoverySince = ""
				incident.RecoveryPending = false
				incident.RecoverySent = false
				incident.IncidentSent = false
			}
			incident.LastFailureState = check.State
			incident.LastFailureSummary = check.Summary
			if !maintenance && !incident.IncidentSent && elapsedSince(incident.PendingSince, now) >= m.Debounce && !hasPendingEpisode(state.Pending, incident, "incident") {
				state.Pending = append(state.Pending, incidentEvent(report.App, incident, now))
			}
		} else if incident.State == StateActive || (incident.State == StateRecovered && !incident.RecoverySent) || incident.RecoveryPending {
			if !incident.IncidentSent && !hasPendingEpisode(state.Pending, incident, "incident") {
				// A short failure flap never becomes an incident. Dropping the
				// unannounced record also prevents a later recovery alert without
				// a corresponding incident.
				if elapsedBetween(incident.PendingSince, failureSeenUntil) < m.Debounce {
					delete(state.Incidents, check.ID)
					continue
				}
				if !maintenance {
					state.Pending = append(state.Pending, incidentEvent(report.App, incident, now))
				}
			}
			// Keep this transition durable even while its positive debounce is
			// pending. Later healthy samples must continue this branch.
			incident.State = StateRecovered
			if incident.RecoverySince == "" {
				incident.RecoverySince = now.Format(time.RFC3339Nano)
			}
			incident.RecoveryPending = !incident.RecoverySent
			queueRecovery(&state, incident, report.App, now, maintenance, m.Debounce)
		}
		state.Incidents[check.ID] = incident
	}
	flushHistoricalEpisodes(&state, report.App, now, maintenance, m.Debounce)
	state.UpdatedAt = now.Format(time.RFC3339Nano)
	reportCopy := cloneReport(report)
	state.LastReport = &reportCopy
	if err := m.saveState(persistCtx, store, state); err != nil {
		return state, err
	}
	var processErr error
	if !maintenance || m.NotifierErr != nil {
		notifyCtx, cancelDelivery := boundedDeliveryContext(deliveryCtx)
		processErr = m.deliver(notifyCtx, persistCtx, store, &state)
		cancelDelivery()
	}
	if err := m.saveState(persistCtx, store, state); err != nil {
		processErr = errors.Join(processErr, err)
	}
	return state, processErr
}

func boundedDeliveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	remaining := time.Until(deadline)
	if remaining <= minPersistReserve {
		child, cancel := context.WithCancel(ctx)
		cancel()
		return child, func() {}
	}
	return context.WithTimeout(ctx, remaining-minPersistReserve)
}

func persistFinalizeContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), minPersistReserve)
}

func boundedPersistContext(parent context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > minPersistReserve {
			return context.WithTimeout(context.Background(), remaining)
		}
	}
	return persistFinalizeContext()
}

const (
	StateActive    = "active"
	StateRecovered = "recovered"
)

func (m AlertManager) deliver(deliveryCtx, persistCtx context.Context, store Store, state *IncidentState) error {
	if m.NotifierErr != nil {
		event := AlertEvent{ID: "notifications.channel", Kind: "incident", CheckID: "notifications.channel", State: StateUnavailable, Summary: "Notification channel is unavailable"}
		return m.deliveryFailure(event, m.NotifierErr)
	}
	if len(state.Pending) == 0 {
		return nil
	}
	if m.Notifier == nil {
		err := errors.New("notification channel is not configured")
		return m.deliveryFailure(state.Pending[0], err)
	}
	for len(state.Pending) > 0 {
		if err := deliveryCtx.Err(); err != nil {
			return err
		}
		event := state.Pending[0]
		var lastErr error
		for attempt := 0; attempt < m.Retries; attempt++ {
			if err := deliveryCtx.Err(); err != nil {
				return err
			}
			lastErr = m.notify(deliveryCtx, event)
			if lastErr == nil {
				break
			}
			if attempt+1 < m.Retries && m.RetryDelay > 0 {
				timer := time.NewTimer(m.RetryDelay)
				select {
				case <-deliveryCtx.Done():
					timer.Stop()
					return deliveryCtx.Err()
				case <-timer.C:
				}
			}
		}
		if lastErr != nil {
			return m.deliveryFailure(event, lastErr)
		}
		state.Pending = state.Pending[1:]
		incident, episodeKey, current := episodeForEvent(state, event)
		if incident.CheckID != "" {
			if event.Kind == "incident" {
				incident.IncidentSent = true
				at := time.Now().UTC()
				if m.Now != nil {
					at = m.Now().UTC()
				}
				queueRecoveryFirst(state, incident, event.App, at, false, m.Debounce)
			} else if event.Kind == "recovery" {
				incident.RecoveryPending = false
				incident.RecoverySent = true
			}
			if current {
				state.Incidents[event.CheckID] = incident
			} else if episodeKey != "" {
				state.Episodes[episodeKey] = incident
			}
		}
		if err := m.saveState(persistCtx, store, *state); err != nil {
			return err
		}
	}
	return nil
}

func (m AlertManager) notify(ctx context.Context, event AlertEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	notifyCtx, cancel := context.WithTimeout(ctx, m.NotifyTimeout)
	defer cancel()
	return m.Notifier.Notify(notifyCtx, Notification{ID: event.ID, Kind: event.Kind, App: event.App, CheckID: event.CheckID, EpisodeID: event.EpisodeID, State: event.State, Summary: event.Summary, CreatedAt: event.CreatedAt})
}

func (m AlertManager) saveState(ctx context.Context, store Store, state IncidentState) error {
	return store.Save(ctx, state)
}

func (m AlertManager) deliveryFailure(event AlertEvent, deliveryErr error) error {
	if logErr := appendDeliveryFailure(m.FailureLog, event, deliveryErr, m.Now); logErr != nil {
		return errors.Join(deliveryErr, fmt.Errorf("persist notification failure: %w", logErr))
	}
	if m.FailureLog == "" && m.NotifierErr == nil {
		// Keep the direct in-memory manager compatibility contract. Installed
		// managers always receive a default failure log and return the outage.
		return nil
	}
	return deliveryErr
}

func appendDeliveryFailure(path string, event AlertEvent, deliveryErr error, now func() time.Time) error {
	if path == "" {
		return nil
	}
	if err := validateFailureLogPath(path); err != nil {
		return err
	}
	at := time.Now().UTC()
	if now != nil {
		at = now().UTC()
	}
	// Only stable event metadata is logged. The webhook URL, credentials and
	// command output are intentionally absent from this record.
	entry := map[string]any{"at": at.Format(time.RFC3339Nano), "event": event.ID, "kind": event.Kind, "check_id": event.CheckID, "error": "notification delivery failed"}
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	directory, err := openRuntimeDirectory(filepath.Dir(path), true)
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := openRuntimeFile(directory, filepath.Base(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, runtimeFileMode, runtimeUID(), true)
	if err != nil {
		return err
	}
	data := append(body, '\n')
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func validateFailureLogPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("delivery failure log path must be an absolute clean path")
	}
	base := filepath.Base(path)
	if base == "incidents.json" || base == "incidents.json.lock" || base == "maintenance.json" || strings.HasPrefix(base, ".incidents-") {
		return errors.New("delivery failure log collides with reserved monitoring state")
	}
	if err := validateExistingPath(path, false); err != nil {
		return err
	}
	return nil
}

func newIncident(checkID string, now time.Time) Incident {
	episodeID := now.UTC().Format(time.RFC3339Nano)
	return Incident{CheckID: checkID, EpisodeID: episodeID, State: StateHealthy, FirstSeen: episodeID, LastSeen: episodeID}
}

func episodeKey(checkID, episodeID string) string {
	return checkID + "\x00" + episodeID
}

func normalizeIncidentState(state *IncidentState) {
	if state.Incidents == nil {
		state.Incidents = map[string]Incident{}
	}
	if state.Episodes == nil {
		state.Episodes = map[string]Incident{}
	}
	for checkID, incident := range state.Incidents {
		if incident.CheckID == "" {
			incident.CheckID = checkID
		}
		if incident.EpisodeID == "" {
			incident.EpisodeID = incident.FirstSeen
		}
		if incident.FirstSeen == "" {
			incident.FirstSeen = incident.EpisodeID
		}
		state.Incidents[checkID] = incident
	}
	for key, incident := range state.Episodes {
		parts := strings.SplitN(key, "\x00", 2)
		if incident.CheckID == "" && len(parts) == 2 {
			incident.CheckID = parts[0]
		}
		if incident.EpisodeID == "" && len(parts) == 2 {
			incident.EpisodeID = parts[1]
		}
		if incident.FirstSeen == "" {
			incident.FirstSeen = incident.EpisodeID
		}
		state.Episodes[episodeKey(incident.CheckID, incident.EpisodeID)] = incident
		if key != episodeKey(incident.CheckID, incident.EpisodeID) {
			delete(state.Episodes, key)
		}
	}
	for index := range state.Pending {
		event := &state.Pending[index]
		if event.EpisodeID != "" {
			continue
		}
		if incident, ok := state.Incidents[event.CheckID]; ok {
			event.EpisodeID = incident.EpisodeID
			continue
		}
		for _, incident := range state.Episodes {
			if incident.CheckID == event.CheckID && event.ID == eventID(event.App, event.CheckID, event.Kind, incident.EpisodeID) {
				event.EpisodeID = incident.EpisodeID
				break
			}
		}
	}
}

func dropAcknowledgedPending(state *IncidentState) {
	kept := state.Pending[:0]
	for _, event := range state.Pending {
		incident, _, _ := episodeForEvent(state, event)
		if (event.Kind == "incident" && incident.IncidentSent) || (event.Kind == "recovery" && incident.RecoverySent) {
			continue
		}
		kept = append(kept, event)
	}
	state.Pending = kept
}

func preserveEpisode(state *IncidentState, incident Incident) {
	if incident.CheckID == "" || incident.EpisodeID == "" {
		return
	}
	if state.Episodes == nil {
		state.Episodes = map[string]Incident{}
	}
	state.Episodes[episodeKey(incident.CheckID, incident.EpisodeID)] = incident
}

func parseStamp(value string, fallback time.Time) time.Time {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed
	}
	return fallback
}

func elapsedBetween(start string, end time.Time) time.Duration {
	from, err := time.Parse(time.RFC3339Nano, start)
	if err != nil || end.Before(from) {
		return 0
	}
	return end.Sub(from)
}

func queueEpisodeEvents(state *IncidentState, incident Incident, app string, now time.Time, maintenance bool, debounce time.Duration) {
	if maintenance {
		return
	}
	if !incident.IncidentSent && elapsedSince(incident.PendingSince, now) >= debounce && !hasPendingEpisode(state.Pending, incident, "incident") {
		state.Pending = append(state.Pending, incidentEvent(app, incident, now))
	}
	queueRecovery(state, incident, app, now, maintenance, debounce)
}

func flushHistoricalEpisodes(state *IncidentState, app string, now time.Time, maintenance bool, debounce time.Duration) {
	keys := make([]string, 0, len(state.Episodes))
	for key := range state.Episodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		incident := state.Episodes[key]
		queueEpisodeEvents(state, incident, app, now, maintenance, debounce)
		state.Episodes[key] = incident
	}
}

func hasPendingEpisode(events []AlertEvent, incident Incident, kind string) bool {
	for _, event := range events {
		if event.CheckID == incident.CheckID && event.EpisodeID == incident.EpisodeID && event.Kind == kind {
			return true
		}
	}
	return false
}

func episodeForEvent(state *IncidentState, event AlertEvent) (Incident, string, bool) {
	if current, ok := state.Incidents[event.CheckID]; ok {
		if event.EpisodeID == "" || current.EpisodeID == event.EpisodeID {
			return current, "", true
		}
	}
	if event.EpisodeID != "" {
		key := episodeKey(event.CheckID, event.EpisodeID)
		if incident, ok := state.Episodes[key]; ok {
			return incident, key, false
		}
	}
	for key, incident := range state.Episodes {
		if incident.CheckID == event.CheckID && event.ID == eventID(event.App, event.CheckID, event.Kind, incident.EpisodeID) {
			return incident, key, false
		}
	}
	return Incident{}, "", false
}

func hasPending(events []AlertEvent, checkID, kind string) bool {
	for _, event := range events {
		if event.CheckID == checkID && event.Kind == kind {
			return true
		}
	}
	return false
}

func removePendingRecovery(events []AlertEvent, checkID string) []AlertEvent {
	kept := events[:0]
	for _, event := range events {
		if event.CheckID == checkID && event.Kind == "recovery" {
			continue
		}
		kept = append(kept, event)
	}
	return kept
}

func elapsedSince(value string, now time.Time) time.Duration {
	then, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || then.After(now) {
		return 0
	}
	return now.Sub(then)
}

func eventID(app, checkID, kind, firstSeen string) string {
	return strings.Join([]string{app, checkID, kind, firstSeen}, ":")
}

func incidentEvent(app string, incident Incident, now time.Time) AlertEvent {
	state := incident.LastFailureState
	if state == "" {
		state = StateDegraded
	}
	summary := incident.LastFailureSummary
	if summary == "" {
		summary = "Check became unhealthy"
	}
	return AlertEvent{ID: eventID(app, incident.CheckID, "incident", incident.EpisodeID), Kind: "incident", CheckID: incident.CheckID, EpisodeID: incident.EpisodeID, App: app, State: state, Summary: summary, CreatedAt: now.Format(time.RFC3339Nano)}
}

func queueRecovery(state *IncidentState, incident Incident, app string, now time.Time, maintenance bool, debounce time.Duration) {
	if event, ok := recoveryEvent(incident, app, now, maintenance, debounce, state.Pending); ok {
		state.Pending = append(state.Pending, event)
	}
}

func queueRecoveryFirst(state *IncidentState, incident Incident, app string, now time.Time, maintenance bool, debounce time.Duration) {
	if event, ok := recoveryEvent(incident, app, now, maintenance, debounce, state.Pending); ok {
		state.Pending = append([]AlertEvent{event}, state.Pending...)
	}
}

func recoveryEvent(incident Incident, app string, now time.Time, maintenance bool, debounce time.Duration, pending []AlertEvent) (AlertEvent, bool) {
	if !incident.IncidentSent || !incident.RecoveryPending || incident.RecoverySent || maintenance || elapsedSince(incident.RecoverySince, now) < debounce || hasPendingEpisode(pending, incident, "recovery") {
		return AlertEvent{}, false
	}
	return AlertEvent{ID: eventID(app, incident.CheckID, "recovery", incident.EpisodeID), Kind: "recovery", CheckID: incident.CheckID, EpisodeID: incident.EpisodeID, App: app, State: StateHealthy, Summary: "Check recovered and is fresh", CreatedAt: now.Format(time.RFC3339Nano)}, true
}

func reportWithDeliveryError(report Report) Report {
	for _, check := range report.Checks {
		if check.ID == "notifications.delivery" {
			return report
		}
	}
	now := time.Now().UTC()
	if len(report.Checks) > 0 {
		if checked, err := time.Parse(time.RFC3339Nano, report.CheckedAt); err == nil {
			now = checked
		}
	}
	report.Checks = append(report.Checks, Result{ID: "notifications.delivery", Title: "Notification delivery", Category: "notifications", Scope: report.Scope, State: StateUnavailable, Summary: "Configured notification channel is unavailable", Details: "The channel configuration could not be validated", CheckedAt: now.Format(time.RFC3339Nano), FreshUntil: now.Format(time.RFC3339Nano), Freshness: Stale})
	report.State = StateUnavailable
	return report
}

func readMaintenanceWithContext(ctx context.Context, read FileReader, path string) ([]byte, error) {
	result := make(chan struct {
		body []byte
		err  error
	}, 1)
	go func() {
		body, err := read(path)
		if int64(len(body)) > maxMaintenanceBytes {
			body = nil
			err = errors.New("monitoring maintenance file exceeds the read limit")
		}
		result <- struct {
			body []byte
			err  error
		}{body: body, err: err}
	}()
	select {
	case value := <-result:
		return value.body, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func ConfiguredNotifier(cfg config.MonitoringConfig, client HTTPDoer) (Notifier, error) {
	if cfg.Notifications.WebhookEnv == "" && cfg.Notifications.WebhookSecretFile == "" {
		return nil, nil
	}
	endpoint, err := secretEndpoint(cfg.Notifications.WebhookEnv, cfg.Notifications.WebhookSecretFile)
	if err != nil {
		return nil, err
	}
	return WebhookNotifier{URL: endpoint, Client: client}, nil
}

func ExternalNotifier(cfg config.MonitoringConfig, client HTTPDoer) (Notifier, error) {
	if cfg.External.WebhookEnv == "" && cfg.External.WebhookSecretFile == "" {
		return nil, nil
	}
	endpoint, err := secretEndpoint(cfg.External.WebhookEnv, cfg.External.WebhookSecretFile)
	if err != nil {
		return nil, err
	}
	return WebhookNotifier{URL: endpoint, Client: client}, nil
}

func secretEndpoint(envName, filename string) (string, error) {
	if envName != "" && filename != "" {
		return "", errors.New("notification channel must use either an environment variable or a root secret file")
	}
	endpoint := ""
	if envName != "" {
		endpoint = strings.TrimSpace(os.Getenv(envName))
	} else {
		body, err := readApprovedRootSecret(filename, maxSecretBytes)
		if err != nil {
			return "", err
		}
		endpoint = strings.TrimSpace(string(body))
	}
	parsed, parseErr := url.Parse(endpoint)
	if endpoint == "" || parseErr != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || strings.ContainsAny(endpoint, "\r\n\x00") {
		return "", errors.New("notification channel must resolve to an HTTPS URL")
	}
	return endpoint, nil
}

func safeSecretPath(filename string) error {
	if filename == "" || !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return errors.New("notification root secret file must be an absolute path")
	}
	allowed := []string{"/etc/shuttle", "/var/lib/shuttle/monitoring", "/var/lib/shuttle/monitoring-external"}
	inside := false
	for _, root := range allowed {
		rel, err := filepath.Rel(root, filename)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			inside = true
			break
		}
	}
	if !inside {
		return errors.New("notification root secret file is outside an approved Shuttle secret root")
	}
	if !approvedSecretPath(filename) {
		return errors.New("notification root secret file is outside an approved Shuttle secret root")
	}
	directory, err := openSecretParentDirectory(filepath.Dir(filename))
	if err != nil {
		return errors.New("notification root secret path could not be inspected safely")
	}
	defer directory.Close()
	info, err := directory.root.Lstat(filepath.Base(filename))
	if err != nil || validateRuntimeFileInfo(info, 0) != nil {
		return errors.New("notification root secret file must be a root-owned 0600 regular file")
	}
	return nil
}

func approvedSecretPath(filename string) bool {
	allowed := []string{"/etc/shuttle", "/var/lib/shuttle/monitoring", "/var/lib/shuttle/monitoring-external"}
	for _, root := range allowed {
		rel, err := filepath.Rel(root, filename)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func readApprovedRootSecret(filename string, limit int64) ([]byte, error) {
	if filename == "" || !filepath.IsAbs(filename) || filepath.Clean(filename) != filename || !approvedSecretPath(filename) {
		return nil, errors.New("notification root secret file is outside an approved Shuttle secret root")
	}
	directory, err := openSecretParentDirectory(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	info, err := directory.root.Lstat(filepath.Base(filename))
	if err != nil || validateRuntimeFileInfo(info, 0) != nil {
		return nil, errors.New("notification root secret file must be a root-owned 0600 regular file")
	}
	file, err := openRuntimeFile(directory, filepath.Base(filename), os.O_RDONLY, runtimeFileMode, 0, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBoundedFile(file, limit)
}

func RunInstalled(ctx context.Context, installed InstalledConfig, adapters Adapters) (Report, error) {
	installed.Monitoring.NormalizeMonitoring()
	engine := New(installed.App, installed.Monitoring, adapters)
	engine.RedisConfigured = installed.RedisConfigured
	engine.RabbitMQConfigured = installed.RabbitMQConfigured
	engine.PostgresVersion = installed.PostgresVersion
	engine.PostgresCluster = installed.PostgresCluster
	engine.SSHPort = installed.SSHPort
	engine.DeployStrategy = installed.DeployStrategy
	cycleCtx, cancelCycle := context.WithTimeout(ctx, monitoringCycleBudget(installed.Monitoring))
	defer cancelCycle()
	report := engine.Run(cycleCtx)
	stateStore := FileStore{Path: statePath(installed.Monitoring)}
	manager := AlertManager{Store: stateStore, FailureLog: installed.Monitoring.Notifications.FailureLog, Retries: installed.Monitoring.Notifications.Retries, RetryDelay: time.Duration(installed.Monitoring.Notifications.RetryDelaySeconds) * time.Second, Debounce: time.Duration(installed.Monitoring.Notifications.DebounceSeconds) * time.Second, NotifyTimeout: time.Duration(installed.Monitoring.TimeoutSeconds) * time.Second, Now: engine.Adapters.Now}
	manager.NotifierFactory = func() (Notifier, error) {
		return ConfiguredNotifier(installed.Monitoring, engine.Adapters.HTTP)
	}
	// Collection may exhaust cycleCtx. Reading maintenance with that same
	// deadline used to return before Process, so LastReport was never
	// written. Persistence gets a short budget that does not inherit the
	// collection deadline. Process still receives cycleCtx as the delivery
	// bound: Notify must not run after the original cycle is cancelled.
	persistCtx, cancelPersist := persistFinalizeContext()
	defer cancelPersist()
	maintenanceUntil, maintenanceErr := loadInstalledMaintenance(persistCtx, filepath.Join(installed.Monitoring.StateDir, "maintenance.json"))
	if maintenanceErr != nil {
		manager.MaintenanceUnknown = true
	} else {
		manager.MaintenanceUntil = maintenanceUntil
	}
	if manager.FailureLog == "" {
		manager.FailureLog = filepath.Join(installed.Monitoring.StateDir, "delivery-failures.jsonl")
	}
	_, processErr := manager.Process(cycleCtx, report)
	return report, errors.Join(maintenanceErr, ctx.Err(), processErr)
}

func loadInstalledMaintenance(ctx context.Context, path string) (string, error) {
	body, err := readMaintenanceWithContext(ctx, func(name string) ([]byte, error) {
		return readRuntimePath(name, maxMaintenanceBytes, runtimeUID(), false)
	}, path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		if errors.Is(err, ctx.Err()) {
			return "", err
		}
		return "", errMaintenanceUnreadable
	}
	until, decodeErr := decodeMaintenanceWindow(body)
	if decodeErr != nil {
		return "", errMaintenanceUnreadable
	}
	return until, nil
}

func decodeMaintenanceWindow(body []byte) (string, error) {
	var maintenance struct {
		Until string `json:"until"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&maintenance); err != nil {
		return "", err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", errors.New("monitoring maintenance file must contain one JSON document")
	}
	if strings.TrimSpace(maintenance.Until) == "" {
		return "", errors.New("monitoring maintenance until is missing")
	}
	if _, err := time.Parse(time.RFC3339Nano, maintenance.Until); err != nil {
		return "", errors.New("monitoring maintenance until is invalid")
	}
	return maintenance.Until, nil
}

func RunExternalInstalled(ctx context.Context, installed InstalledConfig, adapters Adapters) (Report, error) {
	installed.Monitoring.NormalizeMonitoring()
	engine := New(installed.App, installed.Monitoring, adapters)
	externalConfig := installed.Monitoring
	if externalConfig.External.TimeoutSeconds > 0 {
		externalConfig.TimeoutSeconds = externalConfig.External.TimeoutSeconds
	}
	cycleCtx, cancelCycle := context.WithTimeout(ctx, monitoringCycleBudget(externalConfig))
	defer cancelCycle()
	report := engine.RunExternal(cycleCtx)
	if installed.Monitoring.External.URL == "" {
		return report, nil
	}
	state := FileStore{Path: filepath.Join(installed.Monitoring.External.StateDir, "incidents.json")}
	manager := AlertManager{Store: state, FailureLog: filepath.Join(installed.Monitoring.External.StateDir, "delivery-failures.jsonl"), Retries: installed.Monitoring.Notifications.Retries, RetryDelay: time.Duration(installed.Monitoring.Notifications.RetryDelaySeconds) * time.Second, Debounce: time.Duration(installed.Monitoring.Notifications.DebounceSeconds) * time.Second, NotifyTimeout: time.Duration(installed.Monitoring.External.TimeoutSeconds) * time.Second, Now: engine.Adapters.Now}
	manager.NotifierFactory = func() (Notifier, error) {
		return ExternalNotifier(installed.Monitoring, engine.Adapters.HTTP)
	}
	_, processErr := manager.Process(cycleCtx, report)
	return report, errors.Join(ctx.Err(), processErr)
}
