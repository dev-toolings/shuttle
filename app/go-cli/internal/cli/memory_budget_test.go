package cli

import (
	"strings"
	"testing"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/config"
)

const mib = int64(1) << 20

func TestEvaluateMemoryBudgetPassesWithRoom(t *testing.T) {
	decision := evaluateMemoryBudget(8192*mib, 4096*mib, []serviceMemoryLimit{
		{Name: "web", Bytes: 768 * mib},
		{Name: "worker", Bytes: 512 * mib},
	})
	if decision.Refused {
		t.Fatalf("expected pass, got refusal: %v", decision.Err())
	}
	if decision.RequiredBytes != 1280*mib {
		t.Fatalf("required = %d, want %d", decision.RequiredBytes, 1280*mib)
	}
	if decision.Err() != nil {
		t.Fatalf("passing decision must not carry an error: %v", decision.Err())
	}
}

// One byte under the sum is a refusal: the guard exists because a rolling
// update that does not fit is an OOM kill in production, not a slow deploy.
func TestEvaluateMemoryBudgetRefusesJustUnderTheSum(t *testing.T) {
	limits := []serviceMemoryLimit{
		{Name: "web", Bytes: 768 * mib},
		{Name: "worker", Bytes: 512 * mib},
	}
	decision := evaluateMemoryBudget(8192*mib, 1280*mib-1, limits)
	if !decision.Refused {
		t.Fatal("expected refusal one byte below the sum of the limits")
	}
	err := decision.Err()
	if err == nil {
		t.Fatal("refusal must produce an error")
	}
	message := err.Error()
	for _, want := range []string{"deployment refused", "1.25 GiB", "web 768 MiB", "worker 512 MiB", "8.00 GiB"} {
		if !strings.Contains(message, want) {
			t.Fatalf("refusal %q does not name %q", message, want)
		}
	}
}

// Documented threshold: the comparison is `available < required`, so a host
// with exactly the sum of the limits free is allowed to deploy. The limits are
// enforced ceilings, not expected resident sizes; refusing at equality would
// gate on a margin nobody configured.
func TestEvaluateMemoryBudgetPassesExactlyAtTheSum(t *testing.T) {
	decision := evaluateMemoryBudget(8192*mib, 1280*mib, []serviceMemoryLimit{
		{Name: "web", Bytes: 768 * mib},
		{Name: "worker", Bytes: 512 * mib},
	})
	if decision.Refused {
		t.Fatalf("available == required must pass, got: %v", decision.Err())
	}
}

func TestEvaluateMemoryBudgetSingleService(t *testing.T) {
	limits := []serviceMemoryLimit{{Name: "web", Bytes: 768 * mib}}

	if decision := evaluateMemoryBudget(1024*mib, 900*mib, limits); decision.Refused {
		t.Fatalf("768 MiB needed with 900 MiB available must pass, got: %v", decision.Err())
	}
	decision := evaluateMemoryBudget(1024*mib, 700*mib, limits)
	if !decision.Refused {
		t.Fatal("768 MiB needed with 700 MiB available must refuse")
	}
	if got := decision.Err().Error(); !strings.Contains(got, "web 768 MiB") {
		t.Fatalf("refusal %q does not name the single service", got)
	}
}

// Invariant 2: the same stack must always produce the same message. The input
// here is deliberately unsorted, and the services come from a map upstream.
func TestEvaluateMemoryBudgetMessageIsDeterministic(t *testing.T) {
	limits := []serviceMemoryLimit{
		{Name: "worker", Bytes: 512 * mib},
		{Name: "web", Bytes: 768 * mib},
		{Name: "redis", Bytes: 256 * mib},
		{Name: "rabbitmq", Bytes: 256 * mib},
	}
	first := evaluateMemoryBudget(8192*mib, 512*mib, limits)
	second := evaluateMemoryBudget(8192*mib, 512*mib, limits)
	if first.Err().Error() != second.Err().Error() {
		t.Fatalf("refusal is not deterministic:\n%s\n%s", first.Err(), second.Err())
	}
	if first.Summary() != second.Summary() {
		t.Fatalf("summary is not deterministic:\n%s\n%s", first.Summary(), second.Summary())
	}
	wantOrder := []string{"rabbitmq", "redis", "web", "worker"}
	message := first.Err().Error()
	previous := -1
	for _, name := range wantOrder {
		index := strings.Index(message, name+" ")
		if index <= previous {
			t.Fatalf("services are not reported in sorted order: %q", message)
		}
		previous = index
	}
}

// evaluateMemoryBudget must not reorder its caller's slice: the same slice is
// held by the caller for its own reporting.
func TestEvaluateMemoryBudgetDoesNotMutateInput(t *testing.T) {
	limits := []serviceMemoryLimit{
		{Name: "worker", Bytes: 512 * mib},
		{Name: "web", Bytes: 768 * mib},
	}
	evaluateMemoryBudget(8192*mib, 8192*mib, limits)
	if limits[0].Name != "worker" {
		t.Fatalf("input slice was reordered: %+v", limits)
	}
}

func TestStackMemoryLimitsUsesConfiguredLimits(t *testing.T) {
	parsed := &composeFile{Services: map[string]composeService{
		"web":    {Build: "."},
		"worker": {Build: "."},
	}}
	cfg := &config.Config{Services: map[string]config.Service{
		"worker": {Resources: config.Resources{Memory: "256M"}},
	}}
	limits, err := stackMemoryLimits(parsed, cfg)
	if err != nil {
		t.Fatalf("stackMemoryLimits: %v", err)
	}
	if len(limits) != 2 {
		t.Fatalf("limits = %+v, want 2 entries", limits)
	}
	// web declares nothing, so it carries the 768M default the stack will write.
	if limits[0].Name != "web" || limits[0].Bytes != 768*mib {
		t.Fatalf("limits[0] = %+v, want web at the 768M default", limits[0])
	}
	if limits[1].Name != "worker" || limits[1].Bytes != 256*mib {
		t.Fatalf("limits[1] = %+v, want worker at its configured 256M", limits[1])
	}
}

// secureStack adds redis and rabbitmq to the stack when production.redis /
// production.rabbitmq are on, and gives them limits from the same
// cfg.ServiceLimits call. Leaving them out of the budget would under-count by
// their limits.
func TestStackMemoryLimitsIncludesInfrastructureServices(t *testing.T) {
	parsed := &composeFile{Services: map[string]composeService{"web": {Build: "."}}}
	cfg := &config.Config{
		Production: config.ProductionConfig{Redis: true, RabbitMQ: true},
		Services: map[string]config.Service{
			"redis": {Resources: config.Resources{Memory: "128M"}},
		},
	}
	limits, err := stackMemoryLimits(parsed, cfg)
	if err != nil {
		t.Fatalf("stackMemoryLimits: %v", err)
	}
	byName := map[string]int64{}
	for _, limit := range limits {
		byName[limit.Name] = limit.Bytes
	}
	if len(byName) != 3 {
		t.Fatalf("limits = %+v, want web, redis and rabbitmq", limits)
	}
	if byName["redis"] != 128*mib {
		t.Fatalf("redis = %d, want its configured 128M", byName["redis"])
	}
	if byName["rabbitmq"] != 768*mib {
		t.Fatalf("rabbitmq = %d, want the 768M default", byName["rabbitmq"])
	}
	decision := evaluateMemoryBudget(8192*mib, 1024*mib, limits)
	if !decision.Refused {
		t.Fatal("768 + 128 + 768 MiB needed with 1024 MiB available must refuse")
	}
}

func TestStackMemoryLimitsIgnoresInactiveInfrastructure(t *testing.T) {
	parsed := &composeFile{Services: map[string]composeService{"web": {Build: "."}}}
	limits, err := stackMemoryLimits(parsed, &config.Config{})
	if err != nil {
		t.Fatalf("stackMemoryLimits: %v", err)
	}
	if len(limits) != 1 || limits[0].Name != "web" {
		t.Fatalf("limits = %+v, want web alone", limits)
	}
}

// A compose file that declares redis itself must be counted once: the stack
// holds one service by that name.
func TestStackMemoryLimitsCountsADeclaredInfraServiceOnce(t *testing.T) {
	parsed := &composeFile{Services: map[string]composeService{
		"web":   {Build: "."},
		"redis": {Image: "redis"},
	}}
	cfg := &config.Config{Production: config.ProductionConfig{Redis: true}}
	limits, err := stackMemoryLimits(parsed, cfg)
	if err != nil {
		t.Fatalf("stackMemoryLimits: %v", err)
	}
	if len(limits) != 2 {
		t.Fatalf("limits = %+v, want redis counted once", limits)
	}
}

func TestStackMemoryLimitsRefusesAnUnparseableLimit(t *testing.T) {
	parsed := &composeFile{Services: map[string]composeService{"web": {Build: "."}}}
	cfg := &config.Config{Services: map[string]config.Service{
		"web": {Resources: config.Resources{Memory: "lots"}},
	}}
	if _, err := stackMemoryLimits(parsed, cfg); err == nil {
		t.Fatal("an unparseable memory limit must be an error, not a zero requirement")
	}
}

// A real excerpt, copied from a Linux host's /proc/meminfo.
const realMemInfo = `MemTotal:       31757228 kB
MemFree:         1815452 kB
MemAvailable:   21455740 kB
Buffers:         3532880 kB
Cached:         14271632 kB
SwapCached:            0 kB
Active:          9814168 kB
`

func TestParseMemInfoReadsARealExcerpt(t *testing.T) {
	total, available, err := parseMemInfo(realMemInfo)
	if err != nil {
		t.Fatalf("parseMemInfo: %v", err)
	}
	if total != 31757228*1024 {
		t.Fatalf("total = %d, want %d", total, int64(31757228)*1024)
	}
	if available != 21455740*1024 {
		t.Fatalf("available = %d, want %d", available, int64(21455740)*1024)
	}
}

// Every failure below must be an error. A guard that reads a zero out of an
// unreadable file would either refuse every deploy or, worse, pass every one.
func TestParseMemInfoRefusesBadInput(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"missing MemAvailable", "MemTotal:       31757228 kB\nMemFree:         1815452 kB\n"},
		{"missing MemTotal", "MemFree:         1815452 kB\nMemAvailable:   21455740 kB\n"},
		{"empty MemAvailable value", "MemTotal:       31757228 kB\nMemAvailable:\n"},
		{"empty MemAvailable unit only", "MemTotal:       31757228 kB\nMemAvailable:    kB\n"},
		{"non-numeric MemAvailable", "MemTotal:       31757228 kB\nMemAvailable:   plenty kB\n"},
		{"non-numeric MemTotal", "MemTotal:       many kB\nMemAvailable:   21455740 kB\n"},
		{"wrong unit", "MemTotal:       31757228 MB\nMemAvailable:   21455740 MB\n"},
		{"duplicate MemAvailable", "MemTotal:  31757228 kB\nMemAvailable:  100 kB\nMemAvailable:  200 kB\n"},
		{"zero MemTotal", "MemTotal:       0 kB\nMemAvailable:   0 kB\n"},
		{"empty file", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total, available, err := parseMemInfo(tc.raw)
			if err == nil {
				t.Fatalf("expected an error, got total=%d available=%d", total, available)
			}
			if total != 0 || available != 0 {
				t.Fatalf("a failed parse must return zeroes, got total=%d available=%d", total, available)
			}
		})
	}
}

// MemAvailable can legitimately be 0 on a host under real pressure; that is a
// measurement, not a parse failure, and it must reach the guard as a refusal.
func TestParseMemInfoAcceptsZeroAvailable(t *testing.T) {
	total, available, err := parseMemInfo("MemTotal:       8039416 kB\nMemAvailable:          0 kB\n")
	if err != nil {
		t.Fatalf("parseMemInfo: %v", err)
	}
	if total != 8039416*1024 || available != 0 {
		t.Fatalf("total=%d available=%d", total, available)
	}
	decision := evaluateMemoryBudget(total, available, []serviceMemoryLimit{{Name: "web", Bytes: 768 * mib}})
	if !decision.Refused {
		t.Fatal("no available memory must refuse the deploy")
	}
}

func TestFormatMemoryBytes(t *testing.T) {
	cases := map[int64]string{
		0:          "0 MiB",
		768 * mib:  "768 MiB",
		1024 * mib: "1.00 GiB",
		1740 * mib: "1.70 GiB",
	}
	for bytes, want := range cases {
		if got := formatMemoryBytes(bytes); got != want {
			t.Fatalf("formatMemoryBytes(%d) = %q, want %q", bytes, got, want)
		}
	}
}

// A stop-first service stops its old task before starting the new one, so the
// rolling update never holds two copies of it; only start-first services make
// up the overlap.
func TestRollingOverlapLimitsLeavesOutStopFirstServices(t *testing.T) {
	cfg := &config.Config{Services: map[string]config.Service{
		"db-writer": {UpdateOrder: config.UpdateOrderStopFirst},
		"web":       {UpdateOrder: config.UpdateOrderStartFirst},
	}}
	overlap := rollingOverlapLimits([]serviceMemoryLimit{
		{Name: "db-writer", Bytes: 512 * mib},
		{Name: "web", Bytes: 512 * mib},
		{Name: "worker", Bytes: 256 * mib}, // no entry: start-first by default
	}, cfg)
	if len(overlap) != 2 || overlap[0].Name != "web" || overlap[1].Name != "worker" {
		t.Fatalf("overlap = %+v, want web and worker only", overlap)
	}
}

func TestParseMemoryBudgetPolicy(t *testing.T) {
	for value, want := range map[string]memoryBudgetPolicy{"strict": memoryBudgetStrict, "warn": memoryBudgetWarn, " warn ": memoryBudgetWarn} {
		got, err := parseMemoryBudgetPolicy(value)
		if err != nil || got != want {
			t.Fatalf("parseMemoryBudgetPolicy(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
	for _, value := range []string{"", "off", "Warn"} {
		if _, err := parseMemoryBudgetPolicy(value); err == nil {
			t.Fatalf("parseMemoryBudgetPolicy(%q) accepted an unknown policy", value)
		}
	}
}

// The warn paths print Shortfall, never Err: the deploy goes on, so the line
// must not open with a verdict that reads as a failure.
func TestMemoryBudgetShortfallCarriesTheFiguresWithoutAVerdict(t *testing.T) {
	decision := evaluateMemoryBudget(8192*mib, 512*mib, []serviceMemoryLimit{{Name: "web", Bytes: 768 * mib}})
	shortfall := decision.Shortfall()
	if strings.Contains(shortfall, "refused") {
		t.Fatalf("shortfall %q carries a refusal verdict", shortfall)
	}
	for _, want := range []string{"768 MiB", "web 768 MiB", "512 MiB available", "8.00 GiB"} {
		if !strings.Contains(shortfall, want) {
			t.Fatalf("shortfall %q does not name %q", shortfall, want)
		}
	}
	if got, want := decision.Err().Error(), "deployment refused: "+shortfall; got != want {
		t.Fatalf("Err() = %q, want %q", got, want)
	}
}

// A start-first service holds as many replacement tasks beside their
// predecessors as it replaces at once. Parallelism is nil (one at a time), 0
// (every replica at once) or N, and no more tasks than replicas can be replaced.
func TestRollingOverlapLimitsCountsReplacementTasksFromUpdateParallelism(t *testing.T) {
	zero, two, three := 0, 2, 3
	for name, test := range map[string]struct {
		parallelism *int
		replicas    int
		want        int
	}{
		"nil replaces one at a time":                     {parallelism: nil, replicas: 4, want: 1},
		"zero replaces every rendered replica":           {parallelism: &zero, replicas: 4, want: 4},
		"zero on a single replica is one copy":           {parallelism: &zero, replicas: 1, want: 1},
		"N below the replicas replaces N":                {parallelism: &two, replicas: 4, want: 2},
		"N above the replicas is capped by the replicas": {parallelism: &three, replicas: 2, want: 2},
		"an unset replica count reads as one":            {parallelism: &three, replicas: 0, want: 1},
		"zero with an unset replica count reads as one":  {parallelism: &zero, replicas: 0, want: 1},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{Services: map[string]config.Service{"worker": {UpdateParallelism: test.parallelism}}}
			overlap := rollingOverlapLimits([]serviceMemoryLimit{{Name: "worker", Bytes: 256 * mib, Replicas: test.replicas}}, cfg)
			if len(overlap) != 1 || overlap[0].Copies != test.want {
				t.Fatalf("overlap = %+v, want %d copies", overlap, test.want)
			}
		})
	}
}

// The copies are what the guard sums: with parallelism 0 over three replicas the
// rolling update needs three extra copies of the service's limit, not one.
func TestMemoryBudgetCountsEveryReplacementTaskOfAParallelUpdate(t *testing.T) {
	zero := 0
	cfg := &config.Config{Services: map[string]config.Service{"worker": {UpdateParallelism: &zero}}}
	overlap := rollingOverlapLimits([]serviceMemoryLimit{
		{Name: "web", Bytes: 768 * mib, Replicas: 1},
		{Name: "worker", Bytes: 256 * mib, Replicas: 3},
	}, cfg)
	decision := evaluateMemoryBudget(8192*mib, 1536*mib-1, overlap)
	if !decision.Refused || decision.RequiredBytes != 1536*mib {
		t.Fatalf("required = %d refused = %t, want 768 + 3 x 256 MiB and a refusal one byte short", decision.RequiredBytes, decision.Refused)
	}
	if !strings.Contains(decision.Err().Error(), "worker 256 MiB x3") {
		t.Fatalf("refusal %q does not name the three copies", decision.Err())
	}
	if evaluateMemoryBudget(8192*mib, 1536*mib, overlap).Refused {
		t.Fatal("exactly 768 + 3 x 256 MiB available must pass")
	}
}

// The published service is rendered with one replica whatever the compose file
// says; every other service keeps the replicas it declares.
func TestStackMemoryLimitsCarryTheReplicasTheStackRenders(t *testing.T) {
	parsed := &composeFile{
		Services: map[string]composeService{"web": {Build: "."}, "worker": {Build: "."}, "mailer": {Build: "."}},
		Raw: map[string]any{"services": map[string]any{
			"web":    map[string]any{"deploy": map[string]any{"replicas": 4}},
			"worker": map[string]any{"deploy": map[string]any{"replicas": 3}},
			"mailer": map[string]any{},
		}},
	}
	limits, err := stackMemoryLimits(parsed, &config.Config{})
	if err != nil {
		t.Fatalf("stackMemoryLimits: %v", err)
	}
	replicas := map[string]int{}
	for _, limit := range limits {
		replicas[limit.Name] = limit.Replicas
	}
	if replicas["web"] != 1 || replicas["worker"] != 3 || replicas["mailer"] != 1 {
		t.Fatalf("replicas = %v, want web 1 (published), worker 3, mailer 1", replicas)
	}
}
