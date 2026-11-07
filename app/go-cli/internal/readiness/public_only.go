package readiness

import (
	"time"

	"github.com/dev-toolings/deploy-shuttle/go-cli/internal/execx"
)

// RunPublicOnly evaluates the checks that need nothing from the host: the
// public TLS certificate, HSTS, DNS and the health endpoint of the domain.
//
// It exists for deploy.strategy: compose, which installs no root helper and
// therefore cannot run the signed audit every other check depends on. The
// report is honest about that: it carries only what was observed from the
// machine running doctor, under a profile that names it, and nothing about
// the host itself.
func RunPublicOnly(target, domain, healthPath, configPath string) Report {
	adapter := execx.Local{}
	results := []CheckResult{
		evaluateCheck(adapter, checkTLSCertificate(domain)),
		evaluateCheck(adapter, checkHSTSHeader(domain)),
		evaluateCheck(adapter, checkDNSPointsToServer(domain)),
		evaluateCheck(adapter, checkHealthEndpoint(domain, healthPath)),
	}
	return Report{
		Target:      target,
		Profile:     []string{"public-only"},
		ConfigPath:  configPath,
		Score:       Score(results),
		Level:       EvidenceLevel(results),
		Coverage:    SummarizeCoverage(results),
		Validated:   ChecksValidated(results),
		Checks:      results,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}
