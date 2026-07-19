package gwmayhem

// loader.go assembles the full scenario suite: the Go-literal families here plus
// the data specs compiled from qa/gw-scenarios/*.json, with the Mayhem collision
// rule — a spec whose ID collides with a Go scenario's (or another spec's) is a
// LOAD-TIME ERROR, logged and skipped, never a silent shadow, and never a blocker
// for any other file. Data specs reuse the aggregator's campaign schema + engine
// wholesale (a spec IS an aggregator Campaign); its verdict comes from the
// campaign's own registered oracle, surfaced through the campaignPassthrough oracle.

import (
	"context"
	"fmt"

	"csip-tls-test/internal/aggregator"
)

// goScenarios is the Go-literal suite: the families whose logic the data schema
// cannot express (the role×op matrix sweep, the raw hostile-cert / raw-frame
// probes, the concurrent flood).
func goScenarios() []gwScenario {
	out := []gwScenario{
		// Wave 1 — mbaps-northbound-authz + transport abuse (drive the gateway's
		// :802 server as a hostile aggregator).
		roleDenialMatrix(),
		certNegatives(),
		outOfRangeSetpoint(),
		malformedWrites(),
		sessionFlood(),
	}
	// Wave 2 — observe the gateway's fail-closed behaviour from the SOUTHBOUND
	// while a hostile head-end (family A) or a misbehaving DER (family B) is armed.
	out = append(out, northboundMalformScenarios()...)
	out = append(out, southboundFaultScenarios()...)
	// Wave 3 — drive the gateway's write→apply→readback CONTROL LOOP adversarially
	// (family C, :802), and judge the observable effect of a BOARD mutation the
	// orchestrator arms out of band (family D, authority/PKI/infra).
	out = append(out, controlLoopScenarios()...)
	out = append(out, authorityPKIScenarios()...)
	return out
}

// AllScenarios returns the merged Go + spec suite for specDir, plus one error per
// spec file that failed to load or whose ID collided. A collision/broken spec never
// blocks another scenario — the exact guard the Mayhem loader uses.
func AllScenarios(specDir string) ([]gwScenario, []error) {
	gos := goScenarios()
	existing := make(map[string]bool, len(gos))
	for _, s := range gos {
		existing[s.ID] = true
	}
	specs, errs := loadSpecScenarios(specDir, existing)
	return append(gos, specs...), errs
}

// loadSpecScenarios compiles every qa/gw-scenarios/*.json aggregator campaign into a
// spec gwScenario, rejecting any whose ID collides with a Go scenario's.
func loadSpecScenarios(specDir string, existing map[string]bool) ([]gwScenario, []error) {
	camps, errs := aggregator.LoadCampaignDir(specDir)
	var out []gwScenario
	seen := make(map[string]bool)
	for _, c := range camps {
		if existing[c.ID] {
			errs = append(errs, fmt.Errorf("gwmayhem: spec %q collides with a Go scenario — not loaded", c.ID))
			continue
		}
		if seen[c.ID] {
			errs = append(errs, fmt.Errorf("gwmayhem: spec id %q duplicated across files — not loaded", c.ID))
			continue
		}
		seen[c.ID] = true
		out = append(out, specScenario(c))
	}
	return out, errs
}

// specScenario wraps an aggregator campaign as a spec gwScenario: its arm runs the
// campaign through the aggregator engine and stashes the report; campaignPassthrough
// surfaces the verdict. Security/Category are inferred from the campaign's oracle (a
// denial oracle is authz-security-critical).
func specScenario(c *aggregator.Campaign) gwScenario {
	camp := c // capture
	security := c.Oracle.Name == "denyExpected"
	category := "mbaps-spec"
	if security {
		category = "mbaps-northbound-authz"
	}
	return gwScenario{
		ID:       c.ID,
		Desc:     c.Name,
		Category: category,
		Source:   SourceSpec,
		Security: security,
		Expected: c.ExpectedVerdicts,
		oracle:   "campaignPassthrough",
		arm: func(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
			rep, err := w.eng.Run(ctx, camp)
			if err != nil {
				ev.SetupErr = err.Error()
				return nil
			}
			ev.Campaign = &campaignResult{Verdict: rep.Verdict, Findings: rep.Findings, report: rep}
			return nil
		},
	}
}
