// Track G-pagination — CSIP list-pagination Mayhem scenario + oracle (audit
// docs/QA_COMPLETENESS_AUDIT.md P1-1, Batch 3b). New file per the "one
// concern = one file, scenarios + oracles together" convention
// (mayhem_csipedge.go / mayhem_reporting.go).
//
// INV-PAGINATION — a spec-compliant utility server may serve a list resource
// across multiple pages (a single GET returns results < all); the DER client
// MUST follow the s/l pagination query to collect every entry. The hub gained a
// paging loop in this batch (internal/northbound/discovery/paginate.go); before
// it, a single GET saw only page 1 and the hub silently enforced only the first
// page's controls. This scenario arms gridsim's positive-pagination mode
// (POST /admin/paginate) on ONE control list, with the BINDING control sitting
// on page 2, so a hub that fails to page adopts the wrong (page-1) control and
// the oracle catches it.
//
// Construction (why it isolates paging): program 0's DERControlList is cleared
// and rebuilt as exactly two active, overlapping export caps —
//
//	page 1 (offset 0): CTRL-PAGE1, a LOOSE 5000 W export cap, potentiallySuperseded
//	page 2 (offset 1): CTRL-PAGE2, a TIGHT 1000 W export cap, later creationTime
//
// so within-program supersede makes CTRL-PAGE2 the control a correct hub adopts.
// With page_size 1 scoped to /derp/0/derc, a hub that pages sees BOTH and adopts
// the superseding page-2 cap (mRID CTRL-PAGE2, 1000 W); a hub that reads only
// page 1 adopts CTRL-PAGE1 (5000 W) and never learns page 2 exists. The adopted
// mRID/limit on /status is the direct, unambiguous signal — no reliance on the
// fallback/default path.
//
// Oracle registration: a Go-literal `evaluate` closure like every other
// mayhem_*.go track (not a qa/scenarios/*.json spec) — no oracleRegistry entry.

package main

import (
	"fmt"
)

const (
	pageLoserMRID  = "CTRL-PAGE1" // page 1: loose 5 kW cap, potentiallySuperseded
	pageWinnerMRID = "CTRL-PAGE2" // page 2: tight 1 kW cap, later creationTime ⇒ wins
	pageLoserW     = 5000.0
	pageWinnerW    = 1000.0
)

func (d *mayhemDriver) paginationScenarios() []*mayScenario {
	return []*mayScenario{paginationWalkScenario()}
}

func paginationWalkScenario() *mayScenario {
	return &mayScenario{
		ID:         "csip-pagination-walk",
		Name:       "Hub pages a multi-page DERControlList and adopts the page-2 control (CSIP P1-1)",
		Category:   "CSIP discovery (INV-PAGINATION)",
		Hypothesis: "A utility server pages a list: a single GET of /derp/0/derc returns all=2, results=1, and the binding (superseding) control lives on page 2 behind ?s=1. A DER client that does a single GET — the hub before this batch — silently enforces only the first page's 5 kW cap and never sees the page-2 1 kW cap. The hub's new discovery paging loop must follow s/l and assemble every entry.",
		Expected:   fmt.Sprintf("The hub pages the list, sees the superseding page-2 control, and adopts %s (a %.0f W export cap) — NOT the page-1 %s (%.0f W). Its /status shows adopted mRID=%s with an export limit ≈%.0f W, and it holds that cap.", pageWinnerMRID, pageWinnerW, pageLoserMRID, pageLoserW, pageWinnerMRID, pageWinnerW),
		HoldS:      90,
		Fix:        "internal/northbound/discovery/paginate.go (fetchPagedList) + walker.go's paged list fetchers — follow ?s=<offset>&l=<limit> until results==all; a single-GET walker enforces only page 1.",
		setup: func(d *mayhemDriver) (*activeConstraint, error) {
			// Full battery + hard PV ⇒ PV curtailment is the only export lever, so
			// the adopted cap's value shows directly in the metered export.
			_ = d.post("battery", "/inject", map[string]any{"SoC_pct": 100, "Conn": 1})
			d.injectEnv(d.pvHighW, 250)

			// Rebuild program 0's control list as exactly the two overlapping caps.
			d.deleteControls(0)
			if _, err := d.postControl(map[string]any{
				"program": 0, "mrid": pageLoserMRID, "exp_lim_W": int(pageLoserW),
				"start_offset_s": -30, "duration_s": 3600,
				"potentially_superseded": true, "creation_offset_s": -5,
				"description": "mayhem: page-1 loose cap (superseded)",
			}); err != nil {
				return nil, fmt.Errorf("arm page-1 control: %w", err)
			}
			if _, err := d.postControl(map[string]any{
				"program": 0, "mrid": pageWinnerMRID, "exp_lim_W": int(pageWinnerW),
				"start_offset_s": -30, "duration_s": 3600,
				"creation_offset_s": 0,
				"description":       "mayhem: page-2 binding cap (supersedes)",
			}); err != nil {
				return nil, fmt.Errorf("arm page-2 control: %w", err)
			}

			// Arm positive pagination on JUST this list, one entry per page, so the
			// rest of the walk is untouched and the hub must fetch ?s=1 to reach the
			// superseding page-2 control.
			if err := d.post("gridsim", "/admin/paginate", map[string]any{
				"page_size": 1, "path": "/derp/0/derc",
			}); err != nil {
				return nil, fmt.Errorf("arm pagination: %w", err)
			}

			// The correct (paged) outcome is the page-2 1 kW cap; invExport judges
			// against it, so a hub stuck on the page-1 5 kW cap reads as a breach.
			return &activeConstraint{Typ: "exportCap", LimW: pageWinnerW, MRID: pageWinnerMRID}, nil
		},
		perTick:  func(d *mayhemDriver, i int) { d.injectEnv(d.pvHighW, 250) },
		evaluate: diagnosePaginationWalk,
		teardown: func(d *mayhemDriver) {
			_ = d.post("gridsim", "/admin/paginate", map[string]any{"clear": true})
			d.deleteControls(0)
		},
	}
}

// diagnosePaginationWalk judges INV-PAGINATION from which control the hub
// adopted over the back half of the hold (the tail — after the hub has had time
// to walk the paginated list). The adopted mRID is the direct signal: PAGE2 ⇒
// the hub paged and saw every entry; PAGE1 ⇒ it read only page 1 and missed the
// superseding control (the P1-1 bug); neither ⇒ it never adopted (walk failure /
// off-bench).
func diagnosePaginationWalk(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding {
	f := baseFinding(sc)
	if len(s) == 0 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "no samples collected (aborted before any reading)"
		return f
	}
	reach := 0
	for _, smp := range s {
		if smp.HubReachable {
			reach++
		}
	}
	if reach < len(s)/2 {
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "hub /status was unreachable for most of the window"
		f.Diagnosis = []string{"Cannot judge pagination when the hub itself was mostly unreachable — fix connectivity and re-run (this scenario needs the live hub walking gridsim)."}
		return f
	}

	// Tail = the last 40% of samples, where the hub has settled after walking the
	// paginated list at least once.
	tail := s[len(s)*6/10:]
	sawWinner, sawLoser, sawExport := 0, 0, 0
	for _, smp := range tail {
		if !smp.HubAdopted || smp.AdoptedTyp != "exportCap" {
			continue
		}
		sawExport++
		switch smp.AdoptedMRID {
		case pageWinnerMRID:
			sawWinner++
		case pageLoserMRID:
			sawLoser++
		}
	}

	f.Metrics = scanSamples(cons, s)
	breaches := invExport(cons, s)

	switch {
	case sawWinner > 0 && sawLoser == 0:
		f.Verdict = "PASS"
		f.Headline = "hub paged the list and adopted the superseding page-2 control"
		f.Diagnosis = []string{
			fmt.Sprintf("INV-PAGINATION: the hub adopted %s (the ~%.0f W page-2 export cap reachable only via ?s=1) — it followed the s/l pagination and assembled every entry.", pageWinnerMRID, pageWinnerW),
			invSummaryLine("INV-EXPORT", breaches),
			hubVsRealLine(s),
		}
		forceBlindOnConstraintProbeGap(&f, cons, s)
		return f
	case sawLoser > 0:
		f.Verdict = "FAIL"
		f.Headline = "hub enforced only the FIRST page's control — never fetched page 2 (P1-1)"
		f.Diagnosis = []string{
			fmt.Sprintf("The hub adopted %s (the page-1 ~%.0f W cap) and never adopted %s (the superseding page-2 ~%.0f W cap): it did a single GET of the list and silently missed every entry past page 1 — the exact P1-1 field failure.", pageLoserMRID, pageLoserW, pageWinnerMRID, pageWinnerW),
			"Fix: the discovery walker's list fetchers must follow ?s=<offset>&l=<limit> until results==all (internal/northbound/discovery/paginate.go).",
			invSummaryLine("INV-EXPORT", breaches),
			decisionLine(s),
		}
		return f
	case sawExport == 0:
		f.Verdict = "INCONCLUSIVE"
		f.Headline = "hub never adopted an export cap from the paginated program"
		f.Diagnosis = []string{
			"No tail sample shows the hub enforcing an export cap from program 0 — it may not have walked the injected controls, or the walk is failing under pagination. Off-bench (no live hub↔gridsim) this is the expected verdict.",
			decisionLine(s),
		}
		return f
	default:
		// sawWinner>0 AND sawLoser>0 — transitional flapping; judge by the cap.
		if f.Metrics.TailClean {
			f.Verdict = "PASS"
			f.Headline = "hub settled on the page-2 control after a transitional page-1 adoption"
		} else {
			f.Verdict = "FAIL"
			f.Headline = "hub oscillated between the page-1 and page-2 controls under pagination"
		}
		f.Diagnosis = []string{
			fmt.Sprintf("Tail adoption mixed %s (page 1) and %s (page 2); see whether the export cap converged.", pageLoserMRID, pageWinnerMRID),
			invSummaryLine("INV-EXPORT", breaches),
			decisionLine(s),
		}
		return f
	}
}
