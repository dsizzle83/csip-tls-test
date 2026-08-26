package suitecsip

// rampdefault_test.go — BASIC-007's teeth, in the same shape teeth_test.go and
// directoracle_test.go already established: every assertion is driven once
// with input that satisfies it and once with input that does not, and the
// second run is the one that matters.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/diff"
	"lexa-proto/sunspec"
)

// wrmp704 builds a minimal model 704 image holding the given WRmp raw value
// (an unscaled uint16 percent-of-WMax-per-second — derlayout.go's own F("WRmp",
// Tuint16), no scale factor). Every scale factor this layout declares is
// zeroed so nothing else in the block reads as a sentinel.
func wrmp704(t *testing.T, wRmp uint16) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L704.Len())
	v := sunspec.L704.View(regs)
	for _, sfName := range []string{"PF_SF", "WMaxLimPct_SF", "WSet_SF", "WSetPct_SF", "VarSet_SF", "VarSetPct_SF"} {
		v.SetEnum(sfName, 0)
	}
	v.SetEnum("WRmp", wRmp)
	return regs
}

// esrmp703 builds a minimal model 703 image holding the given ESRmpTms
// (seconds, uint32).
func esrmp703(t *testing.T, rampS uint32) []uint16 {
	t.Helper()
	regs := make([]uint16, sunspec.L703.Len())
	v := sunspec.L703.View(regs)
	v.SetEnum("V_SF", 0)
	v.SetEnum("Hz_SF", 0)
	v.SetU32("ESRmpTms", rampS)
	return regs
}

// ── rampGradientOracle: the WRmp half is asserted ───────────────────────────

// GREEN: the DER's own WRmp reads exactly the commanded setGradW-derived
// percent.
func TestRampGradientOracle_PassesADERHoldingTheCommandedWRmp(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW) // 9000 -> 90%
	uv := unitWith(map[uint16][]uint16{704: wrmp704(t, 90)})

	got := o.Judge(uv)
	if got.Verdict != certify.Pass {
		t.Fatalf("verdict = %s against a DER holding WRmp=90 for a commanded setGradW=9000 (90%%): %s",
			got.Verdict, findingObserved(got))
	}
	t.Logf("GREEN — %s", got.Observed)
}

// RED: the DER's WRmp did not move to the commanded percent. This is the
// mutation proof — a referee that always PASSed here would certify a gateway
// that never wrote the register at all.
func TestRampGradientOracle_FailsADERWithTheWrongWRmp(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW) // wants 90
	uv := unitWith(map[uint16][]uint16{704: wrmp704(t, 50)})

	got := o.Judge(uv)
	if got.Verdict != certify.Fail {
		t.Fatalf("verdict = %s against a DER holding WRmp=50 for a commanded 90%%: %s",
			got.Verdict, findingObserved(got))
	}
	for _, want := range []string{"reads 50", "setGradW=9000", "90.00%"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the FAIL does not mention %q, so a reader cannot check the mismatch themselves: %s",
				want, got.Observed)
		}
	}
	t.Logf("RED — %s", got.Observed)
}

// A ±1 register-step tolerance is allowed (704's WRmp carries no scale
// factor, so 1 is its own finest increment) — but not more than that.
func TestRampGradientOracle_ToleratesOneRegisterStepAndNoMore(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW) // wants 90

	if got := o.Judge(unitWith(map[uint16][]uint16{704: wrmp704(t, 89)})); got.Verdict != certify.Pass {
		t.Errorf("WRmp=89 against a commanded 90 should be within the register's own quantization: %s",
			findingObserved(got))
	}
	if got := o.Judge(unitWith(map[uint16][]uint16{704: wrmp704(t, 88)})); got.Verdict != certify.Fail {
		t.Errorf("WRmp=88 against a commanded 90 is TWO steps off and should not be tolerated: %s",
			findingObserved(got))
	}
}

// A DER with no model 704 at all is Unavailable, not FAILed — there is
// nowhere for this row's setGradW half to have landed.
func TestRampGradientOracle_UnavailableWithNoModel704(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW)
	got := o.Judge(unitWith(map[uint16][]uint16{}))
	if got.Unavailable == "" {
		t.Fatalf("a 704-less DER produced a verdict (%s) rather than an unavailability: %s",
			got.Verdict, got.Observed)
	}
}

// ── rampGradientOracle: the ESRmpTms half is reported, never graded ─────────

// The verdict must stay keyed to WRmp alone: an ESRmpTms register holding
// something OTHER than what setSoftGradW would imply must not turn a correct
// WRmp reading into a FAIL, because this row's own procedure never schedules
// the enter-service transition that would cause lexa-gw to write it at all.
func TestRampGradientOracle_ESRmpTmsIsReportedButNeverGrades(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW)
	// ESRmpTms=0 — the register's power-on/never-written value, deliberately
	// NOT the 25s a commanded setSoftGradW=400 would resolve to
	// (100/4.00%=25s) if an energize transition ever executed it.
	uv := unitWith(map[uint16][]uint16{704: wrmp704(t, 90), 703: esrmp703(t, 0)})

	got := o.Judge(uv)
	if got.Verdict != certify.Pass {
		t.Fatalf("a correct WRmp reading was FAILed by an unrelated ESRmpTms register: %s",
			findingObserved(got))
	}
	for _, want := range []string{"ESRmpTms reads 0", "REPORTED, NOT ASSERTED", "Default-Only"} {
		if !strings.Contains(got.Observed, want) {
			t.Errorf("the observed text does not mention %q, so a reader would not know this half was "+
				"measured but not graded: %s", want, got.Observed)
		}
	}
	t.Logf("PASS with ESRmpTms reported, not graded — %s", got.Observed)
}

// A DER with no model 703 at all still grades on WRmp alone, and says why the
// other half has nothing to report.
func TestRampGradientOracle_NoModel703StillGradesWRmp(t *testing.T) {
	o := rampGradientOracle(figure7RampTestSetGradW, figure7RampTestSetSoftGradW)
	got := o.Judge(unitWith(map[uint16][]uint16{704: wrmp704(t, 90)}))
	if got.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: a 703-less DER should still be graded on its WRmp alone: %s",
			got.Verdict, findingObserved(got))
	}
	if !strings.Contains(got.Observed, "serves no model 703") {
		t.Errorf("the observed text does not explain the missing 703, so a reader would not know why "+
			"ESRmpTms is absent from the verdict: %s", got.Observed)
	}
}

// ── critDefaultDERControlCarriesRamp ────────────────────────────────────────

// rampDdercXML builds one <DefaultDERControl>, with setGradW/setSoftGradW as
// SIBLINGS of DERControlBase (IEEE Std 2030.5-2018 p.252's own placement) —
// present only when non-nil, so a caller can build the "neither element"
// shape too. Named distinctly from sepdata_test.go's own no-arg ddercXML,
// which builds an unrelated fixed fixture.
func rampDdercXML(href string, setGradW, setSoftGradW *uint16) string {
	body := `<DefaultDERControl xmlns="urn:ieee:std:2030.5:ns" href="` + href + `">` +
		`<mRID>DDERC-SP-001</mRID>` +
		`<DERControlBase><opModExpLimW><multiplier>0</multiplier><value>5000</value></opModExpLimW></DERControlBase>`
	if setGradW != nil {
		body += rampElemXML("setGradW", *setGradW)
	}
	if setSoftGradW != nil {
		body += rampElemXML("setSoftGradW", *setSoftGradW)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` + body + `</DefaultDERControl>`
}

// rampElemXML renders one <name>v</name> element, reusing teeth_test.go's
// own itoa (int64) rather than declaring a second uint16 overload.
func rampElemXML(name string, v uint16) string {
	return "<" + name + ">" + itoa(int64(v)) + "</" + name + ">"
}

// GREEN: the DUT fetched a DefaultDERControl carrying exactly the row's
// commanded pair.
func TestCritDefaultDERControlCarriesRamp_PassesOnMatchingSibling(t *testing.T) {
	body := rampDdercXML("/derp/0/dderc", ptr(uint16(9000)), ptr(uint16(400)))
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil, synthTranscript(get("/derp/0/dderc", 200, body)))
	if f.Unavailable != "" {
		t.Fatalf("declined to decide where the elements WERE on the wire: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s against an exact match: %s", f.Verdict, f.Observed)
	}
}

// RED: the DefaultDERControl still carries the FIGURE 7 DEFAULT column
// (10000/200), not the Test Values this row commands (9000/400) — the shape a
// stale or never-updated default would leave behind.
func TestCritDefaultDERControlCarriesRamp_FailsOnTheWrongValues(t *testing.T) {
	body := rampDdercXML("/derp/0/dderc", ptr(uint16(10000)), ptr(uint16(200)))
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil, synthTranscript(get("/derp/0/dderc", 200, body)))
	if f.Unavailable != "" {
		t.Fatalf("declined to decide where the elements WERE on the wire, just at the wrong values: %s",
			f.Unavailable)
	}
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s against a DefaultDERControl still carrying the DEFAULT column, not the Test "+
			"Values: %s", f.Verdict, f.Observed)
	}
	for _, want := range []string{"10000", "200", "9000", "400"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the FAIL does not mention %q: %s", want, f.Observed)
		}
	}
}

// FAIL naming the gap, not Unavailable: a DefaultDERControl with NEITHER
// element is the bench lever never having been exercised at all, which is
// still a decided finding about this row, not an abstention.
func TestCritDefaultDERControlCarriesRamp_FailsWhenElementsAbsent(t *testing.T) {
	body := rampDdercXML("/derp/0/dderc", nil, nil)
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil, synthTranscript(get("/derp/0/dderc", 200, body)))
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s (unavailable=%q) against a DefaultDERControl with neither ramp element: %s",
			f.Verdict, f.Unavailable, f.Observed)
	}
	if !strings.Contains(f.Observed, "none carrying a setGradW/setSoftGradW pair") {
		t.Errorf("the FAIL does not say the pair was entirely absent: %s", f.Observed)
	}
}

// No DefaultDERControl in the transcript at all is Unavailable, not FAILed —
// a bench/capture gap, not a statement about the DUT.
func TestCritDefaultDERControlCarriesRamp_UnavailableWithNoDefaultDERControl(t *testing.T) {
	reason := wantUnavailable(t, "no DefaultDERControl",
		critDefaultDERControlCarriesRamp(9000, 400),
		synthTranscript(get("/derp/0/derc", 200, dercListXML())))
	if !strings.Contains(reason, "DefaultDERControl") {
		t.Errorf("the unavailability does not name what was missing: %q", reason)
	}
}

// THE STRUCTURAL PROPERTY this criterion exists to have, that
// critDefaultDERControl's own "first resource of this type" shortcut does
// not: gridsim serves one DefaultDERControl per program (0, 1, 2). A DUT
// that fetches program 1's plain default BEFORE program 0's ramp-bearing one
// must still PASS — a criterion that only looked at the first fetch would
// FAIL a compliant run purely on fetch order.
func TestCritDefaultDERControlCarriesRamp_ScansEveryProgramNotJustTheFirst(t *testing.T) {
	other := rampDdercXML("/derp/1/dderc", nil, nil)
	mine := rampDdercXML("/derp/0/dderc", ptr(uint16(9000)), ptr(uint16(400)))
	f := critDefaultDERControlCarriesRamp(9000, 400).Wire(nil,
		synthTranscript(get("/derp/1/dderc", 200, other), get("/derp/0/dderc", 200, mine)))
	if f.Unavailable != "" {
		t.Fatalf("declined to decide: %s", f.Unavailable)
	}
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: a matching DefaultDERControl fetched SECOND was not found because an "+
			"earlier, unrelated program's default was scanned first: %s", f.Verdict, f.Observed)
	}
}

// ── Registration ─────────────────────────────────────────────────────────────

// BASIC-007 must be a REAL row now: registered, requiring gridsim (it creates
// its own precondition), and in its historical order slot.
func TestBASIC007_IsRegisteredAsARealRow(t *testing.T) {
	reg, ok := certify.Default().Lookup(uid("BASIC-007"))
	if !ok {
		t.Fatal("BASIC-007 is not registered at all")
	}
	if reg.Check == nil {
		t.Fatal("BASIC-007 is registered with a nil Check")
	}
	if reg.Order != 53 {
		t.Errorf("order = %d, want 53 (its slot among the twelve BASIC-004..015 rows)", reg.Order)
	}
	needsGridSim := false
	for _, r := range reg.Requires {
		if r == "gridsim" {
			needsGridSim = true
		}
	}
	if !needsGridSim {
		t.Errorf("Requires = %v: this row authors its own DefaultDERControl precondition and cannot run "+
			"without gridsim's admin API", reg.Requires)
	}
}

// BASIC-007 must no longer appear in inverterControlRows: it has its own
// apparatus now (this row exists to pin that the migration in
// registerInverterControls does not silently regress into a double
// registration, which Register's own panic would catch at init() time, but
// this states the intent directly rather than relying on that side effect).
func TestBASIC007_IsNotInTheUniformInverterControlRows(t *testing.T) {
	for _, r := range inverterControlRows() {
		if r.id == "BASIC-007" {
			t.Fatal("BASIC-007 is still in inverterControlRows: it is registered a second time by " +
				"registerRampRates, which would have panicked at init() — but if this ever stops " +
				"panicking (e.g. a Register() change tolerating duplicates), this row's own apparatus " +
				"would be shadowed by the uniform machinery's unreachableMode shape")
		}
	}
}

// ── register-state-independence: the whole point of the self-baselining fix ──
//
// CSIP-BENCH-BASIC007-ORACLE-STATE-CONTAMINATION: in a full campaign a prior
// ramp row left WRmp already at the Figure-7 target (90), and the old row read
// that as "already held" and refused a clean product. These tests drive the row
// end-to-end against a SCRIPTED fake DUT whose WRmp starts at 0, at 90, and at
// 50, and prove all three PASS — because the row now drives a distinguishable
// baseline first and certifies the MOVE, not the match.

// rampFakeBench is a scripted fake DUT for BASIC-007: a fake gridsim admin whose
// POST /admin/default applies the setGradW it is handed to the DER's model-704
// WRmp (a perfectly-responsive gateway), and a simapi sidecar serving that DER's
// registers plus the 1.1.0 poll barrier so the row's epoch fence has something
// real to wait on. The DER's WRmp starts at `start` — the prior-register state
// the row must be independent of. No board, no product: the "DUT" is this
// handler applying whatever ramp default the row last commanded.
func rampFakeBench(t *testing.T, start uint16) (*certify.RunCtx, *Driver) {
	t.Helper()
	dev := diff.NewDevice(diff.Bench702())
	var mu sync.Mutex
	var poll uint64
	applyWRmp := func(v uint16) { // caller holds mu
		regs, ok := dev.Model(704)
		if !ok {
			t.Fatal("the Bench702 fixture serves no model 704")
		}
		sunspec.L704.View(regs).SetEnum("WRmp", v)
		off := sunspec.L704.Offset("WRmp")
		if off < 0 || off >= len(regs) {
			t.Fatal("the 704 layout has no WRmp point")
		}
		if err := dev.WriteHolding(dev.Bases[704]+uint16(off), []uint16{regs[off]}); err != nil {
			t.Fatalf("write WRmp=%d: %v", v, err)
		}
	}
	mu.Lock()
	applyWRmp(start)
	mu.Unlock()

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin/default", func(w http.ResponseWriter, r *http.Request) {
		var req DefaultRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.SetGradW != nil {
			mu.Lock()
			applyWRmp(*req.SetGradW / 100) // the responsive DUT tracks the commanded default
			poll++                          // and it took a fresh poll cycle to do it
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	})
	adminSrv := httptest.NewServer(adminMux)
	t.Cleanup(adminSrv.Close)

	pollBody := func() []byte {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal(map[string]any{
			"api_version": "1.1.0", "reached": true,
			"poll": map[string]any{"completed": poll},
		})
		return b
	}
	simMux := http.NewServeMux()
	simMux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		snap := dev.Snapshot()
		mu.Unlock()
		out := make(map[string]uint16, len(snap))
		for a, v := range snap {
			out[strconv.Itoa(int(a))] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	simMux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"paused": false, "sessions": []any{}})
	})
	simMux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(pollBody())
	})
	simMux.HandleFunc("/poll/wait", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(pollBody())
	})
	simSrv := httptest.NewServer(simMux)
	t.Cleanup(simSrv.Close)

	rc := &certify.RunCtx{
		Case:    &certify.Case{UID: "csip-conf-v1.3::BASIC-007", ID: "BASIC-007"},
		GridSim: certify.NewAdminClient(adminSrv.URL, http.DefaultClient),
		Targets: certify.Targets{GridSimAdmin: adminSrv.URL},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, simSrv.URL, http.DefaultClient),
		},
	}
	return rc, NewDriver(rc)
}

// driveRampRow runs BASIC-007's Setup then PostWait against a bench, exactly the
// two live-phase calls run() makes, and returns the Observation the citation
// phase (oracleOutcome / spec.Verdict) reads.
func driveRampRow(t *testing.T, rc *certify.RunCtx, d *Driver) *Observation {
	t.Helper()
	ctx := context.Background()
	s := rampRatesSpec()
	// Bound the settle/confirm windows so a run whose value never lands (a dead
	// DUT, or the baseline-disabled mutation) FAILs promptly instead of burning
	// the multi-minute pollCycleWait fallback. A healthy fake applies
	// synchronously and PASSes on the first read, so this never gates a PASS.
	params := map[string]string{pollWindowParam: "300ms"}
	if err := s.Setup(ctx, d, params); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := s.PostWait(ctx, d, params); err != nil {
		t.Fatalf("PostWait: %v", err)
	}
	return &Observation{Params: params}
}

// TestBASIC007_PassesRegardlessOfPriorRegisterState is the fix's deliverable:
// the row PASSes whether the DER's WRmp started at 0, at 90 (the exact
// contamination that reconciled the clean product to FAIL), or at anything else.
func TestBASIC007_PassesRegardlessOfPriorRegisterState(t *testing.T) {
	for _, start := range []uint16{0, 90, 50} {
		t.Run(fmt.Sprintf("WRmp_starts_at_%d", start), func(t *testing.T) {
			rc, d := rampFakeBench(t, start)
			obs := driveRampRow(t, rc, d)

			// The baseline was confirmed and the pre-read of the target FAILed
			// (the DER did not hold 90 once the distinguishable 50 landed).
			if got := obs.Params[oracleDefaultVerdictParam]; got != string(certify.Pass) {
				t.Fatalf("the distinguishable baseline was not confirmed (%s=%q): %s", oracleDefaultVerdictParam,
					got, obs.Params[oracleDefaultObservedParam])
			}
			if got := obs.Params[oraclePreVerdictParam]; got != string(certify.Fail) {
				t.Fatalf("after the baseline landed, the pre-read of the target = %q, want %q — the DER "+
					"should NOT hold WRmp=90 while it holds the 50 baseline: %s", got, certify.Fail,
					obs.Params[oraclePreObservedParam])
			}
			f := oracleOutcome(obs)
			if f.Verdict != certify.Pass {
				t.Fatalf("verdict = %s from a DER whose WRmp started at %d: %s", f.Verdict, start,
					findingObserved(f))
			}
			if !strings.Contains(f.Observed, "MOVE") {
				t.Errorf("the PASS does not cite the MOVE it certifies (it must not read as a bare match): %s",
					f.Observed)
			}
			t.Logf("start=%d -> %s: %s", start, f.Verdict, f.Observed)
		})
	}
}

// TestBASIC007_FailsWhenTheBaselineNeverLands proves the shortfall has teeth: a
// DUT that ignores the distinguishable baseline (its WRmp never becomes 50)
// cannot certify the transition, whatever the post-read shows — the row FAILs on
// the unestablished starting state rather than certifying a stale register.
func TestBASIC007_FailsWhenTheBaselineNeverLands(t *testing.T) {
	// Record a run whose baseline confirmation FAILed (the fake DUT never moved
	// to 50) but whose post-read matched 90 — the exact "the register holds it,
	// but we never proved it moved" shape the fix must refuse.
	obs := &Observation{Params: map[string]string{
		oracleDefaultCommandedParam:  strconv.Itoa(int(rampBaselineSetGradW)),
		oracleDefaultProvenanceParam: "a DISTINGUISHABLE setGradW=5000 baseline",
		oracleDefaultVerdictParam:    string(certify.Fail),
		oracleDefaultObservedParam:   "the DER's own model 704 WRmp register reads 90 against a commanded 50",
		oracleDefaultWindowParam:     "2m30s",
		oracleDefaultMRIDParam:       "gridsim program-0's DefaultDERControl (setGradW=5000)",
		oraclePreVerdictParam:        string(certify.Fail),
		oraclePreObservedParam:       "WRmp reads 90 against a commanded 90 — wait, still 90",
		oracleVerdictParam:           string(certify.Pass),
		oracleObservedParam:          "the DER's own model 704 WRmp register reads 90",
	}}
	f := oracleOutcome(obs)
	if f.Verdict != certify.Fail {
		t.Fatalf("verdict = %s when the distinguishable baseline never landed: a post-read that matches "+
			"cannot certify a transition whose starting state was never established: %s", f.Verdict,
			findingObserved(f))
	}
	if !strings.Contains(f.Observed, "distinguishable") && !strings.Contains(f.Observed, "DISTINGUISHABLE") {
		t.Errorf("the shortfall FAIL does not name the harness-chosen baseline (its provenance): %s", f.Observed)
	}
}

// TestBASIC007_PassCreditIsHonestAboutTheBaselineProvenance pins that a bundle
// reader is never told Figure 7 prescribed the 50 baseline: the credit prose
// names it as a distinguishing value this row invents, not the catalog's Default
// column.
func TestBASIC007_PassCreditIsHonestAboutTheBaselineProvenance(t *testing.T) {
	rc, d := rampFakeBench(t, 90)
	obs := driveRampRow(t, rc, d)
	f := oracleOutcome(obs)
	if f.Verdict != certify.Pass {
		t.Fatalf("verdict = %s: %s", f.Verdict, findingObserved(f))
	}
	if strings.Contains(f.Observed, "the procedure's own") || strings.Contains(f.Observed, "the procedure prescribes") {
		t.Errorf("the ramp PASS claims the procedure prescribed its baseline, which Figure 7 does not: %s",
			f.Observed)
	}
	if !strings.Contains(obs.Params[oracleDefaultProvenanceParam], "Figure 7 does not name") {
		t.Errorf("the recorded provenance does not disclaim Figure 7: %q",
			obs.Params[oracleDefaultProvenanceParam])
	}
}
