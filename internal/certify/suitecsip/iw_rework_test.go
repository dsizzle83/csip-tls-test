package suitecsip

// iw_rework_test.go pins the three behaviours the cancel-then-clean teardown
// rework introduced (HARNESS-TEARDOWN-CANCEL-ONLY-LEAVES-APPLIED-STATE):
//
//   1. teardown VERIFIES the applied DER state released BEFORE it deletes, and
//      a still-applied axis FAILs the run rather than being carried forward;
//   2. BASIC-014's refusal oracle attributes a WSet write to THIS control by the
//      ledger seq fence, so a PRIOR control's release is not counted as its own;
//   3. BASIC-009's response-integrity gate FAILs a Started(2) the declared
//      connect axis (M123 Conn) did not reach, and passes a correct withhold.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/diff"
	"csip-tls-test/internal/invariant"
	"csip-tls-test/sim/gridsim"
	model "lexa-proto/csipmodel"
	"lexa-proto/sunspec"
)

// ── Item 1: cancel-then-delete teardown ───────────────────────────

// serveDER serves a diff.Device's register image at /registers and a minimal
// /state, wired as Sims[oracleSimName].
func serveDER(t *testing.T, dev *diff.Device) *certify.RunCtx {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/registers", func(w http.ResponseWriter, r *http.Request) {
		snap := dev.Snapshot()
		out := make(map[string]uint16, len(snap))
		for addr, v := range snap {
			out[strconv.Itoa(int(addr))] = v
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"paused": false, "sessions": []any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &certify.RunCtx{
		Case: &certify.Case{UID: "test::teardown"},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, srv.URL, http.DefaultClient),
		},
	}
}

// TestReleaseProgramControls_CancelsThenDeletes proves the teardown contract:
// it server-CANCELS (currentStatus=6) so a spec-correct DUT observes the event
// ending, then DELETEs to clean the list up — cancel BEFORE delete for each
// program, all cancels before any delete for the CORE-022 two-program case —
// with NO reversion-verify, and it does NOT fatal when the DER holds a STANDING
// default axis enabled (the board's exp_lim_W WMaxLimPct, which persists by
// design and must not be graded).
func TestReleaseProgramControls_CancelsThenDeletes(t *testing.T) {
	newBench := func(t *testing.T, dev *diff.Device) (*Driver, *recordingRT) {
		t.Helper()
		gs := gridsim.NewServer(benchLFDI)
		adminSrv := httptest.NewServer(gs.AdminHandler())
		t.Cleanup(adminSrv.Close)
		rc := serveDER(t, dev)
		rec := &recordingRT{inner: http.DefaultTransport}
		rc.GridSim = certify.NewAdminClient(adminSrv.URL, rec)
		rc.Targets = certify.Targets{GridSimAdmin: adminSrv.URL}
		d := NewDriver(rc)
		if _, err := d.PostControl(context.Background(), ControlRequest{
			Program: 0, MRID: "CERT-TEARDOWN-1", Description: "teardown fixture",
			StartOffset: 0, DurationS: 600, MaxLimW: ptr(int64(6000)),
		}); err != nil {
			t.Fatalf("PostControl: %v", err)
		}
		return d, rec
	}
	firstDelete := func(rec *recordingRT, from int) int {
		for i := from; i < len(rec.method); i++ {
			if rec.method[i] == http.MethodDelete {
				return i
			}
		}
		return -1
	}
	firstCancel := func(rec *recordingRT, from int) int {
		for i := from; i < len(rec.method); i++ {
			if rec.method[i] == http.MethodPost && strings.Contains(rec.body[i], `"current_status":6`) {
				return i
			}
		}
		return -1
	}
	countCancels := func(rec *recordingRT, from int) int {
		n := 0
		for i := from; i < len(rec.method); i++ {
			if rec.method[i] == http.MethodPost && strings.Contains(rec.body[i], `"current_status":6`) {
				n++
			}
		}
		return n
	}
	lastCancel := func(rec *recordingRT, from int) int {
		last := -1
		for i := from; i < len(rec.method); i++ {
			if rec.method[i] == http.MethodPost && strings.Contains(rec.body[i], `"current_status":6`) {
				last = i
			}
		}
		return last
	}

	t.Run("single program: cancel(6) precedes delete, no fatal", func(t *testing.T) {
		clean, _ := oracleFixture(t)
		d, rec := newBench(t, clean)
		mark := len(rec.method)
		if err := d.releaseProgramControls(context.Background(), 0); err != nil {
			t.Fatalf("releaseProgramControls returned %v", err)
		}
		cancelAt, deleteAt := firstCancel(rec, mark), firstDelete(rec, mark)
		if cancelAt < 0 {
			t.Errorf("no Cancelled(6) edit was issued (requests: %v)", rec.method[mark:])
		}
		if deleteAt < 0 {
			t.Errorf("no DELETE was issued, so the control is left advertised (requests: %v)", rec.method[mark:])
		}
		if cancelAt >= 0 && deleteAt >= 0 && cancelAt > deleteAt {
			t.Errorf("the teardown DELETED (req %d) before it CANCELLED (req %d) — a spec-correct DUT never "+
				"observes the event end", deleteAt, cancelAt)
		}
	})

	t.Run("CORE-022 two programs: all cancels precede any delete", func(t *testing.T) {
		clean, _ := oracleFixture(t)
		d, rec := newBench(t, clean) // posts a control on program 0
		if _, err := d.PostControl(context.Background(), ControlRequest{
			Program: 1, MRID: "CERT-TEARDOWN-2", Description: "teardown fixture p1",
			StartOffset: 0, DurationS: 600, GenLimW: ptr(int64(6000)),
		}); err != nil {
			t.Fatalf("PostControl program 1: %v", err)
		}
		mark := len(rec.method)
		if err := d.releaseProgramControls(context.Background(), 0, 1); err != nil {
			t.Fatalf("releaseProgramControls(0,1) returned %v", err)
		}
		if n := countCancels(rec, mark); n < 2 {
			t.Errorf("only %d Cancelled(6) edits for two programs, want >= 2 (requests: %v)", n, rec.method[mark:])
		}
		lastC, firstD := lastCancel(rec, mark), firstDelete(rec, mark)
		if firstD < 0 {
			t.Fatalf("no DELETE was issued (requests: %v)", rec.method[mark:])
		}
		if lastC < 0 || lastC > firstD {
			t.Errorf("a DELETE (req %d) preceded the last Cancel (req %d): a program was deleted before both "+
				"were cancelled (requests: %v)", firstD, lastC, rec.method[mark:])
		}
	})

	t.Run("a STANDING default axis enabled does NOT fatal the teardown", func(t *testing.T) {
		// The board's shape: a DefaultDERControl leaves WMaxLimPct ENABLED (an
		// export limit that persists BY DESIGN). The teardown must cancel+delete
		// cleanly and NEVER fatal on that enabled axis — the old reversion-verify
		// false-FATALed 9/10 rows on exactly this.
		dev, base := oracleFixture(t)
		pc := model.PerCent{Value: 6250} // 62.5%, the exp_lim_W/WMax default shape
		if err := base.ApplyControl(model.DERControlBase{OpModMaxLimW: &pc}, "standing-default"); err != nil {
			t.Fatalf("ApplyControl(standing default): %v", err)
		}
		d, rec := newBench(t, dev)
		mark := len(rec.method)
		if err := d.releaseProgramControls(context.Background(), 0); err != nil {
			t.Fatalf("a STANDING default axis being enabled FATALed the teardown (%v) — the teardown must "+
				"not read or grade the DER's registers", err)
		}
		if len(d.CleanupErrors()) != 0 {
			t.Errorf("the teardown recorded errors against a working bench: %v", d.CleanupErrors())
		}
		if firstCancel(rec, mark) < 0 || firstDelete(rec, mark) < 0 {
			t.Errorf("the teardown did not cancel+delete despite the enabled default (requests: %v)",
				rec.method[mark:])
		}
	})
}

// ── Item 2: BASIC-014 ledger attribution ────────────────────────────────────

// serveLedger wires an rc whose DER sim answers GET /ledger from a fixed set of
// transactions, honouring since_seq. It carries no /registers: the caller passes
// the UnitView (with Base[704]) to refusalLedgerAttribution directly.
func serveLedger(t *testing.T, entries []simLedgerEntry, high uint64) *certify.RunCtx {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ledger", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseUint(r.URL.Query().Get("since_seq"), 10, 64)
		var out []simLedgerEntry
		for _, e := range entries {
			if e.Seq > since {
				out = append(out, e)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(simLedgerPage{Entries: out, Total: len(out), HighSeq: high, NextSeq: high + 1})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &certify.RunCtx{
		Case: &certify.Case{UID: "test::ledger"},
		Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, srv.URL, http.DefaultClient),
		},
	}
}

// wsetUnitView builds a UnitView whose model-704 base is set, so refusalAxisSpan
// resolves the WSet register span, and returns the absolute WSet register addr.
func wsetUnitView() (uv invariant.UnitView, wsetAddr uint16) {
	const base = uint16(40000)
	u := unitWith(map[uint16][]uint16{704: make([]uint16, sunspec.L704.Len())})
	u.Base[704] = base
	return u, base + uint16(sunspec.L704.Offset("WSet"))
}

// TestRefusalLedgerAttribution_PriorReleaseNotAttributed proves the core fix: a
// WSet write BEFORE this control's fence (a prior control's release) does NOT
// count as this refused control's write, while a write AFTER the fence does.
func TestRefusalLedgerAttribution_PriorReleaseNotAttributed(t *testing.T) {
	uv, wsetAddr := wsetUnitView()
	b := basic014Binding()
	const fenceSeq = uint64(100)
	fence := refusalLedgerFence{Seq: fenceSeq, Have: true}
	// The fingerprint CHANGED across the window (a prior release moved WSet).
	baseline, post := "WSet=4800 W ENABLED", "WSet=0 W disabled"

	t.Run("prior release (seq<=fence) is a PASS, not this row's write", func(t *testing.T) {
		rc := serveLedger(t, []simLedgerEntry{
			{Seq: 50, Epoch: 3, FC: fcWriteMultipleRegisters, Addr: wsetAddr, Count: 2},
		}, 60)
		got, decided := refusalLedgerAttribution(context.Background(), rc, b, fence, uv, baseline, post)
		if !decided {
			t.Fatal("the ledger was reachable but the attribution declined")
		}
		if got.Verdict != certify.Pass {
			t.Fatalf("a WSet write at seq 50 (before the fence at %d) was attributed to this control: %s",
				fenceSeq, got.Observed)
		}
		if !strings.Contains(got.Observed, "PRIOR control's RELEASE") {
			t.Errorf("the PASS does not attribute the change to a prior release: %s", got.Observed)
		}
	})

	t.Run("fenced write (seq>fence) is this control's write, a FAIL", func(t *testing.T) {
		rc := serveLedger(t, []simLedgerEntry{
			{Seq: 150, Epoch: 5, FC: fcWriteMultipleRegisters, Addr: wsetAddr, Count: 2},
		}, 160)
		got, decided := refusalLedgerAttribution(context.Background(), rc, b, fence, uv, baseline, post)
		if !decided {
			t.Fatal("the ledger was reachable but the attribution declined")
		}
		if got.Verdict != certify.Fail {
			t.Fatalf("a WSet write at seq 150 (after the fence at %d) was NOT attributed to this control: %s",
				fenceSeq, got.Observed)
		}
		if !strings.Contains(got.Observed, "LANDED") {
			t.Errorf("the FAIL does not describe the landed write: %s", got.Observed)
		}
	})

	t.Run("no write, unchanged registers is a clean PASS", func(t *testing.T) {
		rc := serveLedger(t, nil, 40)
		got, decided := refusalLedgerAttribution(context.Background(), rc, b, fence, uv, baseline, baseline)
		if !decided || got.Verdict != certify.Pass {
			t.Fatalf("an unchanged axis with no fenced write = decided=%v %s, want a PASS", decided, got.Observed)
		}
	})

	t.Run("no ledger declines to the fingerprint fallback", func(t *testing.T) {
		rc := &certify.RunCtx{Case: &certify.Case{UID: "test::no-ledger"}, Sims: map[string]*certify.SimClient{}}
		if _, decided := refusalLedgerAttribution(context.Background(), rc, b, fence, uv, baseline, post); decided {
			t.Error("the attribution decided a verdict with no ledger reachable; it must decline so " +
				"oracleRefusal falls back to the fingerprint diff")
		}
	})

	t.Run("an autonomous reversion-timer write is OUTSIDE the axis span", func(t *testing.T) {
		// A fenced write to WSetRvrtRem (the self-decrementing countdown, which
		// modsim moves on its own wall clock) must NOT be attributed to the
		// refused WSet axis: the span ends before the timer registers. With the
		// setpoint fingerprint unchanged, that leaves a clean PASS, not a FAIL.
		rvrtRemAddr := uv.Base[704] + uint16(sunspec.L704.Offset("WSetRvrtRem"))
		rc := serveLedger(t, []simLedgerEntry{
			{Seq: 150, Epoch: 5, FC: fcWriteMultipleRegisters, Addr: rvrtRemAddr, Count: 2},
		}, 160)
		got, decided := refusalLedgerAttribution(context.Background(), rc, b, fence, uv, baseline, baseline)
		if !decided {
			t.Fatal("the ledger was reachable but the attribution declined")
		}
		if got.Verdict != certify.Pass {
			t.Fatalf("a write to the autonomous WSetRvrtRem timer was attributed to the WSet axis: %s (%s)",
				got.Verdict, got.Observed)
		}
	})

	t.Run("a truncated ledger page declines rather than false-PASS", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/ledger", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(simLedgerPage{Entries: nil, Total: 0, HighSeq: 9000, Truncated: true})
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		rc := &certify.RunCtx{Case: &certify.Case{UID: "test::trunc"}, Sims: map[string]*certify.SimClient{
			oracleSimName: certify.NewSimClient(oracleSimName, srv.URL, http.DefaultClient),
		}}
		if _, decided := refusalLedgerAttribution(context.Background(), rc, b, fence, uv, baseline, baseline); decided {
			t.Error("a truncated ledger page decided a PASS; it must decline (a dropped fenced write could " +
				"be hiding behind the truncation)")
		}
	})
}

// ── Item 3: BASIC-009 Started-integrity gate ────────────────────────────────

// TestConnectStartedIntegrity_Started2NeedsAMove proves the transition-aware
// gate: a Started(2) the connect axis did not reach FAILs; a Started(2) backed
// by a DISTINGUISHABLE move (baseline did not hold the commanded state, post
// does) PASSes; a Started(2) whose commanded state ALREADY equalled the baseline
// (no observable move — the as-built Conn=1 trap) is WARNed, not credited; and a
// correct withhold PASSes.
func TestConnectStartedIntegrity_Started2NeedsAMove(t *testing.T) {
	const mrid = "CERT-BASIC-009"
	// pre = the oracle's PRE verdict (baseline connect grade); post = its post
	// verdict. pre=Fail means the axis did NOT hold the commanded state at
	// baseline (a distinguishable move is possible); pre=Pass means it already
	// held it (no move observable).
	obsWith := func(pre, post certify.Verdict) *Observation {
		return &Observation{Params: map[string]string{
			oraclePreVerdictParam:  string(pre),
			oraclePreObservedParam: "model 123 Conn read at baseline",
			oracleVerdictParam:     string(post),
			oracleObservedParam:    "model 123 Conn read after the control",
		}}
	}
	started := ServerView{Responses: []AdminResponse{{Subject: mrid, Status: 2}}}
	withheld := ServerView{Responses: []AdminResponse{
		{Subject: mrid, Status: 1}, {Subject: mrid, Status: 252},
	}}

	t.Run("Started(2) without M123 agreement FAILs", func(t *testing.T) {
		// post=Fail: the axis did not reach the commanded state at all.
		c := critConnectStartedIntegrity(mrid, obsWith(certify.Fail, certify.Fail))
		got := c.Server(&started)
		if got.Verdict != certify.Fail {
			t.Fatalf("a Started(2) whose connect axis did NOT reach = %s (%s), want FAIL", got.Verdict, got.Observed)
		}
		if !strings.Contains(got.Observed, "response-integrity") {
			t.Errorf("the FAIL does not name the response-integrity defect: %s", got.Observed)
		}
	})

	t.Run("Started(2) backed by a distinguishable move PASSes", func(t *testing.T) {
		// pre=Fail (did not hold commanded), post=Pass (now holds it) — a real
		// transition, the BASIC-009 connect=false shape (as-built Conn=1 -> 0).
		c := critConnectStartedIntegrity(mrid, obsWith(certify.Fail, certify.Pass))
		got := c.Server(&started)
		if got.Verdict != certify.Pass {
			t.Fatalf("a Started(2) backed by a move = %s (%s), want PASS", got.Verdict, got.Observed)
		}
		if !strings.Contains(got.Observed, "MOVED") {
			t.Errorf("the PASS does not credit an observed move: %s", got.Observed)
		}
	})

	t.Run("Started(2) with NO observable move is WARNed, not credited", func(t *testing.T) {
		// pre=Pass (baseline ALREADY held the commanded state) and post=Pass:
		// the commanded state equalled the as-built, so a Started(2) cannot be
		// credited as proof of execution — report (WARN), do not pass.
		c := critConnectStartedIntegrity(mrid, obsWith(certify.Pass, certify.Pass))
		got := c.Server(&started)
		if got.Verdict != certify.Warn {
			t.Fatalf("a Started(2) against an indistinguishable baseline = %s (%s), want WARN — a "+
				"trivial baseline match must not be credited as execution", got.Verdict, got.Observed)
		}
		if !strings.Contains(got.Observed, "no transition") {
			t.Errorf("the WARN does not explain the indistinguishable baseline: %s", got.Observed)
		}
	})

	t.Run("a correct withhold (no Started(2)) is a PASS, not a FAIL", func(t *testing.T) {
		c := critConnectStartedIntegrity(mrid, obsWith(certify.Fail, certify.Fail))
		if got := c.Server(&withheld); got.Verdict != certify.Pass {
			t.Fatalf("a correct CannotComply withhold = %s (%s), want PASS", got.Verdict, got.Observed)
		}
	})

	t.Run("an unreadable connect oracle declines, never blames the DUT", func(t *testing.T) {
		o := &Observation{Params: map[string]string{oracleUnavailableParam: "the DER sidecar was down"}}
		c := critConnectStartedIntegrity(mrid, o)
		if got := c.Server(&started); got.Unavailable == "" {
			t.Fatalf("an unreadable connect oracle produced a verdict (%s) instead of declining: %s",
				got.Verdict, got.Observed)
		}
	})
}
