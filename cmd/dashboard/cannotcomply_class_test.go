package main

// F5 (adversarial gate finding): gridsim's classifyResponseStatus now marks
// SD-02's 4/5 (OptOut/OptIn, docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md,
// lexa-gw) as compliance alerts alongside 8/10/252/253/254, and every
// /admin/alerts consumer in this package used to key on Subject alone. These
// tests pin the fix: isCannotComplyOnset (mayhem.go) is what now decides
// which alerts count as a CannotComply ONSET, and a breach→recover pair
// (OptOut(4) then OptIn(5) for the SAME mRID) must neither inflate a
// duplicate-POST count nor let the recovery excuse an unrelated violation.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsCannotComplyOnset pins the class/vocab split directly: only the
// legacy 0xF0 vocabulary or SD-02's opt-out class count as an ONSET signal.
func TestIsCannotComplyOnset(t *testing.T) {
	cases := []struct {
		name       string
		vocab, cls string
		wantOnset  bool
	}{
		{"legacy 0xF0", "legacy", "", true},
		{"table27 opt-out (4)", "table27", "opt-out", true},
		{"table27 opt-in (5) — recovery, not onset", "table27", "opt-in", false},
		{"table27 end-of-event partial (8/10)", "table27", "end-of-event-partial", false},
		{"table27 receipt rejection (252/253/254)", "table27", "receipt-rejection", false},
		{"empty (plain lifecycle ack)", "table27", "", false},
	}
	for _, c := range cases {
		if got := isCannotComplyOnset(c.vocab, c.cls); got != c.wantOnset {
			t.Errorf("%s: isCannotComplyOnset(%q,%q) = %v, want %v", c.name, c.vocab, c.cls, got, c.wantOnset)
		}
	}
}

// alertsServer stands up a fake gridsim whose /admin/alerts serves the given
// (status, vocab, class) triples for one fixed subject mRID.
func alertsServer(t *testing.T, mrid string, alerts [][3]string) *httptest.Server {
	t.Helper()
	type alert struct {
		Subject string `json:"subject"`
		Vocab   string `json:"vocab"`
		Class   string `json:"class"`
	}
	var out []alert
	for _, a := range alerts {
		out = append(out, alert{Subject: mrid, Vocab: a[1], Class: a[2]})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"alerts": out, "server_time": int64(0)})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCannotComplyCount_BreachRecoverPairIsNotADuplicate is F5(b)/(c): a
// clean breach→recover episode — OptOut(4) onset, then OptIn(5) recovery, for
// the SAME mRID — must count as ONE onset, not two. Before the fix,
// cannotComplyCount (and mayhem_world.go's maxCount built from it) counted
// every /admin/alerts entry regardless of class, which would have read this
// exact pair as "2 CannotComply POSTs recorded for one episode — a
// duplicate", falsely blaming AD-016's restart-dedupe guarantee.
func TestCannotComplyCount_BreachRecoverPairIsNotADuplicate(t *testing.T) {
	const mrid = "M-EPISODE"
	srv := alertsServer(t, mrid, [][3]string{
		{"4", "table27", "opt-out"},
		{"5", "table27", "opt-in"},
	})
	d := newMayhemDriver(map[string]string{"gridsim": srv.URL})

	if n := d.cannotComplyCount(mrid); n != 1 {
		t.Fatalf("cannotComplyCount(breach+recover) = %d, want 1 (onset only, recovery excluded)", n)
	}
	if !d.reportedCannotComply(mrid) {
		t.Errorf("reportedCannotComply(breach+recover) = false, want true (the onset alone is enough)")
	}
}

// TestCannotComplyCount_RecoveryAloneIsNotAnOnset is the other half: a
// mailformed/synthetic transcript carrying ONLY an OptIn(5) for an mRID (no
// preceding onset) must not be read as a CannotComply at all.
func TestCannotComplyCount_RecoveryAloneIsNotAnOnset(t *testing.T) {
	const mrid = "M-RECOVERY-ONLY"
	srv := alertsServer(t, mrid, [][3]string{
		{"5", "table27", "opt-in"},
	})
	d := newMayhemDriver(map[string]string{"gridsim": srv.URL})

	if n := d.cannotComplyCount(mrid); n != 0 {
		t.Errorf("cannotComplyCount(recovery only) = %d, want 0", n)
	}
	if d.reportedCannotComply(mrid) {
		t.Error("reportedCannotComply(recovery only) = true, want false — OptIn(5) alone excuses nothing")
	}
}

// TestReplayDriver_ReportedCannotComply_RecoveryDoesNotExcuseAViolation is
// F5(a): replay.go's reportedCannotComply feeds directly into whether a
// sampled violation is excused (replay.go's sampleTick). A RECOVERY notice
// (OptIn/5) for the control's mRID must not excuse a violation that has
// nothing to do with it — only an onset (legacy 0xF0 or SD-02 OptOut(4))
// does.
func TestReplayDriver_ReportedCannotComply_RecoveryDoesNotExcuseAViolation(t *testing.T) {
	const mrid = "M-RD-EPISODE"

	// Recovery only: must not excuse.
	recoveryOnly := alertsServer(t, mrid, [][3]string{{"5", "table27", "opt-in"}})
	d := newReplayDriver(map[string]string{"gridsim": recoveryOnly.URL})
	if d.reportedCannotComply(mrid) {
		t.Error("replayDriver.reportedCannotComply(recovery only) = true, want false")
	}

	// Breach then recover: the onset alone is still enough to excuse (the
	// physical resource limit it reported is real), and the pair must not be
	// misread as anything else.
	pair := alertsServer(t, mrid, [][3]string{
		{"4", "table27", "opt-out"},
		{"5", "table27", "opt-in"},
	})
	d2 := newReplayDriver(map[string]string{"gridsim": pair.URL})
	if !d2.reportedCannotComply(mrid) {
		t.Error("replayDriver.reportedCannotComply(breach+recover) = false, want true")
	}

	// Legacy 0xF0 still excuses, unconditionally on class (empty class is
	// expected for the legacy vocab).
	legacy := alertsServer(t, mrid, [][3]string{{"240", "legacy", ""}})
	d3 := newReplayDriver(map[string]string{"gridsim": legacy.URL})
	if !d3.reportedCannotComply(mrid) {
		t.Error("replayDriver.reportedCannotComply(legacy 0xF0) = false, want true")
	}
}
