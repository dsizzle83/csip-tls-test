package main

// report_test.go covers the Reporter's bookkeeping (pure Go, no TLS): the
// per-requirement record/combine rules, the all-62-addressed guard that is the
// suite's own acceptance bar, and the markdown section emission. It runs in the
// fast lane (`make test-fast`).

import (
	"io"
	"strings"
	"testing"
	"time"
)

func quietReporter() *Reporter {
	return &Reporter{w: io.Discard, results: make(map[int]Result), started: time.Now()}
}

// TestReporter_RequirementTableComplete pins the invariant the whole suite rests
// on: the transcribed requirement table covers exactly SunSpecTCP-1..62, once each.
func TestReporter_RequirementTableComplete(t *testing.T) {
	if len(requirements) != 62 {
		t.Fatalf("requirement table has %d rows, want 62", len(requirements))
	}
	seen := make(map[int]bool)
	for _, m := range requirements {
		if m.n < 1 || m.n > 62 {
			t.Errorf("requirement %d out of range 1..62", m.n)
		}
		if seen[m.n] {
			t.Errorf("requirement %d listed twice", m.n)
		}
		seen[m.n] = true
		if m.section == "" || m.summary == "" || m.applies == "" {
			t.Errorf("requirement %d has empty metadata: %+v", m.n, m)
		}
	}
	for n := 1; n <= 62; n++ {
		if !seen[n] {
			t.Errorf("requirement SunSpecTCP-%d missing from the table", n)
		}
	}
}

// TestReporter_MissingRows flags any unrecorded requirement — the "no row prints
// NOT ADDRESSED" acceptance guard.
func TestReporter_MissingRows(t *testing.T) {
	r := quietReporter()
	for n := 1; n <= 62; n++ {
		if n == 42 {
			continue // leave one unrecorded
		}
		r.pass(n, "ok")
	}
	missing := r.missingRows()
	if len(missing) != 1 || missing[0] != 42 {
		t.Fatalf("missingRows() = %v, want [42]", missing)
	}
	// Record the last one and the guard clears.
	r.pass(42, "ok")
	if m := r.missingRows(); len(m) != 0 {
		t.Fatalf("missingRows() = %v after full coverage, want empty", m)
	}
}

// TestReporter_CombineWorse proves a second record for a row can only make the
// verdict stricter (FAIL > WARN > PASS > SKIP), never silently downgrade a PASS
// to a SKIP — the property that lets device-target corroboration re-record safely.
func TestReporter_CombineWorse(t *testing.T) {
	cases := []struct {
		first, second, want Status
	}{
		{StatusPass, StatusFail, StatusFail}, // a later failure wins
		{StatusPass, StatusSkip, StatusPass}, // a skip cannot downgrade a pass
		{StatusFail, StatusPass, StatusFail}, // a later pass cannot rescue a fail
		{StatusWarn, StatusFail, StatusFail}, // fail beats warn
		{StatusPass, StatusWarn, StatusWarn}, // warn beats pass
		{StatusSkip, StatusPass, StatusPass}, // pass beats skip
	}
	for _, tc := range cases {
		r := quietReporter()
		r.record(14, tc.first, "first")
		r.record(14, tc.second, "second")
		if got := r.results[14].Status; got != tc.want {
			t.Errorf("record(%s) then record(%s) = %s, want %s", tc.first, tc.second, got, tc.want)
		}
	}
}

// TestReporter_Summary confirms the pass/fail summary verdict: complete + no fail
// is a clean pass; a single fail or a missing row is not.
func TestReporter_Summary(t *testing.T) {
	full := quietReporter()
	for n := 1; n <= 62; n++ {
		full.pass(n, "ok")
	}
	if !full.summary() {
		t.Error("summary() = false for a complete, fail-free run")
	}

	withFail := quietReporter()
	for n := 1; n <= 62; n++ {
		if n == 10 {
			withFail.fail(n, "boom")
			continue
		}
		withFail.pass(n, "ok")
	}
	if withFail.summary() {
		t.Error("summary() = true despite a FAIL")
	}

	incomplete := quietReporter()
	for n := 1; n <= 61; n++ {
		incomplete.pass(n, "ok")
	}
	if incomplete.summary() {
		t.Error("summary() = true despite a missing requirement")
	}
}

// TestReporter_Markdown emits a section for a full run and checks it names every
// requirement, carries no "NOT ADDRESSED", and groups by the five spec blocks.
func TestReporter_Markdown(t *testing.T) {
	r := quietReporter()
	r.target = "127.0.0.1:802"
	for n := 1; n <= 62; n++ {
		switch n {
		case 3:
			r.skip(n, "server-side capability")
		case 5:
			r.warn(n, "MAY not exercised")
		default:
			r.pass(n, "evidence for %d", n)
		}
	}
	md := r.markdownSection()
	if strings.Contains(md, "NOT ADDRESSED") {
		t.Error("markdown contains NOT ADDRESSED for a complete run")
	}
	for n := 1; n <= 62; n++ {
		if !strings.Contains(md, reqID(n)) {
			t.Errorf("markdown missing %s", reqID(n))
		}
	}
	for _, blk := range []string{"§5.1", "§5.2", "§5.3", "§5.4", "§5.5"} {
		if !strings.Contains(md, blk) {
			t.Errorf("markdown missing block header %s", blk)
		}
	}
}

// TestMdEscape guards the table-cell escaping (a pipe in evidence must not break
// the markdown table).
func TestMdEscape(t *testing.T) {
	if got := mdEscape("a|b\nc"); got != "a\\|b c" {
		t.Errorf("mdEscape = %q, want %q", got, "a\\|b c")
	}
}
