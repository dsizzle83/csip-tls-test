package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// chdirTemp chdirs into a fresh t.TempDir() for the duration of the test (the
// same pattern replay_test.go uses) so writeReport/logs/qa never litter the
// repo, and restores the original CWD on cleanup.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	return dir
}

// reportsMux registers exactly the two routes main.go wires up for the
// report endpoints, so traversal tests exercise the real net/http routing
// (percent-decoding, {name} wildcard extraction) and not just the handler
// function in isolation.
func reportsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/qa/reports", handleQAReports)
	mux.HandleFunc("/api/qa/reports/{name}", handleQAReportFetch)
	return mux
}

// ── writeReport target directory (change 1) ─────────────────────────────────

func TestWriteReport_WritesUnderLogsQA(t *testing.T) {
	chdirTemp(t)
	d := newMayhemDriver(map[string]string{})
	d.status.StartedAt = time.Now()
	d.status.Findings = []mayFinding{{ID: "s1", Name: "s1", Verdict: "PASS", Headline: "ok"}}

	path := d.writeReport()
	if path == "" {
		t.Fatal("writeReport returned empty path")
	}
	wantDir := filepath.Join("logs", "qa")
	if got := filepath.Dir(path); got != wantDir {
		t.Errorf("report dir = %q, want %q", got, wantDir)
	}
	if !qaReportNameRe.MatchString(filepath.Base(path)) {
		t.Errorf("report basename %q does not match the qa-mayhem-<ts>.md scheme", filepath.Base(path))
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("report file not found at returned path: %v", err)
	}
	// The report dir itself must have been created (0o755), not assumed to
	// pre-exist.
	if info, err := os.Stat(wantDir); err != nil || !info.IsDir() {
		t.Errorf("logs/qa was not created by writeReport: %v", err)
	}
}

func TestWriteReport_NoFindingsWritesNothing(t *testing.T) {
	chdirTemp(t)
	d := newMayhemDriver(map[string]string{})
	if path := d.writeReport(); path != "" {
		t.Errorf("writeReport with no findings = %q, want empty (unchanged existing behavior)", path)
	}
	if _, err := os.Stat(filepath.Join("logs", "qa")); !os.IsNotExist(err) {
		t.Errorf("logs/qa should not be created when there is nothing to write, stat err = %v", err)
	}
}

// ── GET /api/qa/reports (list) ───────────────────────────────────────────────

func TestHandleQAReports_ListNewestFirst(t *testing.T) {
	chdirTemp(t)
	if err := os.MkdirAll(mayReportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(mayReportDir, "qa-mayhem-20260101-000000.md")
	newer := filepath.Join(mayReportDir, "qa-mayhem-20260102-000000.md")
	if err := os.WriteFile(older, []byte("# older\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("# newer, a bit longer\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(older, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newer, now, now); err != nil {
		t.Fatal(err)
	}
	// A non-matching file in the same dir must never be listed.
	if err := os.WriteFile(filepath.Join(mayReportDir, "not-a-report.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	handleQAReports(rec, httptest.NewRequest(http.MethodGet, "/api/qa/reports", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []qaReportEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (not-a-report.txt must be excluded): %+v", len(got), got)
	}
	if got[0].Name != "qa-mayhem-20260102-000000.md" || got[1].Name != "qa-mayhem-20260101-000000.md" {
		t.Errorf("order = [%s, %s], want newest-first", got[0].Name, got[1].Name)
	}
	if got[0].Bytes != int64(len("# newer, a bit longer\n")) {
		t.Errorf("bytes = %d, want %d", got[0].Bytes, len("# newer, a bit longer\n"))
	}
	if _, err := time.Parse(time.RFC3339, got[0].MTime); err != nil {
		t.Errorf("mtime %q not RFC3339: %v", got[0].MTime, err)
	}
}

func TestHandleQAReports_MissingDirIsEmptyList(t *testing.T) {
	chdirTemp(t) // logs/qa never created in this test
	rec := httptest.NewRecorder()
	handleQAReports(rec, httptest.NewRequest(http.MethodGet, "/api/qa/reports", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "[]\n" {
		t.Errorf("body = %q, want an empty JSON array (not null)", got)
	}
}

// ── GET /api/qa/reports/{name} (fetch) ───────────────────────────────────────

func TestHandleQAReportFetch_ServesContent(t *testing.T) {
	chdirTemp(t)
	if err := os.MkdirAll(mayReportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "# Mayhem QA report\n\nhello\n"
	if err := os.WriteFile(filepath.Join(mayReportDir, "qa-mayhem-20260113-010203.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(reportsMux())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/qa/reports/qa-mayhem-20260113-010203.md")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/markdown; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	buf := make([]byte, len(body)+16)
	n, _ := resp.Body.Read(buf)
	if string(buf[:n]) != body {
		t.Errorf("body = %q, want %q", string(buf[:n]), body)
	}
}

func TestHandleQAReportFetch_UnknownNameIs404(t *testing.T) {
	chdirTemp(t)
	if err := os.MkdirAll(mayReportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(reportsMux())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/qa/reports/qa-mayhem-99999999-999999.md")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a well-formed but nonexistent name", resp.StatusCode)
	}
}

// TestHandleQAReportFetch_RejectsTraversal is the core threat this route
// exists to defend against: {name} is a single-path-segment wildcard, but
// percent-encoded separators (%2e%2e%2f, ..%2f) decode to literal "../" in
// r.PathValue("name") WITHOUT net/http's own dot-segment redirect ever
// seeing them (that redirect only fires on literal ".." bytes in the raw
// request line — verified empirically: it 404s the plain "../.." case via
// its own path-clean redirect, but passes the percent-encoded case straight
// through to our handler with the decoded ".." intact). qaReportNameRe is
// the only thing standing between that decoded value and os.ReadFile, so
// every variant here must reach the handler and be rejected with 400, and —
// the property that actually matters — never return the secret file's
// content.
func TestHandleQAReportFetch_RejectsTraversal(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.MkdirAll(mayReportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const secretMarker = "TOP-SECRET-OUTSIDE-LOGS-QA"
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte(secretMarker), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also plant a decoy one level above logs/qa, reachable by "../secret.txt"
	// relative to mayReportDir, in case the traversal resolves relative to
	// the report dir rather than the process CWD.
	if err := os.WriteFile(filepath.Join(mayReportDir, "..", "secret.txt"), []byte(secretMarker), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(reportsMux())
	defer srv.Close()

	cases := []struct {
		name string
		path string
	}{
		{"dot-dot-slash literal (path-cleaned away by net/http before routing)", "/api/qa/reports/../../secret.txt"},
		{"dot-dot encoded as %2e%2e with literal slash", "/api/qa/reports/%2e%2e/secret.txt"},
		{"dot-dot-slash percent-encoded slash", "/api/qa/reports/..%2f..%2fsecret.txt"},
		{"fully percent-encoded dot-dot-slash", "/api/qa/reports/%2e%2e%2f%2e%2e%2fsecret.txt"},
		{"absolute-looking name", "/api/qa/reports/%2fetc%2fpasswd"},
		{"wrong extension", "/api/qa/reports/qa-mayhem-20260101-000000.txt"},
		{"wrong prefix", "/api/qa/reports/../qa-mayhem-20260101-000000.md"},
		{"letters where digits are required", "/api/qa/reports/qa-mayhem-abcxyz.md"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return nil // follow net/http's own dot-segment redirects so we see the final response
				},
			}
			resp, err := client.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			got := string(buf[:n])
			if resp.StatusCode == http.StatusOK && containsSecret(got, secretMarker) {
				t.Fatalf("%s: leaked secret content, status=%d body=%q", tc.path, resp.StatusCode, got)
			}
			// The handler-level contract: a request that DOES reach
			// handleQAReportFetch with a non-matching name must 400. Some of
			// the cases above never reach the handler at all (net/http's own
			// clean-path redirect resolves them to a path outside our
			// pattern first, e.g. the literal "../../" case → 404) — that is
			// an equally acceptable outcome (still never leaks the file);
			// only assert 400 when the response isn't a 404 from routing.
			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s: status = %d, want 400 (rejected by name) or 404 (routed away entirely); body=%q", tc.path, resp.StatusCode, got)
			}
		})
	}
}

func containsSecret(body, marker string) bool {
	for i := 0; i+len(marker) <= len(body); i++ {
		if body[i:i+len(marker)] == marker {
			return true
		}
	}
	return false
}

// TestQAReportNameRe is a direct table test of the regex itself — the single
// point of truth path traversal has to get past, independent of how a given
// URL happens to route.
func TestQAReportNameRe(t *testing.T) {
	valid := []string{
		"qa-mayhem-20260113-010203.md",
		"qa-mayhem-1.md",
		"qa-mayhem-0.md",
	}
	for _, name := range valid {
		if !qaReportNameRe.MatchString(name) {
			t.Errorf("MatchString(%q) = false, want true", name)
		}
	}
	invalid := []string{
		"../../etc/passwd",
		"..%2f..%2fetc%2fpasswd", // if ever compared undecoded
		"qa-mayhem-../../x.md",
		"qa-mayhem-1.md.txt",
		"qa-mayhem-1.MD",
		"/etc/passwd",
		"qa-mayhem-abc.md",
		"qa-mayhem-1;rm -rf.md",
		"",
		"qa-mayhem-1.md/../../secret",
		".qa-mayhem-1.md",
	}
	for _, name := range invalid {
		if qaReportNameRe.MatchString(name) {
			t.Errorf("MatchString(%q) = true, want false", name)
		}
	}
}

// ── structured violations (change 3) ────────────────────────────────────────

// TestApplySafetyAudit_ViolationsMatchProse drives a synthetic timeline with
// a sustained INV-CONNECT back-feed through applySafetyAudit and asserts
// f.Violations is exactly the safetyAudit() slice, and that the prose bullet
// it appends to f.Diagnosis is byte-identical to invSummaryLine fed that same
// slice — i.e. the prose is provably derived from f.Violations, not a
// parallel computation that could drift from it.
func TestApplySafetyAudit_ViolationsMatchProse(t *testing.T) {
	cons := &activeConstraint{Typ: "none"}
	s := mkSamples(40, func(i int, smp *maySample) {
		smp.DisconnectActive = true
		smp.SolarW = 4000 // sustained back-feed through the whole disconnect window
	})

	want := safetyAudit(cons, s)
	if len(want) == 0 {
		t.Fatal("precondition: this timeline must produce at least one safety-audit violation")
	}

	base := mayFinding{Verdict: "PASS"}
	f := applySafetyAudit(base, cons, s)

	if len(f.Violations) != len(want) {
		t.Fatalf("len(f.Violations) = %d, want %d", len(f.Violations), len(want))
	}
	for i := range want {
		if f.Violations[i] != want[i] {
			t.Errorf("f.Violations[%d] = %+v, want %+v", i, f.Violations[i], want[i])
		}
	}

	wantProse := "⚠ " + invSummaryLine("SAFETY AUDIT", f.Violations)
	found := false
	for _, line := range f.Diagnosis {
		if line == wantProse {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("diagnosis missing the prose bullet derived from f.Violations; want %q, got %v", wantProse, f.Diagnosis)
	}

	// Sanity: the violations carry the INV-CONNECT name and are JSON-visible
	// (inv/t_s/detail — CONTRACTS.md §4), not just an internal detail.
	raw, err := json.Marshal(f.Violations[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"inv", "t_s", "detail"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("marshaled invViolation missing json key %q: %s", key, raw)
		}
	}
}

// TestApplySafetyAudit_NoViolationsLeavesEmptyViolations mirrors the existing
// "SAFETY AUDIT held: no violations" prose path (unchanged) and asserts the
// structured field agrees: empty/omitted, not a slice of zero-value entries.
func TestApplySafetyAudit_NoViolationsLeavesEmptyViolations(t *testing.T) {
	cons := &activeConstraint{Typ: "none"}
	s := mkSamples(40, func(i int, smp *maySample) {
		smp.DisconnectActive = false
		smp.BatterySimOK = true
		smp.BatSimSOC = 55
		smp.BatterySimW = 0
	})
	base := mayFinding{Verdict: "PASS"}
	f := applySafetyAudit(base, cons, s)
	if len(f.Violations) != 0 {
		t.Errorf("f.Violations = %+v, want empty", f.Violations)
	}
	wantProse := invSummaryLine("SAFETY AUDIT", nil)
	found := false
	for _, line := range f.Diagnosis {
		if line == wantProse {
			found = true
		}
	}
	if !found {
		t.Errorf("diagnosis missing the clean-audit prose line %q; got %v", wantProse, f.Diagnosis)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["violations"]; ok {
		t.Errorf("mayFinding JSON should omit \"violations\" when empty (omitempty), got %s", raw)
	}
}
