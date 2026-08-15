package bundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/evidence/capture"
	"csip-tls-test/internal/evidence/metricscrape"
)

// scrapeWindow produces a real metricscrape.Record — through the package's own
// scraper, over a stubbed transport — rather than a hand-built struct. A
// fixture assembled by hand could satisfy the verifier while the authoring path
// produced something the verifier rejects, which is the one failure a test of
// this channel must not be able to miss.
func scrapeWindow(t *testing.T, label, openBody, closeBody string, sels ...metricscrape.Selector) metricscrape.Record {
	t.Helper()
	n := 0
	src := metricscrape.FuncSource{
		Description: "http://69.0.0.2:9102/metrics",
		Fn: func(context.Context) (metricscrape.Fetch, error) {
			n++
			if n == 1 {
				return metricscrape.Fetch{Body: []byte(openBody), HTTPStatus: 200}, nil
			}
			return metricscrape.Fetch{Body: []byte(closeBody), HTTPStatus: 200}, nil
		},
	}
	s, err := metricscrape.New(src, sels...)
	if err != nil {
		t.Fatalf("metricscrape.New: %v", err)
	}
	return s.Open(context.Background(), label).Close(context.Background())
}

// deadWindow is a window against an endpoint that never answered — the bench
// case where the DUT's metrics_addr is still the product's loopback default and
// nobody set up the forward.
func deadWindow(t *testing.T, label string, sels ...metricscrape.Selector) metricscrape.Record {
	t.Helper()
	src := metricscrape.FuncSource{
		Description: "http://69.0.0.2:9102/metrics",
		Fn: func(context.Context) (metricscrape.Fetch, error) {
			return metricscrape.Fetch{}, errors.New("dial tcp 69.0.0.2:9102: connect: connection refused")
		},
	}
	s, err := metricscrape.New(src, sels...)
	if err != nil {
		t.Fatalf("metricscrape.New: %v", err)
	}
	return s.Open(context.Background(), label).Close(context.Background())
}

const (
	ignoredOpen = "# TYPE lexa_nb_ignored_control_content_total counter\n" +
		"lexa_nb_ignored_control_content_total 12\n"
	ignoredClose = "# TYPE lexa_nb_ignored_control_content_total counter\n" +
		"lexa_nb_ignored_control_content_total 13\n"
)

// buildMetricsBundle is buildBundle's sibling for the scrape channel: the same
// synthetic capture, one case, and two scrape windows — one that read the
// endpoint and one that could not.
func buildMetricsBundle(t *testing.T) string {
	t.Helper()
	work := t.TempDir()
	capturePath := filepath.Join(work, "run.pcapng")
	pkts := writeSyntheticCapture(t, capturePath)

	syn, err := CiteFrames("The session was opened to port 802.", "TCP SYN to the mbaps port",
		Pass, "SYN from 69.0.0.20:51422 to 69.0.0.2:802", pkts, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}

	good := scrapeWindow(t, "CORE-022", ignoredOpen, ignoredClose,
		metricscrape.IgnoredContentTotal(), metricscrape.Sel("lexa_nb_no_such_counter_total"))

	// A window whose endpoint never answered. It carries no bodies, and the
	// bundle must still be able to write and verify it: the record of a failed
	// reading is evidence too, and dropping it would leave a criterion's SKIP
	// with nothing behind it.
	dead := deadWindow(t, "CORE-023", metricscrape.IgnoredContentTotal())

	b := NewBuilder(RunMeta{
		Tool: "evidence-engine-test", ToolVersion: "0.0.1",
		Started:  time.Unix(1_700_000_000, 0).UTC(),
		Finished: time.Unix(1_700_000_060, 0).UTC(),
		DUT:      DUT{Name: "lexa-gw", Address: "69.0.0.2:802"},
	})
	b.SetCapture(capture.Summary{
		Tool: "dumpcap", Interface: "enp1s0", Packets: len(pkts), Format: "pcapng",
	}, capturePath)
	b.AddCase(TestCaseResult{
		ID: "CORE-022", Title: "Volt-var executed without autonomous vRef", Applicable: true,
		Assertions: []Assertion{syn},
	})
	b.AddMetrics(good)
	b.AddMetrics(dead)

	dir := filepath.Join(work, "bundle")
	if _, err := b.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir
}

func TestMetricsScrapeSurvivesWriteAndVerify(t *testing.T) {
	dir := buildMetricsBundle(t)

	b, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(b.Metrics) != 2 {
		t.Fatalf("bundle carries %d metrics windows, want 2", len(b.Metrics))
	}
	rec := b.Metrics[0]
	if rec.Open.BodyFile == "" || rec.Close.BodyFile == "" {
		t.Fatalf("the writer did not record where the bodies went: %+v", rec)
	}
	for _, rel := range []string{rec.Open.BodyFile, rec.Close.BodyFile} {
		if !strings.HasPrefix(rel, MetricsDir+"/") || !strings.HasSuffix(rel, ".prom") {
			t.Errorf("body file %q is not under %s/ with a .prom name", rel, MetricsDir)
		}
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
	// The reading a criterion would act on survived the JSON round trip intact.
	d, ok := rec.Find(metricscrape.IgnoredContentTotal())
	if !ok {
		t.Fatal("the ignored-content reading did not survive bundle.json")
	}
	if d.Outcome != metricscrape.OutcomeIncreased || d.Delta != 1 || !d.Moved() {
		t.Fatalf("reading = %+v, want INCREASED by 1", d)
	}
	// And so did the ABSENT one, which is the distinction the channel exists for.
	abs, ok := rec.Find(metricscrape.Sel("lexa_nb_no_such_counter_total"))
	if !ok || abs.Outcome != metricscrape.OutcomeAbsent || abs.OpenPresent {
		t.Fatalf("absent reading = %+v (found=%v)", abs, ok)
	}
	// The window that never read anything is still in the bundle.
	if b.Metrics[1].Open.BodyFile != "" || b.Metrics[1].Readable() {
		t.Errorf("the unreadable window should carry no artefacts: %+v", b.Metrics[1])
	}
	if b.Metrics[1].Open.Status != metricscrape.StatusUnreachable ||
		!strings.Contains(b.Metrics[1].Open.Error, "connection refused") {
		t.Errorf("the transport failure must survive into bundle.json: %+v", b.Metrics[1].Open)
	}
	if d := b.Metrics[1].Series[0]; d.Outcome != metricscrape.OutcomeUnreadable {
		t.Errorf("an unreachable endpoint must read as %s, not %s — ABSENT would be a claim about "+
			"the DUT's instrumentation nobody made", metricscrape.OutcomeUnreadable, d.Outcome)
	}

	// Every .prom file is covered by the manifest — nothing in this channel is
	// outside the sha256sum -c check a reader runs first.
	listed, err := ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, e := range listed {
		covered[e.Name] = true
	}
	for _, rel := range []string{rec.Open.BodyFile, rec.Close.BodyFile} {
		if !covered[rel] {
			t.Errorf("%s is not listed in %s", rel, ManifestFile)
		}
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("bundle does not verify: %v", rep.Problems)
	}
	if rep.MetricsWindows != 2 {
		t.Errorf("verified %d windows, want 2", rep.MetricsWindows)
	}
	if rep.MetricsSeries != 3 {
		t.Errorf("re-derived %d readings, want 3 (two in the good window, one in the dead one)",
			rep.MetricsSeries)
	}
	if !strings.Contains(rep.String(), "Metrics:") {
		t.Errorf("the verify report does not mention the scrape channel:\n%s", rep.String())
	}
}

// The point of writing the bodies into the bundle: a recorded READING that does
// not follow from the recorded BODY must not verify. This is the scrape
// channel's equivalent of a byte citation whose digest does not match.
func TestVerifyRefusesAReadingItsOwnBodyDoesNotSupport(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Bundle)
		want string
	}{
		{
			name: "delta inflated",
			edit: func(b *Bundle) { b.Metrics[0].Series[0].Delta = 99 },
			want: "does not follow from the exposition bodies",
		},
		{
			name: "absent counter reported as a zero reading",
			edit: func(b *Bundle) {
				// The exact lie the channel exists to make impossible: an
				// absent series rewritten as present-and-zero.
				b.Metrics[0].Series[1].Outcome = metricscrape.OutcomeUnchanged
				b.Metrics[0].Series[1].OpenPresent = true
				b.Metrics[0].Series[1].ClosePresent = true
				b.Metrics[0].Series[1].Detail = ""
			},
			want: "does not follow from the exposition bodies",
		},
		{
			name: "body digest rewritten",
			edit: func(b *Bundle) {
				b.Metrics[0].Open.BodySHA256 = strings.Repeat("0", 64)
			},
			want: "hashes to",
		},
		{
			name: "unreadable reading claims it parsed",
			edit: func(b *Bundle) {
				b.Metrics[0].Open.BodyBytes = len(ignoredOpen) + 1
			},
			want: "bytes, the open reading claims",
		},
		{
			name: "artefact dropped from the record",
			edit: func(b *Bundle) { b.Metrics[0].Close.BodyFile = "" },
			want: "no file to check them against",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := buildMetricsBundle(t)
			editBundle(t, dir, tc.edit)
			rep, err := Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rep.OK {
				t.Fatal("verification passed a record its own artefacts contradict")
			}
			if !strings.Contains(strings.Join(rep.Problems, "\n"), tc.want) {
				t.Errorf("problems do not say %q:\n%s", tc.want, strings.Join(rep.Problems, "\n"))
			}
		})
	}
}

// Editing the exposition body itself is caught twice over: by the manifest,
// which is what a reader checks with sha256sum(1), and — once the manifest is
// refreshed to hide that — by the reading no longer following from the body.
func TestVerifyDetectsATamperedExpositionBody(t *testing.T) {
	dir := buildMetricsBundle(t)
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, filepath.FromSlash(b.Metrics[0].Close.BodyFile))
	if err := os.WriteFile(target, []byte(strings.Replace(ignoredClose, " 13", " 99", 1)), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("an edited exposition body must fail verification")
	}
	if !strings.Contains(strings.Join(rep.Problems, "\n"), "does not match the manifest") {
		t.Errorf("the manifest should have caught it first: %v", rep.Problems)
	}

	// Refresh the manifest, as somebody covering their tracks would, and the
	// reading itself still does not follow from the body.
	if err := WriteManifest(dir); err != nil {
		t.Fatal(err)
	}
	rep, err = Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a refreshed manifest must not rescue a body that no longer supports the reading")
	}
	joined := strings.Join(rep.Problems, "\n")
	if !strings.Contains(joined, "hashes to") && !strings.Contains(joined, "does not follow") {
		t.Errorf("problems = %s", joined)
	}
}

func TestReportShowsTheScrapeChannel(t *testing.T) {
	dir := buildMetricsBundle(t)
	data, err := os.ReadFile(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	for _, want := range []string{
		"## DUT metrics scrapes",
		"http://69.0.0.2:9102/metrics",
		"CORE-022",
		"INCREASED",
		"ABSENT",
		"DEVICE'S TESTIMONY ABOUT ITSELF",
		"UNREACHABLE",
		"metrics/001-core-022-open.prom",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("REPORT.md does not carry %q\n---\n%s", want, report)
		}
	}
	if strings.Contains(report, "%!") {
		t.Error("REPORT.md contains a formatting error")
	}
}

// A bundle that took no scrapes must be byte-for-byte the document it was
// before this channel existed: no metrics key, no metrics/ directory, and a
// verify report that says nothing about it.
func TestBundleWithoutScrapesIsUnchanged(t *testing.T) {
	dir, _, _ := buildBundle(t)
	data, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\"metrics\"") {
		t.Error("bundle.json gained a metrics key for a run that took no scrapes")
	}
	if _, err := os.Stat(filepath.Join(dir, MetricsDir)); err == nil {
		t.Errorf("%s/ was created for a run that took no scrapes", MetricsDir)
	}
	rep, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.MetricsWindows != 0 || rep.MetricsSeries != 0 {
		t.Errorf("verify report = %+v", rep)
	}
	if strings.Contains(rep.String(), "Metrics:") {
		t.Error("the verify report mentions a channel this bundle does not use")
	}
	if strings.Contains(mustReport(t, dir), "DUT metrics scrapes") {
		t.Error("REPORT.md invents a metrics section for a bundle that has none")
	}
}

// The constructor's refusal is the channel's last line of defence: whatever a
// criterion's author intends, a PASS cannot be built on a reading that
// establishes nothing — an absent counter above all.
func TestMetricAssertionRefusesAPassOnAnUnsoundReading(t *testing.T) {
	moved := scrapeWindow(t, "CORE-022", ignoredOpen, ignoredClose, metricscrape.IgnoredContentTotal())
	absent := scrapeWindow(t, "CORE-022", "# TYPE lexa_up gauge\nlexa_up 1\n",
		"# TYPE lexa_up gauge\nlexa_up 1\n", metricscrape.IgnoredContentTotal())

	good, _ := moved.Find(metricscrape.IgnoredContentTotal())
	a, err := MetricAssertion("The gateway disclosed the ignored element.", "DUT metrics scrape",
		Pass, moved, good, metricscrape.IgnoredContentKindCaveat)
	if err != nil {
		t.Fatalf("a sound INCREASED reading must support a PASS: %v", err)
	}
	if a.Citable() {
		t.Error("a metrics assertion must not claim to be a re-checkable citation")
	}
	if !strings.Contains(a.Note, "69.0.0.2:9102") || !strings.Contains(a.Note, "IW15-030") {
		t.Errorf("the provenance and the caveat must travel with the claim: %q", a.Note)
	}
	if !strings.Contains(a.Observed, "INCREASED") {
		t.Errorf("observed = %q", a.Observed)
	}

	bad, _ := absent.Find(metricscrape.IgnoredContentTotal())
	if bad.Outcome != metricscrape.OutcomeAbsent {
		t.Fatalf("fixture: outcome = %s", bad.Outcome)
	}
	if _, err := MetricAssertion("The gateway disclosed the ignored element.", "DUT metrics scrape",
		Pass, absent, bad, ""); err == nil {
		t.Fatal("MetricAssertion built a PASS on an ABSENT counter — the exact reading that would let " +
			"a disclosure oracle pass on a silent DUT")
	}
	// The same reading is perfectly recordable as a WARN.
	if _, err := MetricAssertion("The gateway disclosed the ignored element.", "DUT metrics scrape",
		Warn, absent, bad, ""); err != nil {
		t.Errorf("an unsound reading must still be recordable as a WARN: %v", err)
	}
}

func mustReport(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
