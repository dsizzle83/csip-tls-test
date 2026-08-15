package bundle

// metrics.go carries the BENCH SCRAPE CHANNEL into the bundle: the DUT's own
// Prometheus counters, read at both ends of a stated measurement window, for
// the class of claim that has no wire artefact behind it at all (IW15-030 — see
// the package doc of internal/evidence/metricscrape for why that class exists
// and what it is worth).
//
// It follows the same rule as every other channel here: the SUMMARY goes in
// bundle.json, the BYTES go in the directory, the manifest covers the bytes,
// and Verify re-derives the summary from the bytes rather than believing it.
// For a capture that means re-reading the pcap and re-hashing the cited range;
// for a scrape it means re-parsing the exposition text the reading was taken
// from and recomputing every value and outcome in the record. A metrics record
// whose numbers do not follow from the .prom files shipped beside it does not
// verify, exactly as a byte citation that does not hash does not verify.
//
// WHAT THIS CHANNEL CANNOT DO, stated here because a reader deserves it beside
// the code rather than in a commit message: re-checking establishes that we
// recorded faithfully what the endpoint said. It does not establish that what
// the endpoint said was true. A counter is the device's testimony about itself
// and belongs in a bundle as such — which is why the authoring API renders it
// through Record.Source into a NARRATIVE assertion (certify.Evidence.Narrative)
// with the endpoint and both instants named, and never through CiteBytes.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"csip-tls-test/internal/evidence/metricscrape"
)

// MetricsDir is the bundle subdirectory holding the raw exposition bodies.
const MetricsDir = "metrics"

// AddMetrics records one measurement window's scrape.
//
// The record's bodies are written into the bundle by Write, which is also what
// fills in each reading's BodyFile — the layout of the directory is the
// bundle's business, not the scraper's.
func (b *Builder) AddMetrics(rec metricscrape.Record) { b.metrics = append(b.metrics, rec) }

// Metrics returns the scrape records added so far.
func (b *Builder) Metrics() []metricscrape.Record { return b.metrics }

// writeMetrics materialises the recorded exposition bodies under MetricsDir and
// returns the records with their BodyFile fields filled in.
//
// A reading with no body (an unreachable endpoint never produced one) writes no
// file and keeps an empty BodyFile: absence of an artefact is itself the
// honest record, and an empty file would claim the endpoint answered with
// nothing when in fact it did not answer.
func writeMetrics(dir string, recs []metricscrape.Record) ([]metricscrape.Record, error) {
	if len(recs) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Join(dir, MetricsDir), 0o755); err != nil {
		return nil, fmt.Errorf("bundle: create %s: %w", MetricsDir, err)
	}
	out := make([]metricscrape.Record, 0, len(recs))
	for i, rec := range recs {
		stem := fmt.Sprintf("%03d-%s", i+1, slug(rec.Label))
		for _, phase := range []struct {
			name string
			res  *metricscrape.ScrapeResult
		}{{"open", &rec.Open}, {"close", &rec.Close}} {
			if len(phase.res.Body) == 0 {
				continue
			}
			rel := path.Join(MetricsDir, stem+"-"+phase.name+".prom")
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), phase.res.Body, 0o644); err != nil {
				return nil, fmt.Errorf("bundle: write %s: %w", rel, err)
			}
			phase.res.BodyFile = rel
		}
		out = append(out, rec)
	}
	return out, nil
}

// slug makes a label safe as a file name without making two different labels
// the same file. Anything outside [a-z0-9-_] becomes '-', which can collide, so
// the caller's ordinal prefix (above) is what actually guarantees uniqueness.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "window"
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			sb.WriteByte(c)
		default:
			sb.WriteByte('-')
		}
	}
	return sb.String()
}

// verifyMetrics re-checks every metrics record against the artefacts it points
// at, and records what it found in rep.
//
// Four things are checked, in the order a sceptical reader would check them:
//
//  1. the .prom file the record names exists and hashes to the digest the
//     record recorded (the manifest already proves the file is unmodified since
//     the bundle was written — this proves the RECORD and the FILE were always
//     talking about the same bytes);
//  2. the recorded byte count matches the file;
//  3. a reading claiming OK parses, and one claiming MALFORMED does not
//     (metricscrape.ScrapeResult.CheckBody);
//  4. every value, presence flag, delta and outcome in the record is what
//     re-running the comparison against those bodies produces
//     (metricscrape.Rederive).
//
// A bundle with no metrics records is untouched by this, which is what keeps
// every bundle written before this channel existed verifying exactly as before.
func verifyMetrics(dir string, b *Bundle, rep *VerifyReport) {
	for _, rec := range b.Metrics {
		rep.MetricsWindows++
		loaded := rec
		ok := true
		for _, phase := range []struct {
			name string
			res  *metricscrape.ScrapeResult
		}{{"open", &loaded.Open}, {"close", &loaded.Close}} {
			res := phase.res
			if res.BodyFile == "" {
				if res.BodyBytes > 0 {
					rep.problem(fmt.Sprintf("metrics window %q: the %s reading records %d body bytes but "+
						"no file to check them against", rec.Label, phase.name, res.BodyBytes))
					rep.OK, ok = false, false
				}
				continue
			}
			p := filepath.Join(dir, filepath.FromSlash(res.BodyFile))
			data, err := os.ReadFile(p)
			if err != nil {
				rep.problem(fmt.Sprintf("metrics window %q: the %s reading cites %s, which does not read: %v",
					rec.Label, phase.name, res.BodyFile, err))
				rep.OK, ok = false, false
				continue
			}
			sum, err := sha256File(p)
			if err != nil {
				rep.problem(fmt.Sprintf("metrics window %q: cannot hash %s: %v", rec.Label, res.BodyFile, err))
				rep.OK, ok = false, false
				continue
			}
			if res.BodySHA256 != "" && sum != res.BodySHA256 {
				rep.problem(fmt.Sprintf("metrics window %q: %s hashes to %s, the %s reading claims %s",
					rec.Label, res.BodyFile, sum, phase.name, res.BodySHA256))
				rep.OK, ok = false, false
				continue
			}
			if res.BodyBytes != len(data) {
				rep.problem(fmt.Sprintf("metrics window %q: %s is %d bytes, the %s reading claims %d",
					rec.Label, res.BodyFile, len(data), phase.name, res.BodyBytes))
				rep.OK, ok = false, false
				continue
			}
			res.Body = data
			if err := res.CheckBody(); err != nil {
				rep.problem(fmt.Sprintf("metrics window %q: %s reading: %v", rec.Label, phase.name, err))
				rep.OK, ok = false, false
			}
		}
		if !ok {
			continue
		}

		want, err := metricscrape.Rederive(loaded)
		if err != nil {
			rep.problem(fmt.Sprintf("metrics window %q: %v", rec.Label, err))
			rep.OK = false
			continue
		}
		if len(want) != len(rec.Series) {
			rep.problem(fmt.Sprintf("metrics window %q: records %d series for %d selectors",
				rec.Label, len(rec.Series), len(want)))
			rep.OK = false
			continue
		}
		for i, w := range want {
			got := rec.Series[i]
			if got == w {
				rep.MetricsSeries++
				continue
			}
			// Print both renderings rather than a field name: the point of the
			// message is that a reader can see WHICH claim moved away from the
			// evidence, and the rendering is the sentence the report printed.
			rep.problem(fmt.Sprintf("metrics window %q: recorded reading %q does not follow from the "+
				"exposition bodies in this bundle, which give %q", rec.Label, got.Observed(), w.Observed()))
			rep.OK = false
		}
	}
}

// MetricAssertion builds the assertion for one counter reading, and REFUSES to
// build a PASS on a reading that establishes nothing.
//
// It is the metrics channel's CiteBytes: the constructor a check is meant to go
// through, shaped so the thing that must travel with the claim cannot be left
// off. What travels is the provenance — the endpoint and the window, from
// Record.Source — plus whatever caveat the reading needs (for the
// ignored-content family that is metricscrape.IgnoredContentKindCaveat, until
// the `kind` label lands).
//
// The assertion carries no digest and Verify counts it as narrative, which is
// the honest classification: the re-derivable part of this channel is the
// RECORD, checked against the exposition bodies in metrics/, not a byte range
// in a pcap. A reader who wants to re-check the number goes to the window this
// assertion names.
//
// THE REFUSAL is the point of the constructor. A PASS may rest only on a SOUND
// reading — the series present at both ends and not gone backwards. ABSENT,
// UNREADABLE, AMBIGUOUS, APPEARED, VANISHED, BACKWARDS and NON-FINITE all mean
// the run did not establish what the claim says, and a criterion that treats
// any of them as satisfied is the exact failure IW15-030's remediation was
// written to prevent: a disclosure oracle passing on a device that disclosed
// nothing, because nobody could tell an absent counter from a zero one. Those
// readings are still recordable — as WARN, SKIP or FAIL, whichever the
// criterion's owner decides — but not as a PASS.
func MetricAssertion(claim, method string, v Verdict, rec metricscrape.Record,
	d metricscrape.Delta, caveat string) (Assertion, error) {

	if v == Pass && !d.Sound() {
		return Assertion{}, fmt.Errorf("bundle: refusing a PASS on metric reading %s: %s establishes "+
			"nothing about the claim %q — record it as WARN, SKIP or FAIL with this reading as the reason",
			d.Selector, d.Outcome, claim)
	}
	note := rec.Source()
	if caveat != "" {
		note += " — " + caveat
	}
	return Assertion{
		Claim:    claim,
		Method:   method,
		Verdict:  v,
		Observed: d.Observed(),
		Note:     note,
	}, nil
}

// MetricsReport renders the scrape channel for REPORT.md.
//
// It prints the FAILED and ABSENT readings as prominently as the useful ones.
// A disclosure claim resting on a counter that turned out not to exist must be
// as visible to a reviewer as one resting on a counter that moved — that is the
// whole reason the channel distinguishes them.
func (b *Bundle) metricsReport(sb *strings.Builder) {
	if len(b.Metrics) == 0 {
		return
	}
	fmt.Fprintf(sb, "## DUT metrics scrapes\n\n")
	fmt.Fprintf(sb, "Counters read off the device's own Prometheus endpoint across a stated window. "+
		"These are the DEVICE'S TESTIMONY ABOUT ITSELF, not wire evidence: the raw exposition bodies "+
		"are in `%s/` and the verifier re-derives every reading below from them, which establishes "+
		"that the numbers were recorded faithfully — not that the device was right.\n\n", MetricsDir)
	for _, rec := range b.Metrics {
		fmt.Fprintf(sb, "### %s\n\n", mdEscape(rec.Label))
		fmt.Fprintf(sb, "%s\n\n", mdEscape(rec.Source()))
		fmt.Fprintf(sb, "| Reading | Status | Body | Artefact |\n|---|---|---|---|\n")
		for _, phase := range []struct {
			name string
			res  metricscrape.ScrapeResult
		}{{"open", rec.Open}, {"close", rec.Close}} {
			detail := string(phase.res.Status)
			if phase.res.Error != "" {
				detail += " — " + phase.res.Error
			}
			artefact := "—"
			if phase.res.BodyFile != "" {
				artefact = "`" + phase.res.BodyFile + "`"
			}
			fmt.Fprintf(sb, "| %s | %s | %d bytes | %s |\n",
				phase.name, mdEscape(detail), phase.res.BodyBytes, artefact)
		}
		fmt.Fprintf(sb, "\n")
		for _, d := range rec.Series {
			fmt.Fprintf(sb, "- %s\n", mdEscape(d.Observed()))
		}
		fmt.Fprintf(sb, "\n")
	}
}
