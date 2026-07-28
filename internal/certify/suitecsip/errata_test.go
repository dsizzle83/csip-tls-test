package suitecsip

// errata_test.go pins the published corrections that change an OBSERVABLE.
//
// Why a test and not a comment. The catalog's `steps` and `expected` for a row
// are a verbatim extraction of the PRINTED procedure, corrections and all still
// uncorrected — which is right, because an extraction that silently applied
// Annex A would no longer be checkable against the document a reviewer holds.
// The corrections live beside them in `errata`. That split only works if
// something enforces it: a re-extraction that dropped the errata array would
// leave a catalog whose steps say "status 7", whose corrections say 14, and
// whose only remaining record of the difference is a comment nobody reads.
//
// So each case below pins one erratum from CSIP Conformance Test Procedures
// V1.3, Annex A — Errata I (pp. 226-234) whose effect is visible on the wire,
// and asserts that both halves are still in the catalog: the correction, and
// the amended text where the extraction has already applied it.
//
// Four of the five rows are NOT APPLICABLE to this DUT today — the §4 profile
// matrix scopes them to a DER Aggregator Client, and this DUT is a direct DER
// client. That is exactly why they are pinned NOW. A re-scope makes them live,
// and the first thing an implementer will read is the unamended step list.

import (
	"strings"
	"testing"

	"csip-tls-test/internal/certify"
)

// erratumFor returns the case's erratum with the given seq.
func erratumFor(t *testing.T, cat *certify.Catalog, id string, seq int) (*certify.Case, certify.Erratum) {
	t.Helper()
	c, ok := cat.ByID(doc, id)
	if !ok {
		t.Fatalf("the catalog has no %s %s", doc, id)
	}
	for _, e := range c.Errata {
		if e.Seq == seq {
			return c, e
		}
	}
	t.Fatalf("%s carries no erratum seq %d; it has %d erratum/errata", id, seq, len(c.Errata))
	return nil, certify.Erratum{}
}

// TestAggSupersessionStatusIsFourteen pins Annex A seq 5 (AGG-007) and seq 6
// (AGG-008): "instead of expecting a status 7 when superseded, it should expect
// status 14".
//
// The distinction is substantive, not editorial. Status 7 is Event Superseded;
// status 14 is Event Superseded from another program, and AGG-007/AGG-008
// supersede a control that belongs to a DIFFERENT DERProgram, known before
// either event starts. A harness asserting 7 here would FAIL a conformant
// aggregator. AGG-009 is the control case and keeps 7, because its SY event had
// already started when the TFA event was discovered.
func TestAggSupersessionStatusIsFourteen(t *testing.T) {
	cat := loadCatalog(t)
	for _, tc := range []struct {
		id  string
		seq int
	}{{"AGG-007", 5}, {"AGG-008", 6}} {
		c, e := erratumFor(t, cat, tc.id, tc.seq)
		if !e.ClientRelevant {
			t.Errorf("%s seq %d is not marked client_relevant, so RunCtx.Errata() hides it from the "+
				"implementation it is meant to correct", tc.id, tc.seq)
		}
		if !strings.Contains(strings.Join(e.CorrectiveAction, " "), "status 14") {
			t.Errorf("%s seq %d no longer prescribes status 14: %v", tc.id, tc.seq, e.CorrectiveAction)
		}
		// The extraction applies this one, so the amended text must be present
		// and the superseded status 7 must be gone from the supersession step.
		if !mentions(c.Steps, "status 14") || !mentions(c.Expected, "status 14") {
			t.Errorf("%s steps/expected do not carry the amended status 14", tc.id)
		}
		if s, ok := findContaining(c.Steps, "Superseded"); ok && strings.Contains(s, "status 7") {
			t.Errorf("%s still carries the UNAMENDED status 7 supersession step: %q", tc.id, s)
		}
	}

	// The contrast row: AGG-009 legitimately keeps status 7 and has no such
	// erratum. If a future edit "helpfully" rewrote it to 14 this fails.
	c, ok := cat.ByID(doc, "AGG-009")
	if !ok {
		t.Fatal("the catalog has no AGG-009")
	}
	if !mentions(c.Observables, "status = 7") && !mentions(c.Steps, "status 7") {
		t.Error("AGG-009 no longer expects status 7; the errata correct AGG-007/008 only, because " +
			"AGG-009's superseded event had already STARTED")
	}
}

// TestErr002Step6IsRemoved pins Annex A seq 38: "Remove Step 6".
//
// Printed step 6 has the client re-subscribe to a subscription the server has
// just cancelled with status 1. IEEE 2030.5 does not require that, and a check
// that waited for the re-POST would hang and then fail a conformant client.
func TestErr002Step6IsRemoved(t *testing.T) {
	cat := loadCatalog(t)
	c, e := erratumFor(t, cat, "ERR-002", 38)
	if !strings.Contains(strings.Join(e.CorrectiveAction, " "), "Remove Step 6") {
		t.Errorf("ERR-002 seq 38 no longer removes step 6: %v", e.CorrectiveAction)
	}
	if !e.ClientRelevant {
		t.Error("ERR-002 seq 38 must be client_relevant: it removes a demand on the CLIENT")
	}
	// The extraction keeps the printed step list intact, which is correct — the
	// point of the pin is that the correction travels WITH it.
	if _, ok := findContaining(c.Steps, "removing it from own list of outstanding Subscriptions"); !ok {
		t.Error("ERR-002's printed step 6 has vanished from the extraction; if the extraction now " +
			"applies errata to steps, this test's premise is stale and both must be revisited")
	}
}

// TestCore018And019Drop204 pins Annex A seq 44: "The 204 response is not
// included in the WADL — Remove the acceptance of 204 response in Procedure and
// Pass/Fail Criteria".
//
// This one TIGHTENS: a DUT answering a Notification with 204 is no longer
// conformant for these two rows. It is also narrowly scoped, and the scope is
// the trap: erratum seq 23 ADDS a 204 expectation to CORE-014's PUTs of
// DERCapability and DERSettings, which critDERPut already asserts. A blanket
// "204 is/is not acceptable" rule would break one row or the other.
func TestCore018And019Drop204(t *testing.T) {
	cat := loadCatalog(t)
	for _, id := range []string{"CORE-018", "CORE-019"} {
		_, e := erratumFor(t, cat, id, 44)
		joined := strings.Join(e.CorrectiveAction, " ")
		if !strings.Contains(joined, "Remove the acceptance of 204") {
			t.Errorf("%s seq 44 no longer removes the 204 acceptance: %v", id, e.CorrectiveAction)
		}
		if !e.ClientRelevant {
			t.Errorf("%s seq 44 must be client_relevant", id)
		}
	}

	// CORE-019 additionally drops the parent notification (seq 42).
	_, e := erratumFor(t, cat, "CORE-019", 42)
	if !strings.Contains(strings.Join(e.CorrectiveAction, " "), "Remove steps 10 and 11") {
		t.Errorf("CORE-019 seq 42 no longer removes steps 10 and 11: %v", e.CorrectiveAction)
	}

	// The counterweight: CORE-014 still REQUIRES 204, which is what critDERPut
	// implements. If this ever flips, criteria_2030.go must flip with it.
	c, ok := cat.ByID(doc, "CORE-014")
	if !ok {
		t.Fatal("the catalog has no CORE-014")
	}
	if !mentions(c.Expected, "204") && !mentions(c.Observables, "204") {
		t.Error("CORE-014 no longer expects a 204 on PUT of DERCapabilities/DERSettings, but " +
			"critDERPut still asserts one")
	}
}

// TestMaint002IsOptional pins Annex A seq 32: "Make the test optional/remove
// entirely from the spec". Conformance must not be gated on MAINT-002 — and the
// §4 matrix must not quietly acquire a requirement for it.
func TestMaint002IsOptional(t *testing.T) {
	cat := loadCatalog(t)
	c, e := erratumFor(t, cat, "MAINT-002", 32)
	joined := strings.ToLower(strings.Join(e.CorrectiveAction, " "))
	if !strings.Contains(joined, "optional") {
		t.Errorf("MAINT-002 seq 32 no longer makes the test optional: %v", e.CorrectiveAction)
	}
	pc := c.ProfileConformance
	if pc == nil {
		t.Fatal("MAINT-002 has no profile_conformance row")
	}
	if pc.DERClientRequired || pc.DERAggregatorClientRequired || pc.ServerRequired {
		t.Errorf("MAINT-002 is marked required for some profile (client=%t aggregator=%t server=%t), "+
			"but Annex A seq 32 makes it optional/removed", pc.DERClientRequired,
			pc.DERAggregatorClientRequired, pc.ServerRequired)
	}
	if c.Applicable {
		t.Error("MAINT-002 is marked applicable; the erratum makes it optional and the §4 matrix " +
			"requires it of nobody")
	}
}

// TestComm004RejectionSignalsErratum pins Annex A seq 7 — the one erratum in
// this set that IS live for this DUT, because COMM-004 and its A-G sub-tests
// are required of a direct DER client.
func TestComm004RejectionSignalsErratum(t *testing.T) {
	cat := loadCatalog(t)
	for _, id := range []string{"COMM-004", "COMM-004D", "COMM-004E", "COMM-004F", "COMM-004G"} {
		_, e := erratumFor(t, cat, id, 7)
		joined := strings.Join(e.CorrectiveAction, " ")
		for _, want := range []string{"TCP port disconnect", "403"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%s seq 7 no longer admits %q as an alternative to a TLS alert: %v",
					id, want, e.CorrectiveAction)
			}
		}
	}
	// And the split itself (seq 28), which is why D-G exist as rows at all.
	for _, id := range []string{"COMM-004D", "COMM-004E", "COMM-004F", "COMM-004G"} {
		if _, ok := cat.ByID(doc, id); !ok {
			t.Errorf("the catalog has no %s; Annex A seq 28 splits COMM-004 into seven sub-tests "+
				"A through G and the suite registers all seven", id)
		}
	}
}

// TestNotApplicableRowsCarryTheirErrataForward proves the breadcrumb reaches
// the bundle: a row this suite reports NOT APPLICABLE must still print its
// client-relevant corrections, because the next reader of that row is whoever
// implements it after the aggregator re-scope.
func TestNotApplicableRowsCarryTheirErrataForward(t *testing.T) {
	cat := loadCatalog(t)
	for _, want := range []struct {
		id     string
		phrase string
	}{
		{"AGG-007", "status 14"},
		{"AGG-008", "status 14"},
		{"ERR-002", "Remove Step 6"},
		{"CORE-018", "Remove the acceptance of 204"},
		{"CORE-019", "Remove steps 10 and 11"},
		{"MAINT-002", "optional"},
	} {
		c, ok := cat.ByID(doc, want.id)
		if !ok {
			t.Fatalf("the catalog has no %s %s", doc, want.id)
		}
		res, err := notApplicable(t.Context(), &certify.RunCtx{Case: c})
		if err != nil {
			t.Fatalf("%s: notApplicable: %v", want.id, err)
		}
		if res.Verdict != certify.Skip {
			t.Errorf("%s: verdict %s, want SKIP", want.id, res.Verdict)
		}
		if !strings.Contains(res.Notes, "PUBLISHED ERRATA") {
			t.Errorf("%s: the N/A note carries no errata breadcrumb: %s", want.id, res.Notes)
		}
		if !strings.Contains(res.Notes, want.phrase) {
			t.Errorf("%s: the N/A note does not carry the correction %q", want.id, want.phrase)
		}
	}

	// A row with no errata must not grow a stray heading.
	c, ok := cat.ByID(doc, "MAINT-001")
	if !ok {
		t.Fatal("the catalog has no MAINT-001")
	}
	if len(c.Errata) == 0 {
		res, _ := notApplicable(t.Context(), &certify.RunCtx{Case: c})
		if strings.Contains(res.Notes, "PUBLISHED ERRATA") {
			t.Error("MAINT-001 has no errata but the note announces some")
		}
	}
}

func mentions(ss []string, sub string) bool {
	_, ok := findContaining(ss, sub)
	return ok
}

func findContaining(ss []string, sub string) (string, bool) {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return s, true
		}
	}
	return "", false
}
