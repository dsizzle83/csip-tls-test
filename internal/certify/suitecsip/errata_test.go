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
// # These pins were written a day early, and it paid
//
// When this file was written, four of its five rows were NOT APPLICABLE: the §4
// profile matrix scoped them to a DER Aggregator Client and the DUT was a direct
// DER client. The stated reason for pinning them anyway was that "a re-scope
// makes them live, and the first thing an implementer will read is the unamended
// step list". On 2026-07-28 the owner re-scoped the certification to the DER
// Aggregator Client profile and every one of those rows went live.
//
// The catalog half of each pin is therefore unchanged — that is the point of a
// pin — and a second half is added below: the same correction asserted against
// the CODE that now implements the row. A correction that lives only in the
// catalog is a note; a correction asserted against the implementation is a
// guarantee. TestLiveErrataAreImplemented is that second half.

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
//
// The 2026-07-28 re-scope is what makes this pin bite. It pulled MAINT-001,
// MAINT-003, MAINT-004 and MAINT-005 in as required aggregator-client rows, and
// the obvious mistake would have been to take the whole MAINT block with them.
// §4 leaves MAINT-002 blank in all three columns and the erratum says why, so it
// is the one sibling that stays out.
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
// implements it after a re-scope.
//
// The list shrank on 2026-07-28. It used to hold AGG-007, AGG-008, ERR-002,
// CORE-018 and CORE-019; all five went live with the aggregator re-scope and
// their corrections are now pinned against the implementation instead, in
// TestLiveErrataAreImplemented. What remains is the rows the re-scope did NOT
// reach, which are the rows that most need the breadcrumb: nobody is reading
// their code, because there is none.
func TestNotApplicableRowsCarryTheirErrataForward(t *testing.T) {
	cat := loadCatalog(t)
	for _, want := range []struct {
		id     string
		phrase string
	}{
		{"MAINT-002", "optional"},
		{"CORE-001", "405"},
		{"CORE-004", "with no query string parameter"},
	} {
		c, ok := cat.ByID(doc, want.id)
		if !ok {
			t.Fatalf("the catalog has no %s %s", doc, want.id)
		}
		if c.Applicable {
			t.Fatalf("%s is applicable; this test is about the rows that are NOT", want.id)
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
	c, ok := cat.ByID(doc, "UTIL-001")
	if !ok {
		t.Fatal("the catalog has no UTIL-001")
	}
	if len(c.Errata) == 0 {
		res, _ := notApplicable(t.Context(), &certify.RunCtx{Case: c})
		if strings.Contains(res.Notes, "PUBLISHED ERRATA") {
			t.Error("UTIL-001 has no errata but the note announces some")
		}
	}
}

// TestLiveErrataAreImplemented is the half that only became possible on
// 2026-07-28: the corrections asserted against the CODE, now that the rows they
// correct have code.
//
// Each assertion below would fail a conformant DUT if the implementation had
// been written from the printed procedure instead of the amended one. That is
// the whole test: not "is the erratum recorded" but "does the check do what the
// erratum says".
func TestLiveErrataAreImplemented(t *testing.T) {
	sc := aggScenarios()

	// seq 5 / seq 6 — AGG-007 and AGG-008 expect status 14, not the printed 7.
	for _, id := range []string{"AGG-007", "AGG-008"} {
		s, ok := sc[id]
		if !ok {
			t.Fatalf("no aggregator scenario for %s", id)
		}
		if s.Superseded == "" {
			t.Errorf("%s pins no superseded control, so its supersession status is unasserted", id)
			continue
		}
		if s.SupersedeStatus != 14 {
			t.Errorf("%s asserts supersession status %d; Annex A seq 5/6 correct this row to 14 (Event "+
				"Superseded from another program). Asserting the printed 7 would FAIL a conformant aggregator",
				id, s.SupersedeStatus)
		}
	}

	// The contrast row: AGG-009 keeps 7 because its event had already started.
	if s := sc["AGG-009"]; s.SupersedeStatus != 7 {
		t.Errorf("AGG-009 asserts supersession status %d, want 7 — its SY event had already STARTED when "+
			"the TFA event was discovered, which is exactly why seq 5/6 do not reach it", s.SupersedeStatus)
	}

	// The independent-control family supersedes nothing at all.
	for _, id := range []string{"AGG-010", "AGG-011", "AGG-012"} {
		s := sc[id]
		if s.Superseded != "" {
			t.Errorf("%s pins a supersession status; its two controls carry DIFFERENT modes and IEEE 2030.5 "+
				"independent modes coexist rather than supersede", id)
		}
		if len(s.Independent) != 2 {
			t.Errorf("%s names %d control(s) for the no-supersession criterion, want 2", id, len(s.Independent))
		}
		// And the modes really must differ, or the row asserts nothing.
		if len(s.Controls) == 2 && s.Controls[0].Mode == s.Controls[1].Mode {
			t.Errorf("%s publishes two controls of the SAME mode (%s); the row's whole subject is that "+
				"INDEPENDENT modes do not supersede", id, s.Controls[0].Mode.element())
		}
	}

	// seq 26 — AGG-006's corrected setup: SY at +4 min, TFA at +2 min, 1 min each.
	byMRID := map[string]aggControl{}
	for _, c := range sc["AGG-006"].Controls {
		byMRID[c.MRID] = c
	}
	if c := byMRID["CERT-AGG006SY"]; c.StartOffset != 240 || c.DurationS != 60 {
		t.Errorf("AGG-006's SY control is start+%d s for %d s; Annex A seq 26's corrected setup step 4 is "+
			"start+240 s for 60 s", c.StartOffset, c.DurationS)
	}
	if c := byMRID["CERT-AGG006TFA"]; c.StartOffset != 120 || c.DurationS != 60 {
		t.Errorf("AGG-006's TFA control is start+%d s for %d s; the corrected setup step 5 is start+120 s "+
			"for 60 s", c.StartOffset, c.DurationS)
	}

	// AGG-009 and AGG-012 are the two rows whose outcome depends on the higher-
	// priority control being created AFTER the other has started. Publishing
	// both at setup would silently turn them into AGG-007 and AGG-010.
	for _, id := range []string{"AGG-009", "AGG-012"} {
		late := 0
		for _, c := range sc[id].Controls {
			if c.LateAfterS > 0 {
				late++
			}
		}
		if late != 1 {
			t.Errorf("%s publishes %d control(s) late; its procedure creates the second control only AFTER "+
				"the first has started, and publishing both at setup makes it a different test", id, late)
		}
	}

	// seq 44 — CORE-018 and CORE-019 must NOT accept 204 for a Notification.
	for _, tc := range []struct {
		id    string
		crits []criterion
	}{
		{"CORE-018", core018Criteria(emptyObservation())},
		{"CORE-019", core019Criteria(emptyObservation())},
	} {
		claim, found := notificationClaim(tc.crits)
		if !found {
			t.Errorf("%s has no criterion about the DUT's answer to a Notification", tc.id)
			continue
		}
		if strings.Contains(claim, "204") {
			t.Errorf("%s admits HTTP 204 in %q; Annex A seq 44 removes the acceptance of 204 for this row",
				tc.id, claim)
		}
		if !strings.Contains(claim, "201") {
			t.Errorf("%s does not require HTTP 201 Created in %q", tc.id, claim)
		}
	}

	// ...and the counterweight, which is where a blanket rule would have gone
	// wrong: ERR-002's printed step 3 still admits BOTH, because seq 44 is
	// scoped to CORE-018/CORE-019.
	err002 := err002Criteria(emptyObservation())
	claim, found := notificationClaim(err002)
	if !found {
		t.Fatal("ERR-002 has no criterion about the DUT's answer to a Notification")
	}
	if !strings.Contains(claim, "201") || !strings.Contains(claim, "204") {
		t.Errorf("ERR-002's Notification criterion is %q; its printed step 3 admits 201 Created OR 204 No "+
			"Content, and seq 44's removal of the 204 does not reach this row", claim)
	}

	// seq 38 — "Remove Step 6". No criterion may DEMAND a re-POSTed Subscription
	// after a status=1 cancellation. A check that waited for one would hang for
	// its whole timeout and then fail a conformant client.
	for i, c := range err002 {
		text := c.Claim
		if !strings.Contains(strings.ToLower(text), "cancel") {
			continue
		}
		for _, forbidden := range []string{"re-POST", "re-subscribe", "resubscribe", "posts another subscription"} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
				t.Errorf("ERR-002 criterion %d demands a %s after cancellation: %q. Annex A seq 38 removes "+
					"printed step 6 — IEEE 2030.5 requires no such thing", i, forbidden, text)
			}
		}
	}

	// seq 3 — UTIL-002 PUTs the DER FIELD resources, never the DERListLink.
	// This one is asserted through critDERPut's own claim text, which names the
	// resource it looks for.
	for _, resource := range []string{"DERCapability", "DERSettings"} {
		c := critDERPut(resource)
		if strings.Contains(c.Claim, "DERListLink") {
			t.Errorf("critDERPut(%q) claims a PUT to the DERListLink; Annex A seq 3 corrects UTIL-002 to "+
				"PUT the DER field resources instead: %q", resource, c.Claim)
		}
	}
}

// notificationClaim returns the Claim of the criterion about the DUT's answer to
// a server-pushed Notification.
func notificationClaim(crits []criterion) (string, bool) {
	for _, c := range crits {
		if strings.Contains(c.Claim, "answers a valid server-pushed Notification") {
			return c.Claim, true
		}
	}
	return "", false
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
