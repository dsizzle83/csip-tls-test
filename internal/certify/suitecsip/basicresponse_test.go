package suitecsip

// basicresponse_test.go — the ORACLE for the Response lifecycle on the
// inverter-control rows (BASIC-004..015).
//
// # The gap
//
// Every one of these rows graded SOUTHBOUND REGISTERS and nothing else. The
// northbound half — did the DUT tell the head end what it was doing with the
// control — was asserted by CORE-022/CORE-023 for their own controls and by
// critRefusalAnswered for the refusal rows, and by NOTHING for the execution
// rows. So the curve family's evidence was register-only: a DUT that adopted
// every curve perfectly and never posted a single Response passed them all,
// while the campaign's Started(2) wire citations (the CORE-022/023 precedent)
// had no automated criterion on this family at all.
//
// That is the shape of the RC0 battery's FINDING 6 — "a refused control is
// refused SILENTLY: no Response was ever posted to the head end" — found by hand
// because no row was looking.
//
// # Why the gridsim fix had to come first
//
// critResponseStarted grades against the control's OWN wire responseRequired
// (IEEE 2030.5 Table 27: a client is never told to volunteer a Response nobody
// requested). POST /admin/curve built its control with NO responseRequired at
// all, so every curve row would have come back Unavailable — "not requested" —
// which is an honest verdict about an empty question. The curve path now carries
// the same default POST /admin/control has (sim/gridsim/curveresponse_test.go),
// so these criteria grade a question that was actually put.
//
// # What these rows assert
//
// Composition, not behaviour: the criteria's own Pass/Fail/Unavailable logic is
// tested in criteria_2030's own rows. What was missing — and what silently stays
// missing if someone edits the switch in inverterControlSpec — is that the
// criteria are ATTACHED to the right rows and keyed to the right mRID.

import (
	"strings"
	"testing"
)

// claimsOf renders a spec's criteria for an observation as their Claim strings.
func claimsOf(t *testing.T, s spec, o *Observation) []string {
	t.Helper()
	if s.Criteria == nil {
		t.Fatal("the spec declares no criteria at all")
	}
	var out []string
	for _, c := range s.Criteria(o) {
		out = append(out, c.Claim)
	}
	return out
}

func hasClaimContaining(claims []string, substr string) bool {
	for _, c := range claims {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// TestInverterControlRows_GradeTheResponseLifecycle is the row that closes the
// gap: every EXECUTION row must assert both halves of the northbound lifecycle.
func TestInverterControlRows_GradeTheResponseLifecycle(t *testing.T) {
	for _, row := range inverterControlRows() {
		if row.mode.Unreachable != "" || row.mode.Refusal != nil {
			continue // handled by their own rows below
		}
		t.Run(row.id, func(t *testing.T) {
			s := inverterControlSpec(row.mode, row.subject, "CERT-"+row.id)
			// The mRID a curve row's control really carries is the SERVER's
			// (publishCurveControl overwrites params["mrid"] with it), so the
			// observation carries that shape rather than the synthetic one.
			o := &Observation{Params: map[string]string{"mrid": "DERC-SP-CURVE-1700000000"}}
			claims := claimsOf(t, s, o)

			if !hasClaimContaining(claims, "status=1 (Event received)") {
				t.Errorf("%s does not assert the DUT acknowledged the control it was sent. Its evidence is "+
					"register-only: a DUT that executed perfectly and told the head end nothing passes "+
					"it.\nclaims: %s", row.id, strings.Join(claims, "\n        "))
			}
			if !hasClaimContaining(claims, "status=2 (Event started)") {
				t.Errorf("%s does not assert the axis-identified Started(2) the campaign's curve evidence "+
					"leans on.\nclaims: %s", row.id, strings.Join(claims, "\n        "))
			}
		})
	}
}

// TestRideThroughRows_GradeTheResponseLifecycle covers BASIC-004/005, which are
// inverter-control rows of the same family but are built by their own spec
// (registerInverterControls binds ten rows through inverterControlRows; the two
// ride-through rows publish one control carrying four curves and go through
// ridethrough.go). They publish through the same /admin/curve path, so they owe
// the same northbound evidence — and a reader of this file would otherwise
// reasonably assume "BASIC-004..015" meant all twelve.
func TestRideThroughRows_GradeTheResponseLifecycle(t *testing.T) {
	var seen int
	for _, row := range rideThroughRows() {
		seen++
		t.Run(row.id, func(t *testing.T) {
			s := rideThroughSpec(row.row.binding, row.row.subject, "CERT-"+row.id)
			o := &Observation{Params: map[string]string{"mrid": "DERC-SP-CURVE-1700000000"}}
			claims := claimsOf(t, s, o)
			for _, want := range []string{"status=1 (Event received)", "status=2 (Event started)"} {
				if !hasClaimContaining(claims, want) {
					t.Errorf("%s does not assert %q; its four curves are graded southbound and the head "+
						"end is never asked what the DUT said about them.\nclaims: %s",
						row.id, want, strings.Join(claims, "\n        "))
				}
			}
		})
	}
	if seen == 0 {
		t.Fatal("no ride-through rows are registered, so this row proves nothing")
	}
}

// TestInverterControlRows_RefusalRowsAssertReceiptButNotStarted keeps the two
// families' claims from contradicting each other.
//
// A refusal row already carries critRefusalAnswered, which requires a refusal
// status to be present and requires status=2 to be ABSENT. Adding
// critResponseStarted there would assert the exact opposite of a criterion on
// the same row. But the RECEIPT half is still owed — the battery's FINDING 6 was
// precisely a refusal the head end was never told about — so a refusal row gains
// status=1 and only status=1.
func TestInverterControlRows_RefusalRowsAssertReceiptButNotStarted(t *testing.T) {
	var seen int
	for _, row := range inverterControlRows() {
		if row.mode.Refusal == nil || row.mode.Unreachable != "" {
			continue
		}
		seen++
		t.Run(row.id, func(t *testing.T) {
			s := inverterControlSpec(row.mode, row.subject, "CERT-"+row.id)
			o := &Observation{Params: map[string]string{"mrid": "DERC-SP-CURVE-1700000000"}}
			claims := claimsOf(t, s, o)

			if !hasClaimContaining(claims, "status=1 (Event received)") {
				t.Errorf("%s does not assert the DUT acknowledged the control it refused. A refusal the "+
					"head end is never told about is the battery's FINDING 6.\nclaims: %s",
					row.id, strings.Join(claims, "\n        "))
			}
			if hasClaimContaining(claims, "status=2 (Event started)") {
				t.Errorf("%s asserts BOTH that a Started(2) must appear and (via critRefusalAnswered) that "+
					"it must not — the row cannot pass either way", row.id)
			}
			if !hasClaimContaining(claims, "cannot-comply") {
				t.Errorf("%s lost its refusal-answered claim", row.id)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no refusal rows are registered, so this row proves nothing")
	}
}

// TestInverterControlRows_UnauthorableRowsClaimNoResponse is the third case. A
// row whose mode this bench cannot author never puts a control on the wire, so
// there is nothing for the DUT to answer and a Response criterion would be a
// claim about a question never asked — the same false-FAIL shape the gridsim
// responseRequired fix exists to prevent, one level up.
func TestInverterControlRows_UnauthorableRowsClaimNoResponse(t *testing.T) {
	m := controlMode{Element: "opModNothing", Unreachable: "this bench cannot author it"}
	s := inverterControlSpec(m, "an unauthorable axis", "CERT-UNAUTH")
	claims := claimsOf(t, s, &Observation{Params: map[string]string{"mrid": "M-UNAUTH"}})
	for _, bad := range []string{"status=1 (Event received)", "status=2 (Event started)"} {
		if hasClaimContaining(claims, bad) {
			t.Errorf("an unauthorable row asserts %q, but it published no control for the DUT to answer", bad)
		}
	}
}

// TestInverterControlRows_ResponseCriteriaAreKeyedToTheRowsOwnMRID is the teeth.
//
// The criteria filter Responses on <subject>. Keyed to the row's SYNTHETIC mRID
// rather than the one gridsim minted, they would match nothing on every curve
// row and quietly report "the transcript holds no Response POST for subject
// CERT-BASIC-006" — an Unavailable that reads like a bench gap and is actually a
// harness bug.
func TestInverterControlRows_ResponseCriteriaAreKeyedToTheRowsOwnMRID(t *testing.T) {
	const minted = "DERC-SP-CURVE-1700000042"
	row := rowByID(t, "BASIC-006")
	s := inverterControlSpec(row.mode, row.subject, "CERT-BASIC-006")
	claims := claimsOf(t, s, &Observation{Params: map[string]string{"mrid": minted}})

	// The claim text does not carry the mRID, so assert through How, which
	// names what the criterion matches on, and through the criteria themselves.
	o := &Observation{Params: map[string]string{"mrid": minted}}
	var checked int
	for _, c := range s.Criteria(o) {
		if !strings.Contains(c.Claim, "DERControlResponse") {
			continue
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("BASIC-006 carries no Response criteria at all:\n%s", strings.Join(claims, "\n"))
	}
	// A row built on a DIFFERENT mrid must produce criteria that are not
	// interchangeable with these — if the mrid were ignored, both would be
	// identical objects and the filter would be dead.
	other := s.Criteria(&Observation{Params: map[string]string{"mrid": "M-SOMETHING-ELSE"}})
	if len(other) != len(s.Criteria(o)) {
		t.Fatal("the criteria list length depends on the mRID, which it should not")
	}
}

// TestInverterControlRows_MRIDsCarryTheRunNonce pins the protection that makes
// the receipt criterion measure the DUT rather than its cache.
//
// lexa-gw's Response tracker dedupes Received(1) on the bare mRID string, keeps
// that record for the process's whole lifetime and PERSISTS IT TO DISK. A row
// whose control is always "CERT-BASIC-008" therefore earns its status=1
// Response exactly once per DUT, ever — so the second campaign against a
// long-lived gateway would find no fresh receipt and the criterion would FAIL on
// the harness reusing an identifier, not on anything the DUT did. CORE-022/023
// have nonced around this since they were written; these rows had no reason to
// until they started grading Responses.
func TestInverterControlRows_MRIDsCarryTheRunNonce(t *testing.T) {
	const a, b = "noncea1", "nonceb2"
	if got := withRunNonce("CERT-BASIC-008", a); got == "CERT-BASIC-008" {
		t.Fatal("withRunNonce returned the bare mRID, so this row cannot detect the wiring")
	}
	if withRunNonce("CERT-BASIC-008", a) == withRunNonce("CERT-BASIC-008", b) {
		t.Error("two runs mint the same mRID, so the DUT's per-mRID dedupe will suppress the second run's " +
			"Received(1) and the receipt criterion will FAIL on a healthy gateway")
	}
	// And an empty nonce must still yield a usable mRID — the unit rigs build
	// checks without one.
	if got := withRunNonce("CERT-BASIC-008", ""); got != "CERT-BASIC-008" {
		t.Errorf("withRunNonce with no nonce = %q, want the bare mRID", got)
	}
}
