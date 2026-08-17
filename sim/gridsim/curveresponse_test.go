package gridsim

// curveresponse_test.go — the ORACLE for the curve-bound control's
// RespondableResource attributes.
//
// # The defect these rows exist for
//
// POST /admin/curve built its ExtendedDERControl with NO replyTo and NO
// responseRequired, while POST /admin/control has set both on every control it
// creates since the 2026-08-01 audit (adminDefaultResponseRequired,
// adminResponseReplyTo). So every curve-bound control this bench published asked
// the DUT for NOTHING.
//
// That is not a cosmetic gap. IEEE 2030.5 does not have a client volunteer a
// Response nobody asked for, so a spec-honest DUT answering a curve control with
// silence is CORRECT — and any conformance criterion grading the Response
// lifecycle on a curve row would have been grading the DUT for not answering a
// question the bench never put. toExtendedControl's own doc already records
// exactly this failure for the scalar-onto-widened-program path and calls the
// resulting reading "false"; the curve path itself had the same hole and nothing
// caught it, because no curve row graded Responses.
//
// Wiring critResponsePosted/critResponseStarted onto the BASIC curve rows is
// what makes this reachable, so the attributes have to be right FIRST — hence
// these rows land with that change and not after it.

import (
	"net/http"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// TestAdminCurve_ControlAsksForTheResponseLifecycle is the precondition every
// curve-row Response criterion rests on.
func TestAdminCurve_ControlAsksForTheResponseLifecycle(t *testing.T) {
	s := newTestServer()
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "x_mult": -2, "y_mult": 0,
		"points": [{"x":9570,"y":30},{"x":10430,"y":-30}], "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}

	raw := serveRaw(t, s, "/derp/0/derc")

	// responseRequired: bit 0 (message received) and bit 1 (specific response).
	// Without bit 1 nothing obliges a conformant client to ever report status=2,
	// which is the citation the campaign's curve evidence leans on.
	if !strings.Contains(raw, `responseRequired="03"`) {
		t.Errorf("the curve-bound control does not carry responseRequired=03; a DUT that answers it with "+
			"silence is behaving CORRECTLY and every Response criterion on a curve row would be "+
			"grading the bench's own omission:\n%s", raw)
	}
	// replyTo: without it the DUT has no address to POST the Response to.
	if !strings.Contains(raw, `replyTo="`+adminResponseReplyTo+`"`) {
		t.Errorf("the curve-bound control does not carry replyTo=%q, so a DUT that wanted to answer has "+
			"nowhere to send it:\n%s", adminResponseReplyTo, raw)
	}
}

// TestAdminCurve_ResponseRequiredIsOverridable keeps the escape hatch
// /admin/control already has: a scenario proving the DUT correctly WITHHOLDS a
// Response nobody asked for needs to be able to ask for nothing.
func TestAdminCurve_ResponseRequiredIsOverridable(t *testing.T) {
	s := newTestServer()
	if rec := postAdmin(t, s, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "x_mult": -2, "y_mult": 0,
		"points": [{"x":9570,"y":30}], "activate": true, "response_required": 0
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}
	raw := serveRaw(t, s, "/derp/0/derc")
	// Zero is a REQUEST FOR NOTHING and must be served as such — distinct from
	// the attribute being absent, which is what the standing non-admin fixtures
	// legitimately do.
	if !strings.Contains(raw, `responseRequired="00"`) {
		t.Errorf("response_required:0 did not reach the wire as responseRequired=00:\n%s", raw)
	}
}

// TestAdminCurve_MatchesWhatAdminControlSends pins the two paths together, so a
// future change to one is not silently a divergence from the other. The two
// endpoints publish the same KIND of thing — a DERControl the DUT must answer —
// and the only reason they ever differed is that nobody was looking.
func TestAdminCurve_MatchesWhatAdminControlSends(t *testing.T) {
	scalar := newTestServer()
	postControlOK(t, scalar, `{"program":0,"activate":true,"mrid":"M-SCALAR","connect":true}`)
	scalarRaw := serveRaw(t, scalar, "/derp/0/derc")

	curve := newTestServer()
	if rec := postAdmin(t, curve, "/admin/curve", `{
		"program": 0, "mode": "volt_var", "x_mult": -2, "y_mult": 0,
		"points": [{"x":9570,"y":30}], "activate": true
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/curve = %d: %s", rec.Code, rec.Body)
	}
	curveRaw := serveRaw(t, curve, "/derp/0/derc")

	for _, attr := range []string{
		`responseRequired="03"`,
		`replyTo="` + adminResponseReplyTo + `"`,
	} {
		if strings.Contains(scalarRaw, attr) != strings.Contains(curveRaw, attr) {
			t.Errorf("the two admin publish paths disagree about %s — scalar has it: %v, curve has it: %v",
				attr, strings.Contains(scalarRaw, attr), strings.Contains(curveRaw, attr))
		}
	}
	// And the default really is the constant, not a literal that drifted.
	if want := model.ResponseRequired(adminDefaultResponseRequired); uint8(want) != 0x03 {
		t.Fatalf("adminDefaultResponseRequired = %#x; this row's literals assume 0x03", uint8(want))
	}
}
