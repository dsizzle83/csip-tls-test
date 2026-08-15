package gridsim

// fixedpf_test.go — the opModFixedPF*W lever, on the wire and at its refusals.
//
// Every assertion about the document is made on the BYTES. That is not a style
// choice here: the defect this lever was built to end is invisible to a Go
// round-trip. csipmodel typed these elements *SignedPerCent — a bare chardata
// Int16 — so `<opModFixedPFInjectW>95</opModFixedPFInjectW>` marshalled and
// unmarshalled through this bench's own model perfectly, and decoded to ZERO on
// every conformant client. A test that encoded and decoded through csipmodel
// would have passed for as long as the defect existed.

import (
	"net/http"
	"strings"
	"testing"
)

// TestFixedPF_ServesTheThreeChildrenInTheStandardsShape is the primary claim:
// what goes on the wire is IEEE Std 2030.5-2018 p.258's element.
func TestFixedPF_ServesTheThreeChildrenInTheStandardsShape(t *testing.T) {
	s := NewServer("")
	// Figure 8's Test Values: 0.900 OVER-excited (excitation FALSE — 2018 p.258:
	// "false when DER is injecting reactive power (over-excited)").
	if rec := postAdmin(t, s, "/admin/control", `{
		"program": 0, "duration_s": 300, "activate": true,
		"fixed_pf_inject": {"displacement": 900, "excitation": false, "multiplier": -3}
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/control = %d: %s", rec.Code, rec.Body)
	}
	raw := serveRaw(t, s, "/derp/0/derc")

	// The three children, present and correct. `excitation` false and
	// `multiplier` -3 are exactly the values an errant omitempty would delete
	// and a scalar shape could not express, so each is asserted by its own
	// bytes rather than by the element merely existing.
	for _, want := range []string{
		"<opModFixedPFInjectW>",
		"<displacement>900</displacement>",
		"<excitation>false</excitation>",
		"<multiplier>-3</multiplier>",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the served control does not carry %s:\n%s", want, raw)
		}
	}
	// And NOT the retired scalar shape: a chardata value at the element's own
	// level is the document lexa-proto fe483e7 gave no decode tolerance, so a
	// bench emitting it now serves something the product correctly refuses.
	if strings.Contains(raw, "<opModFixedPFInjectW>900</opModFixedPFInjectW>") ||
		strings.Contains(raw, "<opModFixedPFInjectW>95</opModFixedPFInjectW>") {
		t.Errorf("the served control carries a bare chardata power factor, which is the shape no "+
			"revision of 2030.5 declares and the product gives no decode tolerance:\n%s", raw)
	}
	// The children are in the standard's own order (2018 p.258 lists them
	// displacement, excitation, multiplier). PowerFactorWithExcitation is an
	// xs:sequence like every other 2030.5 structure, so order is validity.
	at := -1
	for _, el := range []string{"<displacement>", "<excitation>", "<multiplier>"} {
		i := strings.Index(raw, el)
		if i < 0 || i < at {
			t.Errorf("%s is missing or out of the 2018 p.258 sequence:\n%s", el, raw)
		}
		at = i
	}
}

// TestFixedPF_StatusRendersTheChildrenAndThePowerFactor pins the admin view: a
// reader checking that this bench served Figure 8's condition needs the number
// 0.9, and a reader checking the DOCUMENT needs the children. Both, or the
// inspector is answering a different question than the one being asked.
func TestFixedPF_StatusRendersTheChildrenAndThePowerFactor(t *testing.T) {
	s := NewServer("")
	if rec := postAdmin(t, s, "/admin/control", `{
		"program": 0, "duration_s": 300, "activate": true,
		"fixed_pf_inject": {"displacement": 900, "excitation": false, "multiplier": -3},
		"fixed_pf_absorb": {"displacement": 950, "excitation": true, "multiplier": -3}
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/control = %d: %s", rec.Code, rec.Body)
	}
	st := adminStatus(t, s.AdminHandler())
	if len(st.Programs[0].Active) != 1 {
		t.Fatalf("program 0 active = %d, want 1", len(st.Programs[0].Active))
	}
	inj := st.Programs[0].Active[0].Base.FixedPFInjectW
	abs := st.Programs[0].Active[0].Base.FixedPFAbsorbW
	if inj == nil || abs == nil {
		t.Fatalf("status does not render both fixed-PF axes: inject=%v absorb=%v", inj, abs)
	}
	if inj.Displacement != 900 || inj.Excitation || inj.Multiplier != -3 {
		t.Errorf("inject children = %+v, want {900 false -3}", *inj)
	}
	if inj.PF != 0.9 {
		t.Errorf("inject PF = %v, want exactly 0.9 — the multiplier is applied by repeated division "+
			"rather than math.Pow precisely so this is not 0.9000000000000001", inj.PF)
	}
	// The two axes are DIFFERENT commands and must not be conflated: absorb is
	// under-excited where inject is over-excited, which is the direction of
	// reactive power and the thing the retired scalar could not carry at all.
	if !abs.Excitation || abs.Displacement != 950 {
		t.Errorf("absorb children = %+v, want {950 true -3}", *abs)
	}
}

// TestFixedPF_WholeOrNothing: all three children are [1], and a partial element
// is REFUSED rather than completed with zeros.
func TestFixedPF_WholeOrNothing(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no displacement", `{"excitation": false, "multiplier": -3}`, "displacement"},
		{"no excitation", `{"displacement": 900, "multiplier": -3}`, "excitation"},
		{"no multiplier", `{"displacement": 900, "excitation": false}`, "multiplier"},
		{"only excitation", `{"excitation": true}`, "displacement"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer("")
			rec := postAdmin(t, s, "/admin/control", `{
				"program": 0, "duration_s": 300, "activate": true,
				"fixed_pf_inject": `+tc.body+`
			}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST = %d, want 400; body: %s", rec.Code, rec.Body)
			}
			for _, want := range []string{tc.want, "opModFixedPFInjectW", "p.258", "[1]"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Errorf("the 400 omits %q: %s", want, rec.Body)
				}
			}
			// A refused request publishes NOTHING: the caller must be able to
			// tell which state the bench was left in.
			if raw := serveRaw(t, s, "/derp/0/derc"); strings.Contains(raw, "opModFixedPF") {
				t.Errorf("a refused fixed-PF request still published an element:\n%s", raw)
			}
		})
	}
}

// TestFixedPF_RefusesWhatIsNotAPowerFactor pins the domain check, which is the
// bench protecting a CORRECT device from a defect in the fixture.
//
// A displacement power factor lives in (0,1]. This server refuses a request
// outside it rather than serving one, because the product refuses it at receipt
// — and a control the DUT rejects for a bench defect is a row that fails a
// conformant device.
func TestFixedPF_RefusesWhatIsNotAPowerFactor(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		// 900 x 10^0 = 900. The classic multiplier slip.
		{"multiplier omitted from the scaling", `{"displacement": 900, "excitation": false, "multiplier": 0}`},
		// displacement 0 is not "absent", it is a power factor of zero.
		{"zero displacement", `{"displacement": 0, "excitation": false, "multiplier": -3}`},
		// 1100 x 10^-3 = 1.1, which no DER can execute.
		{"magnitude above unity", `{"displacement": 1100, "excitation": false, "multiplier": -3}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer("")
			rec := postAdmin(t, s, "/admin/control", `{
				"program": 0, "duration_s": 300, "activate": true,
				"fixed_pf_inject": `+tc.body+`
			}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST = %d, want 400; body: %s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "(0,1]") {
				t.Errorf("the 400 does not state the domain of a displacement power factor: %s", rec.Body)
			}
			// The refusal teaches the shape, because a caller who hits this is
			// one guess away from serving a different power factor than the
			// procedure prints.
			if !strings.Contains(rec.Body.String(), "displacement 900, excitation false, multiplier -3") {
				t.Errorf("the 400 does not name Figure 8's own shape: %s", rec.Body)
			}
		})
	}
	// UNITY IS IN RANGE: PF 1.0 is a legal command and must not be refused.
	s := NewServer("")
	if rec := postAdmin(t, s, "/admin/control", `{
		"program": 0, "duration_s": 300, "activate": true,
		"fixed_pf_inject": {"displacement": 1000, "excitation": false, "multiplier": -3}
	}`); rec.Code != http.StatusCreated {
		t.Fatalf("unity power factor refused (%d): %s", rec.Code, rec.Body)
	}
}

// TestFixedPF_TheRetiredScalarFieldIsRefusedLoudly is the migration guard.
//
// A caller still sending fixed_pf_inject_pct must be TOLD. Dropping it silently
// would publish a control commanding nothing on an axis the operator asked for,
// and the row grading it would report on a condition the DUT was never offered
// — which is worse than the defect the migration fixes, because it is invisible.
func TestFixedPF_TheRetiredScalarFieldIsRefusedLoudly(t *testing.T) {
	for _, field := range []string{"fixed_pf_inject_pct", "fixed_pf_absorb_pct"} {
		t.Run(field, func(t *testing.T) {
			s := NewServer("")
			rec := postAdmin(t, s, "/admin/control", `{
				"program": 0, "duration_s": 300, "activate": true, "`+field+`": 95
			}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("POST with %s = %d, want 400; body: %s", field, rec.Code, rec.Body)
			}
			for _, want := range []string{field, "PowerFactorWithExcitation", "p.258", "excitation"} {
				if !strings.Contains(rec.Body.String(), want) {
					t.Errorf("the 400 omits %q: %s", want, rec.Body)
				}
			}
			// It must NOT guess a translation. The whole hazard is a caller
			// who "fixes" this by inventing the two children the number cannot
			// carry.
			if !strings.Contains(rec.Body.String(), "will not guess") {
				t.Errorf("the 400 does not say the server declines to translate: %s", rec.Body)
			}
		})
	}
}

// TestFixedPF_DefaultDERControlCarriesItToo: the same element on the same
// validator, through the /admin/default path.
//
// Both handlers validate before the store, so a DefaultDERControl cannot be
// left holding an element the control path would have refused — the two entry
// points into buildBase share one rule because buildBase takes the VALIDATED
// pair rather than the request.
func TestFixedPF_DefaultDERControlCarriesItToo(t *testing.T) {
	s := NewServer("")
	if rec := postAdmin(t, s, "/admin/default", `{
		"program": 0,
		"base": {"fixed_pf_inject": {"displacement": 950, "excitation": true, "multiplier": -3}}
	}`); rec.Code != http.StatusOK && rec.Code != http.StatusCreated &&
		rec.Code != http.StatusNoContent {
		t.Fatalf("POST /admin/default = %d: %s", rec.Code, rec.Body)
	}
	raw := serveRaw(t, s, "/derp/0/dderc")
	for _, want := range []string{
		"<displacement>950</displacement>", "<excitation>true</excitation>",
		"<multiplier>-3</multiplier>",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the served DefaultDERControl does not carry %s:\n%s", want, raw)
		}
	}
	// And the same refusal on the same path.
	rec := postAdmin(t, s, "/admin/default", `{
		"program": 0, "base": {"fixed_pf_inject": {"displacement": 950, "excitation": true}}
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a partial element on /admin/default = %d, want 400: %s", rec.Code, rec.Body)
	}
}

// ── The deliberate-violation lever (IEEE 2030.5-2018 p.252-253) ─────────────

// TestNonconformantCurve_ServesTheShapesAConformantLeverRefuses is the opt-in's
// primary claim: a NEGATIVE row can put a malformed document on the wire, and
// only by asking for it by name.
//
// This lever exists because two of this wave's rulings turn on what a DUT does
// with a document the standard forbids, and the ordinary levers correctly refuse
// to build one — vrefFamily enforces both SHALLs. A bench with no way to violate
// them could not grade a refusal at all; a bench that violated them silently
// would put non-conformant documents into ordinary evidence. Opt-in, per
// request, named by clause.
func TestNonconformantCurve_ServesTheShapesAConformantLeverRefuses(t *testing.T) {
	t.Run("autonomousVRefEnable=true with NO time constant", func(t *testing.T) {
		s := NewServer("")
		// The conformant lever refuses this outright — that is the control.
		if rec := postAdmin(t, s, "/admin/curve", `{
			"program": 0, "mode": "volt_var", "points": [{"x":9100,"y":4000}],
			"autonomous_vref_enable": true, "activate": true
		}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("the conformant lever accepted enable=true with no time constant (%d): %s",
				rec.Code, rec.Body)
		}
		// Asked for by name, it is served.
		if rec := postAdmin(t, s, "/admin/curve", `{
			"program": 0, "mode": "volt_var", "points": [{"x":9100,"y":4000}],
			"nonconformant": {"autonomous_vref_without_time_constant": true}, "activate": true
		}`); rec.Code != http.StatusCreated {
			t.Fatalf("the opt-in did not serve the malformed shape (%d): %s", rec.Code, rec.Body)
		}
		raw := serveRaw(t, s, "/derp/0/dc/0")
		if !strings.Contains(raw, "<autonomousVRefEnable>true</autonomousVRefEnable>") {
			t.Errorf("the served curve does not carry autonomousVRefEnable=true:\n%s", raw)
		}
		// The violation IS the absence: 2018 p.252 makes the time constant
		// mandatory when enabled, so a document carrying one would be
		// conformant and would test nothing.
		if strings.Contains(raw, "autonomousVRefTimeConstant") {
			t.Errorf("the malformed shape carries a time constant, which makes it CONFORMANT and tests "+
				"the opposite of what it exists for:\n%s", raw)
		}
	})

	t.Run("vRef outside PerCent's domain", func(t *testing.T) {
		s := NewServer("")
		if rec := postAdmin(t, s, "/admin/curve", `{
			"program": 0, "mode": "volt_var", "points": [{"x":9100,"y":4000}],
			"nonconformant": {"vref": 65535}, "activate": true
		}`); rec.Code != http.StatusCreated {
			t.Fatalf("the opt-in did not serve the out-of-domain vRef (%d): %s", rec.Code, rec.Body)
		}
		if raw := serveRaw(t, s, "/derp/0/dc/0"); !strings.Contains(raw, "<vRef>65535</vRef>") {
			t.Errorf("the served curve does not carry the out-of-domain vRef:\n%s", raw)
		}
	})

	t.Run("the wire type is still a bound", func(t *testing.T) {
		// The lever serves a value PerCent does not ADMIT; it cannot serve one
		// UInt16 cannot CARRY. Those are different defects and only one of them
		// is expressible as a document.
		s := NewServer("")
		rec := postAdmin(t, s, "/admin/curve", `{
			"program": 0, "mode": "volt_var", "points": [{"x":9100,"y":4000}],
			"nonconformant": {"vref": 70000}, "activate": true
		}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST = %d, want 400: %s", rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), "UInt16's WIRE domain") {
			t.Errorf("the refusal does not distinguish the wire type from the value domain: %s", rec.Body)
		}
	})

	t.Run("only on a volt-var curve", func(t *testing.T) {
		// On any other mode the elements are refused by the SHALL NOT, which is
		// a different test — and letting the opt-in bypass THAT would silently
		// widen what "nonconformant" means.
		s := NewServer("")
		rec := postAdmin(t, s, "/admin/curve", `{
			"program": 0, "mode": "freq_watt", "points": [{"x":5900,"y":100}],
			"nonconformant": {"autonomous_vref_without_time_constant": true}, "activate": true
		}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST = %d, want 400: %s", rec.Code, rec.Body)
		}
	})

	t.Run("an unarmed request is untouched", func(t *testing.T) {
		// The opt-in must not change the ordinary path. A request with a
		// `nonconformant` object that asks for nothing is an ordinary request.
		s := NewServer("")
		if rec := postAdmin(t, s, "/admin/curve", `{
			"program": 0, "mode": "volt_var", "points": [{"x":9100,"y":4000}],
			"vref": 9500, "nonconformant": {}, "activate": true
		}`); rec.Code != http.StatusCreated {
			t.Fatalf("an unarmed nonconformant object changed the ordinary path (%d): %s",
				rec.Code, rec.Body)
		}
		if raw := serveRaw(t, s, "/derp/0/dc/0"); !strings.Contains(raw, "<vRef>9500</vRef>") {
			t.Errorf("the conformant vRef did not survive an unarmed opt-in:\n%s", raw)
		}
	})
}
