package gridsim

// defaultengage_test.go — the ORACLE for the connect/energize levers on the
// built-in DefaultDERControls.
//
// # The bench precondition these rows exist for
//
// gridsim's three built-in DefaultDERControls shipped opModConnect=true AND
// opModEnergize=true, on every program, unconditionally. That is a CONTINUOUS
// STANDING COMMAND to connect and energize, underneath every row a bench runs,
// and it confounded two of them across two campaigns:
//
//	BENCH-000 row (j)   a pre-disconnected DER: a gateway holding no ownership
//	                    record must leave it alone. It cannot, while the head
//	                    end it is talking to says "energize" on every poll.
//	BASIC-009's ES half  commands connect=false/energize=false and grades
//	                    model 123 Conn and model 703 ES. With the default
//	                    commanding the opposite underneath, what the row
//	                    measures is which of the two won, not whether the DUT
//	                    honoured the control.
//
// # Why ABSENT and not false
//
// An absent element and a false element are DIFFERENT DOCUMENTS to a 2030.5
// client. `false` is still a command — "disconnect" — and a row that needs the
// axis NOT ENGAGED (so the DER holds whatever state the row put it in) gets the
// opposite of what it asked for. Only absence leaves the axis unspoken, which is
// why the built-in default now omits the elements and a row that wants either
// value has to say so.
//
// The catalog's own table agrees for connect: BASIC-009's Figure 9 row records
// "opmodConnect: Default (blank/not specified)" — blank, not false.
//
// The rows below pin all three states of each axis on the served document,
// because that three-way distinction is the whole point of the change.

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	model "lexa-proto/csipmodel"
)

// ddercRaw serves a program's DefaultDERControl and returns the raw XML.
func ddercRaw(t *testing.T, s *Server, program int) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET",
		"/derp/"+strconv.Itoa(program)+"/dderc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /derp/%d/dderc = %d: %s", program, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// TestDefaultDERControlDoesNotEngageConnectOrEnergize is the precondition
// itself: out of the box, on EVERY program, neither axis is spoken.
func TestDefaultDERControlDoesNotEngageConnectOrEnergize(t *testing.T) {
	s := newTestServer()
	for _, program := range []int{0, 1, 2} {
		raw := ddercRaw(t, s, program)
		for _, el := range []string{"opModConnect", "opModEnergize"} {
			if strings.Contains(raw, "<"+el+">") {
				t.Errorf("program %d's DefaultDERControl still carries <%s> — it is a standing command "+
					"underneath every row the bench runs, and it re-confounds BENCH-000 row (j) and "+
					"BASIC-009's ES half exactly as it did in Wave-I and Leg-B:\n%s", program, el, raw)
			}
		}
		// The export cap is NOT part of this change and must survive: several
		// mayhem scenarios (suppressDefault, armAfterCapAdopted) reason about
		// the program-0 5 kW cap by name.
		if !strings.Contains(raw, "<opModExpLimW>") {
			t.Errorf("program %d's DefaultDERControl lost <opModExpLimW>; only the connect/energize "+
				"axes were meant to become absent", program)
		}
	}
}

// TestDefaultDERControlConnectEnergizeLever proves the three-way distinction on
// the wire: absent, explicitly true, explicitly false.
//
// The lever is POST /admin/default's existing `base` — the same adminCtrlReq
// POST /admin/control takes — so a row engages it with the value it wants and
// gets exactly that value, rather than inheriting one nobody chose.
func TestDefaultDERControlConnectEnergizeLever(t *testing.T) {
	for _, tc := range []struct {
		name         string
		body         string
		wantConnect  string // "" = element must be absent
		wantEnergize string
	}{
		{
			name: "absent by default (no POST at all)",
			body: "",
		},
		{
			name:         "engaged true — the historical shape, now on request",
			body:         `{"program":0,"base":{"connect":true,"energize":true,"exp_lim_W":5000}}`,
			wantConnect:  "true",
			wantEnergize: "true",
		},
		{
			name:         "engaged FALSE — a command, and a different document from absent",
			body:         `{"program":0,"base":{"connect":false,"energize":false,"exp_lim_W":5000}}`,
			wantConnect:  "false",
			wantEnergize: "false",
		},
		{
			name:         "one axis only: energize spoken, connect left unspoken",
			body:         `{"program":0,"base":{"energize":true,"exp_lim_W":5000}}`,
			wantConnect:  "",
			wantEnergize: "true",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer()
			if tc.body != "" {
				if rec := postAdmin(t, s, "/admin/default", tc.body); rec.Code != http.StatusNoContent &&
					rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
					t.Fatalf("POST /admin/default = %d: %s", rec.Code, rec.Body)
				}
			}
			raw := ddercRaw(t, s, 0)
			assertElement(t, raw, "opModConnect", tc.wantConnect)
			assertElement(t, raw, "opModEnergize", tc.wantEnergize)
		})
	}
}

// assertElement checks an element is absent (want == "") or carries want.
func assertElement(t *testing.T, raw, el, want string) {
	t.Helper()
	open, close := "<"+el+">", "</"+el+">"
	i := strings.Index(raw, open)
	if want == "" {
		if i >= 0 {
			t.Errorf("<%s> is present and should be ABSENT (absence is not the same command as false):\n%s",
				el, raw)
		}
		return
	}
	if i < 0 {
		t.Fatalf("<%s> is absent, want %q:\n%s", el, want, raw)
	}
	j := strings.Index(raw[i:], close)
	if got := raw[i+len(open) : i+j]; got != want {
		t.Errorf("<%s> = %q, want %q", el, got, want)
	}
}

// TestDefaultDERControlLeverIsVisibleThroughTheAdminReadback pins that the
// operator-facing read agrees with the wire. GET /admin/default and GET
// /admin/status both render the default through defaultBaseInfoLocked, and a
// lever the wire honours but the readback denies would have an operator
// re-running a row against a posture they cannot see.
func TestDefaultDERControlLeverIsVisibleThroughTheAdminReadback(t *testing.T) {
	s := newTestServer()

	var before map[string]any
	getAdminJSON(t, s, "/admin/default?program=0", &before)
	if _, ok := before["connect"]; ok {
		t.Errorf("GET /admin/default reports a connect axis before any POST: %v", before)
	}
	if _, ok := before["energize"]; ok {
		t.Errorf("GET /admin/default reports an energize axis before any POST: %v", before)
	}

	postAdmin(t, s, "/admin/default", `{"program":0,"base":{"connect":true,"energize":false,"exp_lim_W":5000}}`)

	var after map[string]any
	getAdminJSON(t, s, "/admin/default?program=0", &after)
	if after["connect"] != true {
		t.Errorf("GET /admin/default connect = %v, want true", after["connect"])
	}
	if after["energize"] != false {
		t.Errorf("GET /admin/default energize = %v, want false", after["energize"])
	}
}

// getAdminJSON reads an admin GET into v.
func getAdminJSON(t *testing.T, s *Server, path string, v any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %s: %v (body %s)", path, err, rec.Body)
	}
}

// TestDefaultDERControlDescriptionDoesNotClaimWhatItNoLongerSends is small and
// deliberate. The program-0 description read "Default: export limit 5kW,
// connect and energize" and is served on the wire; leaving it would have made
// the document describe a command it no longer carries — the exact class of
// stale claim a reader of a captured bundle has no way to check.
func TestDefaultDERControlDescriptionDoesNotClaimWhatItNoLongerSends(t *testing.T) {
	s := newTestServer()
	raw := ddercRaw(t, s, 0)
	if strings.Contains(strings.ToLower(raw), "connect and energize") {
		t.Errorf("the served description still claims connect and energize:\n%s", raw)
	}
	// And the resource is otherwise untouched: same mRID, still a
	// DefaultDERControl, still carrying the cap.
	var doc model.DefaultDERControl
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("the served default does not decode: %v", err)
	}
	if doc.MRID != "DDERC-SP-001" {
		t.Errorf("mRID = %q, want DDERC-SP-001 — the identity must not move", doc.MRID)
	}
}
