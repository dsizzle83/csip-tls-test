package gridsim

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	model "lexa-proto/csipmodel"
)

// Regression for audit finding GS-1: watt values above int16 range were
// truncated (40000 W → −25536 W). apFromWatts must scale into the
// power-of-ten multiplier so the round-tripped wattage is preserved.
func TestAPFromWatts_ScalesBeyondInt16(t *testing.T) {
	cases := []struct {
		in       int64
		wantVal  int16
		wantMult int8
	}{
		{0, 0, 0},
		{1000, 1000, 0},
		{32767, 32767, 0},
		{-32768, -32768, 0},
		{40000, 4000, 1},
		{-40000, -4000, 1},
		{2500000, 25000, 2},
	}
	for _, c := range cases {
		got := apFromWatts(&c.in)
		if got.Value != c.wantVal || got.Multiplier != c.wantMult {
			t.Errorf("apFromWatts(%d) = {Value:%d Multiplier:%d}, want {Value:%d Multiplier:%d}",
				c.in, got.Value, got.Multiplier, c.wantVal, c.wantMult)
		}
	}
	if apFromWatts(nil) != nil {
		t.Error("apFromWatts(nil) should pass nil through")
	}
}

// TestAPFromWatts_Sweep0To1e9 is TASK-053's step-3 encode-scaling property
// applied to this repo's own product-analogous watt encoder (the bench's
// gridsim admin API mirrors the hub's OpMod*LimW encoding path — GS-1/MTR-1):
// across a dense log-scale sweep of +-1e9 W, Value must stay in int16 range
// and Value×10^Multiplier must reconstruct the input within one full scale
// step (apFromWatts truncates via integer division, unlike the hub's
// float64+math.Round encoders, so its precision bound is one full step, not
// half — see the lexa-hub counterpart in cmd/hub/state_test.go /
// cmd/modbus/control_test.go for the rounding variant).
func TestAPFromWatts_Sweep0To1e9(t *testing.T) {
	step := int64(1)
	for w := int64(-1_000_000_000); w <= 1_000_000_000; w += step {
		wCopy := w
		ap := apFromWatts(&wCopy)
		if ap.Value > math.MaxInt16 || ap.Value < math.MinInt16 {
			t.Fatalf("apFromWatts(%d) value=%d out of int16 range", w, ap.Value)
		}
		decoded := float64(ap.Value) * math.Pow10(int(ap.Multiplier))
		tol := math.Pow10(int(ap.Multiplier))
		if math.Abs(decoded-float64(w)) > tol {
			t.Fatalf("apFromWatts(%d) = {Value:%d Mult:%d} -> %g, want within %g (one scale step)",
				w, ap.Value, ap.Multiplier, decoded, tol)
		}
		if w > 0 && decoded < 0 {
			t.Fatalf("apFromWatts(%d): sign flip, decoded=%g", w, decoded)
		}
		if w < 0 && decoded > 0 {
			t.Fatalf("apFromWatts(%d): sign flip, decoded=%g", w, decoded)
		}
		// Geometric progression: dense near zero, still bounded iteration
		// count out to +-1e9 (TASK-053: CI-fast, not -fuzz).
		if w != 0 {
			step = int64(math.Abs(float64(w)) * 0.001)
			if step < 1 {
				step = 1
			}
		}
	}
}

// End-to-end: a 40 kW export limit posted to /admin/control must read back
// as 40000 W from /admin/status (not a sign-flipped truncation).
func TestAdminControl_LargeWattLimitRoundTrip(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	body := []byte(`{"program":0,"exp_lim_W":40000,"duration_s":300,"activate":true}`)
	post := httptest.NewRequest("POST", "/admin/control", bytes.NewReader(body))
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, post)
	if postRec.Code != 201 {
		t.Fatalf("POST /admin/control = %d, want 201; body: %s", postRec.Code, postRec.Body)
	}

	get := httptest.NewRequest("GET", "/admin/status", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, get)
	if getRec.Code != 200 {
		t.Fatalf("GET /admin/status = %d", getRec.Code)
	}

	var status adminStatusResp
	if err := json.Unmarshal(getRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if len(status.Programs) == 0 || len(status.Programs[0].Active) == 0 {
		t.Fatalf("program 0 has no active control after activate=true")
	}
	got := status.Programs[0].Active[0].Base.ExpLimW
	if got == nil || *got != 40000 {
		t.Fatalf("active control exp_lim_W = %v, want 40000", got)
	}
}

// adminStatus is a test helper: GET /admin/status decoded.
func adminStatus(t *testing.T, h http.Handler) adminStatusResp {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/status", nil))
	if rec.Code != 200 {
		t.Fatalf("GET /admin/status = %d", rec.Code)
	}
	var status adminStatusResp
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return status
}

func postControl(t *testing.T, h http.Handler, body string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/control", bytes.NewReader([]byte(body))))
	if rec.Code != 201 {
		t.Fatalf("POST /admin/control = %d; body: %s", rec.Code, rec.Body)
	}
}

// Regression for audit finding GS-2: a control with a future start must be
// created as Scheduled (status 0) and must not appear in the active list;
// an immediate control is Active (status 1) and does.
func TestAdminControl_EventStatusFollowsWindow(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	// Program 1 starts with an empty active list and 2 scheduled controls.
	// Future event (+120 s): Scheduled, active list untouched.
	postControl(t, h, `{"program":1,"exp_lim_W":4000,"start_offset_s":120,"duration_s":300}`)
	st := adminStatus(t, h)
	p1 := st.Programs[1]
	if len(p1.Active) != 0 {
		t.Errorf("future control leaked into active list: %+v", p1.Active)
	}
	found := false
	for _, c := range p1.Scheduled {
		if c.Base.ExpLimW != nil && *c.Base.ExpLimW == 4000 {
			found = true
			if c.Status != 0 {
				t.Errorf("future control status = %d, want 0 (Scheduled)", c.Status)
			}
		}
	}
	if !found {
		t.Fatal("future control not found in scheduled list")
	}

	// Immediate event with activate=true: replaces both lists, status 1.
	postControl(t, h, `{"program":1,"exp_lim_W":3000,"duration_s":300,"activate":true}`)
	st = adminStatus(t, h)
	p1 = st.Programs[1]
	if len(p1.Active) != 1 || p1.Active[0].Status != 1 {
		t.Fatalf("immediate activate: active = %+v, want one entry with status 1", p1.Active)
	}

	// Future event with activate=true: replaces derc, clears the active list.
	postControl(t, h, `{"program":1,"exp_lim_W":2000,"start_offset_s":600,"duration_s":300,"activate":true}`)
	st = adminStatus(t, h)
	p1 = st.Programs[1]
	if len(p1.Active) != 0 {
		t.Errorf("future activate: active list not cleared: %+v", p1.Active)
	}
	if len(p1.Scheduled) != 1 || p1.Scheduled[0].Status != 0 {
		t.Fatalf("future activate: scheduled = %+v, want one entry with status 0", p1.Scheduled)
	}
}

// Clock skew: POST /admin/clock must warp /admin/status server_time and the
// Start stamp of subsequently created controls, so the hub's scheduler
// (which trusts /tm-derived serverNow) agrees with gridsim about event
// windows during accelerated replay. offset 0 restores wall time.
func TestAdminClock_SkewsServerTimeAndControlStart(t *testing.T) {
	s := NewServer("")
	h := s.AdminHandler()

	doJSON := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	const skew = int64(30 * 24 * 3600) // 30 days ahead
	rec := doJSON("POST", "/admin/clock", []byte(`{"offset_s":2592000}`))
	if rec.Code != 200 {
		t.Fatalf("POST /admin/clock = %d; body: %s", rec.Code, rec.Body)
	}
	var clk struct {
		OffsetS    int64 `json:"offset_s"`
		ServerTime int64 `json:"server_time"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &clk); err != nil {
		t.Fatal(err)
	}
	if clk.OffsetS != skew {
		t.Fatalf("offset_s = %d, want %d", clk.OffsetS, skew)
	}
	wallNow := clk.ServerTime - skew

	// A control created under skew must start in skewed time.
	rec = doJSON("POST", "/admin/control", []byte(`{"program":0,"imp_lim_W":500,"duration_s":300,"activate":true}`))
	if rec.Code != 201 {
		t.Fatalf("POST /admin/control = %d", rec.Code)
	}
	rec = doJSON("GET", "/admin/status", nil)
	var status struct {
		ServerTime int64 `json:"server_time"`
		Programs   []struct {
			Active []struct {
				Start int64 `json:"start"`
			} `json:"active"`
		} `json:"programs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if got := status.ServerTime - wallNow; got < skew-5 || got > skew+5 {
		t.Errorf("status server_time skew = %d, want ~%d", got, skew)
	}
	if len(status.Programs) == 0 || len(status.Programs[0].Active) == 0 {
		t.Fatal("expected an active control on program 0")
	}
	if got := status.Programs[0].Active[0].Start - wallNow; got < skew-5 || got > skew+5 {
		t.Errorf("control start skew = %d, want ~%d", got, skew)
	}

	// set_unix form and reset-to-zero.
	rec = doJSON("POST", "/admin/clock", []byte(`{"offset_s":0}`))
	if rec.Code != 200 {
		t.Fatalf("reset POST /admin/clock = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &clk); err != nil {
		t.Fatal(err)
	}
	if clk.OffsetS != 0 {
		t.Errorf("offset after reset = %d, want 0", clk.OffsetS)
	}
}

// TestAdminAlerts_RecordsCannotComply verifies that only CannotComply Responses
// (status ≥ alertStatusFloor) register as compliance alerts, and that
// GET /admin/alerts surfaces them for the dashboard.
func TestAdminAlerts_RecordsCannotComply(t *testing.T) {
	s := NewServer("")

	// A normal lifecycle Response (Started=2) must NOT register as an alert.
	ok := `<Response xmlns="urn:ieee:std:2030.5:ns"><endDeviceLFDI>ABC</endDeviceLFDI><status>2</status><subject>EVT-1</subject></Response>`
	s.handleResponsePost(httptest.NewRecorder(),
		httptest.NewRequest("POST", "/rsps/0/r", bytes.NewReader([]byte(ok))), "/rsps/0/r")

	// A CannotComply Response (status 240) must register as an alert.
	bad := `<Response xmlns="urn:ieee:std:2030.5:ns"><endDeviceLFDI>ABC</endDeviceLFDI><status>240</status><subject>EVT-2</subject></Response>`
	s.handleResponsePost(httptest.NewRecorder(),
		httptest.NewRequest("POST", "/rsps/0/r", bytes.NewReader([]byte(bad))), "/rsps/0/r")

	alerts := s.ComplianceAlerts()
	if len(alerts) != 1 {
		t.Fatalf("got %d compliance alerts, want 1 (only the CannotComply)", len(alerts))
	}
	if alerts[0].Subject != "EVT-2" || alerts[0].Status != 240 {
		t.Errorf("alert = %+v, want subject=EVT-2 status=240", alerts[0])
	}

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/admin/alerts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/alerts = %d, want 200", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("EVT-2")) {
		t.Errorf("/admin/alerts body missing the alert: %s", rec.Body.String())
	}
}

// TestAdminStatus_PublishesTheAdvertisedPollRate: the rate a poll_rate_mode
// "honor" client keeps is the SERVER's, so the server is the only honest place
// to ask. A conformance harness sizing an observation window used to read the
// DUT's own configured interval, which is a floor — and waited for a walk the
// server had told the device not to make.
func TestAdminStatus_PublishesTheAdvertisedPollRate(t *testing.T) {
	s := NewServer("")

	// The stock tree already advertises something; whatever it is, the status
	// endpoint must report the same number the client's pacing would compute.
	if got, want := advertisedFromStatus(t, s), s.AdvertisedPollRate(); got != want {
		t.Fatalf("/admin/status poll_rate_s = %d, want %d", got, want)
	}
	stock := s.AdvertisedPollRate()
	if stock == 0 {
		t.Fatal("the stock tree advertises no pollRate at all, so a client honouring it has nothing to pace to")
	}

	s.SetAdvertisedPollRate(60)
	if got := advertisedFromStatus(t, s); got != 60 {
		t.Errorf("after -poll-rate-s 60 the status reports %d, want 60", got)
	}
	if stock <= 60 {
		t.Fatalf("the stock advertised rate is %d: this test cannot show that the maximum, not the "+
			"minimum, governs", stock)
	}
}

// TestAdvertisedPollRateIsTheSlowestAdvertisement pins the rule the DUT
// applies: it paces at the MAXIMUM advertised rate, so one resource left at 300
// holds the whole walk to 300 however fast /dcap says to go. Reading the
// minimum here would tell a harness to wait a fifth of the time the device
// takes.
func TestAdvertisedPollRateIsTheSlowestAdvertisement(t *testing.T) {
	s := NewServer("")
	s.SetAdvertisedPollRate(60)
	if got := s.AdvertisedPollRate(); got != 60 {
		t.Fatalf("AdvertisedPollRate = %d, want 60", got)
	}

	// One DERControlList left behind at 300 — exactly the case the fast path
	// misses — must drag the answer back up to 300.
	s.mu.Lock()
	for path, r := range s.resources {
		if l, ok := r.(*model.DERControlList); ok {
			l.PollRate = 300
			t.Logf("left %s advertising 300", path)
			break
		}
	}
	s.mu.Unlock()
	if got := s.AdvertisedPollRate(); got != 300 {
		t.Errorf("AdvertisedPollRate = %d, want 300: the slowest advertisement paces the walk", got)
	}
	if got := advertisedFromStatus(t, s); got != 300 {
		t.Errorf("/admin/status poll_rate_s = %d, want 300", got)
	}
}

func advertisedFromStatus(t *testing.T, s *Server) uint32 {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/admin/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/status = %d", rec.Code)
	}
	var got struct {
		PollRateS uint32 `json:"poll_rate_s"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got.PollRateS
}

// TestAdminStatus_IdentifiesItsOwnProcessAndDataPlane: two reachable ports do
// not prove one process. An orphaned gridsim held the admin port beside a live
// one holding the data port, and a harness read one server's observations about
// the other server's traffic — publishing "the DUT never dialled" for hours.
// The status endpoint answers the question that ends it.
func TestAdminStatus_IdentifiesItsOwnProcessAndDataPlane(t *testing.T) {
	s := NewServer("")

	var before struct {
		PID       int    `json:"pid"`
		DataPlane string `json:"data_plane"`
	}
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/admin/status", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &before); err != nil {
		t.Fatal(err)
	}
	if before.PID != os.Getpid() {
		t.Errorf("pid = %d, want this process (%d)", before.PID, os.Getpid())
	}
	// An embedding binary that never published a listener must not have one
	// invented for it: "unknown" is a usable answer, a guess is not.
	if before.DataPlane != "" {
		t.Errorf("data_plane = %q before any listener was published", before.DataPlane)
	}

	s.SetDataPlaneAddr("0.0.0.0:11113")
	if got := s.DataPlaneAddr(); got != "0.0.0.0:11113" {
		t.Errorf("DataPlaneAddr = %q", got)
	}
	var after struct {
		DataPlane string `json:"data_plane"`
	}
	rec = httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/admin/status", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after.DataPlane != "0.0.0.0:11113" {
		t.Errorf("data_plane = %q, want the published listener address", after.DataPlane)
	}
}
