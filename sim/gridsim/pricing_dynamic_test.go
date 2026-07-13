package gridsim

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"csip-tls-test/internal/tariff"
	model "lexa-proto/csipmodel"
)

// A synthetic full-year, all-week two-tier TOU plan (internal/tariff schema).
// Import rates (period + 0.02 riders): night = 0.10, day = 0.22 $/kWh. The
// night period wraps midnight (21:00–06:00) — the midnight-wrap fixture.
const dynTariffJSON = `{
  "id": "test-dyn-tou",
  "name": "TEST Dynamic TOU",
  "short_name": "DynTOU",
  "utility": "Synthetic Test",
  "territory": "test",
  "timezone": "America/Chicago",
  "currency": "USD",
  "effective": { "from": "2025-01-01", "to": "2027-12-31" },
  "provenance": { "source_url": "https://example.test", "retrieved": "2026-07-12",
                  "confidence": "estimated", "notes": "synthetic dynamic-pricing test fixture" },
  "fixed_monthly_usd": 0.0,
  "energy": {
    "seasons": [{
      "id": "all", "months": [1,2,3,4,5,6,7,8,9,10,11,12],
      "day_types": [{
        "days": ["mon","tue","wed","thu","fri","sat","sun"],
        "periods": [
          { "id": "night", "label": "Night", "start": "21:00", "end": "06:00", "rate_usd_per_kwh": 0.08 },
          { "id": "day",   "label": "Day",   "start": "06:00", "end": "21:00", "rate_usd_per_kwh": 0.20 }
        ]
      }]
    }]
  },
  "riders_usd_per_kwh": 0.02,
  "export": { "type": "buyback", "rate_usd_per_kwh": 0.05 }
}`

func chicago(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatalf("load America/Chicago: %v", err)
	}
	return loc
}

func req(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func setClock(t *testing.T, admin http.Handler, unix int64) {
	t.Helper()
	rec := req(t, admin, "POST", "/admin/clock", []byte(fmt.Sprintf(`{"set_unix":%d}`, unix)))
	if rec.Code != 200 {
		t.Fatalf("POST /admin/clock = %d; body: %s", rec.Code, rec.Body)
	}
}

func loadTariff(t *testing.T, admin http.Handler, body string) tariffSummary {
	t.Helper()
	rec := req(t, admin, "POST", "/admin/tariff", []byte(body))
	if rec.Code != 200 {
		t.Fatalf("POST /admin/tariff = %d; body: %s", rec.Code, rec.Body)
	}
	var sum tariffSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatalf("decode tariff summary: %v", err)
	}
	return sum
}

func getSummary(t *testing.T, admin http.Handler) (tariffSummary, int) {
	t.Helper()
	rec := req(t, admin, "GET", "/admin/tariff", nil)
	var sum tariffSummary
	if rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
			t.Fatalf("decode tariff summary: %v", err)
		}
	}
	return sum, rec.Code
}

func getTTIList(t *testing.T, main http.Handler, path string) model.TimeTariffIntervalList {
	t.Helper()
	rec := req(t, main, "GET", path, nil)
	if rec.Code != 200 {
		t.Fatalf("GET %s = %d", path, rec.Code)
	}
	var l model.TimeTariffIntervalList
	if err := xml.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return l
}

// TestPricingDynamic_LoadContiguousActive: loading a tariff yields a contiguous,
// gap-free TTI tiling of the ~48 h window with correct per-interval prices, and
// the active list is exactly the interval containing server time.
func TestPricingDynamic_LoadContiguousActive(t *testing.T) {
	loc := chicago(t)
	s := NewServer("")
	admin, main := s.AdminHandler(), s.Handler()

	noon := time.Date(2026, 7, 15, 12, 0, 0, 0, loc).Unix() // deep inside the Day period
	setClock(t, admin, noon)
	sum := loadTariff(t, admin, dynTariffJSON)

	if sum.TariffID != "test-dyn-tou" || sum.Name != "TEST Dynamic TOU" {
		t.Fatalf("summary id/name = %q/%q", sum.TariffID, sum.Name)
	}
	if len(sum.Intervals) < 2 {
		t.Fatalf("want multiple intervals, got %d", len(sum.Intervals))
	}

	// Contiguity + no overlap; window ~[now-24h, now+24h).
	for i := 1; i < len(sum.Intervals); i++ {
		if sum.Intervals[i].Start != sum.Intervals[i-1].End {
			t.Errorf("gap/overlap: interval[%d].start=%d != interval[%d].end=%d",
				i, sum.Intervals[i].Start, i-1, sum.Intervals[i-1].End)
		}
	}
	span := sum.Intervals[len(sum.Intervals)-1].End - sum.Intervals[0].Start
	if span < 47*3600 || span > 49*3600 {
		t.Errorf("window span = %ds, want ~48h", span)
	}

	// Active = Day at noon: import rate 0.20 + 0.02 = 0.22, contains now.
	if sum.ActivePeriod.ID != "day" {
		t.Fatalf("active period id = %q, want day", sum.ActivePeriod.ID)
	}
	if !approx(sum.ActivePeriod.RateUSDPerKWh, 0.22) {
		t.Errorf("active rate = %g, want 0.22", sum.ActivePeriod.RateUSDPerKWh)
	}
	if !(sum.ActivePeriod.Start <= noon && noon < sum.ActivePeriod.End) {
		t.Errorf("active period [%d,%d) does not contain now=%d",
			sum.ActivePeriod.Start, sum.ActivePeriod.End, noon)
	}

	// XML tree: TTI list matches the summary count; the active list holds exactly
	// one interval whose start equals the summary's active start; TouTier ranks
	// price (day=2 > night=1); the active interval's CTI price = 22000 (0.22).
	ttis := getTTIList(t, main, "/tp/0/rc/0/tti")
	if int(ttis.All) != len(sum.Intervals) || len(ttis.TimeTariffInterval) != len(sum.Intervals) {
		t.Errorf("tti list all=%d len=%d, want %d", ttis.All, len(ttis.TimeTariffInterval), len(sum.Intervals))
	}
	act := getTTIList(t, main, "/tp/0/rc/0/acttti")
	if act.All != 1 || len(act.TimeTariffInterval) != 1 {
		t.Fatalf("acttti all=%d len=%d, want 1", act.All, len(act.TimeTariffInterval))
	}
	if act.TimeTariffInterval[0].Interval.Start != sum.ActivePeriod.Start {
		t.Errorf("acttti start=%d != summary active start=%d",
			act.TimeTariffInterval[0].Interval.Start, sum.ActivePeriod.Start)
	}
	// Find the active interval's index in the full list, read its CTI price.
	idx := -1
	for i, iv := range ttis.TimeTariffInterval {
		if iv.Interval.Start == sum.ActivePeriod.Start {
			idx = i
			if iv.Description != "Day" || iv.TouTier != 2 {
				t.Errorf("active tti desc=%q touTier=%d, want Day/2", iv.Description, iv.TouTier)
			}
		}
	}
	if idx < 0 {
		t.Fatal("active interval not found in tti list")
	}
	assertCTIPrice(t, main, fmt.Sprintf("/tp/0/rc/0/tti/%d/cti", idx), 22000)
}

func assertCTIPrice(t *testing.T, main http.Handler, path string, want int32) {
	t.Helper()
	rec := req(t, main, "GET", path, nil)
	if rec.Code != 200 {
		t.Fatalf("GET %s = %d", path, rec.Code)
	}
	var cti model.ConsumptionTariffIntervalList
	if err := xml.Unmarshal(rec.Body.Bytes(), &cti); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if len(cti.ConsumptionTariffInterval) != 1 || cti.ConsumptionTariffInterval[0].Price != want {
		t.Errorf("%s price = %+v, want %d", path, cti.ConsumptionTariffInterval, want)
	}
}

// TestPricingDynamic_ActiveFollowsWarpedClock: warping the clock regenerates the
// tree so the active interval tracks warped server time, matching an independent
// RateAt over the same tariff.
func TestPricingDynamic_ActiveFollowsWarpedClock(t *testing.T) {
	loc := chicago(t)
	parsed, err := tariff.Parse([]byte(dynTariffJSON))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	s := NewServer("")
	admin := s.AdminHandler()

	base := time.Date(2026, 7, 15, 12, 0, 0, 0, loc).Unix()
	setClock(t, admin, base)
	loadTariff(t, admin, dynTariffJSON)

	for _, tc := range []struct {
		name string
		at   int64
		want string // period id
	}{
		{"noon-day", base, "day"},
		{"+12h-midnight-night", base + 12*3600, "night"},
		{"-6h-morning-day", base - 6*3600, "day"},    // 06:00 → day boundary start
		{"+10h-late-night", base + 10*3600, "night"}, // 22:00 → night
	} {
		t.Run(tc.name, func(t *testing.T) {
			setClock(t, admin, tc.at) // clock hook regenerates the window
			sum, code := getSummary(t, admin)
			if code != 200 {
				t.Fatalf("GET /admin/tariff = %d", code)
			}
			exp := parsed.RateAt(time.Unix(tc.at, 0))
			if sum.ActivePeriod.ID != tc.want || sum.ActivePeriod.ID != exp.PeriodID {
				t.Errorf("active id=%q, want %q (RateAt=%q)", sum.ActivePeriod.ID, tc.want, exp.PeriodID)
			}
			if !approx(sum.ActivePeriod.RateUSDPerKWh, exp.ImportUSDPerKWh) {
				t.Errorf("active rate=%g, want %g", sum.ActivePeriod.RateUSDPerKWh, exp.ImportUSDPerKWh)
			}
			if !(sum.ActivePeriod.Start <= tc.at && tc.at < sum.ActivePeriod.End) {
				t.Errorf("active [%d,%d) does not contain warped now=%d",
					sum.ActivePeriod.Start, sum.ActivePeriod.End, tc.at)
			}
		})
	}
}

// TestPricingDynamic_MidnightWrap: at 23:00 the active interval is the single
// 21:00→06:00 night interval spanning midnight — 9 h, not split at 00:00.
func TestPricingDynamic_MidnightWrap(t *testing.T) {
	loc := chicago(t)
	s := NewServer("")
	admin := s.AdminHandler()

	at := time.Date(2026, 7, 15, 23, 0, 0, 0, loc).Unix()
	setClock(t, admin, at)
	sum := loadTariff(t, admin, dynTariffJSON)

	if sum.ActivePeriod.ID != "night" {
		t.Fatalf("active id = %q, want night", sum.ActivePeriod.ID)
	}
	if dur := sum.ActivePeriod.End - sum.ActivePeriod.Start; dur != 9*3600 {
		t.Errorf("night interval duration = %ds, want 9h (32400) — should not split at midnight", dur)
	}
	// Local wall clock: starts 21:00, ends 06:00.
	if h := time.Unix(sum.ActivePeriod.Start, 0).In(loc).Hour(); h != 21 {
		t.Errorf("night interval local start hour = %d, want 21", h)
	}
	if h := time.Unix(sum.ActivePeriod.End, 0).In(loc).Hour(); h != 6 {
		t.Errorf("night interval local end hour = %d, want 6", h)
	}
	// And it genuinely straddles midnight.
	if time.Unix(sum.ActivePeriod.Start, 0).In(loc).Day() == time.Unix(sum.ActivePeriod.End, 0).In(loc).Day() {
		t.Error("night interval does not cross a day boundary")
	}
}

// TestPricingDynamic_DeleteRestoresLegacy: DELETE clears the dynamic tree and
// restores the legacy static two-tier tree (2 intervals, 12000/45000, 12h/6h),
// with no stale dynamic intervals lingering, and GET /admin/tariff → 404.
func TestPricingDynamic_DeleteRestoresLegacy(t *testing.T) {
	loc := chicago(t)
	s := NewServer("")
	admin, main := s.AdminHandler(), s.Handler()

	// Load a tariff that generates many intervals (48h → >2), then delete.
	setClock(t, admin, time.Date(2026, 7, 15, 12, 0, 0, 0, loc).Unix())
	loadTariff(t, admin, dynTariffJSON)
	if l := getTTIList(t, main, "/tp/0/rc/0/tti"); l.All <= 2 {
		t.Fatalf("dynamic tree only has %d intervals; test needs >2 to prove cleanup", l.All)
	}

	rec := req(t, admin, "DELETE", "/admin/tariff", nil)
	if rec.Code != 204 {
		t.Fatalf("DELETE /admin/tariff = %d, want 204", rec.Code)
	}

	// Legacy static tree back: exactly 2 intervals, off-peak then peak.
	l := getTTIList(t, main, "/tp/0/rc/0/tti")
	if l.All != 2 || len(l.TimeTariffInterval) != 2 {
		t.Fatalf("post-delete tti all=%d len=%d, want 2", l.All, len(l.TimeTariffInterval))
	}
	if d := l.TimeTariffInterval[0].Interval.Duration; d != 12*3600 {
		t.Errorf("off-peak duration = %d, want 12h", d)
	}
	if d := l.TimeTariffInterval[1].Interval.Duration; d != 6*3600 {
		t.Errorf("peak duration = %d, want 6h", d)
	}
	assertCTIPrice(t, main, "/tp/0/rc/0/tti/0/cti", 12000)
	assertCTIPrice(t, main, "/tp/0/rc/0/tti/1/cti", 45000)

	// No stale dynamic interval beyond index 1.
	if rec := req(t, main, "GET", "/tp/0/rc/0/tti/2/cti", nil); rec.Code != 404 {
		t.Errorf("stale dynamic CTI /tp/0/rc/0/tti/2/cti still served: %d", rec.Code)
	}
	// GET /admin/tariff now reports no dynamic tariff.
	if _, code := getSummary(t, admin); code != 404 {
		t.Errorf("GET /admin/tariff after delete = %d, want 404", code)
	}
}

// TestPricingDynamic_FreshServerLegacyTree: a brand-new server (no tariff) serves
// the exact legacy static pricing tree — the byte-for-byte back-compat contract.
func TestPricingDynamic_FreshServerLegacyTree(t *testing.T) {
	s := NewServer("")
	main := s.Handler()
	l := getTTIList(t, main, "/tp/0/rc/0/tti")
	if l.All != 2 {
		t.Fatalf("fresh server tti all=%d, want 2 (static tree)", l.All)
	}
	assertCTIPrice(t, main, "/tp/0/rc/0/tti/0/cti", 12000)
	assertCTIPrice(t, main, "/tp/0/rc/0/tti/1/cti", 45000)
	if _, code := getSummary(t, s.AdminHandler()); code != 404 {
		t.Errorf("GET /admin/tariff on fresh server = %d, want 404", code)
	}
}

// TestPricingDynamic_InvalidLeavesTreeIntact: an invalid tariff → 400 and the
// previously loaded tree is untouched; an invalid tariff with nothing loaded →
// 400 and the legacy static tree is untouched.
func TestPricingDynamic_InvalidLeavesTreeIntact(t *testing.T) {
	loc := chicago(t)
	s := NewServer("")
	admin, main := s.AdminHandler(), s.Handler()

	// (a) Invalid with no tariff loaded: 400, static tree intact, still 404.
	rec := req(t, admin, "POST", "/admin/tariff", []byte(`{"not":"a tariff"}`))
	if rec.Code != 400 {
		t.Fatalf("POST invalid (fresh) = %d, want 400", rec.Code)
	}
	if l := getTTIList(t, main, "/tp/0/rc/0/tti"); l.All != 2 {
		t.Errorf("static tree disturbed by rejected POST: all=%d", l.All)
	}
	if _, code := getSummary(t, admin); code != 404 {
		t.Errorf("GET /admin/tariff still 404 expected, got %d", code)
	}

	// Load a valid tariff, capture its summary.
	setClock(t, admin, time.Date(2026, 7, 15, 12, 0, 0, 0, loc).Unix())
	before := loadTariff(t, admin, dynTariffJSON)

	// (b) Malformed JSON → 400, previous dynamic tree unchanged.
	if rec := req(t, admin, "POST", "/admin/tariff", []byte(`{bad json`)); rec.Code != 400 {
		t.Fatalf("POST malformed = %d, want 400", rec.Code)
	}
	// (c) Well-formed JSON failing Validate (rate over the 5 $/kWh ceiling) → 400.
	badRate := `{"id":"x","name":"x","currency":"USD","timezone":"America/Chicago",
	  "effective":{"from":"2025-01-01","to":"2025-12-31"},
	  "provenance":{"confidence":"estimated"},
	  "energy":{"seasons":[{"id":"all","months":[1,2,3,4,5,6,7,8,9,10,11,12],
	    "day_types":[{"days":["mon","tue","wed","thu","fri","sat","sun"],
	      "periods":[{"id":"p","label":"P","start":"00:00","end":"24:00","rate_usd_per_kwh":9.99}]}]}]},
	  "export":{"type":"none"}}`
	if rec := req(t, admin, "POST", "/admin/tariff", []byte(badRate)); rec.Code != 400 {
		t.Fatalf("POST over-ceiling rate = %d, want 400", rec.Code)
	}

	after, code := getSummary(t, admin)
	if code != 200 {
		t.Fatalf("GET /admin/tariff after rejected POSTs = %d", code)
	}
	if after.TariffID != before.TariffID || len(after.Intervals) != len(before.Intervals) {
		t.Errorf("previous tree changed by rejected POST: before id=%s n=%d, after id=%s n=%d",
			before.TariffID, len(before.Intervals), after.TariffID, len(after.Intervals))
	}
}

// TestPricingDynamic_Race hammers the pricing tree concurrently — reads of the
// XML tree, clock warps that regenerate it, and summary GETs — to exercise the
// mu discipline under `go test -race`.
func TestPricingDynamic_Race(t *testing.T) {
	loc := chicago(t)
	s := NewServer("")
	admin, main := s.AdminHandler(), s.Handler()
	base := time.Date(2026, 7, 15, 12, 0, 0, 0, loc).Unix()
	setClock(t, admin, base)
	loadTariff(t, admin, dynTariffJSON)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers of the served XML tree (lazy staleness path).
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					req(t, main, "GET", "/tp/0/rc/0/tti", nil)
					req(t, main, "GET", "/tp/0/rc/0/acttti", nil)
				}
			}
		}()
	}
	// Summary readers.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					req(t, admin, "GET", "/admin/tariff", nil)
				}
			}
		}()
	}
	// Clock warps that force full regeneration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for h := 0; h < 200; h++ {
			select {
			case <-stop:
				return
			default:
				setClockRace(admin, base+int64(h)*3600)
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// setClockRace is a fatal-free clock POST for use inside goroutines (t.Fatalf
// must not be called from a non-test goroutine).
func setClockRace(admin http.Handler, unix int64) {
	req0 := httptest.NewRequest("POST", "/admin/clock", bytes.NewReader([]byte(fmt.Sprintf(`{"set_unix":%d}`, unix))))
	admin.ServeHTTP(httptest.NewRecorder(), req0)
}

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}
