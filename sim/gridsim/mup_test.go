package gridsim

// mup_test.go covers the MirrorUsagePoint registration flow's durable admin
// record (BASIC-029, audit 2026-07-30): GET /admin/mups, the ReadingType uom
// extraction that model.MirrorUsagePoint's XML unmarshal silently drops, and
// the read-only enforcement every other admin surface gets.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// adminMUPsResp mirrors the JSON body of GET /admin/mups for test decoding.
type adminMUPsResp struct {
	MUPs       []AdminMUP `json:"mups"`
	ServerTime int64      `json:"server_time"`
}

func getAdminMUPs(t *testing.T, s *Server) adminMUPsResp {
	t.Helper()
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/mups", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/mups = %d, want 200: %s", rec.Code, rec.Body)
	}
	var got adminMUPsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET /admin/mups: bad JSON: %v (%s)", err, rec.Body)
	}
	return got
}

// TestAdminMUPs_EmptyByDefault: a fresh server has registered nothing.
func TestAdminMUPs_EmptyByDefault(t *testing.T) {
	s := NewServer("")
	got := getAdminMUPs(t, s)
	if len(got.MUPs) != 0 {
		t.Fatalf("fresh server: /admin/mups = %+v, want none", got.MUPs)
	}
	if got.ServerTime == 0 {
		t.Error("server_time should be populated")
	}
}

// TestAdminMUPs_ReadOnly: like every other admin observation surface,
// /admin/mups answers 405 to anything but GET.
func TestAdminMUPs_ReadOnly(t *testing.T) {
	s := NewServer("")
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(method, "/admin/mups", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /admin/mups = %d, want 405", method, rec.Code)
		}
	}
}

// TestMUPCreate_RecordsAdminState is the core regression lock: registering a
// MirrorUsagePoint must publish a durable record — the mTLS-authenticated
// peer LFDI (not a self-declared body value), the ReadingType uom(s) the body
// embeds anywhere under the element (this DUT nests ReadingType directly
// inside the MirrorUsagePoint POST, not under a separate MirrorMeterReading
// resource — see basic.go's critMUPRegistered Wire tier), and a created-at
// timestamp — that GET /admin/mups can still answer from long after the
// one-time registration POST has aged out of the request log's bounded ring.
func TestMUPCreate_RecordsAdminState(t *testing.T) {
	s := NewServer("")
	const lfdi = "8E5E2FEE3190F4058B54692EE57A2D673D347586"
	body := `<MirrorUsagePoint xmlns="urn:ieee:std:2030.5:ns">` +
		`<deviceLFDI>ignored-body-value</deviceLFDI>` +
		`<MirrorMeterReading><ReadingType><uom>38</uom></ReadingType></MirrorMeterReading>` +
		`</MirrorUsagePoint>`

	req := httptest.NewRequest(http.MethodPost, "/mup", bytes.NewReader([]byte(body)))
	req.Header.Set("X-Peer-LFDI", lfdi)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /mup = %d, want 201: %s", rec.Code, rec.Body)
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("POST /mup answered 201 with no Location header")
	}

	got := getAdminMUPs(t, s)
	if len(got.MUPs) != 1 {
		t.Fatalf("/admin/mups = %+v, want exactly 1 entry", got.MUPs)
	}
	m := got.MUPs[0]
	if m.Href != loc {
		t.Errorf("href = %q, want the Location the POST answered with (%q)", m.Href, loc)
	}
	// The mTLS-authenticated peer LFDI wins over whatever the body claimed —
	// handleMUPCreate already enforces this for the 2030.5 resource itself;
	// the admin record must agree.
	if m.LFDI != lfdi {
		t.Errorf("lfdi = %q, want the authenticated peer LFDI %q (not the body's claim)", m.LFDI, lfdi)
	}
	if len(m.ReadingTypes) != 1 || m.ReadingTypes[0] != 38 {
		t.Errorf("reading_types = %v, want [38]", m.ReadingTypes)
	}
	if m.Readings != 0 {
		t.Errorf("readings = %d, want 0 (no MirrorMeterReading POSTed yet)", m.Readings)
	}
	if m.CreatedAt == 0 {
		t.Error("created_at should be populated")
	}
}

// TestMUPReadings_MergeReadingTypesAndIncrementCount: a later POST of a
// reading is folded into the SAME record (matched by href) — its own
// ReadingType (a standards-shaped MirrorMeterReading declares one) is merged
// in without duplicating one already known, and the reading count increments.
func TestMUPReadings_MergeReadingTypesAndIncrementCount(t *testing.T) {
	s := NewServer("")
	regBody := `<MirrorUsagePoint xmlns="urn:ieee:std:2030.5:ns">` +
		`<ReadingType><uom>38</uom></ReadingType></MirrorUsagePoint>`
	req := httptest.NewRequest(http.MethodPost, "/mup", bytes.NewReader([]byte(regBody)))
	req.Header.Set("X-Peer-LFDI", "ABC123")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registration POST = %d, want 201", rec.Code)
	}
	href := rec.Header().Get("Location")

	reading := `<MirrorMeterReading xmlns="urn:ieee:std:2030.5:ns">` +
		`<ReadingType><uom>63</uom></ReadingType></MirrorMeterReading>`
	for i := 0; i < 2; i++ {
		rrec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rrec, httptest.NewRequest(http.MethodPost, href, bytes.NewReader([]byte(reading))))
		if rrec.Code != http.StatusNoContent {
			t.Fatalf("reading POST #%d = %d, want 204", i, rrec.Code)
		}
	}

	got := getAdminMUPs(t, s)
	if len(got.MUPs) != 1 {
		t.Fatalf("/admin/mups = %+v, want exactly 1 entry", got.MUPs)
	}
	m := got.MUPs[0]
	if m.Readings != 2 {
		t.Errorf("readings = %d, want 2", m.Readings)
	}
	wantUOMs := map[uint8]bool{38: true, 63: true}
	if len(m.ReadingTypes) != len(wantUOMs) {
		t.Fatalf("reading_types = %v, want exactly {38, 63} (deduped, registration's own uom kept)", m.ReadingTypes)
	}
	for _, u := range m.ReadingTypes {
		if !wantUOMs[u] {
			t.Errorf("unexpected uom %d in %v", u, m.ReadingTypes)
		}
	}
}

// TestMUPReadings_UnknownHrefIs404AndDoesNotFabricateARecord: a reading POST
// to an href nothing ever registered stays 404 (unchanged behaviour) and must
// not create an admin record out of thin air.
func TestMUPReadings_UnknownHrefIs404AndDoesNotFabricateARecord(t *testing.T) {
	s := NewServer("")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mup/999", bytes.NewReader(nil)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST to an unregistered /mup/{n} = %d, want 404", rec.Code)
	}
	if got := getAdminMUPs(t, s); len(got.MUPs) != 0 {
		t.Errorf("/admin/mups = %+v, want none (nothing was ever registered)", got.MUPs)
	}
}

// TestMupReadingTypeUOMs_FindsUomNestedAnywhere exercises the extraction
// helper directly against both shapes seen in practice: uom nested straight
// under a MirrorUsagePoint (this DUT's shape) and under a standards-shaped
// MirrorMeterReading. A body with no ReadingType at all yields nil, and
// non-numeric or out-of-range text is skipped rather than panicking.
func TestMupReadingTypeUOMs_FindsUomNestedAnywhere(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []uint8
	}{
		{"embedded in MirrorUsagePoint", `<MirrorUsagePoint xmlns="urn:ieee:std:2030.5:ns">` +
			`<ReadingType><uom>38</uom></ReadingType></MirrorUsagePoint>`, []uint8{38}},
		{"standard MirrorMeterReading", `<MirrorMeterReading xmlns="urn:ieee:std:2030.5:ns">` +
			`<ReadingType><uom>63</uom></ReadingType></MirrorMeterReading>`, []uint8{63}},
		{"multiple ReadingTypes", `<MirrorUsagePoint xmlns="urn:ieee:std:2030.5:ns">` +
			`<ReadingType><uom>38</uom></ReadingType><ReadingType><uom>33</uom></ReadingType>` +
			`</MirrorUsagePoint>`, []uint8{38, 33}},
		{"no ReadingType at all", `<MirrorUsagePoint xmlns="urn:ieee:std:2030.5:ns"><deviceLFDI>X</deviceLFDI></MirrorUsagePoint>`, nil},
		{"garbage uom text is skipped", `<MirrorUsagePoint xmlns="urn:ieee:std:2030.5:ns">` +
			`<ReadingType><uom>not-a-number</uom></ReadingType></MirrorUsagePoint>`, nil},
		{"not well-formed XML", `<MirrorUsagePoint>`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mupReadingTypeUOMs([]byte(c.body))
			if len(got) != len(c.want) {
				t.Fatalf("mupReadingTypeUOMs(%q) = %v, want %v", c.body, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("mupReadingTypeUOMs(%q)[%d] = %d, want %d", c.body, i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestMergeUOMs_DedupesPreservingOrder: repeated MirrorMeterReading POSTs of
// the same ReadingType must not grow the list without bound, and the
// first-seen position is kept stable.
func TestMergeUOMs_DedupesPreservingOrder(t *testing.T) {
	got := mergeUOMs([]uint8{38}, []uint8{38, 63})
	want := []uint8{38, 63}
	if len(got) != len(want) {
		t.Fatalf("mergeUOMs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mergeUOMs[%d] = %d, want %d (order: first-seen keeps its position)", i, got[i], want[i])
		}
	}

	// Merging the same uom again must not duplicate it.
	got2 := mergeUOMs(got, []uint8{38})
	if len(got2) != 2 {
		t.Errorf("re-merging an already-known uom grew the list: %v", got2)
	}
}
