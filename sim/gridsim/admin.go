package gridsim

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	model "lexa-proto/csipmodel"
)

// AdminHandler returns a plain HTTP handler for the gridsim management API.
// Mount this on a separate port (default 11112) — it is NOT mTLS-protected.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/status", cors(s.handleAdminStatus))
	mux.HandleFunc("/admin/control", cors(s.handleAdminControl))
	mux.HandleFunc("/admin/curve", cors(s.handleAdminCurve))
	mux.HandleFunc("/admin/default", cors(s.handleAdminDefault))
	mux.HandleFunc("/admin/clock", cors(s.handleAdminClock))
	mux.HandleFunc("/admin/tariff", cors(s.handleAdminTariff))
	mux.HandleFunc("/admin/alerts", cors(s.handleAdminAlerts))
	mux.HandleFunc("/admin/malform", cors(s.handleAdminMalform))
	mux.HandleFunc("/admin/outage", cors(s.handleAdminOutage))
	mux.HandleFunc("/admin/redirect", cors(s.handleAdminRedirect))
	mux.HandleFunc("/admin/derputs", cors(s.handleAdminDERPuts))
	mux.HandleFunc("/admin/logevents", cors(s.handleAdminLogEvents))
	mux.HandleFunc("/admin/logs", cors(s.logBuf.ServeHTTP))
	return mux
}

// handleAdminAlerts returns the CannotComply Responses the hub has POSTed —
// the observable proof that the DER reported it could not meet a control.
func (s *Server) handleAdminAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	alerts := s.ComplianceAlerts()
	if alerts == nil {
		alerts = []ComplianceAlert{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"alerts":      alerts,
		"server_time": s.Now(),
	})
}

func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

// ── Status ───────────────────────────────────────────────────────────────────

type adminCtrlInfo struct {
	MRID        string        `json:"mrid"`
	Description string        `json:"description"`
	Start       int64         `json:"start"`
	DurationS   int           `json:"duration_s"`
	Status      int           `json:"status"`
	Base        adminBaseInfo `json:"base"`
	// Curve names the bound DER curve for a curve-linked (extended) control,
	// e.g. "volt_var -> /derp/0/dc/0". Empty for scalar controls.
	Curve string `json:"curve,omitempty"`
}

// adminBaseInfo mirrors DERControlBase as JSON-friendly nullable fields.
type adminBaseInfo struct {
	ExpLimW        *int64 `json:"exp_lim_W,omitempty"`
	MaxLimW        *int64 `json:"max_lim_W,omitempty"`
	ImpLimW        *int64 `json:"imp_lim_W,omitempty"`
	GenLimW        *int64 `json:"gen_lim_W,omitempty"`
	LoadLimW       *int64 `json:"load_lim_W,omitempty"`
	FixedW         *int64 `json:"fixed_W,omitempty"`
	Connect        *bool  `json:"connect,omitempty"`
	Energize       *bool  `json:"energize,omitempty"`
	FixedPFInjectW *int64 `json:"fixed_pf_inject_pct,omitempty"`
	FixedPFAbsorbW *int64 `json:"fixed_pf_absorb_pct,omitempty"`
	FixedVarPct    *int64 `json:"fixed_var_pct,omitempty"`
}

type adminProgInfo struct {
	ID          int             `json:"id"`
	MRID        string          `json:"mrid"`
	Description string          `json:"description"`
	Primacy     int             `json:"primacy"`
	Default     *adminBaseInfo  `json:"default,omitempty"`
	Active      []adminCtrlInfo `json:"active"`
	Scheduled   []adminCtrlInfo `json:"scheduled"`
}

type adminStatusResp struct {
	Programs   []adminProgInfo `json:"programs"`
	ServerTime int64           `json:"server_time"`
}

var progMeta = []struct {
	MRID        string
	Description string
	Primacy     int
}{
	{"DERP-SP-001", "Service Point (primacy 1)", 1},
	{"DERP-SITE-001", "Site-Level (primacy 5)", 5},
	{"DERP-SYS-001", "System-Level (primacy 10)", 10},
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var programs []adminProgInfo
	for i, pm := range progMeta {
		ap := adminProgInfo{
			ID:          i,
			MRID:        pm.MRID,
			Description: pm.Description,
			Primacy:     pm.Primacy,
		}
		if dderc, ok := s.resources[fmt.Sprintf("/derp/%d/dderc", i)].(*model.DefaultDERControl); ok {
			b := baseToInfo(dderc.DERControlBase)
			ap.Default = &b
		}
		// derc/actderc hold *model.DERControlList normally, or
		// *model.ExtendedDERControlList once POST /admin/curve has bound a
		// curve-linked control (curve.go) — surface either.
		switch v := s.resources[fmt.Sprintf("/derp/%d/actderc", i)].(type) {
		case *model.DERControlList:
			for _, c := range v.DERControl {
				ap.Active = append(ap.Active, ctrlToInfo(c))
			}
		case *model.ExtendedDERControlList:
			for _, c := range v.DERControl {
				ap.Active = append(ap.Active, extCtrlToInfo(c))
			}
		}
		switch v := s.resources[fmt.Sprintf("/derp/%d/derc", i)].(type) {
		case *model.DERControlList:
			for _, c := range v.DERControl {
				ap.Scheduled = append(ap.Scheduled, ctrlToInfo(c))
			}
		case *model.ExtendedDERControlList:
			for _, c := range v.DERControl {
				ap.Scheduled = append(ap.Scheduled, extCtrlToInfo(c))
			}
		}
		programs = append(programs, ap)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminStatusResp{
		Programs:   programs,
		ServerTime: s.Now(),
	})
}

// ── Clock skew GET/POST ──────────────────────────────────────────────────────

// adminClockReq is the body for POST /admin/clock. Exactly one of the two
// fields is used: set_unix (absolute CSIP time) wins over offset_s.
type adminClockReq struct {
	OffsetS *int64 `json:"offset_s,omitempty"` // skew relative to wall clock
	SetUnix *int64 `json:"set_unix,omitempty"` // absolute server time to serve "now"
}

type adminClockResp struct {
	OffsetS    int64 `json:"offset_s"`
	ServerTime int64 `json:"server_time"`
}

func (s *Server) handleAdminClock(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// fall through to the response below
	case http.MethodPost:
		var req adminClockReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch {
		case req.SetUnix != nil:
			s.SetClockSkew(*req.SetUnix - time.Now().Unix())
		case req.OffsetS != nil:
			s.SetClockSkew(*req.OffsetS)
		default:
			http.Error(w, "offset_s or set_unix required", http.StatusBadRequest)
			return
		}
		log.Printf("[gridsim] clock skew set: offset=%ds server_time=%d", s.ClockSkew(), s.Now())
		// A dynamic tariff's window is centered on server time, so re-check it
		// now that the clock has been warped (no-op on the legacy static tree,
		// and a cheap no-op when the warp stays inside the current interval —
		// replay warps the clock every tick, so the minimal refresh matters).
		s.mu.Lock()
		if s.tariff != nil {
			s.refreshPricingLocked(s.Now())
		}
		s.mu.Unlock()
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminClockResp{
		OffsetS:    s.ClockSkew(),
		ServerTime: s.Now(),
	})
}

func ctrlToInfo(c model.DERControl) adminCtrlInfo {
	info := adminCtrlInfo{
		MRID:        c.MRID,
		Description: c.Description,
		Start:       c.Interval.Start,
		DurationS:   int(c.Interval.Duration),
		Base:        baseToInfo(c.DERControlBase),
	}
	if c.EventStatus != nil {
		info.Status = int(c.EventStatus.CurrentStatus)
	}
	return info
}

func baseToInfo(b model.DERControlBase) adminBaseInfo {
	info := adminBaseInfo{
		Connect:  b.OpModConnect,
		Energize: b.OpModEnergize,
	}
	if b.OpModExpLimW != nil {
		v := apW(b.OpModExpLimW)
		info.ExpLimW = &v
	}
	if b.OpModMaxLimW != nil {
		v := apW(b.OpModMaxLimW)
		info.MaxLimW = &v
	}
	if b.OpModImpLimW != nil {
		v := apW(b.OpModImpLimW)
		info.ImpLimW = &v
	}
	if b.OpModGenLimW != nil {
		v := apW(b.OpModGenLimW)
		info.GenLimW = &v
	}
	if b.OpModLoadLimW != nil {
		v := apW(b.OpModLoadLimW)
		info.LoadLimW = &v
	}
	if b.OpModFixedW != nil {
		v := apW(b.OpModFixedW)
		info.FixedW = &v
	}
	if b.OpModFixedPFInjectW != nil {
		v := int64(b.OpModFixedPFInjectW.Value)
		info.FixedPFInjectW = &v
	}
	if b.OpModFixedPFAbsorbW != nil {
		v := int64(b.OpModFixedPFAbsorbW.Value)
		info.FixedPFAbsorbW = &v
	}
	if b.OpModFixedVar != nil {
		v := int64(b.OpModFixedVar.Value.Value)
		info.FixedVarPct = &v
	}
	return info
}

func apW(ap *model.ActivePower) int64 {
	return int64(math.Round(float64(ap.Value) * math.Pow10(int(ap.Multiplier))))
}

// ── Control POST/DELETE ───────────────────────────────────────────────────────

// adminCtrlReq is the JSON body for POST /admin/control.
// All OpMod fields are optional (nil = not included in the control).
type adminCtrlReq struct {
	Program     int    `json:"program"`
	Description string `json:"description"`
	StartOffset int    `json:"start_offset_s"` // seconds from now
	DurationS   int    `json:"duration_s"`     // default 300
	Activate    bool   `json:"activate"`       // true = replace active list

	// DERControlBase fields — only non-nil ones are included in the event.
	ExpLimW        *int64 `json:"exp_lim_W,omitempty"`
	MaxLimW        *int64 `json:"max_lim_W,omitempty"`
	ImpLimW        *int64 `json:"imp_lim_W,omitempty"`
	GenLimW        *int64 `json:"gen_lim_W,omitempty"`
	LoadLimW       *int64 `json:"load_lim_W,omitempty"`
	FixedW         *int64 `json:"fixed_W,omitempty"`
	Connect        *bool  `json:"connect,omitempty"`
	Energize       *bool  `json:"energize,omitempty"`
	FixedPFInjectW *int64 `json:"fixed_pf_inject_pct,omitempty"`
	FixedPFAbsorbW *int64 `json:"fixed_pf_absorb_pct,omitempty"`
	FixedVarPct    *int64 `json:"fixed_var_pct,omitempty"`
}

func (s *Server) handleAdminControl(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.adminCtrlPost(w, r)
	case http.MethodDelete:
		s.adminCtrlDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

var progPrefixes = []string{"SP", "SITE", "SYS"}

func (s *Server) adminCtrlPost(w http.ResponseWriter, r *http.Request) {
	var req adminCtrlReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}
	if req.DurationS <= 0 {
		req.DurationS = 300
	}
	if req.Description == "" {
		req.Description = "Admin control"
	}

	// Control intervals are stamped in server (possibly skewed) time so the
	// hub's scheduler — which compares against serverNow from /tm — agrees
	// with gridsim about when the window opens.
	now := s.Now()
	// Event status follows the IEEE 2030.5 event state machine (finding GS-2:
	// previously always 1/Active, even for events whose window hadn't opened —
	// a spec-correct client could have started them early).
	activeNow := req.StartOffset <= 0
	var status uint8
	if !activeNow {
		status = 0 // Scheduled
	} else {
		status = 1 // Active
	}
	ctrl := model.DERControl{
		Resource:     model.Resource{Href: fmt.Sprintf("/derp/%d/derc/admin", req.Program)},
		MRID:         fmt.Sprintf("DERC-%s-ADMIN-%d", progPrefixes[req.Program], now),
		Description:  req.Description,
		CreationTime: now,
		EventStatus: &model.EventStatus{
			CurrentStatus: status,
			DateTime:      now,
		},
		Interval: model.DateTimeInterval{
			Duration: uint32(req.DurationS),
			Start:    now + int64(req.StartOffset),
		},
		DERControlBase: buildBase(req),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Write to derc (scheduled list) — this is what the hub's walker reads via
	// DERControlListLink. The scheduler evaluates the time window and marks it
	// active when start <= serverNow < start+duration.
	dercPath := fmt.Sprintf("/derp/%d/derc", req.Program)
	// A prior POST /admin/curve may have left an ExtendedDERControlList here;
	// widen this scalar control into it rather than silently no-op'ing.
	switch dercList := s.resources[dercPath].(type) {
	case *model.DERControlList:
		if req.Activate {
			dercList.DERControl = []model.DERControl{ctrl}
		} else {
			dercList.DERControl = append(dercList.DERControl, ctrl)
		}
		dercList.All = uint32(len(dercList.DERControl))
		dercList.Results = dercList.All
	case *model.ExtendedDERControlList:
		ext := toExtendedControl(ctrl)
		if req.Activate {
			dercList.DERControl = []model.ExtendedDERControl{ext}
		} else {
			dercList.DERControl = append(dercList.DERControl, ext)
		}
		dercList.All = uint32(len(dercList.DERControl))
		dercList.Results = dercList.All
	}

	// Mirror into actderc (status display) only when the event window is
	// already open; ActiveDERControlList must contain active events only.
	// Activate=true keeps its replace semantics: a future event clears the
	// stale active list rather than joining it.
	actPath := fmt.Sprintf("/derp/%d/actderc", req.Program)
	switch actList := s.resources[actPath].(type) {
	case *model.DERControlList:
		switch {
		case req.Activate && activeNow:
			actList.DERControl = []model.DERControl{ctrl}
		case req.Activate:
			actList.DERControl = nil
		case activeNow:
			actList.DERControl = append(actList.DERControl, ctrl)
		}
		actList.All = uint32(len(actList.DERControl))
		actList.Results = actList.All
	case *model.ExtendedDERControlList:
		ext := toExtendedControl(ctrl)
		switch {
		case req.Activate && activeNow:
			actList.DERControl = []model.ExtendedDERControl{ext}
		case req.Activate:
			actList.DERControl = nil
		case activeNow:
			actList.DERControl = append(actList.DERControl, ext)
		}
		actList.All = uint32(len(actList.DERControl))
		actList.Results = actList.All
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"mrid": ctrl.MRID})
}

func (s *Server) adminCtrlDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Program int `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, path := range []string{
		fmt.Sprintf("/derp/%d/derc", req.Program),
		fmt.Sprintf("/derp/%d/actderc", req.Program),
	} {
		// Either a scalar list or a curve-bound extended list (curve.go) can
		// be sitting at these paths — clear whichever it is.
		switch list := s.resources[path].(type) {
		case *model.DERControlList:
			list.DERControl = nil
			list.All = 0
			list.Results = 0
		case *model.ExtendedDERControlList:
			list.DERControl = nil
			list.All = 0
			list.Results = 0
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// buildBase constructs a DERControlBase from an adminCtrlReq.
// Only fields that are non-nil in the request are set.
func buildBase(req adminCtrlReq) model.DERControlBase {
	b := model.DERControlBase{
		OpModConnect:  req.Connect,
		OpModEnergize: req.Energize,
	}
	b.OpModExpLimW = apFromWatts(req.ExpLimW)
	b.OpModMaxLimW = apFromWatts(req.MaxLimW)
	b.OpModImpLimW = apFromWatts(req.ImpLimW)
	b.OpModGenLimW = apFromWatts(req.GenLimW)
	b.OpModLoadLimW = apFromWatts(req.LoadLimW)
	b.OpModFixedW = apFromWatts(req.FixedW)
	if req.FixedPFInjectW != nil {
		b.OpModFixedPFInjectW = &model.SignedPerCent{Value: int16(*req.FixedPFInjectW)}
	}
	if req.FixedPFAbsorbW != nil {
		b.OpModFixedPFAbsorbW = &model.SignedPerCent{Value: int16(*req.FixedPFAbsorbW)}
	}
	if req.FixedVarPct != nil {
		b.OpModFixedVar = &model.FixedVar{
			RefType: 1, // 1 = rated capacity
			Value:   model.SignedPerCent{Value: int16(*req.FixedVarPct)},
		}
	}
	return b
}

// apFromWatts converts a watt value into an ActivePower, scaling into the
// power-of-ten multiplier when the magnitude exceeds the int16 value range
// (e.g. 40000 W → value=4000, multiplier=1). nil passes through.
func apFromWatts(w *int64) *model.ActivePower {
	if w == nil {
		return nil
	}
	v := *w
	var mult int8
	for v > math.MaxInt16 || v < math.MinInt16 {
		v /= 10
		mult++
	}
	return &model.ActivePower{Value: int16(v), Multiplier: mult}
}

// ── DefaultDERControl GET/POST ────────────────────────────────────────────────

// adminDefaultReq is the body for POST /admin/default.
type adminDefaultReq struct {
	Program int          `json:"program"`
	Base    adminCtrlReq `json:"base"`
	Clear   bool         `json:"clear,omitempty"`
}

func (s *Server) handleAdminDefault(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.adminDefaultGet(w, r)
	case http.MethodPost:
		s.adminDefaultPost(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) adminDefaultGet(w http.ResponseWriter, r *http.Request) {
	prog := 0
	if p := r.URL.Query().Get("program"); p != "" {
		fmt.Sscanf(p, "%d", &prog)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	path := fmt.Sprintf("/derp/%d/dderc", prog)
	if dderc, ok := s.resources[path].(*model.DefaultDERControl); ok {
		b := baseToInfo(dderc.DERControlBase)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(b)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) adminDefaultPost(w http.ResponseWriter, r *http.Request) {
	var req adminDefaultReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := fmt.Sprintf("/derp/%d/dderc", req.Program)
	if dderc, ok := s.resources[path].(*model.DefaultDERControl); ok {
		if req.Clear {
			dderc.DERControlBase = model.DERControlBase{}
		} else {
			dderc.DERControlBase = buildBase(req.Base)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
