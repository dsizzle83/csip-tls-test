package gridsim

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"csip-tls-test/internal/csip/model"
)

// AdminHandler returns a plain HTTP handler for the gridsim management API.
// Mount this on a separate port (default 11112) — it is NOT mTLS-protected.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/status", cors(s.handleAdminStatus))
	mux.HandleFunc("/admin/control", cors(s.handleAdminControl))
	mux.HandleFunc("/admin/default", cors(s.handleAdminDefault))
	return mux
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
	MRID        string          `json:"mrid"`
	Description string          `json:"description"`
	Start       int64           `json:"start"`
	DurationS   int             `json:"duration_s"`
	Status      int             `json:"status"`
	Base        adminBaseInfo   `json:"base"`
}

// adminBaseInfo mirrors DERControlBase as JSON-friendly nullable fields.
type adminBaseInfo struct {
	ExpLimW        *int64   `json:"exp_lim_W,omitempty"`
	MaxLimW        *int64   `json:"max_lim_W,omitempty"`
	ImpLimW        *int64   `json:"imp_lim_W,omitempty"`
	GenLimW        *int64   `json:"gen_lim_W,omitempty"`
	LoadLimW       *int64   `json:"load_lim_W,omitempty"`
	FixedW         *int64   `json:"fixed_W,omitempty"`
	Connect        *bool    `json:"connect,omitempty"`
	Energize       *bool    `json:"energize,omitempty"`
	FixedPFInjectW *int64   `json:"fixed_pf_inject_pct,omitempty"`
	FixedPFAbsorbW *int64   `json:"fixed_pf_absorb_pct,omitempty"`
	FixedVarPct    *int64   `json:"fixed_var_pct,omitempty"`
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
		if actList, ok := s.resources[fmt.Sprintf("/derp/%d/actderc", i)].(*model.DERControlList); ok {
			for _, c := range actList.DERControl {
				ap.Active = append(ap.Active, ctrlToInfo(c))
			}
		}
		if schList, ok := s.resources[fmt.Sprintf("/derp/%d/derc", i)].(*model.DERControlList); ok {
			for _, c := range schList.DERControl {
				ap.Scheduled = append(ap.Scheduled, ctrlToInfo(c))
			}
		}
		programs = append(programs, ap)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminStatusResp{
		Programs:   programs,
		ServerTime: time.Now().Unix(),
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
	Program        int    `json:"program"`
	Description    string `json:"description"`
	StartOffset    int    `json:"start_offset_s"` // seconds from now
	DurationS      int    `json:"duration_s"`     // default 300
	Activate       bool   `json:"activate"`       // true = replace active list

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

	now := time.Now().Unix()
	ctrl := model.DERControl{
		Resource:     model.Resource{Href: fmt.Sprintf("/derp/%d/derc/admin", req.Program)},
		MRID:         fmt.Sprintf("DERC-%s-ADMIN-%d", progPrefixes[req.Program], now),
		Description:  req.Description,
		CreationTime: now,
		EventStatus: &model.EventStatus{
			CurrentStatus: 1,
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
	if dercList, ok := s.resources[dercPath].(*model.DERControlList); ok {
		if req.Activate {
			dercList.DERControl = []model.DERControl{ctrl}
		} else {
			dercList.DERControl = append(dercList.DERControl, ctrl)
		}
		dercList.All = uint32(len(dercList.DERControl))
		dercList.Results = dercList.All
	}

	// Also mirror into actderc for status display.
	actPath := fmt.Sprintf("/derp/%d/actderc", req.Program)
	if actList, ok := s.resources[actPath].(*model.DERControlList); ok {
		if req.Activate {
			actList.DERControl = []model.DERControl{ctrl}
		} else {
			actList.DERControl = append(actList.DERControl, ctrl)
		}
		actList.All = uint32(len(actList.DERControl))
		actList.Results = actList.All
	}
	w.WriteHeader(http.StatusCreated)
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
		if list, ok := s.resources[path].(*model.DERControlList); ok {
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
	ap16 := func(v *int64) *model.ActivePower {
		if v == nil {
			return nil
		}
		return &model.ActivePower{Value: int16(*v), Multiplier: 0}
	}
	b.OpModExpLimW = ap16(req.ExpLimW)
	b.OpModMaxLimW = ap16(req.MaxLimW)
	b.OpModImpLimW = ap16(req.ImpLimW)
	b.OpModGenLimW = ap16(req.GenLimW)
	b.OpModLoadLimW = ap16(req.LoadLimW)
	b.OpModFixedW = ap16(req.FixedW)
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

// ── DefaultDERControl GET/POST ────────────────────────────────────────────────

// adminDefaultReq is the body for POST /admin/default.
type adminDefaultReq struct {
	Program int           `json:"program"`
	Base    adminCtrlReq  `json:"base"`
	Clear   bool          `json:"clear,omitempty"`
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
