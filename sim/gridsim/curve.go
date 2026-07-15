package gridsim

// curve.go — POST/DELETE /admin/curve: push a dynamic DER curve (Volt-VAr /
// Volt-Watt / Freq-Watt / Watt-PF) AND bind it into an active DERControl so
// the hub discovers and adopts it via its normal walk. The static tree serves
// one Volt-VAr curve at /derp/0/dc but no control references it (the hub sees
// an empty CurveSet); this endpoint is what lights the curve path up.
//
// The bound control is stored as an ExtendedDERControl (its DERControlBase
// carries opMod*<curve> link hrefs). Because ExtendedDERControlList shares its
// XMLName ("DERControlList") with the scalar DERControlList, a walker fetching
// /derp/{p}/derc parses either — so the derc/actderc paths can hold either
// type after this endpoint runs (see the type-tolerant edits in admin.go).

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"

	model "lexa-proto/csipmodel"
)

// curvePoint is one (x, y) breakpoint in the request. Accepted as float64 and
// rounded into the model's int32 CurveData.
type curvePoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// adminCurveReq is the JSON body for POST /admin/curve.
type adminCurveReq struct {
	Program     int          `json:"program"`
	Mode        string       `json:"mode"` // volt_var|volt_watt|freq_watt|watt_pf
	Points      []curvePoint `json:"points"`
	VRef        int16        `json:"vref"`       // nominal AC voltage (V) for volt curves; 0 = omit
	XMult       int8         `json:"x_mult"`     // 10^n multiplier on x values
	YMult       int8         `json:"y_mult"`     // 10^n multiplier on y values
	XRefType    uint8        `json:"x_ref_type"` // physical quantity on the x axis (Table 19)
	YRefType    uint8        `json:"y_ref_type"` // physical quantity on the y axis (Table 19)
	Description string       `json:"description"`
	DurationS   int          `json:"duration_s"`     // default 300
	StartOffset int          `json:"start_offset_s"` // seconds from now
	Activate    bool         `json:"activate"`       // true = replace curve + control lists
	// FixedVarPct, when present, rides along as an opModFixedVar scalar overlay
	// on the same control (RefType 1 = rated capacity), mirroring adminCtrlReq.
	FixedVarPct *float64 `json:"fixed_var_pct,omitempty"`
}

// curveTypeForMode maps the request's mode to the Table-19 DERCurveType code
// and returns whether the mode is recognized.
func curveTypeForMode(mode string) (uint16, bool) {
	switch mode {
	case "volt_var":
		return model.CurveTypeVoltVar, true // 0
	case "freq_watt":
		return model.CurveTypeFreqWatt, true // 1
	case "watt_pf":
		return model.CurveTypeWattPF, true // 2
	case "volt_watt":
		return model.CurveTypeVoltWatt, true // 3
	default:
		return 0, false
	}
}

// setCurveLink attaches the curve href to the DERControlBase link field that
// matches the mode (volt_var→OpModVoltVar, etc.).
func setCurveLink(b *model.ExtendedDERControlBase, mode, href string) {
	link := &model.CurveLink{Href: href}
	switch mode {
	case "volt_var":
		b.OpModVoltVar = link
	case "volt_watt":
		b.OpModVoltWatt = link
	case "freq_watt":
		b.OpModFreqWatt = link
	case "watt_pf":
		b.OpModWattPF = link
	}
}

func (s *Server) handleAdminCurve(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.adminCurvePost(w, r)
	case http.MethodDelete:
		s.adminCurveDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) adminCurvePost(w http.ResponseWriter, r *http.Request) {
	var req adminCurveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Program < 0 || req.Program > 2 {
		http.Error(w, "program must be 0, 1, or 2", http.StatusBadRequest)
		return
	}
	curveType, ok := curveTypeForMode(req.Mode)
	if !ok {
		http.Error(w, "mode must be one of volt_var|volt_watt|freq_watt|watt_pf", http.StatusBadRequest)
		return
	}
	if req.DurationS <= 0 {
		req.DurationS = 300
	}
	if req.Description == "" {
		req.Description = fmt.Sprintf("Admin %s curve", req.Mode)
	}

	now := s.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// ── 1. upsert the curve into the program's DERCurveList (/derp/{p}/dc) ──
	dcPath := fmt.Sprintf("/derp/%d/dc", req.Program)
	cl, _ := s.resources[dcPath].(*model.DERCurveList)
	if cl == nil {
		cl = &model.DERCurveList{Resource: model.Resource{Href: dcPath}, PollRate: 300}
		s.resources[dcPath] = cl
	}
	if req.Activate {
		cl.DERCurve = nil // replace: this becomes the only curve (index 0)
	}
	idx := len(cl.DERCurve)
	curveHref := fmt.Sprintf("/derp/%d/dc/%d", req.Program, idx)

	curve := model.DERCurve{
		Resource:     model.Resource{Href: curveHref},
		MRID:         fmt.Sprintf("CURVE-%s-%d-%d", strings.ToUpper(req.Mode), req.Program, now),
		Description:  req.Description,
		CreationTime: now,
		CurveType:    curveType,
		XMultiplier:  req.XMult,
		YMultiplier:  req.YMult,
		XRefType:     req.XRefType,
		YRefType:     req.YRefType,
		CurveData:    pointsToCurveData(req.Points),
	}
	if req.VRef != 0 {
		v := req.VRef
		curve.VRef = &v
	}
	cl.DERCurve = append(cl.DERCurve, curve)
	cl.All = uint32(len(cl.DERCurve))
	cl.Results = cl.All

	// Ensure the program advertises its DERCurveList so the walker discovers
	// the curve (program 0 already links it; 1/2 get the link on first use).
	s.ensureCurveListLinkLocked(req.Program, dcPath, cl.All)

	// ── 2. build the ExtendedDERControl that binds the curve ──────────────
	activeNow := req.StartOffset <= 0
	var status uint8
	if activeNow {
		status = 1 // Active
	} else {
		status = 0 // Scheduled
	}
	base := model.ExtendedDERControlBase{}
	setCurveLink(&base, req.Mode, curveHref)
	if req.FixedVarPct != nil {
		base.OpModFixedVar = &model.FixedVar{
			RefType: 1, // 1 = rated capacity
			Value:   model.SignedPerCent{Value: int16(math.Round(*req.FixedVarPct))},
		}
	}
	ctrl := model.ExtendedDERControl{
		Resource:     model.Resource{Href: fmt.Sprintf("/derp/%d/derc/curve", req.Program)},
		MRID:         fmt.Sprintf("DERC-%s-CURVE-%d", progPrefixes[req.Program], now),
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
		DERControlBase: base,
	}

	// ── 3. store into derc (scheduled list the walker reads) ──────────────
	dercPath := fmt.Sprintf("/derp/%d/derc", req.Program)
	s.putExtendedControl(dercPath, ctrl, req.Activate)

	// ── 4. mirror active into actderc (status display; active events only) ─
	actPath := fmt.Sprintf("/derp/%d/actderc", req.Program)
	switch {
	case req.Activate && activeNow:
		s.resources[actPath] = &model.ExtendedDERControlList{
			Resource:   model.Resource{Href: actPath},
			All:        1,
			Results:    1,
			PollRate:   60,
			DERControl: []model.ExtendedDERControl{ctrl},
		}
	case req.Activate:
		// future event with activate=true clears the stale active list
		s.resources[actPath] = &model.ExtendedDERControlList{
			Resource: model.Resource{Href: actPath}, PollRate: 60,
		}
	case activeNow:
		s.putExtendedControl(actPath, ctrl, false)
	}

	log.Printf("[gridsim] POST /admin/curve: program=%d mode=%s curve=%s control=%s active_now=%v",
		req.Program, req.Mode, curveHref, ctrl.MRID, activeNow)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"mrid":       ctrl.MRID,
		"curve_mrid": curve.MRID,
		"curve_href": curveHref,
	})
}

// adminCurveDelete clears the program's bound control (derc + actderc) and
// resets its curve list (/derp/{p}/dc) to the original static curve —
// program 0 back to its Volt-VAr fixture, others back to an empty list.
func (s *Server) adminCurveDelete(w http.ResponseWriter, r *http.Request) {
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

	// Clear the control lists back to empty scalar lists (restores the normal
	// type at these paths so subsequent scalar /admin/control posts are plain).
	for _, path := range []string{
		fmt.Sprintf("/derp/%d/derc", req.Program),
		fmt.Sprintf("/derp/%d/actderc", req.Program),
	} {
		s.resources[path] = &model.DERControlList{Resource: model.Resource{Href: path}, PollRate: 60}
	}

	// Reset the curve list to the original static fixture.
	dcPath := fmt.Sprintf("/derp/%d/dc", req.Program)
	reset := staticCurveList(req.Program)
	s.resources[dcPath] = reset
	s.ensureCurveListLinkLocked(req.Program, dcPath, reset.All)

	w.WriteHeader(http.StatusNoContent)
}

// putExtendedControl stores ctrl into the ExtendedDERControlList at path,
// replacing the list when activate is set, else appending. If the path
// currently holds a scalar DERControlList (or nothing), a fresh
// ExtendedDERControlList is created — the append case starts fresh rather than
// mixing control types in one list.
func (s *Server) putExtendedControl(path string, ctrl model.ExtendedDERControl, activate bool) {
	if activate {
		s.resources[path] = &model.ExtendedDERControlList{
			Resource:   model.Resource{Href: path},
			All:        1,
			Results:    1,
			PollRate:   60,
			DERControl: []model.ExtendedDERControl{ctrl},
		}
		return
	}
	el, ok := s.resources[path].(*model.ExtendedDERControlList)
	if !ok {
		el = &model.ExtendedDERControlList{Resource: model.Resource{Href: path}, PollRate: 60}
		s.resources[path] = el
	}
	el.DERControl = append(el.DERControl, ctrl)
	el.All = uint32(len(el.DERControl))
	el.Results = el.All
}

// ensureCurveListLinkLocked wires (or refreshes) the DERProgram's
// DERCurveListLink so a walker following /edev/2/fsa/0/derp discovers the
// curve list. Program 0 ships with the link; 1/2 gain it on first curve POST.
// Caller must hold s.mu.
func (s *Server) ensureCurveListLinkLocked(program int, dcPath string, count uint32) {
	dpl, ok := s.resources["/edev/2/fsa/0/derp"].(*model.DERProgramList)
	if !ok || program < 0 || program >= len(dpl.DERProgram) {
		return
	}
	dp := &dpl.DERProgram[program]
	if dp.DERCurveListLink == nil {
		dp.DERCurveListLink = &model.ListLink{Link: model.Link{Href: dcPath}}
	}
	dp.DERCurveListLink.All = count
}

// staticCurveList returns the fixture curve list a DELETE restores a program
// to: program 0's Volt-VAr curve, or an empty list for the others (which have
// no original static curve).
func staticCurveList(program int) *model.DERCurveList {
	if program == 0 {
		return staticVoltVarCurve0()
	}
	path := fmt.Sprintf("/derp/%d/dc", program)
	return &model.DERCurveList{Resource: model.Resource{Href: path}, PollRate: 300}
}

// pointsToCurveData rounds request points into the model's int32 CurveData.
func pointsToCurveData(pts []curvePoint) []model.DERCurveData {
	if len(pts) == 0 {
		return nil
	}
	out := make([]model.DERCurveData, 0, len(pts))
	for _, p := range pts {
		out = append(out, model.DERCurveData{
			XValue: int32(math.Round(p.X)),
			YValue: int32(math.Round(p.Y)),
		})
	}
	return out
}

// ── scalar → extended control conversion (for the type-tolerant scalar
// /admin/control post when a curve has already made derc/actderc extended) ──

// toExtendedControl widens a scalar DERControl into an ExtendedDERControl so a
// scalar /admin/control post can append to a list a prior curve post made
// extended, without mixing types.
func toExtendedControl(c model.DERControl) model.ExtendedDERControl {
	return model.ExtendedDERControl{
		Resource:          c.Resource,
		MRID:              c.MRID,
		Description:       c.Description,
		Version:           c.Version,
		CreationTime:      c.CreationTime,
		EventStatus:       c.EventStatus,
		Interval:          c.Interval,
		DERControlBase:    scalarBaseToExtended(c.DERControlBase),
		RandomizeStart:    c.RandomizeStart,
		RandomizeDuration: c.RandomizeDuration,
	}
}

func scalarBaseToExtended(b model.DERControlBase) model.ExtendedDERControlBase {
	return model.ExtendedDERControlBase{
		OpModConnect:        b.OpModConnect,
		OpModEnergize:       b.OpModEnergize,
		OpModFixedPFAbsorbW: b.OpModFixedPFAbsorbW,
		OpModFixedPFInjectW: b.OpModFixedPFInjectW,
		OpModFixedVar:       b.OpModFixedVar,
		OpModFixedW:         b.OpModFixedW,
		OpModMaxLimW:        b.OpModMaxLimW,
		OpModExpLimW:        b.OpModExpLimW,
		OpModGenLimW:        b.OpModGenLimW,
		OpModImpLimW:        b.OpModImpLimW,
		OpModLoadLimW:       b.OpModLoadLimW,
		RampTms:             b.RampTms,
	}
}

// ── extended → adminCtrlInfo (for GET /admin/status) ──────────────────────

// extCtrlToInfo renders an ExtendedDERControl into the same adminCtrlInfo the
// status endpoint uses for scalar controls, adding the bound-curve label.
func extCtrlToInfo(c model.ExtendedDERControl) adminCtrlInfo {
	info := adminCtrlInfo{
		MRID:        c.MRID,
		Description: c.Description,
		Start:       c.Interval.Start,
		DurationS:   int(c.Interval.Duration),
		Base:        extBaseToInfo(c.DERControlBase),
		Curve:       curveLabel(c.DERControlBase),
	}
	if c.EventStatus != nil {
		info.Status = int(c.EventStatus.CurrentStatus)
	}
	return info
}

// curveLabel renders the bound curve as "<mode> -> <href>" for the inspector,
// or "" when no curve link is set.
func curveLabel(b model.ExtendedDERControlBase) string {
	switch {
	case b.OpModVoltVar != nil:
		return "volt_var -> " + b.OpModVoltVar.Href
	case b.OpModVoltWatt != nil:
		return "volt_watt -> " + b.OpModVoltWatt.Href
	case b.OpModFreqWatt != nil:
		return "freq_watt -> " + b.OpModFreqWatt.Href
	case b.OpModWattPF != nil:
		return "watt_pf -> " + b.OpModWattPF.Href
	}
	return ""
}

// extBaseToInfo mirrors baseToInfo (admin.go) for the extended control base —
// same scalar fields, surfaced identically so status JSON is uniform.
func extBaseToInfo(b model.ExtendedDERControlBase) adminBaseInfo {
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
