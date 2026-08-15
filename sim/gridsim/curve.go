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
	Program int          `json:"program"`
	Mode    string       `json:"mode"` // volt_var|volt_watt|freq_watt|watt_pf|watt_var
	Points  []curvePoint `json:"points"`
	VRef    int16        `json:"vref"`   // nominal AC voltage (V) for volt curves; 0 = omit
	XMult   int8         `json:"x_mult"` // 10^n multiplier on x values
	YMult   int8         `json:"y_mult"` // 10^n multiplier on y values
	// x_ref_type is GONE (2026-08-14), and a request still carrying it is
	// REJECTED (400) rather than silently ignored — see XRefTypeGone below.
	// sep 2.0.4 declares NO xRefType element — `grep -c xRefType
	// docs/schema/sep-2.0.4.xsd` in lexa-proto is 0 — so this server was
	// emitting an element the standard does not define, in documents used to
	// certify conformance against it. (csipmodel.DERCurve has an XRefType field
	// that decodes that non-existent element; that is an upstream defect this
	// note records and does not fix.) The x-axis reference is fixed by the MODE
	// at both ends and needs no carriage: volt-var and volt-watt take an
	// effective percent voltage, freq-watt takes Hz, watt-PF takes %setMaxW.
	YRefType uint8 `json:"y_ref_type"` // DERUnitRefType for the y axis (sep 2.0.4)
	// XRefTypeGone traps a caller still sending the removed field. A pointer,
	// so "absent" and "sent as 0" are distinguishable: silently accepting a
	// request whose x_ref_type the server no longer honours would leave the
	// caller believing it had set something.
	XRefTypeGone *uint8 `json:"x_ref_type,omitempty"`
	Description  string `json:"description"`
	DurationS    int    `json:"duration_s"`     // default 300
	StartOffset  int    `json:"start_offset_s"` // seconds from now
	Activate     bool   `json:"activate"`       // true = replace curve + control lists
	// FixedVarPct, when present, rides along as an opModFixedVar scalar overlay
	// on the same control, mirroring adminCtrlReq. It is emitted with
	// DERUnitRefType 2 (%setMaxVar) — a percentage of the REACTIVE nameplate;
	// see the emission site for why it used to say RefType 1.
	FixedVarPct *float64 `json:"fixed_var_pct,omitempty"`
	// OpenLoopTms is the DERCurve's own openLoopTms element: the time to reach
	// 90 % of the commanded output after a step change, in HUNDREDTHS of a
	// second, 0 meaning "no limit" (sep-2.0.4.xsd DERCurve, minOccurs=0).
	//
	// It is here because a certification Figure prescribes it and this server
	// could not send it: CSIP CTP v1.3's Figure 6 prints openLoopTms Default 10
	// against Test Values 5, so a BASIC-006 run without this field never offered
	// the DUT the condition the row exists to create, and the row held itself at
	// FAIL saying exactly that. It is the ONLY DERCurve scalar any Figure in the
	// catalog prescribes beyond CurveData, the two multipliers, curveType and
	// yRefType — rampDecTms/rampIncTms/rampPT1Tms/vRef appear in no Figure, so no
	// lever is offered for them and none is claimed.
	//
	// A pointer: 0 is "no limit", a real value a Figure could prescribe, so
	// "absent" and "sent as 0" must stay distinguishable.
	OpenLoopTms *uint16 `json:"open_loop_tms,omitempty"`
	// FreqDroop rides along as an INLINE opModFreqDroop element on the same
	// control that carries the curve link, which is the shape CSIP CTP v1.3's
	// Figure 12 prescribes for BASIC-012: ONE DERControl carrying both the
	// frequency-WATT curve (opModFreqWatt, a curve link) and the immediate
	// frequency-DROOP control (opModFreqDroop, inline parameters). See
	// freqdroop.go for the units, the whole-or-nothing rule and the element
	// ordering note.
	FreqDroop *freqDroopReq `json:"freq_droop,omitempty"`
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
	case "watt_var":
		// opModWattVar, DERCurveType 10. It is the axis SunSpec model 712
		// actually implements, and until now there was no lever that could put
		// an <opModWattVar> DERCurveLink on the wire at all — so the strongest
		// curve axis the 7xx product has was the one nothing exercised, and
		// BASIC-015's opModWattPF was graded against 712 in its place. Both
		// halves of that substitution are now expressible separately, which is
		// the only way a row can show they are different commands.
		return model.CurveTypeWattVar, true // 10
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
	case "watt_var":
		b.OpModWattVar = link
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
	if req.XRefTypeGone != nil {
		http.Error(w, "x_ref_type is not a field of this API: sep 2.0.4 declares no xRefType element on "+
			"DERCurve, so this server cannot serve one. Remove it from the request; the x-axis reference "+
			"is fixed by the mode.", http.StatusBadRequest)
		return
	}
	curveType, ok := curveTypeForMode(req.Mode)
	if !ok {
		http.Error(w, "mode must be one of volt_var|volt_watt|freq_watt|watt_pf|watt_var",
			http.StatusBadRequest)
		return
	}
	// The droop is validated BEFORE anything is stored: a request whose
	// opModFreqDroop cannot be authored must publish no curve either, or a
	// caller that asked for both halves of Figure 12 would get one half plus a
	// 400 and could not tell which state the bench was left in.
	droop, err := req.FreqDroop.toModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		// No XRefType: see adminCurveReq. The csipmodel field stays zero and
		// its `omitempty` keeps the element off the wire entirely.
		YRefType:  req.YRefType,
		CurveData: pointsToCurveData(req.Points),
		// openLoopTms rides on the DERCurve, not on the control: sep 2.0.4
		// declares it a child of DERCurve, and the Figure that prescribes it
		// (Figure 6) names it "opModVoltVar.DERCurve.openLoopTms" for that
		// reason. A copy, so a later mutation of the request cannot reach a
		// curve this server has already published.
		OpenLoopTms: copyU16(req.OpenLoopTms),
	}
	if req.VRef != 0 {
		v := req.VRef
		curve.VRef = &v
	}
	cl.DERCurve = append(cl.DERCurve, curve)
	cl.All = uint32(len(cl.DERCurve))
	cl.Results = cl.All

	// A curve-linked DERControl carries an HREF, not content. Until now the
	// server MINTED that href and stored only the list, so every individual
	// /derp/{p}/dc/{i} answered 404 and a DUT that followed the link received a
	// link and no curve. That made every curve row's southbound silence
	// unattributable: "the DUT refused the axis" and "the bench served the
	// curve nowhere" look identical from outside, which is exactly the
	// ambiguity critDERCurveResolvable was written to disambiguate and could
	// not, because the bench always 404'd. Publish the individual resources so
	// the link a control carries actually resolves.
	// The clear MUST come first. An activating POST truncates the list to one
	// entry, so republishing 0..len-1 alone would leave every /derp/{p}/dc/{i}
	// this program had published above that index still served — a curve at an
	// href the list no longer mentions, which is precisely the leak the
	// teardown exists to prevent, arriving through the publish path instead.
	s.clearCurveResourcesLocked(req.Program)
	s.publishCurveResourcesLocked(req.Program, cl)

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
	// The inline droop, on the SAME control as the curve link. Figure 12
	// prescribes exactly that pairing for BASIC-012 — opModFreqWatt (Curve) and
	// opModFreqDroop (Immediate) on one DERControl — and publishing them as two
	// controls would have made the row's own procedure unfollowable.
	base.OpModFreqDroop = droop
	if req.FixedVarPct != nil {
		base.OpModFixedVar = &model.FixedVar{
			// DERUnitRefType 2 = %setMaxVar: a percentage of the REACTIVE
			// nameplate, which is what this field has always meant end-to-end
			// ("fixed_var_pct ... signed % of setMaxVar" on the bus doc both
			// consumers carry it on).
			//
			// It used to emit RefType 1 under the comment "1 = rated
			// capacity". That is the wrong code for that sentence: 1 is
			// %setMaxW, a percentage of the ACTIVE-power nameplate. It went
			// unnoticed while derbase ignored refType entirely and resolved
			// every code against VarMaxPct — the fixture was wrong and the
			// product was wrong in the opposite direction, and the two
			// cancelled. lexa-proto d60e1ca made derbase READ the code, so
			// they stop cancelling: on the 60 kW / 26.4 kvar bench inverter
			// this would ask 80 % of 60 kW = 48 kvar from a 26.4 kvar machine
			// (DIFF-CTL-001), and 24x that on a 2 kvar one (DIFF-CTL-002).
			RefType: model.RefTypeSetMaxVar,
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
			PollRate:   s.controlListPollRateLocked(),
			DERControl: []model.ExtendedDERControl{ctrl},
		}
	case req.Activate:
		// future event with activate=true clears the stale active list
		s.resources[actPath] = &model.ExtendedDERControlList{
			Resource: model.Resource{Href: actPath}, PollRate: s.controlListPollRateLocked(),
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
		s.resources[path] = &model.DERControlList{
			Resource: model.Resource{Href: path}, PollRate: s.controlListPollRateLocked(),
		}
	}

	// Reset the curve list to the original static fixture — and with it the
	// INDIVIDUAL curve resources, or a cleared program would go on serving the
	// previous run's curve at an href its control list no longer mentions. A
	// teardown that leaves a fetchable curve behind is the contamination the
	// clear exists to remove.
	dcPath := fmt.Sprintf("/derp/%d/dc", req.Program)
	s.clearCurveResourcesLocked(req.Program)
	reset := staticCurveList(req.Program)
	s.resources[dcPath] = reset
	s.publishCurveResourcesLocked(req.Program, reset)
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
			PollRate:   s.controlListPollRateLocked(),
			DERControl: []model.ExtendedDERControl{ctrl},
		}
		return
	}
	el, ok := s.resources[path].(*model.ExtendedDERControlList)
	if !ok {
		el = &model.ExtendedDERControlList{
			Resource: model.Resource{Href: path}, PollRate: s.controlListPollRateLocked(),
		}
		s.resources[path] = el
	}
	el.DERControl = append(el.DERControl, ctrl)
	el.All = uint32(len(el.DERControl))
	el.Results = el.All
}

// publishCurveResourcesLocked serves every DERCurve of a program's list at its
// OWN href, so a DERControl's curve link resolves for a DUT that follows it.
//
// Each entry is stored as a COPY rather than as a pointer into the list's
// backing array: appending to cl.DERCurve reallocates, and a stored pointer
// into the old array would go on serving a curve the list no longer holds.
// Caller must hold s.mu.
func (s *Server) publishCurveResourcesLocked(program int, cl *model.DERCurveList) {
	if cl == nil {
		return
	}
	for i := range cl.DERCurve {
		c := cl.DERCurve[i]
		href := c.Href
		if href == "" {
			href = fmt.Sprintf("/derp/%d/dc/%d", program, i)
			c.Href = href
		}
		s.resources[href] = &c
		s.curveHrefs[href] = true
	}
}

// clearCurveResourcesLocked removes the individually-addressable curve
// resources this server minted for a program. Caller must hold s.mu.
func (s *Server) clearCurveResourcesLocked(program int) {
	prefix := fmt.Sprintf("/derp/%d/dc/", program)
	for href := range s.curveHrefs {
		if strings.HasPrefix(href, prefix) {
			delete(s.resources, href)
			delete(s.curveHrefs, href)
		}
	}
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
//
// ReplyTo/ResponseRequired must ride along explicitly (audit 2026-08-01):
// they are adminCtrlPost's own RespondableResource attributes (see
// adminDefaultResponseRequired/adminResponseReplyTo in admin.go), set fresh on
// every scalar ctrl it builds, and ExtendedDERControl carries the identical
// pair of fields for exactly this reason (der.go's ExtendedDERControl doc:
// "the extended (curve-linked) DERControl carries the same replyTo/
// responseRequired the plain DERControl does"). Before this fix they were the
// only two fields this conversion dropped, so a scalar /admin/control POST
// landing on a program a PRIOR /admin/curve POST had already widened to
// Extended silently served that control with NO replyTo and NO
// responseRequired at all — indistinguishable on the wire from one of the
// standing, non-admin-seeded bench fixtures (buildProgram0's doc) that
// legitimately omit them to exercise the DUT's fallback-to-advertised-default
// path. A conformance check reading either attribute for an admin-posted
// control on a curve-bound program got exactly that false "not requested" /
// "not recovered" reading regardless of what gridsim was actually told to
// serve — see CORE-022's coreResponsesSpec doc and
// TestAdminControl_ScalarPostOntoExtendedProgramKeepsResponseAttrs
// (curve_test.go) for the reproduction.
func toExtendedControl(c model.DERControl) model.ExtendedDERControl {
	return model.ExtendedDERControl{
		Resource:          c.Resource,
		ReplyTo:           c.ReplyTo,
		ResponseRequired:  c.ResponseRequired,
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
		// IW13-001: PerCent, not ActivePower — see baseToInfo's identical
		// correction in admin.go.
		v := int64(b.OpModMaxLimW.Value)
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
		// IW13-001: SignedPerCent, not ActivePower.
		v := int64(b.OpModFixedW.Value)
		info.FixedW = &v
	}
	if b.OpModTargetW != nil {
		v := apW(b.OpModTargetW)
		info.TargetW = &v
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
	info.FreqDroop = freqDroopToInfo(b.OpModFreqDroop)
	return info
}

// copyU16 returns a fresh pointer to the same value, so a stored resource never
// aliases a request struct the caller still owns.
func copyU16(v *uint16) *uint16 {
	if v == nil {
		return nil
	}
	n := *v
	return &n
}
