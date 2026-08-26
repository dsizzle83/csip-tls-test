package gridsim

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
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
	mux.HandleFunc("/admin/gone", cors(s.handleAdminGone))
	mux.HandleFunc("/admin/delay", cors(s.handleAdminDelay))
	mux.HandleFunc("/admin/paginate", cors(s.handleAdminPaginate))
	mux.HandleFunc("/admin/responses", cors(s.handleAdminResponses))
	mux.HandleFunc("/admin/derputs", cors(s.handleAdminDERPuts))
	// The durable MirrorUsagePoint registration STATE (BASIC-029, audit
	// 2026-07-30): unlike the request log this survives a window opening after
	// the DUT's one-time registration POST, at the cost of not surviving a
	// gridsim restart. See AdminMUP in server.go.
	mux.HandleFunc("/admin/mups", cors(s.handleAdminMUPs))
	mux.HandleFunc("/admin/logevents", cors(s.handleAdminLogEvents))
	// CORE-009/CORE-014 lever (rehome.go): re-home the DUT's DERCapability/
	// DERSettings hrefs so its next discovery walk notices the change and
	// re-PUTs them, per CSIP IG §6.3.5.2. A test-server action, not an EUT one.
	mux.HandleFunc("/admin/rehome", cors(s.handleAdminRehome))
	// The DER AGGREGATOR CLIENT levers (2026-07-28 re-scope). Both are inert
	// unless the corresponding capability was enabled at startup, and both
	// report that state so a preflight can PROBE for the fixture rather than
	// assume it: /admin/fleet lists the CTP Figure-15 EndDevices and adjusts a
	// per-device pIN or aggregator binding, /admin/subscriptions lists the live
	// subscriptions WITH the notificationURI the DUT registered (which is the
	// only place a harness can learn the DUT's inbound listener address), and
	// /admin/notifications is what the server pushed and what came back.
	mux.HandleFunc("/admin/fleet", cors(s.handleAdminFleet))
	mux.HandleFunc("/admin/subscriptions", cors(s.handleAdminSubscriptions))
	mux.HandleFunc("/admin/notifications", cors(s.handleAdminNotifications))
	// The runtime certificate-chain lever (COMM-004 D/E/F/G). See chain.go for
	// why it takes PEM text rather than paths, and why a gridsim with no TLS
	// data plane answers it 501 rather than 404.
	mux.HandleFunc("/admin/chain", cors(s.handleAdminChain))
	mux.HandleFunc("/admin/logs", cors(s.logBuf.ServeHTTP))
	// Cursor-based JSON read of the same ring. The SSE stream above is for the
	// dashboard; a programmatic reader must use this, because deriving a delta
	// from the SSE replay's length breaks silently once the ring wraps (see
	// simapi.LogBuffer.firstSeq).
	mux.HandleFunc("/admin/logs.json", cors(s.logBuf.ServeSince))
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

// AdminResponse is one Response POST the hub has sent, surfaced by
// GET /admin/responses. Unlike /admin/alerts (which records only
// CannotComply-family statuses) this exposes EVERY Response — including the
// server-driven lifecycle acks Cancelled(6) and Superseded(7) that
// classifyResponseStatus deliberately does NOT treat as alerts — so a bench
// scenario can prove the hub emits 6/7 over the wire (CORE-022/023, audit
// P1-2). A thin JSON DTO rather than the XML-tagged model.Response so the
// admin JSON stays stable and label-free.
type AdminResponse struct {
	Subject string `json:"subject"` // the DERControl mRID being acknowledged
	Status  uint8  `json:"status"`  // 2030.5 Response status (1/2/3/6/7/…)
	LFDI    string `json:"lfdi"`    // responding device
}

// handleAdminResponses returns every Response the hub has POSTed (all
// statuses), for scenarios asserting the server-driven Cancelled(6)/
// Superseded(7) emissions.
func (s *Server) handleAdminResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	recv := s.ReceivedResponses()
	out := make([]AdminResponse, 0, len(recv))
	for _, rp := range recv {
		out = append(out, AdminResponse{Subject: rp.Subject, Status: rp.Status, LFDI: rp.EndDeviceLFDI})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"responses":   out,
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
//
// IW13-001 (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md): MaxLimW and
// FixedW carry HUNDREDTHS OF A PERCENT now (opModMaxLimW/opModFixedW's real
// wire unit — SignedPerCent/PerCent), NOT watts, even though the field/JSON
// names are kept unchanged to avoid rippling the admin API surface for a
// units-only fix — the design's own BASIC-013/014 harness changes construct
// these fields with catalog-stated hundredths values directly (e.g.
// FixedW=6000 meaning 60.00%), not watts. ExpLimW/ImpLimW/GenLimW/LoadLimW
// are unaffected (§1.2 — still genuine watts, ActivePower).
type adminBaseInfo struct {
	ExpLimW  *int64 `json:"exp_lim_W,omitempty"`
	MaxLimW  *int64 `json:"max_lim_W,omitempty"` // hundredths of a percent (IW13-001) — see type doc
	ImpLimW  *int64 `json:"imp_lim_W,omitempty"`
	GenLimW  *int64 `json:"gen_lim_W,omitempty"`
	LoadLimW *int64 `json:"load_lim_W,omitempty"`
	FixedW   *int64 `json:"fixed_W,omitempty"` // hundredths of a percent, signed (IW13-001) — see type doc
	// TargetW is opModTargetW (genuine watts, ActivePower — §1.1) — only ever
	// set on an ExtendedDERControlBase (extBaseToInfo, curve.go); baseToInfo's
	// scalar DERControlBase has no such field to read at all.
	TargetW  *int64 `json:"target_W,omitempty"`
	Connect  *bool  `json:"connect,omitempty"`
	Energize *bool  `json:"energize,omitempty"`
	// The two fixed-PF axes are STRUCTURED elements, not magnitudes — IEEE Std
	// 2030.5-2018 p.258, PowerFactorWithExcitation. They were `*int64`
	// "fixed_pf_*_pct" until 2026-08-15; see fixedpf.go for why a bare number
	// cannot carry two of the three mandatory children.
	FixedPFInjectW *adminFixedPFInfo `json:"fixed_pf_inject,omitempty"`
	FixedPFAbsorbW *adminFixedPFInfo `json:"fixed_pf_absorb,omitempty"`
	FixedVarPct    *int64            `json:"fixed_var_pct,omitempty"`
	// FreqDroop is opModFreqDroop's five inline parameters (freqdroop.go).
	// Like TargetW it exists only on an ExtendedDERControlBase, so only
	// extBaseToInfo and the extended DefaultDERControl ever set it; the scalar
	// DERControlBase that baseToInfo reads has no such field at all.
	FreqDroop *adminFreqDroopInfo `json:"freq_droop,omitempty"`
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
	// PollRateS is the pollRate this server ADVERTISES, which is the cadence a
	// client in poll_rate_mode "honor" keeps. It is published because this is
	// the only place the number is authoritative: the client's own configured
	// discovery interval is a floor, not the rate, and a harness that sizes an
	// observation window from the floor waits for a walk the server itself told
	// the device not to make. See Server.AdvertisedPollRate.
	PollRateS uint32 `json:"poll_rate_s"`
	// PID and DataPlane identify the PROCESS answering this request and the
	// 2030.5 listener that process serves. Two reachable ports do not prove one
	// process: an orphan holding the admin port beside a live instance holding
	// the data port is exactly how a harness came to read one server's
	// observations about another server's traffic. See Server.SetDataPlaneAddr.
	PID       int    `json:"pid"`
	DataPlane string `json:"data_plane,omitempty"`

	// Fleet and Subscription publish the two DER AGGREGATOR CLIENT capabilities
	// this simulator can be started with, so a conformance run can PROBE for
	// them instead of assuming either way.
	//
	// Assuming is the failure mode worth naming. A harness that assumed the
	// fixture was present would report a one-EndDevice bench as a DUT that
	// ignored four devices; one that assumed it was absent would keep SKIPping
	// rows the bench had grown the ability to run, and the SKIP would look like
	// diligence rather than staleness. Both are silent. Publishing the state
	// makes the question answerable in one GET.
	Fleet        AdminFleetStatus        `json:"fleet"`
	Subscription AdminSubscriptionStatus `json:"subscription"`

	// TLS is the evidence-grade posture of this process's TLS data plane, or
	// ABSENT when the embedding binary never declared one. The two are
	// different facts — an old gridsim versus a misconfigured bench — and a
	// fail-closed caller must be able to tell them apart, which is why this is
	// a pointer with omitempty rather than a struct that would report false.
	// See Server.SetTLSPosture.
	TLS *AdminTLSPosture `json:"tls,omitempty"`
}

// AdminTLSPosture is the pair of launch flags that decide whether a conformance
// run's certificate evidence can exist at all. See Server.SetTLSPosture.
type AdminTLSPosture struct {
	// NoTickets reports -no-tickets: no session tickets issued and no session
	// cache, so every dial is a FULL mTLS handshake with the certificates on
	// the wire.
	NoTickets bool `json:"no_tickets"`
	// IdleTimeoutS reports -idle-timeout-s: an idle connection is closed after
	// this many seconds, so each poll cycle opens its own observable session.
	// Zero means disabled — one connection may span the whole run.
	IdleTimeoutS int `json:"idle_timeout_s"`
}

// AdminFleetStatus is the CTP Figure-15 topology's state, in /admin/status.
type AdminFleetStatus struct {
	// Enabled is whether the four managed EndDevices are being served.
	Enabled bool `json:"enabled"`
	// Size is the number of MANAGED devices (the served EndDeviceList holds one
	// more — the aggregator's own).
	Size int `json:"size"`
	// Devices names them, in the document's order.
	Devices []string `json:"devices,omitempty"`
	// AggregatorHref is the EndDevice the DUT's own certificate LFDI maps to.
	AggregatorHref string `json:"aggregator_href,omitempty"`
}

// AdminSubscriptionStatus is the Subscription/Notification function set's
// state, in /admin/status.
type AdminSubscriptionStatus struct {
	// Enabled is whether SubscriptionListLinks are advertised and Notifications
	// originated.
	Enabled bool `json:"enabled"`
	// Subscriptions is how many the DUT currently holds, and Notifications how
	// many the server has pushed. A check reading zero notifications against a
	// non-zero subscription count is reading a bench that never changed
	// anything, not a DUT that ignored one.
	Subscriptions int `json:"subscriptions"`
	Notifications int `json:"notifications"`
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

	// Collected BEFORE the read lock below: Subscriptions/SentNotifications
	// take s.mu themselves, and re-entering a RWMutex read lock deadlocks the
	// moment a writer is queued between the two acquisitions.
	subStatus := AdminSubscriptionStatus{
		Enabled:       s.SubscriptionsEnabled(),
		Subscriptions: len(s.Subscriptions()),
		Notifications: len(s.SentNotifications()),
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var tlsPosture *AdminTLSPosture
	if s.tlsPosture != nil {
		cp := *s.tlsPosture
		tlsPosture = &cp
	}

	fleetStatus := AdminFleetStatus{Enabled: s.fleet != nil}
	if s.fleet != nil {
		fleetStatus.Size = len(s.fleet.devices)
		fleetStatus.AggregatorHref = fmt.Sprintf("/edev/%d", aggregatorEdevIndex)
		for _, d := range s.fleet.devices {
			fleetStatus.Devices = append(fleetStatus.Devices, d.Name)
		}
	}

	var programs []adminProgInfo
	for i, pm := range progMeta {
		ap := adminProgInfo{
			ID:          i,
			MRID:        pm.MRID,
			Description: pm.Description,
			Primacy:     pm.Primacy,
		}
		// Either shape: a default carrying opModFreqDroop is stored extended
		// (putDefaultBaseLocked), and a status that silently omitted it would
		// report "this program has no default" about a program that has one.
		if b, ok := s.defaultBaseInfoLocked(fmt.Sprintf("/derp/%d/dderc", i)); ok {
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
		PollRateS:  s.advertisedPollRateLocked(),
		PID:        os.Getpid(),
		DataPlane:  s.dataPlaneAddr,

		Fleet:        fleetStatus,
		Subscription: subStatus,
		TLS:          tlsPosture,
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
		// IW13-001: PerCent, not ActivePower — the raw hundredths value IS
		// the wire unit, no multiplier to decode (docs/design/
		// IW13_ACTIVE_POWER_UNITS_2026-08-12.md §4.2). info.MaxLimW keeps its
		// name (matching adminCtrlReq's own field below) but now carries
		// hundredths-of-a-percent, not watts.
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
		// IW13-001: SignedPerCent, not ActivePower — same as MaxLimW above.
		v := int64(b.OpModFixedW.Value)
		info.FixedW = &v
	}
	info.FixedPFInjectW = fixedPFToInfo(b.OpModFixedPFInjectW)
	info.FixedPFAbsorbW = fixedPFToInfo(b.OpModFixedPFAbsorbW)
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

// nonconformantControlEdit is the deliberate-violation opt-in for a POST that
// reuses an EXISTING mRID and wants to author more than IEEE Std
// 2030.5-2018 §10.2.3.3 c) permits: "Editing Events SHALL NOT be allowed
// except for updating status. Service providers SHALL cancel Events that
// they wish clients to not act upon and/or provide new superseding Events."
//
// Same shape as curve.go's nonconformantCurve — each field names the
// specific SHALL it breaks, so a reader of a request, or of the bundle
// carrying it, can see that the edit was deliberate rather than a gap in
// this server's own policing. Without either field set, an update to an
// existing mRID may change only EventStatus (current_status,
// potentially_superseded); see adminCtrlPost's guard and
// (adminCtrlReq).nonStatusEdits.
type nonconformantControlEdit struct {
	// AllowContentEdit permits an update to re-author anything §10.2.3.3(c)
	// reserves to a NEW Event: description, response_required,
	// randomize_start/randomize_duration, null_axes, and every
	// DERControlBase-bearing field buildBase reads (exp_lim_W, max_lim_W,
	// imp_lim_W, gen_lim_W, load_lim_W, fixed_W, target_W, connect,
	// energize, fixed_pf_inject/absorb, fixed_var_pct, freq_droop). Without
	// it, an update carrying any of these is refused (400) before anything
	// is stored — this is the lever that used to be gridsim's unconditional
	// default and let a fixture author server behaviour no conformant
	// service provider could produce.
	AllowContentEdit bool `json:"allow_content_edit,omitempty"`
	// AllowCreationTimeMove permits creation_offset_s to move creationTime on
	// an update to an EXISTING mRID. creationTime is rule f)'s supersession
	// tiebreak — exactly as load-bearing to an event's identity as the
	// interval/window, which is unconditionally protected (controlIdentity)
	// — so moving it is just as much an edit as authoring new content, and
	// gets its own named lever rather than riding AllowContentEdit's.
	AllowCreationTimeMove bool `json:"allow_creation_time_move,omitempty"`
}

// armed reports whether either deliberate violation was requested.
func (n *nonconformantControlEdit) armed() bool {
	return n != nil && (n.AllowContentEdit || n.AllowCreationTimeMove)
}

// adminCtrlReq is the JSON body for POST /admin/control.
// All OpMod fields are optional (nil = not included in the control).
type adminCtrlReq struct {
	Program     int    `json:"program"`
	Description string `json:"description"`
	StartOffset int    `json:"start_offset_s"` // seconds from now
	DurationS   int    `json:"duration_s"`     // default 300
	Activate    bool   `json:"activate"`       // true = replace active list

	// Event-lifecycle controls (audit P1-2/P1-3 — let a scenario drive the
	// hub's server-side Cancelled(6)/Superseded(7) emission and its
	// randomizeDuration consumption over the wire; the hub already does all
	// three, these seams just make a bench scenario prove it e2e):
	//
	//   MRID                  — explicit mRID (default: auto-generated). When a
	//                           control with this mRID already exists in the
	//                           program's list, the POST UPDATES it in place
	//                           rather than adding a new one — the two-step a
	//                           server-cancel needs (post a control, let the hub
	//                           receive it, then flip its currentStatus→6; the
	//                           hub drops events that arrive already-cancelled).
	//   PotentiallySuperseded — sets EventStatus.potentiallySuperseded on the
	//                           built event (the loser of an overlapping pair).
	//   CurrentStatus         — overrides EventStatus.currentStatus (e.g. 6 =
	//                           Cancelled); nil ⇒ the window-derived 0/1.
	//   CreationOffsetS        — shifts creationTime by N seconds so an
	//                           overlapping pair has a DETERMINISTIC winner (the
	//                           later creationTime supersedes) without relying
	//                           on wall-clock spacing between two POSTs.
	//   RandomizeStart/Duration — served straight through to the DERControl.
	//   ResponseRequired      — overrides the responseRequired bitmap the
	//                           control carries (default
	//                           adminDefaultResponseRequired — see that
	//                           const's doc for the bit semantics and why an
	//                           admin control needs it at all). A scenario
	//                           proving the DUT correctly withholds a
	//                           Response when none was asked for passes 0
	//                           here.
	MRID                  string `json:"mrid,omitempty"`
	PotentiallySuperseded *bool  `json:"potentially_superseded,omitempty"`
	CurrentStatus         *uint8 `json:"current_status,omitempty"`
	CreationOffsetS       *int   `json:"creation_offset_s,omitempty"`
	RandomizeStart        *int32 `json:"randomize_start,omitempty"`
	RandomizeDuration     *int32 `json:"randomize_duration,omitempty"`
	ResponseRequired      *uint8 `json:"response_required,omitempty"`

	// DERControlBase fields — only non-nil ones are included in the event.
	//
	// IW13-001 (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §4.2):
	// MaxLimW/FixedW are HUNDREDTHS OF A PERCENT (opModMaxLimW/opModFixedW's
	// real wire unit), not watts — buildBase wraps them directly into
	// PerCent/SignedPerCent with no multiplier scaling, unlike
	// ExpLimW/ImpLimW/GenLimW/LoadLimW (still genuine watts, §1.2, still
	// scaled through apFromWatts's ActivePower encoder). The field/JSON names
	// are unchanged from their pre-fix (watts) meaning deliberately, to avoid
	// rippling the admin API surface for a units-only fix — every caller is
	// this repo's own harness code, not an external consumer.
	ExpLimW  *int64 `json:"exp_lim_W,omitempty"`
	MaxLimW  *int64 `json:"max_lim_W,omitempty"` // hundredths of a percent (IW13-001)
	ImpLimW  *int64 `json:"imp_lim_W,omitempty"`
	GenLimW  *int64 `json:"gen_lim_W,omitempty"`
	LoadLimW *int64 `json:"load_lim_W,omitempty"`
	FixedW   *int64 `json:"fixed_W,omitempty"` // hundredths of a percent, signed (IW13-001)
	// TargetW is opModTargetW (genuine nested ActivePower, watts — §1.1,
	// already correct, untouched by IW13-001) on the EXTENDED control base.
	// Added by §4.2 specifically for BASIC-014, which previously had no
	// request-surface lever for this axis at all and rode the wrong FixedW
	// field instead; mirrors ExpLimW's own watts shape.
	TargetW  *int64 `json:"target_W,omitempty"`
	Connect  *bool  `json:"connect,omitempty"`
	Energize *bool  `json:"energize,omitempty"`
	// The two fixed-PF axes, each a PowerFactorWithExcitation with three
	// mandatory children (IEEE Std 2030.5-2018 p.258 — see fixedpf.go for the
	// whole-or-nothing rule and why the retired scalar is refused rather than
	// translated).
	FixedPFInjectW *fixedPFReq `json:"fixed_pf_inject,omitempty"`
	FixedPFAbsorbW *fixedPFReq `json:"fixed_pf_absorb,omitempty"`
	// The retired scalar fields, trapped so a caller still sending one is told
	// rather than silently served a control with no PF element at all. Pointers,
	// so "absent" and "sent as 0" stay distinguishable.
	FixedPFInjectPctGone *int64 `json:"fixed_pf_inject_pct,omitempty"`
	FixedPFAbsorbPctGone *int64 `json:"fixed_pf_absorb_pct,omitempty"`
	FixedVarPct          *int64 `json:"fixed_var_pct,omitempty"`
	// FreqDroop is opModFreqDroop's five inline parameters (curve plan #32 —
	// freqdroop.go for units, the whole-or-nothing rule and the ordering note).
	// Like TargetW it exists ONLY on the extended control base, so a request
	// carrying it forces this control into extended storage exactly as TargetW
	// already does; buildBase's narrow DERControlBase cannot hold it at all.
	FreqDroop *freqDroopReq `json:"freq_droop,omitempty"`

	// NullAxes names DERControlBase elements this control serves as PRESENT
	// AND EXPLICITLY NULL — `<opModVoltVar xsi:nil="true"/>` — rather than by
	// value or by leaving them out. The vocabulary is the model's own element
	// names, and nothing else is accepted; explicitnil.go holds the mechanism,
	// what IEEE Std 2030.5-2018 does and does not say about it (it says
	// nothing), and why a document-level lever rather than a struct field is
	// the only way to author one.
	//
	// A NAMED OPT-IN, like curve.go's `nonconformant`, because the shape it
	// authors is one the standard neither requires nor describes: a reader of
	// a request — or of the bundle carrying it — has to be able to see that
	// the document was deliberate. Unlike the other fields here it does not
	// go through buildBase at all; it never reaches the stored resource,
	// because no csipmodel field could hold it.
	NullAxes []string `json:"null_axes,omitempty"`

	// Nonconformant is the named opt-in for a same-mRID update that
	// deliberately breaks IEEE Std 2030.5-2018 §10.2.3.3 c) — see
	// nonconformantControlEdit. Every update that does not set it is held to
	// the rule: only EventStatus may change.
	Nonconformant *nonconformantControlEdit `json:"nonconformant,omitempty"`
}

// nonStatusEdits names every element of req that would author content
// §10.2.3.3 c) reserves to a NEW Event, for a POST that reuses an EXISTING
// mRID. explicitDescription is whether the caller actually sent a
// description, taken BEFORE adminCtrlPost substitutes the "Admin control"
// default — a caller who simply omitted it on a status-only update is not
// authoring anything and must not be flagged for the default's own text.
// droop/nullAxes are the already-validated derived values (droop from
// req.FreqDroop.toModel(), nullAxes from req.explicitNilAxes()) rather than
// the raw request fields, so this reads the same "did this request actually
// ask for one of these" question buildBase and its siblings answer.
func (req adminCtrlReq) nonStatusEdits(explicitDescription bool, droop *model.FreqDroop, nullAxes []string) []string {
	var edits []string
	add := func(present bool, name string) {
		if present {
			edits = append(edits, name)
		}
	}
	add(explicitDescription, "description")
	add(req.ResponseRequired != nil, "response_required")
	add(req.RandomizeStart != nil, "randomize_start")
	add(req.RandomizeDuration != nil, "randomize_duration")
	add(req.ExpLimW != nil, "exp_lim_W")
	add(req.MaxLimW != nil, "max_lim_W")
	add(req.ImpLimW != nil, "imp_lim_W")
	add(req.GenLimW != nil, "gen_lim_W")
	add(req.LoadLimW != nil, "load_lim_W")
	add(req.FixedW != nil, "fixed_W")
	add(req.TargetW != nil, "target_W")
	add(req.Connect != nil, "connect")
	add(req.Energize != nil, "energize")
	add(req.FixedPFInjectW != nil, "fixed_pf_inject")
	add(req.FixedPFAbsorbW != nil, "fixed_pf_absorb")
	add(req.FixedVarPct != nil, "fixed_var_pct")
	add(droop != nil, "freq_droop")
	add(len(nullAxes) > 0, "null_axes")
	return edits
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

// adminDefaultResponseRequired is the IEEE 2030.5 responseRequired bitmap
// (hexBinary8, Table 27 / RespondableResource — see lexa-proto
// csipmodel/resources.go's ResponseRequired doc, which this mirrors) an
// admin-created event control carries unless a request overrides it:
//
//	bit 0 (0x01, RespReqMessageReceived)   — the DUT shall POST a Response
//	                                         acknowledging the event was
//	                                         received;
//	bit 1 (0x02, RespReqSpecificResponse)  — the DUT shall ALSO POST the
//	                                         specific-outcome Response
//	                                         (started/completed/superseded/
//	                                         etc.) as the event's lifecycle
//	                                         proceeds;
//	bit 2 (0x04, RespReqCustomerResponse)  — the DUT shall ALSO POST status
//	                                         11 (User acknowledged) on a
//	                                         customer's own acknowledgment.
//
// All three are set (F7/#18, 2026-08-17: raised from 0x03 — bit 0/1 only —
// to 0x07 to match the catalog procedures' own responseRequired=7, catalog
// fidelity this bench was previously short of). Without bit 1 a
// spec-compliant client has nothing obliging it to ever report status=2
// (Event started) — IEEE 2030.5 does not have a client volunteer a Response
// nobody asked for — so CORE-022/CORE-023 could never observe the
// started/completed/superseded lifecycle from any DUT that actually
// implements that "do not respond unless asked" rule.
//
// Bit 2 is a no-op on this bench: nothing in it simulates a customer-facing
// UI, so status 11 (User acknowledged, gated on bit 2 by
// csipmodel.Table27RequiredBit) is neither posted by lexa-gw nor demanded by
// any criterion in this suite — setting the bit only widens what a DUT is
// PERMITTED to answer, and #17/F2's per-bit criterion gating (criteria_2030.go's
// respReqNotRequested) means a bit being SET can never SUPPRESS grading of a
// status that bit doesn't govern, so this change is catalog-fidelity-only:
// TestResponseRequiredMatchesCatalogFidelity below proves no criterion
// regresses under it. (lexa-gw's northbound tracker —
// internal/northbound/responses/tracker.go's postResponse — now does its own
// PER-BIT gating keyed by the same csipmodel.Table27RequiredBit table, SD-02;
// the "currently lenient, bit-level subsetting is a future refinement" this
// comment used to carry described the pre-SD-02 gateway and is no longer
// true of either side.)
const adminDefaultResponseRequired = model.RespReqMessageReceived | model.RespReqSpecificResponse | model.RespReqCustomerResponse

// adminResponseReplyTo is the Response POST target an admin-created control's
// replyTo attribute points at: gridsim's own advertised default ResponseSet
// (/rsps/0/r — seeded in server.go's buildResourceTree alongside
// DeviceCapability.ResponseSetListLink, and where handleResponsePost listens;
// see server.go's "Response log" section). The standing bench controls (the
// ones server.go seeds directly into /derp/*/derc rather than through this
// admin API) never set replyTo either, and still arrive here because a
// consumer with no per-event replyTo falls back to this exact advertised
// default — so pointing admin-created controls at the same href, rather than
// leaving it to that fallback, keeps the two paths' wire behavior consistent
// and gives CORE-022's "POSTs to the control's OWN replyTo" criterion
// (core.go) something to actually distinguish from the fallback case.
const adminResponseReplyTo = "/rsps/0/r"

// notifyControlChange is the Subscription function set's hook into the control
// levers: a DERControlList that gained or changed an entry is a change a
// subscriber asked to be told about.
//
// It is called AFTER the resource tree already holds the new list and with no
// lock held, so a client that GETs the href out of the Notification reads the
// state the Notification described. The ActiveDERControlList is notified too
// because it is separately subscribable and separately mutated.
func (s *Server) notifyControlChange(program int) {
	s.notifyChanged(
		fmt.Sprintf("/derp/%d/derc", program),
		fmt.Sprintf("/derp/%d/actderc", program),
	)
}

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
	if err := percentDomainErr(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Validated before anything is stored, for the reason adminCurvePost gives:
	// a control that cannot be authored whole must not be half-published.
	droop, err := req.FreqDroop.toModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	injectPF, absorbPF, err := req.fixedPF()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	nullAxes, err := req.explicitNilAxes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Captured BEFORE the "Admin control" default below is substituted, so
	// nonStatusEdits can tell "this request authored a description" from
	// "this request just left it out" — the two must not be flagged alike.
	explicitDescription := req.Description != ""
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
	// a spec-correct client could have started them early). CurrentStatus
	// overrides it directly (e.g. 6/Cancelled for a server-cancel).
	activeNow := req.StartOffset <= 0
	var status uint8
	if activeNow {
		status = 1 // Active
	}
	if req.CurrentStatus != nil {
		status = *req.CurrentStatus
	}
	mrid := req.MRID
	if mrid == "" {
		mrid = fmt.Sprintf("DERC-%s-ADMIN-%d", progPrefixes[req.Program], now)
	}
	creationTime := now
	if req.CreationOffsetS != nil {
		creationTime = now + int64(*req.CreationOffsetS)
	}
	interval := model.DateTimeInterval{
		Duration: uint32(req.DurationS),
		Start:    now + int64(req.StartOffset),
	}

	// ── §10.2.3 c): AN UPDATE-IN-PLACE MAY CHANGE STATUS AND NOTHING ELSE ─────
	//
	// IEEE Std 2030.5-2018 §10.2.3.3 rule c) is unconditional: "Editing Events
	// SHALL NOT be allowed except for updating status. Service providers SHALL
	// cancel Events that they wish clients to not act upon and/or provide new
	// superseding Events." An explicit mRID that already exists is precisely
	// that edit (the server-cancel two-step this endpoint was built for).
	//
	// IW27-005: this used to stop at protecting creationTime/interval (the
	// history immediately below) while leaving Description, ResponseRequired,
	// RandomizeStart/RandomizeDuration and the ENTIRE DERControlBase (via
	// buildBase(req, ...)) unconditionally re-authored from whatever the
	// update's request body said — which is precisely the edit rule c)
	// forbids, just of different elements than the ones the original guard
	// covered. A test fixture could author server behaviour no conformant
	// service provider could ever produce (re-describe an event, flip its
	// content, even move its creationTime via creation_offset_s) and grade a
	// DUT against a moving target while believing it was testing the DUT.
	// The guard below closes that: by DEFAULT, an update to an existing mRID
	// may change only what EventStatus holds (current_status,
	// potentially_superseded) plus the two ALREADY-protected identity fields;
	// everything else is refused (400) before anything is stored, unless the
	// caller explicitly opts into authoring it as a NAMED non-conformant
	// negative test (nonconformantControlEdit).
	//
	// creationTime is the tiebreak rule f) uses to decide which of two
	// same-primacy Overlapping Events supersedes the other, and
	// interval/start is the window rules m)/n)/o) reason about — so a
	// status-only flip that silently re-stamped either made the cancelled
	// event both NEWER and LATER-STARTING than everything it had been
	// arbitrated against, and a DUT that re-arbitrates on the edited copy is
	// being graded against a fixture that moved under it. Reproduced in
	// runs/verify-796fbc3-20260819T203800Z: CERT-CORE022-CANCEL-893ce120 was
	// served creationTime/start 1787171378 before the cancel and
	// creationTime/start 1787171532 after it, with only currentStatus meant to
	// change (frames 1143 vs 1281 of that bundle's capture).
	//
	// So a matched in-place update inherits the stored copy's creationTime and
	// interval, and refuses any request that would move either without the
	// nonconformant.allow_creation_time_move escape hatch (a caller that wants
	// a different WINDOW publishes a different mRID, which is what rule c)
	// leaves it). Deliberately does not consult ActiveDERControlList: derc is
	// the scheduled list and the authority for an event's own identity, and
	// the two lists' copies may diverge (finding #4, first-copy-wins).
	var prior controlIdentity
	var hadPrior bool
	if req.MRID != "" {
		s.mu.RLock()
		prior, hadPrior = s.controlIdentityLocked(req.Program, mrid)
		s.mu.RUnlock()
		if hadPrior {
			nc := req.Nonconformant
			if edits := req.nonStatusEdits(explicitDescription, droop, nullAxes); len(edits) > 0 && !(nc.armed() && nc.AllowContentEdit) {
				http.Error(w, fmt.Sprintf("mrid %q already exists: IEEE Std 2030.5-2018 §10.2.3.3 c) — "+
					"\"Editing Events SHALL NOT be allowed except for updating status. Service providers "+
					"SHALL cancel Events that they wish clients to not act upon and/or provide new "+
					"superseding Events\" — so this update may change only EventStatus (current_status, "+
					"potentially_superseded), not %s. Publish a NEW mrid instead, or set "+
					"nonconformant.allow_content_edit:true to deliberately author the illegal edit for a "+
					"negative test", mrid, strings.Join(edits, ", ")), http.StatusBadRequest)
				return
			}
			if req.CreationOffsetS != nil && !(nc.armed() && nc.AllowCreationTimeMove) {
				http.Error(w, fmt.Sprintf("mrid %q already exists: creation_offset_s would move "+
					"creationTime, which IEEE Std 2030.5-2018 §10.2.3.3 c) reserves to a NEW Event (rule "+
					"f)'s supersession tiebreak runs on it) — omit creation_offset_s on this update, or set "+
					"nonconformant.allow_creation_time_move:true to deliberately author the illegal redate "+
					"for a negative test", mrid), http.StatusBadRequest)
				return
			}
			if req.CreationOffsetS == nil {
				creationTime = prior.creationTime
			}
			interval = prior.interval
			// The default status below is derived from the window, so it has to
			// be re-derived from the window this update actually serves rather
			// than from the request's own offset. An explicit CurrentStatus
			// (the server-cancel's whole point) still overrides it.
			activeNow = interval.Start <= now
			status = 0
			if activeNow {
				status = 1
			}
			if req.CurrentStatus != nil {
				status = *req.CurrentStatus
			}
		}
	}
	// responseRequired defaults ON (adminDefaultResponseRequired — see its doc
	// for the bit semantics) so the DUT is actually asked for the Response
	// lifecycle CORE-022/CORE-023 grade; ResponseRequired lets a scenario
	// override it (e.g. 0, to prove the DUT correctly withholds a Response
	// nobody asked for).
	responseRequired := model.ResponseRequired(adminDefaultResponseRequired)
	if req.ResponseRequired != nil {
		responseRequired = model.ResponseRequired(*req.ResponseRequired)
	}
	newStatus := &model.EventStatus{
		CurrentStatus:         status,
		DateTime:              now,
		PotentiallySuperseded: req.PotentiallySuperseded != nil && *req.PotentiallySuperseded,
	}

	// inheritStored is true for a matched update that passed the guard above
	// WITHOUT an armed content edit — i.e. an ordinary status-only flip. Such
	// a request's content fields are now guaranteed empty (the guard already
	// rejected anything else), so building a fresh DERControlBase from req
	// via buildBase would author an EMPTY one and WIPE every axis this event
	// was carrying — exactly the kind of edit rule c) forbids, just arrived at
	// by omission instead of by re-authoring. So this path does not call
	// buildBase (or even read the content fields of req) at all: it clones
	// the STORED resource — scalar or extended, whichever it actually is —
	// and swaps in only the new EventStatus.
	inheritStored := hadPrior && len(req.nonStatusEdits(explicitDescription, droop, nullAxes)) == 0
	var ctrl model.DERControl
	var extCtrl *model.ExtendedDERControl
	switch {
	case inheritStored && prior.extended != nil:
		e := *prior.extended
		e.EventStatus = newStatus
		// creationTime is NOT necessarily prior.creationTime unchanged: the
		// guard above already applied nonconformant.allow_creation_time_move
		// (or left it at prior.creationTime when that lever was not armed) —
		// this local var, not the clone's own stamp, is the one place that
		// decision landed.
		e.CreationTime = creationTime
		extCtrl = &e
		// ctrl itself is not the stored resource in this case (extCtrl is) —
		// MRID is the only field of it anything downstream still reads.
		ctrl.MRID = mrid
	case inheritStored && prior.scalar != nil:
		ctrl = *prior.scalar
		ctrl.EventStatus = newStatus
		ctrl.CreationTime = creationTime // see the extended case's comment above
	default:
		ctrl = model.DERControl{
			// Href keyed by mRID so distinct admin controls are distinct addressable
			// resources (a re-post of the same mRID — the server-cancel update — keeps
			// the same href and upserts). A shared href would collapse two controls
			// into one for any client that de-duplicates a paged list by href.
			Resource: model.Resource{Href: fmt.Sprintf("/derp/%d/derc/%s", req.Program, mrid)},
			// ReplyTo/ResponseRequired: IEEE 2030.5 Event-base (RespondableResource)
			// attributes — see adminResponseReplyTo/adminDefaultResponseRequired.
			ReplyTo:           adminResponseReplyTo,
			ResponseRequired:  &responseRequired,
			MRID:              mrid,
			Description:       req.Description,
			CreationTime:      creationTime,
			EventStatus:       newStatus,
			Interval:          interval,
			RandomizeStart:    req.RandomizeStart,
			RandomizeDuration: req.RandomizeDuration,
			DERControlBase:    buildBase(req, injectPF, absorbPF),
		}
	}

	// IW13-001 §4.2: opModTargetW only exists on the EXTENDED control base —
	// buildBase's narrow DERControlBase (ctrl.DERControlBase above) cannot
	// carry it at all. When req.TargetW is set, pre-build the ExtendedDERControl
	// this control is stored as, TargetW included, and route BOTH list writes
	// below through the extended path unconditionally — the same widen-in-place
	// pattern POST /admin/curve already established for curve-linked controls.
	//
	// opModFreqDroop (curve plan #32) joins it on the identical footing and
	// through the identical path: an extended-only element, forcing extended
	// storage, pre-built here so the direct store below cannot drop it. Both
	// may ride the SAME control — a request carrying TargetW and FreqDroop
	// produces one control carrying both, which is what a caller who asked for
	// both would expect and what a second `if` would have quietly broken.
	//
	// Not reached when extCtrl is already set by the inheritStored branch
	// above (that branch's req.TargetW/droop are guaranteed nil — both are
	// content fields nonStatusEdits gates — so this condition is false and
	// the cloned extCtrl stands untouched).
	if req.TargetW != nil || droop != nil {
		e := toExtendedControl(ctrl)
		e.DERControlBase.OpModTargetW = apFromWatts(req.TargetW)
		e.DERControlBase.OpModFreqDroop = droop
		extCtrl = &e
	}

	// The explicit-nil conflict is checked HERE and not with the other
	// validation above because it is the only rule that needs the control this
	// request will actually serve rather than the request itself: an axis is
	// "valued" if the built base carries it, whichever of the two bases ends up
	// holding it. Still ahead of every store — nothing below this point can be
	// reached without passing it.
	var conflictBases []any
	if extCtrl != nil {
		conflictBases = append(conflictBases, extCtrl.DERControlBase)
	}
	conflictBases = append(conflictBases, ctrl.DERControlBase)
	if err := explicitNilValueConflict(nullAxes, conflictBases...); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(nullAxes) > 0 {
		// The same self-documenting audit line POST /admin/curve writes for a
		// deliberately non-conformant curve, and for the same reason: the log
		// beside a capture has to say what the document was MEANT to be. This
		// one names what the standard does not say, because a reader who finds
		// xsi:nil in a bundle will reasonably assume it does.
		log.Printf("[gridsim] POST /admin/control: EXPLICIT xsi:nil BY REQUEST — program=%d mrid=%s "+
			"axes=%s. These elements are served PRESENT AND NULL rather than omitted. IEEE Std "+
			"2030.5-2018 declares them [0..1] (p.248-251) and says nothing about explicit nil — the "+
			"distinction this document draws is the PRODUCT's claim, not the standard's requirement",
			req.Program, mrid, strings.Join(nullAxes, ","))
	}

	// An explicit mRID that already exists is an UPDATE-in-place (the flip a
	// server-cancel needs), never an add; an absent/auto mRID keeps the
	// original activate/append semantics exactly.
	matchMRID := req.MRID != ""

	// NOT deferred: the Notification this change owes its subscribers is pushed
	// after the unlock (notifyControlChange dials out, and holding the resource
	// lock across a network round-trip to the DUT would stall every CSIP
	// request the DUT makes in the meantime — including the GET it makes
	// BECAUSE of the Notification). There is no early return between here and
	// the unlock below.
	s.mu.Lock()

	// Write to derc (scheduled list) — this is what the hub's walker reads via
	// DERControlListLink. The scheduler evaluates the time window and marks it
	// active when start <= serverNow < start+duration.
	dercPath := fmt.Sprintf("/derp/%d/derc", req.Program)
	if extCtrl != nil {
		// TargetW forces extended storage — widen a still-scalar list in
		// place first, then store the PRE-BUILT extended control directly
		// (upsertExtendedControl's usual re-derive via toExtendedControl(ctrl)
		// would drop OpModTargetW, which only exists on extCtrl, never on
		// ctrl.DERControlBase — see upsertExtendedControlDirect).
		if _, ok := s.resources[dercPath].(*model.ExtendedDERControlList); !ok {
			s.resources[dercPath] = &model.ExtendedDERControlList{
				Resource: model.Resource{Href: dercPath}, PollRate: s.controlListPollRateLocked(),
			}
		}
		dercList := s.resources[dercPath].(*model.ExtendedDERControlList)
		dercList.DERControl = upsertExtendedControlDirect(dercList.DERControl, *extCtrl, req.Activate, matchMRID)
		dercList.All = uint32(len(dercList.DERControl))
		dercList.Results = dercList.All
	} else {
		// A prior POST /admin/curve may have left an ExtendedDERControlList
		// here; widen this scalar control into it rather than silently no-op'ing.
		switch dercList := s.resources[dercPath].(type) {
		case *model.DERControlList:
			dercList.DERControl = upsertScalarControl(dercList.DERControl, ctrl, req.Activate, matchMRID)
			dercList.All = uint32(len(dercList.DERControl))
			dercList.Results = dercList.All
		case *model.ExtendedDERControlList:
			dercList.DERControl = upsertExtendedControl(dercList.DERControl, ctrl, req.Activate, matchMRID)
			dercList.All = uint32(len(dercList.DERControl))
			dercList.Results = dercList.All
		}
	}

	// Mirror into actderc (status display) only when the event window is
	// already open; ActiveDERControlList must contain active events only.
	// Activate=true keeps its replace semantics: a future event clears the
	// stale active list rather than joining it. For an in-place UPDATE
	// (matchMRID) refresh the existing entry only — never add a (possibly
	// now-cancelled) control to the active list.
	actPath := fmt.Sprintf("/derp/%d/actderc", req.Program)
	if extCtrl != nil {
		if _, ok := s.resources[actPath].(*model.ExtendedDERControlList); !ok {
			s.resources[actPath] = &model.ExtendedDERControlList{
				Resource: model.Resource{Href: actPath}, PollRate: s.controlListPollRateLocked(),
			}
		}
		actList := s.resources[actPath].(*model.ExtendedDERControlList)
		if matchMRID {
			replaceExtendedInPlace(actList.DERControl, *extCtrl)
		} else {
			switch {
			case req.Activate && activeNow:
				actList.DERControl = []model.ExtendedDERControl{*extCtrl}
			case req.Activate:
				actList.DERControl = nil
			case activeNow:
				actList.DERControl = append(actList.DERControl, *extCtrl)
			}
		}
		actList.All = uint32(len(actList.DERControl))
		actList.Results = actList.All
	} else {
		switch actList := s.resources[actPath].(type) {
		case *model.DERControlList:
			if matchMRID {
				replaceScalarInPlace(actList.DERControl, ctrl)
			} else {
				switch {
				case req.Activate && activeNow:
					actList.DERControl = []model.DERControl{ctrl}
				case req.Activate:
					actList.DERControl = nil
				case activeNow:
					actList.DERControl = append(actList.DERControl, ctrl)
				}
			}
			actList.All = uint32(len(actList.DERControl))
			actList.Results = actList.All
		case *model.ExtendedDERControlList:
			if matchMRID {
				replaceExtendedInPlace(actList.DERControl, toExtendedControl(ctrl))
			} else {
				ext := toExtendedControl(ctrl)
				switch {
				case req.Activate && activeNow:
					actList.DERControl = []model.ExtendedDERControl{ext}
				case req.Activate:
					actList.DERControl = nil
				case activeNow:
					actList.DERControl = append(actList.DERControl, ext)
				}
			}
			actList.All = uint32(len(actList.DERControl))
			actList.Results = actList.All
		}
	}

	// The explicit-nil marker is armed AFTER the writes, and the orphan sweep
	// runs after it, so both decide against the list as it now stands rather
	// than as the request described it — an activate:true POST, for instance,
	// has just discarded every other control in the program, and their markers
	// go with them. See explicitnil.go.
	s.setExplicitNilLocked(req.Program, ctrl.MRID, nullAxes)
	s.forgetOrphanedExplicitNilLocked(req.Program)
	s.mu.Unlock()

	s.notifyControlChange(req.Program)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"mrid": ctrl.MRID})
}

// controlIdentity is the part of a stored DERControl that IEEE Std 2030.5-2018
// §10.2.3.3 c) forbids an update from editing: the event's creationTime (rule
// f)'s supersession tiebreak) and its interval (the window rules m)/n)/o) all
// reason about). These two are protected unconditionally, inherited from the
// stored copy on every matched update. IW27-005: description, responseRequired,
// randomization and the control base used to be re-authored from the request
// unconditionally too, on the premise that a scenario re-POSTing the same mRID
// is expected to carry them through unchanged — but "expected to" is not
// enforced, and adminCtrlPost's guard (nonStatusEdits) now refuses a request
// that would author any of them, by default; nonconformantControlEdit is the
// opt-in for a fixture that deliberately wants the old behaviour back.
//
// scalar/extended carry the FULL stored resource (exactly one of them set,
// matching whichever storage width the program's list actually has), not just
// creationTime/interval: a default-path status-only update clones one of
// these and swaps in only the new EventStatus (see adminCtrlPost), rather than
// re-deriving a DERControlBase from a request the guard has already forced to
// carry no content — which would author an EMPTY one and wipe every axis the
// event was carrying.
type controlIdentity struct {
	creationTime int64
	interval     model.DateTimeInterval
	scalar       *model.DERControl
	extended     *model.ExtendedDERControl
}

// controlIdentityLocked returns the stored identity of program's control with
// this mRID, from the SCHEDULED list (/derp/N/derc) in whichever storage width
// that list currently has. ok is false when no such control is stored, which is
// the ordinary "this POST is an add, not an edit" case.
//
// Must be called with s.mu held (read is enough).
func (s *Server) controlIdentityLocked(program int, mrid string) (controlIdentity, bool) {
	switch list := s.resources[fmt.Sprintf("/derp/%d/derc", program)].(type) {
	case *model.DERControlList:
		for i := range list.DERControl {
			if list.DERControl[i].MRID == mrid {
				c := list.DERControl[i]
				return controlIdentity{creationTime: c.CreationTime, interval: c.Interval, scalar: &c}, true
			}
		}
	case *model.ExtendedDERControlList:
		for i := range list.DERControl {
			if list.DERControl[i].MRID == mrid {
				c := list.DERControl[i]
				return controlIdentity{creationTime: c.CreationTime, interval: c.Interval, extended: &c}, true
			}
		}
	}
	return controlIdentity{}, false
}

// upsertScalarControl adds ctrl to a scalar DERControl list, or — when
// matchMRID is set and an entry with the same mRID already exists — replaces
// that entry in place (the server-cancel status flip). With no match it honors
// the original semantics: activate replaces the whole list, else it appends.
func upsertScalarControl(list []model.DERControl, ctrl model.DERControl, activate, matchMRID bool) []model.DERControl {
	if matchMRID {
		for i := range list {
			if list[i].MRID == ctrl.MRID {
				list[i] = ctrl
				return list
			}
		}
	}
	if activate {
		return []model.DERControl{ctrl}
	}
	return append(list, ctrl)
}

// upsertExtendedControl is upsertScalarControl for a curve-bound
// ExtendedDERControlList (a prior POST /admin/curve widened the list).
func upsertExtendedControl(list []model.ExtendedDERControl, ctrl model.DERControl, activate, matchMRID bool) []model.ExtendedDERControl {
	ext := toExtendedControl(ctrl)
	if matchMRID {
		for i := range list {
			if list[i].MRID == ext.MRID {
				list[i] = ext
				return list
			}
		}
	}
	if activate {
		return []model.ExtendedDERControl{ext}
	}
	return append(list, ext)
}

// upsertExtendedControlDirect is upsertExtendedControl for a caller that
// already holds the built ExtendedDERControl (IW13-001 §4.2's TargetW path,
// which sets OpModTargetW on the widened base BEFORE storage — re-deriving
// via toExtendedControl(ctrl) the way upsertExtendedControl does would drop
// that field, since it only exists on the extended struct, never on the
// narrow ctrl.DERControlBase toExtendedControl reads from).
func upsertExtendedControlDirect(list []model.ExtendedDERControl, ext model.ExtendedDERControl, activate, matchMRID bool) []model.ExtendedDERControl {
	if matchMRID {
		for i := range list {
			if list[i].MRID == ext.MRID {
				list[i] = ext
				return list
			}
		}
	}
	if activate {
		return []model.ExtendedDERControl{ext}
	}
	return append(list, ext)
}

// replaceScalarInPlace refreshes an existing same-mRID entry (if present) and
// is a no-op otherwise — used to mirror an in-place update into actderc
// without ever adding a new active entry.
func replaceScalarInPlace(list []model.DERControl, ctrl model.DERControl) {
	for i := range list {
		if list[i].MRID == ctrl.MRID {
			list[i] = ctrl
			return
		}
	}
}

func replaceExtendedInPlace(list []model.ExtendedDERControl, ext model.ExtendedDERControl) {
	for i := range list {
		if list[i].MRID == ext.MRID {
			list[i] = ext
			return
		}
	}
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
	// Every control just went; so does every explicit-nil marker armed on one.
	// A marker that outlived its control re-attaches to whatever control next
	// claims that mRID (explicitnil.go).
	s.forgetOrphanedExplicitNilLocked(req.Program)
	s.mu.Unlock()

	// Clearing a list is a change to it too. A subscriber that heard about the
	// control's creation and not about its removal would hold a schedule the
	// server has stopped serving.
	s.notifyControlChange(req.Program)

	w.WriteHeader(http.StatusNoContent)
}

// fixedPF validates BOTH fixed-PF elements of a request and renders them, or
// returns the reason one of them cannot be authored.
//
// It also traps the RETIRED scalar fields. A caller still sending
// fixed_pf_inject_pct gets a 400 naming the replacement, never a silently
// PF-less control: the old field named a real axis, so dropping it quietly
// would publish a control that commands nothing where the operator asked for a
// power factor, and the row grading it would report on a condition the DUT was
// never offered. Same rule that retired x_ref_type.
func (req adminCtrlReq) fixedPF() (inject, absorb *model.PowerFactorWithExcitation, err error) {
	if req.FixedPFInjectPctGone != nil {
		return nil, nil, fixedPFScalarGone("fixed_pf_inject_pct", fixedPFInjectElement)
	}
	if req.FixedPFAbsorbPctGone != nil {
		return nil, nil, fixedPFScalarGone("fixed_pf_absorb_pct", fixedPFAbsorbElement)
	}
	// ONE validator for both axes, so the two cannot drift into different rules
	// about the same wire type.
	if inject, err = req.FixedPFInjectW.toModel(fixedPFInjectElement); err != nil {
		return nil, nil, err
	}
	if absorb, err = req.FixedPFAbsorbW.toModel(fixedPFAbsorbElement); err != nil {
		return nil, nil, err
	}
	return inject, absorb, nil
}

// buildBase constructs a DERControlBase from an adminCtrlReq.
// Only fields that are non-nil in the request are set.
//
// THE TWO FIXED-PF ELEMENTS ARRIVE ALREADY VALIDATED, as parameters rather than
// off req, and that is a type-level guarantee rather than a convention: they are
// the one part of a control base this server can REFUSE to author (three
// mandatory children, a domain on each, and a product that must land in (0,1] —
// fixedpf.go), and refusing belongs in the handler where a 400 can be written.
// Reading them off req here would let a future caller build a base from an
// unvalidated request and serve a document the product correctly rejects, which
// is the whole defect class this wave exists to close. Same shape as
// opModFreqDroop, which the handlers likewise validate before the store.
func buildBase(req adminCtrlReq, injectPF, absorbPF *model.PowerFactorWithExcitation) model.DERControlBase {
	b := model.DERControlBase{
		OpModConnect:  req.Connect,
		OpModEnergize: req.Energize,
	}
	b.OpModExpLimW = apFromWatts(req.ExpLimW)
	// IW13-001 (docs/design/IW13_ACTIVE_POWER_UNITS_2026-08-12.md §4.2):
	// opModMaxLimW/opModFixedW are PerCent/SignedPerCent, not ActivePower —
	// req.MaxLimW/FixedW already carry the wire's own hundredths-of-a-percent
	// unit directly (see adminCtrlReq's doc comment), so no apFromWatts
	// multiplier scaling applies; a bare int16 wrap is the whole conversion.
	b.OpModMaxLimW = percentFromHundredths(req.MaxLimW)
	b.OpModImpLimW = apFromWatts(req.ImpLimW)
	b.OpModGenLimW = apFromWatts(req.GenLimW)
	b.OpModLoadLimW = apFromWatts(req.LoadLimW)
	b.OpModFixedW = signedPercentFromHundredths(req.FixedW)
	b.OpModFixedPFInjectW = injectPF
	b.OpModFixedPFAbsorbW = absorbPF
	if req.FixedVarPct != nil {
		b.OpModFixedVar = &model.FixedVar{
			// DERUnitRefType 2 = %setMaxVar — see the identical correction in
			// curve.go for why this was RefType 1 ("rated capacity", which is
			// not what code 1 means) and why lexa-proto d60e1ca is what makes
			// the difference observable.
			RefType: model.RefTypeSetMaxVar,
			Value:   model.SignedPerCent{Value: int16(*req.FixedVarPct)},
		}
	}
	return b
}

// apFromWatts converts a watt value into an ActivePower, scaling into the
// power-of-ten multiplier when the magnitude exceeds the int16 value range
// (e.g. 40000 W → value=4000, multiplier=1). nil passes through.
//
// Still correct for opModExpLimW/opModImpLimW/opModGenLimW/opModLoadLimW
// (§1.2, unaffected by IW13-001) and for opModTargetW (§1.1, already
// correct). NOT used for opModMaxLimW/opModFixedW any more — see
// percentFromHundredths/signedPercentFromHundredths below.
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

// percentDomainErr rejects admin percent inputs outside their wire type's
// representable domain BEFORE buildBase wraps them: PerCent is a uint16
// (0..65535) and SignedPerCent an int16 (-32768..32767), so an out-of-domain
// int64 would otherwise wrap silently into a plausible-looking control the
// operator never authored (e.g. max_lim_W:-100 → 65436 on the wire, and the
// pcap then records a control nobody asked for). Domain check only — the
// product-range [0,10000] screen is the DUT's job, and sending
// in-domain-but-over-range values is a legitimate test input.
func percentDomainErr(req adminCtrlReq) error {
	if req.MaxLimW != nil && (*req.MaxLimW < 0 || *req.MaxLimW > 65535) {
		return fmt.Errorf("max_lim_W %d outside PerCent's uint16 wire domain [0,65535]", *req.MaxLimW)
	}
	if req.FixedW != nil && (*req.FixedW < -32768 || *req.FixedW > 32767) {
		return fmt.Errorf("fixed_W %d outside SignedPerCent's int16 wire domain [-32768,32767]", *req.FixedW)
	}
	return nil
}

// percentFromHundredths wraps a raw hundredths-of-a-percent value directly
// into a PerCent (opModMaxLimW's real wire type, IW13-001) — no multiplier
// scaling: PerCent carries none at all, unlike ActivePower. nil passes
// through. Domain is enforced by percentDomainErr at the handler boundary.
func percentFromHundredths(v *int64) *model.PerCent {
	if v == nil {
		return nil
	}
	return &model.PerCent{Value: uint16(*v)}
}

// signedPercentFromHundredths is percentFromHundredths's signed sibling
// (opModFixedW's real wire type, SignedPerCent).
func signedPercentFromHundredths(v *int64) *model.SignedPerCent {
	if v == nil {
		return nil
	}
	return &model.SignedPerCent{Value: int16(*v)}
}

// ── DefaultDERControl GET/POST ────────────────────────────────────────────────

// adminDefaultReq is the body for POST /admin/default.
type adminDefaultReq struct {
	Program int          `json:"program"`
	Base    adminCtrlReq `json:"base"`
	Clear   bool         `json:"clear,omitempty"`

	// SetGradW / SetSoftGradW are IEEE 2030.5-2018's ramp-rate defaults, which
	// live on the DefaultDERControl itself and NOT inside DERControlBase — so
	// they sit here beside Base rather than in it. Units are the standard's own:
	// hundredths of a percent of setMaxW per second (PerCent). They are the only
	// route by which a DER client can be told a soft-start ramp, so without this
	// lever the 703 ESRmpTms write path (SetEnergizeWithRamp) is unreachable from
	// a bench. See softgrad.go for why they are carried on a local wrapper type.
	SetGradW     *uint16 `json:"set_grad_w,omitempty"`
	SetSoftGradW *uint16 `json:"set_soft_grad_w,omitempty"`
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
	// BOTH shapes, because a droop-carrying default is stored as the EXTENDED
	// type (see adminDefaultPost). Reading only the narrow one would answer 404
	// for a default this same endpoint had just accepted, which is the shape of
	// bug the derc/actderc widening already had to be taught out of.
	if b, ok := s.defaultBaseInfoLocked(path); ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(b)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

// defaultBaseInfoLocked renders whichever DefaultDERControl shape is stored at
// path. Caller must hold s.mu (read or write).
func (s *Server) defaultBaseInfoLocked(path string) (adminBaseInfo, bool) {
	switch d := s.resources[path].(type) {
	case *defaultDERControlRamps:
		return baseToInfo(d.DERControlBase), true
	case *model.DefaultDERControl:
		return baseToInfo(d.DERControlBase), true
	case *model.ExtendedDefaultDERControl:
		return extBaseToInfo(d.DERControlBase), true
	}
	return adminBaseInfo{}, false
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
	if err := percentDomainErr(req.Base); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	injectPF, absorbPF, err := req.Base.fixedPF()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	droop, err := req.Base.FreqDroop.toModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// REFUSED, not ignored. This endpoint shares adminCtrlReq with
	// POST /admin/control, so null_axes decodes here too and would otherwise be
	// silently dropped — the operator would get a 204, believe a
	// DefaultDERControl was authored with an explicitly-null axis, and grade
	// the DUT on a document that was never sent. The overlay deliberately does
	// not reach DefaultDERControl (explicitnil.go's scope note), so saying so
	// is the honest answer. Same rule as the retired fixed_pf_*_pct scalars.
	if len(req.Base.NullAxes) > 0 {
		http.Error(w, "null_axes is a DERControl lever and does not apply to DefaultDERControl: a default "+
			"is not an event and has no release to grade. Use POST /admin/control.",
			http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	path := fmt.Sprintf("/derp/%d/dderc", req.Program)
	s.putDefaultBaseLocked(path, req, droop, injectPF, absorbPF)
	s.mu.Unlock()

	s.notifyChanged(path)

	w.WriteHeader(http.StatusNoContent)
}

// putDefaultBaseLocked writes a program's DefaultDERControl base, choosing the
// resource SHAPE from what the request actually asks for. Caller must hold s.mu.
//
// opModFreqDroop exists only on the extended base (csipmodel's
// ExtendedDefaultDERControl), so a default that carries one has to be stored as
// that type — the same widen-in-place the derc/actderc paths already do for a
// curve-linked or TargetW-carrying control. Both types marshal under the same
// XMLName ("DefaultDERControl"), so the WIRE is unchanged and only this
// server's own Go type moves.
//
// CLEAR NARROWS IT BACK, deliberately. A teardown's job is to leave the tree as
// it found it, and a program left holding an extended resource with an empty
// base is not the tree the golden pins — nor is it what the next reader of
// s.resources[path] would expect to type-assert. The identifying fields are
// carried across both ways so the resource keeps its href, mRID and version:
// re-minting them would change what the DUT sees at a stable path.
//
// SO DOES ANY DROOPLESS POST, and that is the same rule rather than a second
// one. A POST REPLACES this program's DERControlBase — it always has; the
// pre-#32 code assigned buildBase(req.Base) over whatever was there — so a
// request naming no droop is a default that commands no droop, and the resource
// returns to the narrow shape rather than staying widened for a base that
// cannot carry the extended element.
//
// KNOWN, PRE-EXISTING GAP: opModTargetW is still dropped here. buildBase has no
// TargetW field (only adminCtrlPost's own extended path sets one), so a
// /admin/default carrying target_W has never served it — and now that a
// droop-carrying default IS stored as the extended type, which CAN hold
// opModTargetW, that drop is newly INCONSISTENT rather than newly wrong. No
// Figure in this catalog prescribes opModTargetW on a DefaultDERControl, so no
// lever is built for it here; closing it means giving buildBase an extended
// sibling, not special-casing this path.
func (s *Server) putDefaultBaseLocked(path string, req adminDefaultReq, droop *model.FreqDroop,
	injectPF, absorbPF *model.PowerFactorWithExcitation) {
	var res model.Resource
	var mrid, desc string
	var version uint16
	switch d := s.resources[path].(type) {
	case *defaultDERControlRamps:
		res, mrid, desc, version = d.Resource, d.MRID, d.Description, d.Version
	case *model.DefaultDERControl:
		res, mrid, desc, version = d.Resource, d.MRID, d.Description, d.Version
	case *model.ExtendedDefaultDERControl:
		res, mrid, desc, version = d.Resource, d.MRID, d.Description, d.Version
	default:
		return // this program serves no DefaultDERControl; nothing to write
	}
	if req.Clear || droop == nil {
		// The narrow shape covers every base this server can author WITHOUT a
		// droop, so a droopless POST keeps the tree in its original type rather
		// than widening it for nothing.
		narrow := &model.DefaultDERControl{
			Resource: res, MRID: mrid, Description: desc, Version: version,
		}
		if !req.Clear {
			narrow.DERControlBase = buildBase(req.Base, injectPF, absorbPF)
		}
		// The ramp-rate defaults ride the wrapper shape (softgrad.go) and ONLY
		// when asked for, so a default naming neither is stored as the plain
		// narrow type it has always been.
		if req.wantsRamps() {
			s.resources[path] = &defaultDERControlRamps{
				DefaultDERControl: *narrow,
				SetGradW:          req.SetGradW,
				SetSoftGradW:      req.SetSoftGradW,
			}
			return
		}
		s.resources[path] = narrow
		return
	}
	base := scalarBaseToExtended(buildBase(req.Base, injectPF, absorbPF))
	base.OpModFreqDroop = droop
	s.resources[path] = &model.ExtendedDefaultDERControl{
		Resource: res, MRID: mrid, Description: desc, Version: version, DERControlBase: base,
	}
}
