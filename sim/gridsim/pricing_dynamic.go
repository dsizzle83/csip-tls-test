package gridsim

// pricing_dynamic.go — makes the IEEE 2030.5 §10.5 Pricing function set dynamic
// (dashboard V2, CONTRACTS.md §5). POST /admin/tariff loads an internal/tariff
// plan and regenerates the /tp… tree (TariffProfile → RateComponent →
// TimeTariffInterval → ConsumptionTariffInterval) from its TOU periods for a
// rolling 48 h window centered on the warped server clock (s.Now()). The tree
// re-centers on tariff set, on every /admin/clock change, and lazily on read
// when server time leaves the generated window (or crosses an interval edge).
//
// With no tariff loaded the server keeps the legacy static two-tier tree that
// buildPricing() has always produced, so existing behavior is unchanged and
// DELETE /admin/tariff restores it exactly.
//
// Locking: every field this file reads or writes on Server (tariff,
// tariffIntervals, tariffWin*/tariffActive*, and the /tp… entries in
// s.resources) is guarded by s.mu, the same RWMutex the request handlers use.
// The "Locked" suffix on a helper means the caller already holds s.mu for
// writing.

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/tariff"
	model "lexa-proto/csipmodel"
)

// pricingWindowHalf is half the rolling window width: the tree spans
// [now-24h, now+24h), i.e. a 48 h window centered on server time (CONTRACTS §5).
const pricingWindowHalf = int64(24 * 3600)

// pricingIv is one contiguous, non-overlapping TOU interval in the generated
// window. rate is the per-kWh IMPORT price from tariff.RateAt (period energy
// rate + riders — see handleAdminTariff doc), the value the §10.5 price encodes.
type pricingIv struct {
	start, end int64   // server-time unix bounds, [start, end)
	periodID   string  // tariff Period.ID this interval came from
	label      string  // tariff Period.Label (human)
	rate       float64 // import $/kWh at this interval (RateAt.ImportUSDPerKWh)
	touTier    uint8   // rank among distinct rates: 1 = cheapest (higher = pricier)
}

// ── Regeneration ──────────────────────────────────────────────────────────────

// refreshPricingIfStale is the cheap read-path staleness gate. It takes only the
// read lock to decide whether the active interval (and hence the tree) is out of
// date, and upgrades to the write lock — via refreshPricingLocked, which
// re-checks — only when server time has actually left the current interval.
// A no-op (and lock-free past the RLock) when no tariff is loaded.
func (s *Server) refreshPricingIfStale() {
	now := s.Now()
	s.mu.RLock()
	stale := s.tariff != nil && (now < s.tariffActiveStart || now >= s.tariffActiveEnd)
	s.mu.RUnlock()
	if !stale {
		return
	}
	s.mu.Lock()
	s.refreshPricingLocked(s.Now())
	s.mu.Unlock()
}

// refreshPricingLocked brings the pricing tree up to date for now, doing the
// least work required: nothing if the active interval still holds, a full window
// rebuild if now has left the window (or the tree was never built), otherwise
// just re-pointing the active list at the interval now falls in. Caller holds
// s.mu for writing.
func (s *Server) refreshPricingLocked(now int64) {
	if s.tariff == nil {
		return
	}
	if now >= s.tariffActiveStart && now < s.tariffActiveEnd {
		return // active interval still current — nothing to do
	}
	if len(s.tariffIntervals) == 0 || now < s.tariffWinStart || now >= s.tariffWinEnd {
		s.regenPricingLocked(now) // window exit / first build → re-center
		return
	}
	s.setActiveLocked(now) // crossed an interval edge inside the window
}

// regenPricingLocked rebuilds the entire /tp… tree from the loaded tariff for a
// fresh 48 h window centered on now. Caller holds s.mu for writing and has
// ensured s.tariff != nil.
func (s *Server) regenPricingLocked(now int64) {
	winStart := now - pricingWindowHalf
	winEnd := now + pricingWindowHalf
	ivs := s.buildIntervals(winStart, winEnd)

	s.tariffIntervals = ivs
	s.tariffWinStart, s.tariffWinEnd = winStart, winEnd

	s.clearPricingLocked()
	s.writePricingTreeLocked(ivs)
	s.setActiveLocked(now)
}

// buildIntervals computes the merged, contiguous interval set tiling
// [winStart, winEnd). Every TOU boundary lands on either local midnight or a
// period start/end minute, so the union of those minutes across the tariff
// (applied to each local day the window spans) is a superset of the real
// boundaries; segments between consecutive candidates have a single rate, and
// adjacent segments with the same period+rate are merged (so a midnight-wrapping
// period such as 21:00–06:00 yields one interval, not two).
func (s *Server) buildIntervals(winStart, winEnd int64) []pricingIv {
	t := s.tariff
	loc, err := time.LoadLocation(t.Timezone)
	if err != nil {
		loc = time.UTC
	}
	mins := startEndMinutes(t)

	// Candidate boundary instants strictly inside the window.
	var cand []int64
	first := time.Unix(winStart, 0).In(loc)
	day := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, loc)
	for day.Unix() < winEnd {
		for _, m := range mins {
			c := time.Date(day.Year(), day.Month(), day.Day(), m/60, m%60, 0, 0, loc).Unix()
			if c > winStart && c < winEnd {
				cand = append(cand, c)
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	sort.Slice(cand, func(i, j int) bool { return cand[i] < cand[j] })

	// Boundary points: winStart, the sorted unique candidates, winEnd.
	points := []int64{winStart}
	for _, c := range cand {
		if c > points[len(points)-1] {
			points = append(points, c)
		}
	}
	if points[len(points)-1] != winEnd {
		points = append(points, winEnd)
	}

	// One segment per consecutive pair; merge adjacent same period+rate.
	var ivs []pricingIv
	for i := 0; i+1 < len(points); i++ {
		segStart, segEnd := points[i], points[i+1]
		if segEnd <= segStart {
			continue
		}
		ri := t.RateAt(time.Unix(segStart, 0))
		if n := len(ivs); n > 0 && ivs[n-1].periodID == ri.PeriodID && ivs[n-1].rate == ri.ImportUSDPerKWh {
			ivs[n-1].end = segEnd
			continue
		}
		ivs = append(ivs, pricingIv{
			start:    segStart,
			end:      segEnd,
			periodID: ri.PeriodID,
			label:    ri.PeriodLabel,
			rate:     ri.ImportUSDPerKWh,
		})
	}
	assignTouTiers(ivs)
	return ivs
}

// startEndMinutes returns the sorted, unique set of minute-of-day boundaries the
// tariff can transition on: midnight plus every period start and end across all
// seasons and day_types (a superset — extra candidates that don't change the
// rate are merged away in buildIntervals).
func startEndMinutes(t *tariff.Tariff) []int {
	set := map[int]bool{0: true}
	for _, se := range t.Energy.Seasons {
		for _, dt := range se.DayTypes {
			for _, p := range dt.Periods {
				if m, ok := hhmm(p.Start); ok && m < 1440 {
					set[m] = true
				}
				if m, ok := hhmm(p.End); ok && m < 1440 {
					set[m] = true
				}
			}
		}
	}
	out := make([]int, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Ints(out)
	return out
}

// hhmm parses "HH:MM" into minutes-of-day [0,1440]. "24:00" → 1440.
func hhmm(s string) (int, bool) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 24 || m < 0 || m > 59 || (h == 24 && m != 0) {
		return 0, false
	}
	return h*60 + m, true
}

// assignTouTiers ranks the distinct rates ascending and stamps touTier =
// rank+1, so a higher touTier always means a pricier interval (§10.5.3.8).
func assignTouTiers(ivs []pricingIv) {
	seen := map[float64]bool{}
	for _, iv := range ivs {
		seen[iv.rate] = true
	}
	rates := make([]float64, 0, len(seen))
	for r := range seen {
		rates = append(rates, r)
	}
	sort.Float64s(rates)
	rank := make(map[float64]uint8, len(rates))
	for i, r := range rates {
		rank[r] = uint8(i + 1)
	}
	for i := range ivs {
		ivs[i].touTier = rank[ivs[i].rate]
	}
}

// ── Tree assembly ─────────────────────────────────────────────────────────────

// clearPricingLocked drops every /tp… resource so a rebuild (or DELETE) never
// leaves stale intervals/CTIs from a longer previous window. Caller holds s.mu.
func (s *Server) clearPricingLocked() {
	for k := range s.resources {
		if strings.HasPrefix(k, "/tp") {
			delete(s.resources, k)
		}
	}
}

// writePricingTreeLocked installs the TariffProfile → RateComponent → TTI list →
// per-interval CTI lists for ivs. It does NOT set the active list; callers pair
// it with setActiveLocked. Caller holds s.mu for writing.
func (s *Server) writePricingTreeLocked(ivs []pricingIv) {
	t := s.tariff

	s.resources["/tp"] = &model.TariffProfileList{
		Resource: model.Resource{Href: "/tp"},
		All:      1, Results: 1, PollRate: 300,
		TariffProfile: []model.TariffProfile{{
			Resource:                  model.Resource{Href: "/tp/0"},
			MRID:                      "TP-" + strings.ToUpper(t.ID),
			Description:               t.Name,
			Currency:                  840, // USD
			PricePowerOfTenMultiplier: -3,
			Primacy:                   1,
			RateCode:                  t.ID,
			ServiceCategoryKind:       0, // electricity
			RateComponentListLink:     &model.ListLink{Link: model.Link{Href: "/tp/0/rc"}, All: 1},
		}},
	}

	n := uint32(len(ivs))
	s.resources["/tp/0/rc"] = &model.RateComponentList{
		Resource: model.Resource{Href: "/tp/0/rc"},
		All:      1, Results: 1,
		RateComponent: []model.RateComponent{{
			Resource:                         model.Resource{Href: "/tp/0/rc/0"},
			MRID:                             "RC-FWD-001",
			Description:                      "Forward (consumption) rate",
			RoleFlags:                        0x0004, // isPrimary (forward)
			TimeTariffIntervalListLink:       &model.ListLink{Link: model.Link{Href: "/tp/0/rc/0/tti"}, All: n},
			ActiveTimeTariffIntervalListLink: &model.ListLink{Link: model.Link{Href: "/tp/0/rc/0/acttti"}, All: 1},
		}},
	}

	ttis := make([]model.TimeTariffInterval, len(ivs))
	for i, iv := range ivs {
		ttis[i] = ttiFor(i, iv)
		s.resources[fmt.Sprintf("/tp/0/rc/0/tti/%d/cti", i)] = ctiListFor(i, iv)
	}
	s.resources["/tp/0/rc/0/tti"] = &model.TimeTariffIntervalList{
		Resource: model.Resource{Href: "/tp/0/rc/0/tti"},
		All:      n, Results: n,
		TimeTariffInterval: ttis,
	}
}

// setActiveLocked points ActiveTimeTariffIntervalList at exactly the interval
// containing now, and records its bounds as the fast-path staleness window.
// Caller holds s.mu for writing.
func (s *Server) setActiveLocked(now int64) {
	ivs := s.tariffIntervals
	idx := -1
	for i, iv := range ivs {
		if now >= iv.start && now < iv.end {
			idx = i
			break
		}
	}
	if idx < 0 {
		// now is outside every interval (should not happen — it sits at the
		// window center). Serve an empty active list and mark the whole window
		// active so we don't hot-loop regenerating.
		s.resources["/tp/0/rc/0/acttti"] = &model.TimeTariffIntervalList{
			Resource: model.Resource{Href: "/tp/0/rc/0/acttti"},
			All:      0, Results: 0,
		}
		s.tariffActiveStart, s.tariffActiveEnd = s.tariffWinStart, s.tariffWinEnd
		return
	}
	s.resources["/tp/0/rc/0/acttti"] = &model.TimeTariffIntervalList{
		Resource: model.Resource{Href: "/tp/0/rc/0/acttti"},
		All:      1, Results: 1,
		TimeTariffInterval: []model.TimeTariffInterval{ttiFor(idx, ivs[idx])},
	}
	s.tariffActiveStart, s.tariffActiveEnd = ivs[idx].start, ivs[idx].end
}

// ttiFor builds the TimeTariffInterval resource for interval i. Following the
// static tree's convention, TTIs carry no EventStatus — "which interval is
// active now" is conveyed solely by ActiveTimeTariffIntervalList.
func ttiFor(i int, iv pricingIv) model.TimeTariffInterval {
	return model.TimeTariffInterval{
		Resource:    model.Resource{Href: fmt.Sprintf("/tp/0/rc/0/tti/%d", i)},
		MRID:        fmt.Sprintf("TTI-%s-%d", strings.ToUpper(iv.periodID), iv.start),
		Description: iv.label,
		TouTier:     iv.touTier,
		Interval:    model.DateTimeInterval{Start: iv.start, Duration: uint32(iv.end - iv.start)},
		ConsumptionTariffIntervalListLink: &model.ListLink{
			Link: model.Link{Href: fmt.Sprintf("/tp/0/rc/0/tti/%d/cti", i)}, All: 1,
		},
	}
}

// ctiListFor builds the single-entry ConsumptionTariffIntervalList for interval
// i. The price is the import rate in the TariffProfile's milli-currency:
// round(rate_usd_per_kwh * 100 * 1000), matching the 12000 = 12.0 ¢/kWh
// convention of the legacy static tree.
func ctiListFor(i int, iv pricingIv) *model.ConsumptionTariffIntervalList {
	base := fmt.Sprintf("/tp/0/rc/0/tti/%d/cti", i)
	return &model.ConsumptionTariffIntervalList{
		Resource: model.Resource{Href: base},
		All:      1, Results: 1,
		ConsumptionTariffInterval: []model.ConsumptionTariffInterval{{
			Resource:         model.Resource{Href: base + "/0"},
			ConsumptionBlock: 0,
			Price:            priceMilli(iv.rate),
			StartValue:       0,
		}},
	}
}

// priceMilli encodes a $/kWh rate as the §10.5 price under
// PricePowerOfTenMultiplier=-3: 0.12 → 12000 (12.0 ¢/kWh).
func priceMilli(rateUSDPerKWh float64) int32 {
	return int32(math.Round(rateUSDPerKWh * 100 * 1000))
}

// ── Admin API (POST/GET/DELETE /admin/tariff) ─────────────────────────────────

// handleAdminTariff dispatches the dynamic-tariff admin endpoint.
func (s *Server) handleAdminTariff(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.adminTariffPost(w, r)
	case http.MethodGet:
		s.adminTariffGet(w, r)
	case http.MethodDelete:
		s.adminTariffDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// adminTariffPost loads a tariff (internal/tariff schema) and rebuilds the
// pricing tree from it. Invalid JSON or a tariff that fails Validate → 400 with
// the previous tree left untouched. On success → 200 with the same summary
// GET /admin/tariff returns.
//
// Rate convention: the §10.5 price and the summary's rate_usd_per_kwh both use
// tariff.RateAt().ImportUSDPerKWh — the period energy rate PLUS riders — which
// is the all-in per-kWh import price the pricing signal represents. (RateAt is
// the specified rate source in CONTRACTS §5; it exposes the import rate, not the
// bare period rate. Tier adders remain excluded — they are monthly state.)
func (s *Server) adminTariffPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t, err := tariff.Parse(body) // Parse validates; invalid → error
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.tariff = t
	s.regenPricingLocked(s.Now())
	s.mu.Unlock()

	log.Printf("[gridsim] tariff loaded: id=%s name=%q → dynamic §10.5 pricing", t.ID, t.Name)
	s.writeTariffSummary(w)
}

// adminTariffDelete drops the loaded tariff and restores the legacy static
// two-tier pricing tree exactly as buildPricing produces it at startup (wall
// clock, matching the original semantics). 204 whether or not a tariff was set.
func (s *Server) adminTariffDelete(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tariff = nil
	s.tariffIntervals = nil
	s.tariffWinStart, s.tariffWinEnd = 0, 0
	s.tariffActiveStart, s.tariffActiveEnd = 0, 0
	s.clearPricingLocked()
	s.buildPricing(time.Now().Unix())
	s.mu.Unlock()
	log.Printf("[gridsim] tariff cleared → legacy static pricing tree restored")
	w.WriteHeader(http.StatusNoContent)
}

// adminTariffGet returns the JSON the UI inspector reads (no XML): tariff id,
// name, the active period, and every generated interval. 404 when no tariff is
// loaded (the server is on the legacy static tree).
func (s *Server) adminTariffGet(w http.ResponseWriter, r *http.Request) {
	s.refreshPricingIfStale() // report the interval that actually holds now
	s.writeTariffSummary(w)
}

// tariffSummary is the GET /admin/tariff (and POST reply) body — CONTRACTS §5.
type tariffSummary struct {
	TariffID     string           `json:"tariff_id"`
	Name         string           `json:"name"`
	ActivePeriod tariffActivePer  `json:"active_period"`
	Intervals    []tariffInterval `json:"intervals"`
}

type tariffActivePer struct {
	ID            string  `json:"id"`
	Label         string  `json:"label"`
	RateUSDPerKWh float64 `json:"rate_usd_per_kwh"`
	Start         int64   `json:"start"`
	End           int64   `json:"end"`
}

type tariffInterval struct {
	Start         int64   `json:"start"`
	End           int64   `json:"end"`
	RateUSDPerKWh float64 `json:"rate_usd_per_kwh"`
	PeriodID      string  `json:"period_id"`
}

// writeTariffSummary emits the current tariff summary, or 404 if none is loaded.
func (s *Server) writeTariffSummary(w http.ResponseWriter) {
	now := s.Now()
	s.mu.RLock()
	if s.tariff == nil {
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "no tariff loaded"})
		return
	}
	sum := tariffSummary{TariffID: s.tariff.ID, Name: s.tariff.Name}
	active := -1
	for i, iv := range s.tariffIntervals {
		sum.Intervals = append(sum.Intervals, tariffInterval{
			Start: iv.start, End: iv.end, RateUSDPerKWh: iv.rate, PeriodID: iv.periodID,
		})
		if now >= iv.start && now < iv.end {
			active = i
		}
	}
	if active < 0 && len(s.tariffIntervals) > 0 {
		active = 0 // defensive; now sits at the window center in practice
	}
	if active >= 0 {
		iv := s.tariffIntervals[active]
		sum.ActivePeriod = tariffActivePer{
			ID: iv.periodID, Label: iv.label, RateUSDPerKWh: iv.rate, Start: iv.start, End: iv.end,
		}
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sum)
}
