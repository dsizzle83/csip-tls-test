package aggregator

// campaign.go is the SCENARIO SCHEMA + loader for the aggregator's control
// campaigns (T06.6): the `camp_v:1` JSON family under qa/aggregator/*.json. It is
// the SIBLING of the dashboard's Mayhem schema (qa/scenarios/*.json, spec_v:1 —
// PN-3), designed in the same spirit but with its own vocabulary (role sessions,
// typed point writes, readback SLAs, exception assertions) and its own engine
// (engine.go) driving a different target (the gateway's mbaps :802 server, not
// the hub over CSIP). The two never share a driver.
//
// A campaign is DATA. It selects a named oracle (oracle.go) and lists steps from
// a fixed action vocabulary — no conditionals, loops, or expressions. Anything
// that needs real logic stays a Go test. Everything here is validated at LOAD
// time (a bad file names its own offending field and is excluded; other files
// and the run are unaffected — the exact guard the Mayhem loader uses), so a
// malformed campaign can never reach the engine and turn the QA driver into an
// unreviewed rules engine (the explicit anti-goal in qa/scenarios/README.md).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CampaignV is the current campaign-schema version. A file whose "camp_v" is not
// this value is rejected at load — the schema is versioned so the dashboard and
// CI can reason about a file's shape without guessing.
const CampaignV = 1

// Step verbs — the action vocabulary v1. Each verb maps 1:1 to exactly one
// engine driver method (engine.go), the same discipline as the Mayhem vocabulary
// (each verb ↔ one mayhemDriver method). The vocabulary can only grow by adding a
// verb that mirrors a driver primitive, never by adding control flow.
//
// The TLS-fault verbs (StepResume, StepRenegotiate) drive the transport layer so
// the T06.8 probes can exercise resumption and renegotiation policy; they map to
// driver methods exactly like every other verb (no control flow added).
const (
	StepConnectAs       = "connect_as"       // switch the session role mid-campaign
	StepDiscover        = "discover"         // walk the per-device unit map
	StepPoll            = "poll"             // start a background telemetry loop
	StepWritePoint      = "write_point"      // typed, scale-correct control write
	StepWriteMulti      = "write_multi"      // raw FC16 register write (escape hatch)
	StepReadback        = "readback"         // poll a status/echo point to convergence
	StepExpectException = "expect_exception" // assert a write yields a given exception
	StepDisconnect      = "disconnect"       // close the current session
	StepResume          = "resume"           // re-establish the session (reconnect, resuming the TLS session if allowed)
	StepRenegotiate     = "renegotiate"      // attempt a client-initiated TLS renegotiation (refusal probe, T06.8)
	StepSleep           = "sleep_s"          // wait (ctx-cancellable), e.g. a hold window
	StepSimFault        = "sim_fault"        // arm/clear a fault on a named sim via its simapi
)

// knownVerbs is the accepted v1 vocabulary, used to reject a typo'd or
// not-yet-supported verb at load time rather than silently ignore it.
var knownVerbs = map[string]bool{
	StepConnectAs: true, StepDiscover: true, StepPoll: true,
	StepWritePoint: true, StepWriteMulti: true, StepReadback: true,
	StepExpectException: true, StepDisconnect: true, StepResume: true,
	StepRenegotiate: true, StepSleep: true, StepSimFault: true,
}

// Target names a campaign's connection target, resolved to a dial address by the
// engine's Resolve func. Kept a small closed set (not a free-form string) so a
// typo is a load error, not a confusing connect failure at run time. "gateway" is
// the lexa-gw northbound :802 server; "device" is a loopback mbapsdev (or the
// authz loopback the integration test stands up).
const (
	TargetGateway = "gateway"
	TargetDevice  = "device"
)

// Campaign is one JSON control campaign (a qa/aggregator/*.json file). It is a
// declarative description a runner executes against a role session; it carries no
// pass/fail logic — that is the named Oracle's, resolved from the registry.
type Campaign struct {
	CampV int    `json:"camp_v"`
	ID    string `json:"id"`   // unique across all campaigns in a dir
	Name  string `json:"name"` // human-readable title
	Role  Role   `json:"role"` // session role to connect as (a bench Role)
	// Target resolves to a :802 address by the runner (TargetGateway/TargetDevice).
	Target string `json:"target"`

	// Narrative fields (documentation; the oracle ignores them): the real-world
	// fault the campaign represents, what a correct gateway does, and where to
	// look if it doesn't — mirrors the Mayhem hypothesis/expected/fix triad.
	Hypothesis string `json:"hypothesis,omitempty"`
	Expected   string `json:"expected,omitempty"`
	Fix        string `json:"fix,omitempty"`
	Notes      string `json:"notes,omitempty"` // JSON has no comments; authoring notes here

	Steps  []Step    `json:"steps"`
	Oracle OracleRef `json:"oracle"`

	// ExpectedVerdicts documents the acceptable outcomes (the "expected-FAIL pins
	// the gap" pattern as data). The engine records whether the actual verdict is
	// in this set (report.VerdictExpected) so a CI/gate run can exit non-zero on a
	// surprise; an empty list means "no expectation", never a gate trip.
	ExpectedVerdicts []Verdict `json:"expected_verdicts,omitempty"`
}

// OracleRef selects a registered oracle by name with optional per-oracle params.
// An unknown name or malformed params is a load-time error (validateCampaign
// builds the oracle to prove it), never a runtime surprise.
type OracleRef struct {
	Name   string          `json:"name"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Step is one action in a campaign. Exactly one verb-specific field group is
// meaningful per Do verb — see validateStep and the engine's dispatch for which
// fields each verb reads. Unknown JSON keys are rejected at decode
// (DisallowUnknownFields), so a typo'd field never silently no-ops.
type Step struct {
	Do string `json:"do"`

	// connect_as
	Role Role `json:"role,omitempty"`

	// discover / poll — Units is "*" (all discovered so far) or an explicit list.
	Units   *UnitSel `json:"units,omitempty"`
	PeriodS float64  `json:"period_s,omitempty"` // poll cadence, seconds (>0)

	// write_point / write_multi / readback / expect_exception target
	Unit  uint8  `json:"unit,omitempty"`  // per-device unit (1..246; 0 is invalid)
	Model uint16 `json:"model,omitempty"` // SunSpec model id (fixed-shape only)
	Point string `json:"point,omitempty"` // named point in the model layout

	// write_point / readback value
	Value float64 `json:"value,omitempty"` // engineering value (write); 0 is valid

	// write_point reversion timers (704-family): when >0 the engine also writes
	// the companion <point>RvrtTms register so the gateway reverts on expiry
	// (design 04 B.2 — the mode service owns reversion timers). WinTms is recorded
	// and written only if a <point>WinTms companion exists in the layout (it does
	// not in 704; see the reviewer note in engine.go).
	WinTms  uint32 `json:"win_tms,omitempty"`
	RvrtTms uint32 `json:"rvrt_tms,omitempty"`

	// write_multi raw register write (escape hatch for a point the typed writer
	// cannot address — e.g. a repeating-group point).
	Addr   uint16   `json:"addr,omitempty"`
	Values []uint16 `json:"values,omitempty"`

	// readback
	Expect float64 `json:"expect,omitempty"` // commanded/echoed value to converge to (0 valid)
	SLAS   float64 `json:"sla_s,omitempty"`  // convergence deadline, seconds (>0, required)
	Tol    float64 `json:"tol,omitempty"`    // absolute tolerance; 0 ⇒ default
	// Phase tags a readback for the reversionOnExpiry oracle: "hold" (the ceiling
	// must have held) or "revert" (the value must have returned to the safe
	// default). Empty for the plain convergeWithinSLA oracle.
	Phase string `json:"phase,omitempty"`

	// expect_exception
	ExpectCode uint8 `json:"expect_code,omitempty"` // expected exception code; 0 ⇒ 1 (authz)

	// sleep_s
	Seconds float64 `json:"seconds,omitempty"` // wait duration, seconds (>0)

	// sim_fault — arm/clear a fault on a named sim (mbapsdev/plain sim) via the
	// engine's Fault injector (simapi over HTTP for a live run; an in-process hook
	// for the loopback test). Fault is the raw simapi body ({"kind":...} or
	// {"kind":...,"clear":true}) passed through unchanged.
	Target string          `json:"target,omitempty"`
	Fault  json.RawMessage `json:"fault,omitempty"`
}

// UnitSel selects units for discover/poll. It decodes from either the wildcard
// JSON string "*" (all units discovered so far this campaign) or a JSON array of
// unit numbers. The two-form encoding matches the Mayhem schema's pv_w
// number-or-"high" sentinel — a small, auditable union, not an expression syntax.
type UnitSel struct {
	All   bool
	Units []uint8
}

// UnmarshalJSON accepts "*" or a numeric array; anything else is a decode error
// naming the offending value.
func (u *UnitSel) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "*" {
			return fmt.Errorf(`units string must be "*" (all discovered), got %q`, s)
		}
		u.All = true
		u.Units = nil
		return nil
	}
	var list []uint8
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf(`units must be "*" or a list of unit numbers: %w`, err)
	}
	u.All = false
	u.Units = list
	return nil
}

// DecodeCampaign parses and fully validates a campaign from its bytes. It is a
// pure function of the input (no driver, no network), so the schema is unit-
// testable without a bench. A successful decode guarantees the engine can run the
// campaign without a schema surprise.
func DecodeCampaign(buf []byte) (*Campaign, error) {
	var c Campaign
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields() // a typo'd field name must fail loud, not silently no-op
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if err := validateCampaign(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// validateCampaign enforces every structural rule: the version gate, required
// fields, the role/target enums, at-least-one step, per-step field rules, and
// that the named oracle is registered and its params decode. It builds the oracle
// (discarding it) purely to prove the params are well-formed at load time.
func validateCampaign(c *Campaign) error {
	if c.CampV != CampaignV {
		return fmt.Errorf("camp_v %d unsupported (want %d)", c.CampV, CampaignV)
	}
	for _, f := range []struct{ name, val string }{{"id", c.ID}, {"name", c.Name}} {
		if strings.TrimSpace(f.val) == "" {
			return fmt.Errorf("%q is required", f.name)
		}
	}
	if !knownRole(c.Role) {
		return fmt.Errorf("role %q is not a bench role (want one of %v)", c.Role, Roles())
	}
	if c.Target != TargetGateway && c.Target != TargetDevice {
		return fmt.Errorf("target %q must be %q or %q", c.Target, TargetGateway, TargetDevice)
	}
	if len(c.Steps) == 0 {
		return fmt.Errorf("campaign has no steps")
	}
	for i := range c.Steps {
		if err := validateStep(i, c.Steps[i]); err != nil {
			return fmt.Errorf("steps[%d] (%s): %w", i, c.Steps[i].Do, err)
		}
	}
	for _, v := range c.ExpectedVerdicts {
		if !ValidVerdict(v) {
			return fmt.Errorf("expected_verdicts: %q is not one of PASS|DEGRADED|FAIL|BLIND|INCONCLUSIVE", v)
		}
	}
	if strings.TrimSpace(c.Oracle.Name) == "" {
		return fmt.Errorf("oracle.name is required")
	}
	builder, ok := oracleRegistry[c.Oracle.Name]
	if !ok {
		return fmt.Errorf("oracle %q is not registered (have %s)", c.Oracle.Name, registeredOracles())
	}
	if _, err := builder(c.Oracle.Params); err != nil {
		return fmt.Errorf("oracle %q: %w", c.Oracle.Name, err)
	}
	return nil
}

// validateStep checks the verb-specific required fields and ranges. Every write/
// read target is validated against the actual SunSpec layout (layoutFor + Has),
// so a typo'd model or point is a load error, not a confusing run-time exception.
func validateStep(i int, s Step) error {
	if !knownVerbs[s.Do] {
		return fmt.Errorf("unknown verb %q", s.Do)
	}
	switch s.Do {
	case StepConnectAs:
		if !knownRole(s.Role) {
			return fmt.Errorf("role %q is not a bench role", s.Role)
		}
	case StepDiscover:
		// units optional (default: probe 1..246); an explicit empty "*" is fine.
	case StepPoll:
		if s.PeriodS <= 0 {
			return fmt.Errorf("period_s must be > 0")
		}
	case StepWritePoint:
		if err := validatePointTarget(s.Unit, s.Model, s.Point); err != nil {
			return err
		}
	case StepWriteMulti:
		if s.Unit == 0 {
			return fmt.Errorf("unit must be 1..246")
		}
		if len(s.Values) == 0 {
			return fmt.Errorf("values must be a non-empty register list")
		}
	case StepReadback:
		unit, model := s.Unit, s.Model
		if model == 0 {
			model = controlModel // the control model whose projection echoes the command
		}
		if err := validatePointTarget(unit, model, s.Point); err != nil {
			return err
		}
		if s.SLAS <= 0 {
			return fmt.Errorf("sla_s must be > 0")
		}
		if s.Phase != "" && s.Phase != "hold" && s.Phase != "revert" {
			return fmt.Errorf(`phase %q must be "hold" or "revert" (or omitted)`, s.Phase)
		}
	case StepExpectException:
		if err := validatePointTarget(s.Unit, s.Model, s.Point); err != nil {
			return err
		}
	case StepDisconnect, StepResume:
		// no fields
	case StepRenegotiate:
		// unit is OPTIONAL: when >0 the probe does a post-renegotiation liveness
		// read on that unit to confirm the session survived (or cleanly
		// recovered); 0 skips the liveness read. No other fields apply.
	case StepSleep:
		if s.Seconds <= 0 {
			return fmt.Errorf("seconds must be > 0")
		}
	case StepSimFault:
		if strings.TrimSpace(s.Target) == "" {
			return fmt.Errorf("target (the sim to fault) is required")
		}
		if len(s.Fault) == 0 {
			return fmt.Errorf(`fault body is required (e.g. {"kind":"drop_session"})`)
		}
		if !json.Valid(s.Fault) {
			return fmt.Errorf("fault body is not valid JSON")
		}
	}
	return nil
}

// validatePointTarget checks a unit/model/point triple: a real per-device unit, a
// fixed-shape model the typed writer/reader can address, and a point that exists
// in that model's layout.
func validatePointTarget(unit uint8, model uint16, point string) error {
	if unit == 0 {
		return fmt.Errorf("unit must be 1..246 (0 is the Modbus broadcast address, never a device)")
	}
	l, err := layoutFor(model)
	if err != nil {
		return err
	}
	if strings.TrimSpace(point) == "" {
		return fmt.Errorf("point is required")
	}
	if !l.Has(point) {
		return fmt.Errorf("point %q is not in model %d layout", point, model)
	}
	return nil
}

// knownRole reports whether r is one of the five bench roles.
func knownRole(r Role) bool {
	for _, k := range Roles() {
		if k == r {
			return true
		}
	}
	return false
}

// LoadCampaign reads and validates one campaign file.
func LoadCampaign(path string) (*Campaign, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("aggregator: read campaign %s: %w", path, err)
	}
	c, err := DecodeCampaign(buf)
	if err != nil {
		return nil, fmt.Errorf("aggregator: campaign %s: %w", path, err)
	}
	return c, nil
}

// LoadCampaignDir reads every *.json in dir (deterministic, sorted order),
// decoding+validating each, and returns the valid campaigns plus one error per
// file that failed to load or whose id collides with an already-loaded file. A
// bad or colliding file NEVER blocks any other file — one broken campaign must
// not take a whole batch down, exactly the guard the Mayhem loader uses. An id
// collision is a load error, never a silent shadow.
func LoadCampaignDir(dir string) ([]*Campaign, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no campaign dir yet — nothing to load, not an error
		}
		return nil, []error{fmt.Errorf("aggregator: campaign dir %s: %w", dir, err)}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names) // deterministic load order run to run

	var out []*Campaign
	var errs []error
	seen := map[string]string{} // id -> file that already claimed it
	for _, name := range names {
		path := filepath.Join(dir, name)
		c, err := LoadCampaign(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if other, dup := seen[c.ID]; dup {
			errs = append(errs, fmt.Errorf("aggregator: campaign %s: id %q collides with %s — not loaded", path, c.ID, other))
			continue
		}
		seen[c.ID] = path
		out = append(out, c)
	}
	return out, errs
}
