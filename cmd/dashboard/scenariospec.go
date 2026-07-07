// scenariospec.go — TASK-076: Mayhem scenarios-as-data.
//
// A scenario spec is a JSON file that DECODES INTO the same mayScenario the
// hand-written Go literals in scenarios()/worldScenarios()/mqttScenarios()
// build. The interpreter here is a COMPILER, not a new execution engine: a
// spec's setup/per_tick/teardown phases compile to closures that call the
// exact same mayhemDriver methods (post, injectEnv, postCap, postConnect,
// deleteControls, suppressDefault, mqttFault/mqttInject/mqttReset, hubSSH) the
// Go scenarios call directly — so the run loop, sampling, invariant audit, and
// verdict machinery in mayhem.go are completely untouched (see run() / the
// task's "Blast radius" note).
//
// Boundary (decided, not this file's to relitigate): oracles/diagnosers STAY
// IN GO — see oracleRegistry below, which looks a spec's "oracle.name" up
// among the existing named diagnose* funcs. A spec can only select and
// parameterize an oracle, never define new decision logic. If a scenario
// needs a new oracle, that oracle is written in Go and registered here; the
// scenario itself still ships as data.
//
// Specs load PER RUN (scenarios() is called fresh by handleStart on every
// POST /api/qa/start — never once at process start), so editing or adding a
// spec file takes effect with NO dashboard rebuild and NO csip-dashboard
// restart. That is the entire point: the 2026-07-03 stale-bin/dashboard
// incident happened because a scenario change required a rebuild+redeploy
// that got skipped; a spec change cannot make that mistake because there is
// nothing to rebuild.
//
// See qa/scenarios/README.md for the authoring guide and the full action
// vocabulary reference.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const scenarioSpecVersion = 1

// ── Action vocabulary v1 ─────────────────────────────────────────────────────
//
// Mirrors mayhemDriver's own methods 1:1 (see "Read first" list in
// TASK-076): the compiler is a thin switch, and anything the vocabulary
// cannot express stays a hand-written Go scenario until the vocabulary grows
// (077 will force the remaining verbs out as it migrates the full suite).
const (
	actSimPost         = "sim_post"         // d.post(target, path, body)
	actGridsimAdmin    = "gridsim_admin"    // d.post("gridsim", path, body) — sugar for sim_post{target:"gridsim"}
	actInjectEnv       = "inject_env"       // d.injectEnv(pvW, loadW)
	actPostCap         = "post_cap"         // d.postCap(typ, limW, holdS, desc)          — constraint-producing
	actPostCapProg     = "post_cap_prog"    // d.postCapProg(program, typ, limW, holdS, desc) — constraint-producing
	actPostConnect     = "post_connect"     // d.postConnect(connect, holdS, desc)        — constraint-producing
	actPostControl     = "post_control"     // d.postControl(body) + author-declared typ/lim_w — constraint-producing
	actDeleteControls  = "delete_controls"  // d.deleteControls(program)
	actSuppressDefault = "suppress_default" // d.suppressDefault(); auto-restored at teardown end
	actMqttFault       = "mqtt_fault"       // d.mqttFault(mode, latencyMs, durationS)
	actMqttInject      = "mqtt_inject"      // d.mqttInject(topic, payload, retain)
	actMqttReset       = "mqtt_reset"       // d.mqttReset()
	actSSHHub          = "ssh_hub"          // d.hubSSH(command) — PRIVILEGED, see README
	actSleepS          = "sleep_s"          // time.Sleep — setup/teardown only, never per_tick
)

// isConstraintAction reports the verbs that produce an *activeConstraint and
// so are only valid inside "setup" (directly, or via the "constraint" sugar
// field below) — never in per_tick or teardown, which have no way to return
// one to the run loop.
func isConstraintAction(action string) bool {
	switch action {
	case actPostCap, actPostCapProg, actPostConnect, actPostControl:
		return true
	}
	return false
}

// knownSimTargets are the backend names mayhemDriver.backends is wired with in
// main.go (mayhem := newMayhemDriver(map[string]string{...})). Kept as a
// static set (rather than reading d.backends) so validation is pure and
// unit-testable without a live driver — compile-time errors must never depend
// on which Pis happen to be reachable.
var knownSimTargets = map[string]bool{
	"hub": true, "gridsim": true, "solar": true, "battery": true,
	"meter": true, "ev": true, "mqttproxy": true,
}

// ── Schema ───────────────────────────────────────────────────────────────────

// scenarioSpec is the on-disk JSON shape (see qa/scenarios/README.md for the
// full reference and qa/scenarios/export-cap-full-battery.json for a worked
// example — the pilot, a JSON twin of its Go literal in scenarios()).
type scenarioSpec struct {
	SpecV      int    `json:"spec_v"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Hypothesis string `json:"hypothesis"`
	Expected   string `json:"expected"`
	Fix        string `json:"fix"`
	HoldS      int    `json:"hold_s"`
	Extended   bool   `json:"extended,omitempty"` // RSK-12 long-running opt-out of default runs; see filterExtended
	Notes      string `json:"notes,omitempty"`    // JSON has no comments; authoring notes live here

	Setup    []scenarioAction `json:"setup,omitempty"`
	PerTick  []scenarioAction `json:"per_tick,omitempty"`
	Teardown []scenarioAction `json:"teardown,omitempty"`

	// Constraint is sugar for "append this as one more constraint-producing
	// action at the end of setup" (see constraintAsAction) — the common case
	// of a single grid cap/disconnect is then one declarative block instead
	// of one more setup array entry. A scenario needing MULTIPLE constraint
	// posts (e.g. a primacy conflict: low-primacy cap, then the high-primacy
	// one that must win) writes them directly in "setup" instead and omits
	// this field — the LAST constraint-producing action to run is always
	// what the run loop judges against, exactly mirroring the Go scenarios'
	// own "return d.postCapProg(...)" semantics.
	Constraint *scenarioConstraint `json:"constraint,omitempty"`

	Oracle scenarioOracleRef `json:"oracle"`

	// ExpectedVerdicts documents the "expected-FAIL pins the gap" pattern
	// (06_TESTING_STRATEGY.md §4.5) as data — informational for the report
	// and for a future CI comparison, not enforced by the interpreter itself.
	ExpectedVerdicts []string `json:"expected_verdicts,omitempty"`
}

// scenarioAction is one step of a setup/per_tick/teardown phase. Exactly one
// action-specific field group is populated per Action verb — see the
// vocabulary comment block above and compileStepAction/compileConstraintAction
// for which fields each verb reads.
type scenarioAction struct {
	Action string `json:"action"`

	// AtTick: per_tick only. Absent ⇒ runs every tick; present ⇒ runs exactly
	// once, when the tick index equals this value. Ticks are ~wall-seconds
	// only at the default 1000 ms sample interval (mayDefaultSampleMs) — see
	// README "at_tick caveat" — matching how the hand-written scenarios use
	// `i == 15` etc. today.
	AtTick *int `json:"at_tick,omitempty"`

	// sim_post / gridsim_admin
	Target string         `json:"target,omitempty"` // sim_post only; gridsim_admin fixes this to "gridsim"
	Path   string         `json:"path,omitempty"`
	Body   map[string]any `json:"body,omitempty"`

	// inject_env — PVW is a number OR the sentinel string "high", resolved at
	// run time to d.pvHighW (the nameplate-aware full-sun setpoint, only known
	// after baseline() runs — see resolvePVW).
	PVW   json.RawMessage `json:"pv_w,omitempty"`
	LoadW *float64        `json:"load_w,omitempty"`

	// post_cap / post_cap_prog / post_control / constraint sugar
	Typ     string  `json:"typ,omitempty"`
	LimW    float64 `json:"lim_w,omitempty"`
	HoldS   int     `json:"hold_s,omitempty"`
	Desc    string  `json:"desc,omitempty"`
	Program *int    `json:"program,omitempty"` // delete_controls, post_cap_prog; default 0

	// post_connect
	Connect *bool `json:"connect,omitempty"`

	// mqtt_fault
	Mode      string `json:"mode,omitempty"`
	LatencyMs int    `json:"latency_ms,omitempty"`
	DurationS int    `json:"duration_s,omitempty"`

	// mqtt_inject
	Topic   string `json:"topic,omitempty"`
	Payload string `json:"payload,omitempty"`
	Retain  bool   `json:"retain,omitempty"`

	// ssh_hub — PRIVILEGED: runs an arbitrary command on the hub Pi over SSH
	// (see mayhemDriver.hubSSH). The bench is trusted, but a spec author must
	// still see this called out; qa/scenarios/README.md flags it explicitly.
	Command string `json:"command,omitempty"`

	// sleep_s — setup/teardown only; see actSleepS.
	Seconds float64 `json:"seconds,omitempty"`
}

// scenarioConstraint is the "constraint" sugar field — see scenarioSpec.Constraint.
type scenarioConstraint struct {
	Type    string  `json:"type"` // exportCap|importCap|genLimit|connect|none/absent
	LimitW  float64 `json:"limit_w,omitempty"`
	Program *int    `json:"program,omitempty"` // non-zero ⇒ post_cap_prog instead of post_cap
	HoldS   int     `json:"hold_s"`
	Desc    string  `json:"desc"`
	Connect *bool   `json:"connect,omitempty"` // required when type=="connect"
}

// scenarioOracleRef selects a registered Go oracle by name, with JSON params
// decoded per-oracle (see oracleRegistry). An unknown oracle name or malformed
// params is a load-time error, never a runtime surprise (task step 2).
type scenarioOracleRef struct {
	Name   string          `json:"name"`
	Params json.RawMessage `json:"params,omitempty"`
}

// ── Oracle registry ──────────────────────────────────────────────────────────

// evaluateFn is exactly mayScenario.evaluate's type, named for readability.
type evaluateFn = func(sc *mayScenario, cons *activeConstraint, s []maySample) mayFinding

type oracleEntry struct {
	build func(params json.RawMessage) (evaluateFn, error)
	// requiresConstraint gates the "constraint present when the oracle needs
	// one" compile-time check (task step 3). False for oracles that only read
	// samples (diagnoseRecovery, diagnoseStale) — cons is always non-nil
	// ({Typ:"none"} by default) so nothing actually crashes without it, but a
	// spec author who forgets a constraint-producing action for e.g.
	// diagnoseConstraint has almost certainly made a mistake, and this catches
	// it at load time instead of a confusing PASS-with-no-cap at runtime.
	requiresConstraint bool
}

// oracleRegistry seeds the oracles TASK-076's pilot + proof scenarios need.
// TASK-077 (wave 1) adds the four more diagnose* funcs its first migration
// batch needs (diagnoseTransport/diagnoseBatteryGarbage/diagnoseReboot/
// diagnoseExpiry) — still not the final/complete set: diagnoseEVFreeze,
// diagnoseEVFlap, diagnoseEVUnits and the world/mqtt-scenario oracles remain
// unregistered, retained on their Go literals (see docs/qa-spec-migration.md).
var oracleRegistry = map[string]oracleEntry{
	"diagnoseConstraint":     {build: noParamOracle(diagnoseConstraint), requiresConstraint: true},
	"diagnoseConverge":       {build: noParamOracle(diagnoseConverge), requiresConstraint: true},
	"diagnoseStale":          {build: noParamOracle(diagnoseStale), requiresConstraint: false},
	"diagnoseRecovery":       {build: noParamOracle(diagnoseRecovery), requiresConstraint: false},
	"diagnoseSOC":            {build: noParamOracle(diagnoseSOC), requiresConstraint: true},
	"diagnoseDisconnect":     {build: noParamOracle(diagnoseDisconnect), requiresConstraint: true},
	"diagnoseMalform":        {build: noParamOracle(diagnoseMalform), requiresConstraint: true},
	"diagnoseSurvival":       {build: buildDiagnoseSurvival, requiresConstraint: true},
	"diagnoseTransport":      {build: noParamOracle(diagnoseTransport), requiresConstraint: false},
	"diagnoseBatteryGarbage": {build: noParamOracle(diagnoseBatteryGarbage), requiresConstraint: false},
	"diagnoseReboot":         {build: noParamOracle(diagnoseReboot), requiresConstraint: false},
	"diagnoseExpiry":         {build: noParamOracle(diagnoseExpiry), requiresConstraint: true},
}

// noParamOracle adapts a plain named diagnose* func (the common case) into
// the registry's build signature, rejecting any params a spec mistakenly
// supplies for an oracle that does not take any.
func noParamOracle(fn evaluateFn) func(json.RawMessage) (evaluateFn, error) {
	return func(params json.RawMessage) (evaluateFn, error) {
		if isNonEmptyParams(params) {
			return nil, fmt.Errorf("takes no params")
		}
		return fn, nil
	}
}

func isNonEmptyParams(params json.RawMessage) bool {
	s := strings.TrimSpace(string(params))
	return s != "" && s != "null" && s != "{}"
}

// buildDiagnoseSurvival wires the one parameterized oracle in the initial
// registry: diagnoseSurvival(label) rewords diagnoseMalform's prose for a
// non-malform survivability scenario (e.g. "the WAN outage" — see
// worldScenarios' wan-outage-hold).
func buildDiagnoseSurvival(params json.RawMessage) (evaluateFn, error) {
	var p struct {
		Label string `json:"label"`
	}
	if isNonEmptyParams(params) {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}
	if p.Label == "" {
		return nil, fmt.Errorf("requires params.label")
	}
	return diagnoseSurvival(p.Label), nil
}

// ── Decode + validate ────────────────────────────────────────────────────────

// decodeSpec parses and structurally validates a spec. Purely a function of
// its bytes — no driver, no network — so it is unit-testable without a bench.
func decodeSpec(buf []byte) (*scenarioSpec, error) {
	var spec scenarioSpec
	dec := json.NewDecoder(strings.NewReader(string(buf)))
	dec.DisallowUnknownFields() // a typo'd field name must fail loud, not silently no-op
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if err := validateSpec(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

const validVerdicts = "PASS|DEGRADED|FAIL|BLIND|INCONCLUSIVE"

func isValidVerdict(v string) bool {
	switch v {
	case "PASS", "DEGRADED", "FAIL", "BLIND", "INCONCLUSIVE":
		return true
	}
	return false
}

// validateSpec checks everything that does not require building closures:
// required fields, the version gate, action-verb/target vocabulary, at_tick
// bounds, and the expected_verdicts enum. compileSpec catches the rest
// (action-specific required fields, phase restrictions, oracle registration).
func validateSpec(spec *scenarioSpec) error {
	if spec.SpecV != scenarioSpecVersion {
		return fmt.Errorf("spec_v %d unsupported (want %d)", spec.SpecV, scenarioSpecVersion)
	}
	for _, field := range []struct{ name, val string }{
		{"id", spec.ID}, {"name", spec.Name}, {"category", spec.Category},
		{"hypothesis", spec.Hypothesis}, {"expected", spec.Expected},
	} {
		if strings.TrimSpace(field.val) == "" {
			return fmt.Errorf("%q is required", field.name)
		}
	}
	if spec.HoldS <= 0 {
		return fmt.Errorf("hold_s must be > 0")
	}
	if strings.TrimSpace(spec.Oracle.Name) == "" {
		return fmt.Errorf("oracle.name is required")
	}
	for _, v := range spec.ExpectedVerdicts {
		if !isValidVerdict(v) {
			return fmt.Errorf("expected_verdicts: %q is not one of %s", v, validVerdicts)
		}
	}
	if err := validatePhase("setup", spec.Setup, false); err != nil {
		return err
	}
	if err := validatePhase("per_tick", spec.PerTick, true); err != nil {
		return err
	}
	if err := validatePhase("teardown", spec.Teardown, false); err != nil {
		return err
	}
	for i, a := range spec.PerTick {
		if a.AtTick != nil && (*a.AtTick < 0 || *a.AtTick >= spec.HoldS) {
			return fmt.Errorf("per_tick[%d]: at_tick %d must be in [0, hold_s=%d) — ticks run at ~1/s under the default sampling interval", i, *a.AtTick, spec.HoldS)
		}
	}
	if spec.Constraint != nil {
		if _, err := constraintAsAction(spec.Constraint); err != nil {
			return fmt.Errorf("constraint: %w", err)
		}
	}
	return nil
}

// knownActions is the full v1 vocabulary, used to reject a typo'd or
// not-yet-supported verb at load time rather than silently no-op it.
var knownActions = map[string]bool{
	actSimPost: true, actGridsimAdmin: true, actInjectEnv: true,
	actPostCap: true, actPostCapProg: true, actPostConnect: true, actPostControl: true,
	actDeleteControls: true, actSuppressDefault: true,
	actMqttFault: true, actMqttInject: true, actMqttReset: true,
	actSSHHub: true, actSleepS: true,
}

// validatePhase checks structural rules common to a whole action list:
// unknown verbs, known sim_post targets, and phase restrictions (at_tick only
// in per_tick; constraint-producing verbs and sleep_s never in per_tick).
func validatePhase(phase string, actions []scenarioAction, isPerTick bool) error {
	for i, a := range actions {
		if !knownActions[a.Action] {
			return fmt.Errorf("%s[%d]: unknown action %q", phase, i, a.Action)
		}
		if a.Action == actSimPost && !knownSimTargets[a.Target] {
			return fmt.Errorf("%s[%d]: sim_post target %q is not a known backend", phase, i, a.Target)
		}
		if !isPerTick && a.AtTick != nil {
			return fmt.Errorf("%s[%d]: at_tick is only valid in per_tick", phase, i)
		}
		if isPerTick {
			if a.AtTick != nil && *a.AtTick < 0 {
				return fmt.Errorf("per_tick[%d]: at_tick must be >= 0", i)
			}
			if isConstraintAction(a.Action) {
				return fmt.Errorf("per_tick[%d]: %q is constraint-producing and only valid in setup", i, a.Action)
			}
			if a.Action == actSuppressDefault {
				return fmt.Errorf("per_tick[%d]: suppress_default is only valid in setup", i)
			}
			if a.Action == actSleepS {
				return fmt.Errorf("per_tick[%d]: sleep_s is only valid in setup/teardown (a per_tick sleep would block the sampling cadence)", i)
			}
		} else if phase == "teardown" && isConstraintAction(a.Action) {
			return fmt.Errorf("teardown[%d]: %q is constraint-producing and only valid in setup", i, a.Action)
		} else if phase == "teardown" && a.Action == actSuppressDefault {
			return fmt.Errorf("teardown[%d]: suppress_default is a setup action; its restore is applied to teardown automatically", i)
		}
	}
	return nil
}

// ── Compile ──────────────────────────────────────────────────────────────────

func validCapType(t string) bool {
	switch t {
	case "exportCap", "importCap", "genLimit":
		return true
	}
	return false
}

// constraintAsAction turns the "constraint" sugar field into the equivalent
// setup scenarioAction it stands for, so the compiler has exactly one code
// path (compileConstraintAction) for every constraint-producing verb. Errors
// for an absent/"none" type — the caller only invokes this when spec.Constraint
// is non-nil.
func constraintAsAction(c *scenarioConstraint) (scenarioAction, error) {
	switch c.Type {
	case "", "none":
		return scenarioAction{}, fmt.Errorf(`type must be one of exportCap|importCap|genLimit|connect (omit "constraint" entirely for no cap)`)
	case "connect":
		if c.Connect == nil {
			return scenarioAction{}, fmt.Errorf(`type "connect" requires "connect": true|false`)
		}
		if c.HoldS <= 0 {
			return scenarioAction{}, fmt.Errorf("hold_s must be > 0")
		}
		return scenarioAction{Action: actPostConnect, Connect: c.Connect, HoldS: c.HoldS, Desc: c.Desc}, nil
	case "exportCap", "importCap", "genLimit":
		if c.HoldS <= 0 {
			return scenarioAction{}, fmt.Errorf("hold_s must be > 0")
		}
		if c.Program != nil && *c.Program != 0 {
			return scenarioAction{Action: actPostCapProg, Typ: c.Type, LimW: c.LimitW, HoldS: c.HoldS, Desc: c.Desc, Program: c.Program}, nil
		}
		return scenarioAction{Action: actPostCap, Typ: c.Type, LimW: c.LimitW, HoldS: c.HoldS, Desc: c.Desc}, nil
	default:
		return scenarioAction{}, fmt.Errorf("unknown type %q", c.Type)
	}
}

// resolvePVW decodes inject_env's pv_w: a plain number, or the "high"
// sentinel resolved at run time to d.pvHighW (only known post-baseline()).
func resolvePVW(raw json.RawMessage) (func(d *mayhemDriver) float64, error) {
	if len(raw) == 0 {
		return func(d *mayhemDriver) float64 { return 0 }, nil
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		if asStr != "high" {
			return nil, fmt.Errorf(`pv_w string sentinel must be "high", got %q`, asStr)
		}
		return func(d *mayhemDriver) float64 { return d.pvHighW }, nil
	}
	var asNum float64
	if err := json.Unmarshal(raw, &asNum); err == nil {
		return func(d *mayhemDriver) float64 { return asNum }, nil
	}
	return nil, fmt.Errorf(`pv_w must be a number or "high"`)
}

// compileStepAction compiles a non-constraint-producing, non-suppress_default
// verb into a fire-and-forget runner — matching how every hand-written
// scenario treats setup/per_tick/teardown side effects (`_ = d.post(...)`):
// errors from per_tick/teardown steps are swallowed by the caller; a setup
// step's error is NOT swallowed (compileSpec's setup wraps it and the run
// loop turns it into an INCONCLUSIVE "could not arm the fault" finding, same
// as a Go scenario's setup returning an error).
func compileStepAction(a scenarioAction) (func(d *mayhemDriver) error, error) {
	switch a.Action {
	case actSimPost:
		if a.Target == "" || a.Path == "" {
			return nil, fmt.Errorf("sim_post requires target and path")
		}
		target, path, body := a.Target, a.Path, a.Body
		return func(d *mayhemDriver) error { return d.post(target, path, body) }, nil
	case actGridsimAdmin:
		if a.Path == "" {
			return nil, fmt.Errorf("gridsim_admin requires path")
		}
		path, body := a.Path, a.Body
		return func(d *mayhemDriver) error { return d.post("gridsim", path, body) }, nil
	case actInjectEnv:
		pv, err := resolvePVW(a.PVW)
		if err != nil {
			return nil, err
		}
		loadW := 0.0
		if a.LoadW != nil {
			loadW = *a.LoadW
		}
		return func(d *mayhemDriver) error { d.injectEnv(pv(d), loadW); return nil }, nil
	case actDeleteControls:
		program := 0
		if a.Program != nil {
			program = *a.Program
		}
		return func(d *mayhemDriver) error { d.deleteControls(program); return nil }, nil
	case actMqttFault:
		if a.Mode == "" {
			return nil, fmt.Errorf("mqtt_fault requires mode")
		}
		mode, lat, dur := a.Mode, a.LatencyMs, a.DurationS
		return func(d *mayhemDriver) error { return d.mqttFault(mode, lat, dur) }, nil
	case actMqttInject:
		if a.Topic == "" {
			return nil, fmt.Errorf("mqtt_inject requires topic")
		}
		topic, payload, retain := a.Topic, a.Payload, a.Retain
		return func(d *mayhemDriver) error { return d.mqttInject(topic, payload, retain) }, nil
	case actMqttReset:
		return func(d *mayhemDriver) error { return d.mqttReset() }, nil
	case actSSHHub:
		if a.Command == "" {
			return nil, fmt.Errorf("ssh_hub requires command")
		}
		cmd := a.Command
		return func(d *mayhemDriver) error { return d.hubSSH(cmd) }, nil
	case actSleepS:
		if a.Seconds <= 0 {
			return nil, fmt.Errorf("sleep_s requires seconds > 0")
		}
		secs := a.Seconds
		return func(d *mayhemDriver) error {
			time.Sleep(time.Duration(secs * float64(time.Second)))
			return nil
		}, nil
	case actSuppressDefault:
		return nil, fmt.Errorf("suppress_default is compiled by its phase (setup), not as a generic step")
	default:
		if isConstraintAction(a.Action) {
			return nil, fmt.Errorf("%q is constraint-producing — only valid in setup", a.Action)
		}
		return nil, fmt.Errorf("unknown action %q", a.Action)
	}
}

// compileConstraintAction compiles a constraint-producing verb (post_cap,
// post_cap_prog, post_connect, post_control) into the (*activeConstraint,
// error) runner setup() needs — the direct analogue of a Go scenario's
// `return d.postCap(...)`.
func compileConstraintAction(a scenarioAction) (func(d *mayhemDriver) (*activeConstraint, error), error) {
	switch a.Action {
	case actPostCap:
		if a.HoldS <= 0 {
			return nil, fmt.Errorf("post_cap requires hold_s > 0")
		}
		if !validCapType(a.Typ) {
			return nil, fmt.Errorf("post_cap: unknown typ %q (want exportCap|importCap|genLimit)", a.Typ)
		}
		typ, limW, holdS, desc := a.Typ, a.LimW, a.HoldS, a.Desc
		return func(d *mayhemDriver) (*activeConstraint, error) { return d.postCap(typ, limW, holdS, desc) }, nil
	case actPostCapProg:
		if a.HoldS <= 0 {
			return nil, fmt.Errorf("post_cap_prog requires hold_s > 0")
		}
		if !validCapType(a.Typ) {
			return nil, fmt.Errorf("post_cap_prog: unknown typ %q (want exportCap|importCap|genLimit)", a.Typ)
		}
		program := 0
		if a.Program != nil {
			program = *a.Program
		}
		typ, limW, holdS, desc := a.Typ, a.LimW, a.HoldS, a.Desc
		return func(d *mayhemDriver) (*activeConstraint, error) {
			return d.postCapProg(program, typ, limW, holdS, desc)
		}, nil
	case actPostConnect:
		if a.Connect == nil {
			return nil, fmt.Errorf("post_connect requires connect (bool)")
		}
		if a.HoldS <= 0 {
			return nil, fmt.Errorf("post_connect requires hold_s > 0")
		}
		connect, holdS, desc := *a.Connect, a.HoldS, a.Desc
		return func(d *mayhemDriver) (*activeConstraint, error) { return d.postConnect(connect, holdS, desc) }, nil
	case actPostControl:
		if a.Body == nil {
			return nil, fmt.Errorf("post_control requires body")
		}
		if a.Typ == "" {
			return nil, fmt.Errorf("post_control requires typ (the constraint type the run loop judges against)")
		}
		body, typ, limW := a.Body, a.Typ, a.LimW
		return func(d *mayhemDriver) (*activeConstraint, error) {
			mrid, err := d.postControl(body)
			if err != nil {
				return nil, err
			}
			return &activeConstraint{Typ: typ, LimW: limW, MRID: mrid}, nil
		}, nil
	default:
		return nil, fmt.Errorf("%q is not a constraint-producing action", a.Action)
	}
}

// setupOp is one compiled setup-phase step: exactly one of the three kinds is
// populated. Kept as a slice (not two passes) so setup executes in EXACTLY
// the JSON array's order, matching how the Go scenarios interleave side
// effects with constraint posts (e.g. conflicting-primacy's low-primacy cap
// then the high-primacy one that must win — the LAST constraint action's
// result is what setup() returns, exactly mirroring `return d.postCapProg(...)`).
type setupOp struct {
	suppressDefault bool
	constraintRun   func(d *mayhemDriver) (*activeConstraint, error)
	stepRun         func(d *mayhemDriver) error
}

func compileSetupOps(actions []scenarioAction) ([]setupOp, error) {
	ops := make([]setupOp, 0, len(actions))
	for i, a := range actions {
		switch {
		case a.Action == actSuppressDefault:
			ops = append(ops, setupOp{suppressDefault: true})
		case isConstraintAction(a.Action):
			run, err := compileConstraintAction(a)
			if err != nil {
				return nil, fmt.Errorf("setup[%d]: %w", i, err)
			}
			ops = append(ops, setupOp{constraintRun: run})
		default:
			run, err := compileStepAction(a)
			if err != nil {
				return nil, fmt.Errorf("setup[%d]: %w", i, err)
			}
			ops = append(ops, setupOp{stepRun: run})
		}
	}
	return ops, nil
}

// perTickOp is one compiled per_tick step, with its at_tick gate (nil ⇒ every
// tick).
type perTickOp struct {
	atTick *int
	run    func(d *mayhemDriver) error
}

func compilePerTickOps(actions []scenarioAction) ([]perTickOp, error) {
	ops := make([]perTickOp, 0, len(actions))
	for i, a := range actions {
		run, err := compileStepAction(a)
		if err != nil {
			return nil, fmt.Errorf("per_tick[%d]: %w", i, err)
		}
		ops = append(ops, perTickOp{atTick: a.AtTick, run: run})
	}
	return ops, nil
}

func compileTeardownOps(actions []scenarioAction) ([]func(d *mayhemDriver) error, error) {
	ops := make([]func(d *mayhemDriver) error, 0, len(actions))
	for i, a := range actions {
		run, err := compileStepAction(a)
		if err != nil {
			return nil, fmt.Errorf("teardown[%d]: %w", i, err)
		}
		ops = append(ops, run)
	}
	return ops, nil
}

// compileSpec turns a validated spec into a runnable *mayScenario. This is
// the interpreter: nothing here talks to the network — it only builds
// closures over the mayhemDriver methods, which run exactly when mayhem.run()
// calls sc.setup/perTick/evaluate/teardown, identically to a Go literal.
func compileSpec(spec *scenarioSpec) (*mayScenario, error) {
	if err := validateSpec(spec); err != nil {
		return nil, err
	}

	oracle, ok := oracleRegistry[spec.Oracle.Name]
	if !ok {
		return nil, fmt.Errorf("oracle %q is not registered", spec.Oracle.Name)
	}
	evalFn, err := oracle.build(spec.Oracle.Params)
	if err != nil {
		return nil, fmt.Errorf("oracle %q: %w", spec.Oracle.Name, err)
	}

	fullSetup := spec.Setup
	if spec.Constraint != nil {
		act, err := constraintAsAction(spec.Constraint)
		if err != nil {
			return nil, fmt.Errorf("constraint: %w", err)
		}
		fullSetup = append(append([]scenarioAction(nil), spec.Setup...), act)
	}

	setupOps, err := compileSetupOps(fullSetup)
	if err != nil {
		return nil, err
	}
	if oracle.requiresConstraint && !anyConstraintOp(setupOps) {
		return nil, fmt.Errorf("oracle %q needs a constraint but setup/constraint never posts one (post_cap/post_cap_prog/post_connect/post_control, or the top-level \"constraint\" field)", spec.Oracle.Name)
	}
	perTickOps, err := compilePerTickOps(spec.PerTick)
	if err != nil {
		return nil, err
	}
	teardownOps, err := compileTeardownOps(spec.Teardown)
	if err != nil {
		return nil, err
	}
	usesSuppressDefault := anySuppressDefaultOp(setupOps)

	sc := &mayScenario{
		ID: spec.ID, Name: spec.Name, Category: spec.Category,
		Hypothesis: spec.Hypothesis, Expected: spec.Expected, Fix: spec.Fix,
		HoldS: spec.HoldS, Extended: spec.Extended,
		Source:           "spec",
		ExpectedVerdicts: append([]string(nil), spec.ExpectedVerdicts...),
	}

	var restoreDefault func()
	sc.setup = func(d *mayhemDriver) (*activeConstraint, error) {
		var cons *activeConstraint
		for i, op := range setupOps {
			switch {
			case op.suppressDefault:
				restoreDefault = d.suppressDefault()
			case op.constraintRun != nil:
				c, err := op.constraintRun(d)
				if err != nil {
					return nil, fmt.Errorf("setup step %d: %w", i, err)
				}
				cons = c
			default:
				if err := op.stepRun(d); err != nil {
					return nil, fmt.Errorf("setup step %d: %w", i, err)
				}
			}
		}
		if cons == nil {
			cons = &activeConstraint{Typ: "none"}
		}
		return cons, nil
	}
	sc.perTick = func(d *mayhemDriver, i int) {
		for _, op := range perTickOps {
			if op.atTick != nil && *op.atTick != i {
				continue
			}
			_ = op.run(d) // per_tick side effects are fire-and-forget, matching every hand-written scenario
		}
	}
	sc.teardown = func(d *mayhemDriver) {
		for _, run := range teardownOps {
			_ = run(d)
		}
		// suppress_default auto-restores LAST, after every explicit teardown
		// action — mirrors wan-outage-expiry's Go teardown ordering exactly
		// (gridsimOutageClear(); deleteControls(0); restoreDefault()).
		if usesSuppressDefault && restoreDefault != nil {
			restoreDefault()
		}
	}
	sc.evaluate = evalFn
	return sc, nil
}

func anyConstraintOp(ops []setupOp) bool {
	for _, op := range ops {
		if op.constraintRun != nil {
			return true
		}
	}
	return false
}

func anySuppressDefaultOp(ops []setupOp) bool {
	for _, op := range ops {
		if op.suppressDefault {
			return true
		}
	}
	return false
}

// ── Loading ──────────────────────────────────────────────────────────────────

// loadSpecScenarios reads every *.json in dir (deterministic, sorted order),
// decodes+validates+compiles it, and returns the compiled scenarios plus one
// error per file that failed to load or whose ID collides with an existing
// scenario (a Go one, via existingIDs, or another spec in the same dir). A
// bad or colliding file NEVER blocks any other file or any Go scenario — one
// broken spec must not take a whole Mayhem run down (see run() error
// handling this mirrors: a scenario setup error already degrades to a single
// INCONCLUSIVE finding, not an aborted campaign).
//
// dir == "" means specs are disabled (the default for every existing test
// driver built via newMayhemDriver, and for any deployment that has not set
// -scenario-dir) — returns immediately, no filesystem access.
func (d *mayhemDriver) loadSpecScenarios(dir string, existingIDs map[string]bool) ([]*mayScenario, []error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no spec dir on disk yet — nothing to load, not an error
		}
		return nil, []error{fmt.Errorf("scenario spec dir %q: %w", dir, err)}
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names) // deterministic load order run to run

	var out []*mayScenario
	var errs []error
	seen := map[string]string{} // id -> file that already claimed it
	for _, name := range names {
		path := filepath.Join(dir, name)
		buf, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		spec, err := decodeSpec(buf)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		sc, err := compileSpec(spec)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		if existingIDs[sc.ID] {
			errs = append(errs, fmt.Errorf("%s: id %q collides with an existing Go scenario — not loaded (delete the Go twin in TASK-077, or rename this spec, before both can run)", path, sc.ID))
			continue
		}
		if other, dup := seen[sc.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: id %q collides with %s — not loaded", path, sc.ID, other))
			continue
		}
		seen[sc.ID] = path
		out = append(out, sc)
	}
	return out, errs
}
