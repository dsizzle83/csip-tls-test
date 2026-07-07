package main

// scenariospec_migration_test.go — TASK-077: parity proofs that each migrated
// qa/scenarios/*.json spec calls the exact same mayhemDriver methods, with the
// exact same bodies/constraint, and wires the exact same oracle, that its
// now-deleted Go twin in cmd/dashboard/mayhem.go called (see
// docs/qa-spec-migration.md for the full migration table and the Go source
// this was diffed against at deletion time). These are unit-level proofs
// (fake HTTP backends via httptest, no bench) — same lane as TASK-076's own
// parity tests in scenariospec_test.go, which this file complements rather
// than duplicates.
//
// Each case checks: (1) HoldS/oracle wiring, (2) setup's constraint result
// (Typ/LimW/Connect), (3) the scenario-specific fault-arm/inject call(s) that
// distinguish it from every other scenario, (4) teardown's cleanup call(s).
// Generic battery-full/inject_env setup calls are exercised exhaustively by
// TestCompileSpec_ExportCapFullBattery_MatchesGoTwin already; here the focus
// is the part that's easy to get wrong migrating each individual scenario.

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func mustCompileMigratedSpec(t *testing.T, id string) *mayScenario {
	t.Helper()
	path := filepath.Join(repoRootFromTest(t), "qa", "scenarios", id+".json")
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	spec, err := decodeSpec(buf)
	if err != nil {
		t.Fatalf("decodeSpec(%s): %v", id, err)
	}
	sc, err := compileSpec(spec)
	if err != nil {
		t.Fatalf("compileSpec(%s): %v", id, err)
	}
	if sc.ID != id {
		t.Fatalf("file %s.json declares id %q, want %q", id, sc.ID, id)
	}
	if sc.Source != "spec" {
		t.Errorf("%s: Source = %q, want spec", id, sc.Source)
	}
	return sc
}

// sameOracle proves the compiled spec's evaluate func IS the named registered
// diagnose* func (not a copy/reimplementation) — the "same oracle path" half
// of the parity protocol (TASK-077 step 5). noParamOracle returns the
// function value itself, so this is a legitimate function-pointer identity
// check, not a fragile behavioral proxy.
func sameOracle(t *testing.T, sc *mayScenario, want evaluateFn) {
	t.Helper()
	got := reflect.ValueOf(sc.evaluate).Pointer()
	wantPtr := reflect.ValueOf(want).Pointer()
	if got != wantPtr {
		t.Errorf("%s: evaluate is not the expected registered oracle", sc.ID)
	}
}

func wantBody(t *testing.T, call *recordedCall, scenario, desc string, kv map[string]any) {
	t.Helper()
	if call == nil {
		t.Fatalf("%s: expected %s, got no matching call", scenario, desc)
	}
	for k, want := range kv {
		if got := call.Body[k]; got != want {
			t.Errorf("%s: %s body[%q] = %v, want %v", scenario, desc, k, got, want)
		}
	}
}

// ── diagnoseConverge family ──────────────────────────────────────────────────

func TestMigrated_AckBeforeEffect(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "ack-before-effect")
	if sc.HoldS != 90 {
		t.Errorf("HoldS = %d, want 90", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConverge)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "genLimit" || cons.LimW != 1000 {
		t.Errorf("constraint = %+v, want {genLimit 1000}", cons)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm",
		map[string]any{"kind": "ack_before_effect", "delay_s": float64(45)})

	before := logs["solar"].count("POST", "/fault")
	sc.teardown(d)
	if got := logs["solar"].count("POST", "/fault"); got != before+1 {
		t.Errorf("teardown: solar /fault POST count = %d, want %d (the clear call)", got, before+1)
	}
}

func TestMigrated_RejectWriteCurtail(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "reject-write-curtail")
	if sc.HoldS != 50 {
		t.Errorf("HoldS = %d, want 50", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConverge)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "genLimit" || cons.LimW != 1000 {
		t.Errorf("constraint = %+v, want {genLimit 1000}", cons)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm",
		map[string]any{"kind": "reject_write"})

	before := logs["solar"].count("POST", "/fault")
	sc.teardown(d)
	if got := logs["solar"].count("POST", "/fault"); got != before+1 {
		t.Errorf("teardown: solar /fault POST count = %d, want %d (the clear call)", got, before+1)
	}
}

func TestMigrated_EnableGateCurtail(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "enable-gate-curtail")
	if sc.HoldS != 50 {
		t.Errorf("HoldS = %d, want 50", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConverge)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "genLimit" || cons.LimW != 1000 {
		t.Errorf("constraint = %+v, want {genLimit 1000}", cons)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm",
		map[string]any{"kind": "enable_gate"})
}

func TestMigrated_RampLimitCurtail(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "ramp-limit-curtail")
	if sc.HoldS != 100 {
		t.Errorf("HoldS = %d, want 100", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConverge)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "genLimit" || cons.LimW != 1000 {
		t.Errorf("constraint = %+v, want {genLimit 1000}", cons)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm",
		map[string]any{"kind": "ramp_limit", "max_ramp_w_per_s": float64(120)})
}

// ── diagnoseSOC / diagnoseConstraint battery family ─────────────────────────

func TestMigrated_BatteryWrongSign(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "battery-wrong-sign")
	if sc.HoldS != 90 {
		t.Errorf("HoldS = %d, want 90", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseSOC)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "exportCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {exportCap 0}", cons)
	}
	wantBody(t, logs["battery"].find("POST", "/inject"), sc.ID, "battery inject",
		map[string]any{"SoC_pct": float64(10.5), "Conn": float64(1)})
	wantBody(t, logs["battery"].find("POST", "/fault"), sc.ID, "battery fault arm",
		map[string]any{"kind": "wrong_sign"})
}

func TestMigrated_BatterySocRefuse(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "battery-soc-refuse")
	if sc.HoldS != 70 {
		t.Errorf("HoldS = %d, want 70", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "importCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {importCap 0}", cons)
	}
	wantBody(t, logs["battery"].find("POST", "/fault"), sc.ID, "battery fault arm",
		map[string]any{"kind": "soc_refuse"})
	wantBody(t, logs["meter"].find("POST", "/inject"), sc.ID, "meter inject (load_w=5000)",
		map[string]any{"LoadW_W": float64(5000)})
}

func TestMigrated_BatteryChargeDisabled(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "battery-charge-disabled")
	if sc.HoldS != 70 {
		t.Errorf("HoldS = %d, want 70", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "exportCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {exportCap 0}", cons)
	}
	wantBody(t, logs["battery"].find("POST", "/fault"), sc.ID, "battery fault arm",
		map[string]any{"kind": "charge_disabled"})
}

func TestMigrated_BatteryEmptyImportCap(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "battery-empty-import-cap")
	if sc.HoldS != 90 {
		t.Errorf("HoldS = %d, want 90", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "importCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {importCap 0}", cons)
	}
	wantBody(t, logs["battery"].find("POST", "/inject"), sc.ID, "battery inject",
		map[string]any{"SoC_pct": float64(5)})

	// No teardown in the Go twin — must not panic and must call nothing.
	before := len(logs["gridsim"].calls)
	sc.teardown(d)
	if got := len(logs["gridsim"].calls); got != before {
		t.Errorf("teardown made %d unexpected gridsim calls (Go twin has none)", got-before)
	}
}

// ── EV constraint family ────────────────────────────────────────────────────

func TestMigrated_EvProfileReject(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "ev-profile-reject")
	if sc.HoldS != 70 {
		t.Errorf("HoldS = %d, want 70", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "ev", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "importCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {importCap 0}", cons)
	}
	wantBody(t, logs["ev"].find("POST", "/fault"), sc.ID, "ev fault arm",
		map[string]any{"kind": "profile_reject"})

	before := logs["ev"].count("POST", "/inject")
	sc.teardown(d)
	if got := logs["ev"].count("POST", "/inject"); got != before+1 {
		t.Errorf("teardown: ev /inject count = %d, want %d (stop_session)", got, before+1)
	}
}

func TestMigrated_EvAcceptButIgnore(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "ev-accept-but-ignore")
	if sc.HoldS != 70 {
		t.Errorf("HoldS = %d, want 70", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "ev", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "importCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {importCap 0}", cons)
	}
	wantBody(t, logs["ev"].find("POST", "/fault"), sc.ID, "ev fault arm",
		map[string]any{"kind": "apply_next_tx"})
}

func TestMigrated_EvMinCurrentFloor(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "ev-min-current-floor")
	if sc.HoldS != 70 {
		t.Errorf("HoldS = %d, want 70", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "ev", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "importCap" || cons.LimW != 800 {
		t.Errorf("constraint = %+v, want {importCap 800}", cons)
	}
	wantBody(t, logs["ev"].find("POST", "/fault"), sc.ID, "ev fault arm",
		map[string]any{"kind": "min_current_floor", "amps_a": float64(6)})
}

func TestMigrated_EvDelayedObey(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "ev-delayed-obey")
	if sc.HoldS != 80 {
		t.Errorf("HoldS = %d, want 80", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "ev", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "importCap" || cons.LimW != 2000 {
		t.Errorf("constraint = %+v, want {importCap 2000}", cons)
	}
	wantBody(t, logs["battery"].find("POST", "/inject"), sc.ID, "battery inject",
		map[string]any{"SoC_pct": float64(12)})
	wantBody(t, logs["ev"].find("POST", "/fault"), sc.ID, "ev fault arm",
		map[string]any{"kind": "apply_delayed", "delay_s": float64(20)})
}

// ── grid-disconnect / conflicting-primacy / solar-reboot-forget ────────────

func TestMigrated_GridDisconnect(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "grid-disconnect")
	if sc.HoldS != 45 {
		t.Errorf("HoldS = %d, want 45", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseDisconnect)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "connect" {
		t.Errorf("constraint.Typ = %q, want connect", cons.Typ)
	}
	call := logs["gridsim"].find("POST", "/admin/control")
	wantBody(t, call, sc.ID, "disconnect control", map[string]any{"connect": false})

	sc.teardown(d)
	del := logs["gridsim"].find("DELETE", "/admin/control")
	wantBody(t, del, sc.ID, "teardown delete_controls", map[string]any{"program": float64(0)})
}

func TestMigrated_ConflictingPrimacy(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "conflicting-primacy")
	if sc.HoldS != 70 {
		t.Errorf("HoldS = %d, want 70", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// The run loop must judge against the LAST constraint action's result —
	// the high-primacy (program 0) 0 W cap, not the low-primacy 5 kW one.
	if cons.Typ != "exportCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {exportCap 0} (the high-primacy cap must win)", cons)
	}
	calls := logs["gridsim"].calls
	var controlCalls []recordedCall
	for _, c := range calls {
		if c.Method == "POST" && c.Path == "/admin/control" {
			controlCalls = append(controlCalls, c)
		}
	}
	if len(controlCalls) != 2 {
		t.Fatalf("expected exactly 2 POST /admin/control calls (low then high primacy), got %d", len(controlCalls))
	}
	if controlCalls[0].Body["program"] != float64(2) || controlCalls[0].Body["exp_lim_W"] != float64(5000) {
		t.Errorf("first control = %v, want program:2 exp_lim_W:5000", controlCalls[0].Body)
	}
	if controlCalls[1].Body["program"] != float64(0) || controlCalls[1].Body["exp_lim_W"] != float64(0) {
		t.Errorf("second control = %v, want program:0 exp_lim_W:0", controlCalls[1].Body)
	}

	sc.teardown(d)
	if got := logs["gridsim"].count("DELETE", "/admin/control"); got != 2 {
		t.Errorf("teardown: DELETE /admin/control count = %d, want 2 (program 0 and 2)", got)
	}
}

func TestMigrated_SolarRebootForget(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "solar-reboot-forget")
	if sc.HoldS != 70 {
		t.Errorf("HoldS = %d, want 70", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseConstraint)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "exportCap" || cons.LimW != 0 {
		t.Errorf("constraint = %+v, want {exportCap 0}", cons)
	}

	setupInjects := logs["solar"].count("POST", "/inject") // setup's own inject_env call
	for i := 0; i < 25; i++ {
		sc.perTick(d, i)
	}
	if got := logs["solar"].count("POST", "/inject"); got != setupInjects+25 {
		// 25 fixed re-injects for i=0..24, none of them the at_tick=25 one yet.
		t.Errorf("solar /inject count after ticks 0-24 = %d, want %d (no WMaxLimPct reset yet)", got, setupInjects+25)
	}
	sc.perTick(d, 25)
	call := logs["solar"].find("POST", "/inject") // first match; use body scan for the WMaxLimPct one
	found := false
	for _, c := range logs["solar"].calls {
		if c.Method == "POST" && c.Path == "/inject" && c.Body["WMaxLimPct_pct"] == float64(100) {
			found = true
		}
	}
	_ = call
	if !found {
		t.Error("expected solar /inject WMaxLimPct_pct:100 exactly at tick 25 (the reboot-forgets-the-limit event)")
	}
}

// ── Transport / battery-garbage / reboot / expiry (wave B: new oracles) ────

func TestMigrated_NanSentinel(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "nan-sentinel")
	if sc.HoldS != 35 {
		t.Errorf("HoldS = %d, want 35", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseTransport)

	d, logs := newTestDriver(t, "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "none" {
		t.Errorf("constraint.Typ = %q, want none", cons.Typ)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm", map[string]any{"kind": "nan_sentinel"})
}

func TestMigrated_ModbusException(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "modbus-exception")
	if sc.HoldS != 35 {
		t.Errorf("HoldS = %d, want 35", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseTransport)

	d, logs := newTestDriver(t, "solar", "meter", "gridsim")
	if _, err := sc.setup(d); err != nil {
		t.Fatalf("setup: %v", err)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm", map[string]any{"kind": "exception_code"})
}

func TestMigrated_ModbusLatency(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "modbus-latency")
	if sc.HoldS != 35 {
		t.Errorf("HoldS = %d, want 35", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseTransport)

	d, logs := newTestDriver(t, "solar", "meter", "gridsim")
	if _, err := sc.setup(d); err != nil {
		t.Fatalf("setup: %v", err)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm",
		map[string]any{"kind": "latency", "latency_ms": float64(800)})
}

func TestMigrated_SolarBadScale(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "solar-bad-scale")
	if sc.HoldS != 35 {
		t.Errorf("HoldS = %d, want 35", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseTransport)

	d, logs := newTestDriver(t, "solar", "meter", "gridsim")
	if _, err := sc.setup(d); err != nil {
		t.Fatalf("setup: %v", err)
	}
	wantBody(t, logs["solar"].find("POST", "/fault"), sc.ID, "solar fault arm", map[string]any{"kind": "bad_scale"})
}

func TestMigrated_BatteryNanSentinel(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "battery-nan-sentinel")
	if sc.HoldS != 35 {
		t.Errorf("HoldS = %d, want 35", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseBatteryGarbage)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "none" {
		t.Errorf("constraint.Typ = %q, want none", cons.Typ)
	}
	wantBody(t, logs["battery"].find("POST", "/fault"), sc.ID, "battery fault arm", map[string]any{"kind": "nan_sentinel"})
}

func TestMigrated_BatteryReboot(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "battery-reboot")
	if sc.HoldS != 50 {
		t.Errorf("HoldS = %d, want 50", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseReboot)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "none" {
		t.Errorf("constraint.Typ = %q, want none", cons.Typ)
	}
	wantBody(t, logs["battery"].find("POST", "/fault"), sc.ID, "battery fault arm", map[string]any{"kind": "exception_code"})

	for i := 0; i < 20; i++ {
		sc.perTick(d, i)
	}
	if got := logs["battery"].count("POST", "/fault"); got != 1 {
		t.Errorf("battery /fault POST count before tick 20 = %d, want 1 (only the arm call)", got)
	}
	sc.perTick(d, 20)
	if got := logs["battery"].count("POST", "/fault"); got != 2 {
		t.Errorf("battery /fault POST count at tick 20 = %d, want 2 (arm + at_tick clear)", got)
	}
	lastClear := logs["battery"].calls[len(logs["battery"].calls)-1]
	if lastClear.Body["clear"] != true {
		t.Errorf("at_tick=20 call body = %v, want clear:true", lastClear.Body)
	}

	before := logs["battery"].count("POST", "/fault")
	sc.teardown(d)
	if got := logs["battery"].count("POST", "/fault"); got != before+1 {
		t.Errorf("teardown: battery /fault POST count = %d, want %d (defensive re-clear)", got, before+1)
	}
}

func TestMigrated_ExpiredControl(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "expired-control")
	if sc.HoldS != 90 {
		t.Errorf("HoldS = %d, want 90", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseExpiry)

	d, logs := newTestDriver(t, "battery", "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "exportCap" || cons.LimW != 0 || cons.MRID == "" {
		t.Errorf("constraint = %+v, want {exportCap 0 <non-empty MRID>}", cons)
	}
	call := logs["gridsim"].find("POST", "/admin/control")
	wantBody(t, call, sc.ID, "expiring control",
		map[string]any{"duration_s": float64(30), "exp_lim_W": float64(0), "activate": true})
}

// ── curtailment-release: suppress_default + at_tick delete_controls ────────

func TestMigrated_CurtailmentRelease(t *testing.T) {
	sc := mustCompileMigratedSpec(t, "curtailment-release")
	if sc.HoldS != 60 {
		t.Errorf("HoldS = %d, want 60", sc.HoldS)
	}
	sameOracle(t, sc, diagnoseRecovery)

	d, logs := newTestDriver(t, "solar", "meter", "gridsim")
	cons, err := sc.setup(d)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cons.Typ != "genLimit" || cons.LimW != 1500 {
		t.Errorf("constraint = %+v, want {genLimit 1500}", cons)
	}
	// suppress_default's GET /admin/default fetch happens at setup, restoring
	// the program-0 default is deferred to teardown (see the README).
	if logs["gridsim"].find("GET", "/admin/default") == nil {
		t.Error("expected suppress_default's GET /admin/default fetch during setup")
	}

	for i := 0; i < 15; i++ {
		sc.perTick(d, i)
	}
	if got := logs["gridsim"].count("DELETE", "/admin/control"); got != 0 {
		t.Fatalf("delete_controls fired before tick 15 (%d calls)", got)
	}
	sc.perTick(d, 15)
	if got := logs["gridsim"].count("DELETE", "/admin/control"); got != 1 {
		t.Errorf("expected exactly 1 delete_controls at tick 15, got %d", got)
	}

	before := logs["gridsim"].count("DELETE", "/admin/control")
	sc.teardown(d)
	// teardown's own delete_controls(0) plus suppress_default's auto-restore
	// (a POST /admin/control re-asserting the saved default) — the ordering
	// invariant proven generically by TestCompileSpec_SuppressDefault_RestoresAfterExplicitTeardown.
	if got := logs["gridsim"].count("DELETE", "/admin/control"); got != before+1 {
		t.Errorf("teardown: DELETE /admin/control count = %d, want %d", got, before+1)
	}
}

// ── real qa/scenarios/ directory: no collisions, stable total count ────────

// migratedSpecIDs is the authoritative list of TASK-077's wave-1 migration —
// kept here (not derived) so a regression that silently drops a file from
// qa/scenarios/ or reintroduces a Go/spec ID collision fails loudly, and so
// this list itself is one place a reviewer can diff against
// docs/qa-spec-migration.md's table.
var migratedSpecIDs = []string{
	"export-cap-full-battery", "ack-before-effect", "reject-write-curtail",
	"enable-gate-curtail", "ramp-limit-curtail", "battery-wrong-sign",
	"battery-soc-refuse", "battery-charge-disabled", "battery-empty-import-cap",
	"ev-profile-reject", "ev-accept-but-ignore", "ev-min-current-floor",
	"ev-delayed-obey", "grid-disconnect", "conflicting-primacy",
	"solar-reboot-forget", "curtailment-release", "nan-sentinel",
	"modbus-exception", "modbus-latency", "solar-bad-scale",
	"battery-nan-sentinel", "battery-reboot", "expired-control",
}

// TestScenarios_RealSpecDirLoadsCleanlyNoCollisions pins the acceptance
// criterion "mayhem.py --list count constant across the whole task" (task's
// regression checklist) statically: scenarios() against the REAL
// qa/scenarios directory must load exactly len(migratedSpecIDs) spec-sourced
// scenarios, all previously-Go IDs among them must have NO Go twin left (so
// no collision error was logged and excluded one), and the total scenario
// count must equal the Go-literal count plus the migrated count — i.e. this
// migration replaced 24 Go twins 1-for-1, it did not shrink or duplicate the
// suite.
func TestScenarios_RealSpecDirLoadsCleanlyNoCollisions(t *testing.T) {
	d := newMayhemDriver(map[string]string{})
	d.scenarioDir = filepath.Join(repoRootFromTest(t), "qa", "scenarios")
	scs := d.scenarios()

	bySource := map[string]int{}
	byID := map[string]int{}
	for _, s := range scs {
		bySource[s.Source]++
		byID[s.ID]++
		if byID[s.ID] > 1 {
			t.Errorf("scenario ID %q appears %d times — collision", s.ID, byID[s.ID])
		}
	}
	if bySource["spec"] != len(migratedSpecIDs) {
		t.Errorf("spec-sourced scenario count = %d, want %d (len(migratedSpecIDs)) — did a qa/scenarios/*.json file get lost, or collide?", bySource["spec"], len(migratedSpecIDs))
	}
	for _, id := range migratedSpecIDs {
		if byID[id] != 1 {
			t.Errorf("migrated scenario %q appears %d times, want exactly 1", id, byID[id])
			continue
		}
	}
	for _, s := range scs {
		for _, id := range migratedSpecIDs {
			if s.ID == id && s.Source != "spec" {
				t.Errorf("migrated scenario %q loaded with Source=%q, want spec (a Go twin must not still exist)", id, s.Source)
			}
		}
	}
}
