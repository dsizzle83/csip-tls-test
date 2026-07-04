# TASK-076 — Mayhem scenarios-as-data: spec schema + engine (R6)

*Status: TODO · Phase: P6 · Effort: L (≈8 h) · Difficulty: high · Risk: low*

## Objective
A declarative scenario-spec format (JSON, stdlib-decoded) and an
interpreter inside the Mayhem engine exist, covering everything the
hand-written Go scenarios use: injector actions (simapi, gridsim admin,
mqttproxy, SSH), phase/timing structure (setup / per-tick / teardown /
HoldS), oracle selection by name with parameters, and expected-verdict
annotations. One pilot scenario runs from a spec file with verdict parity
against its Go twin. New scenarios become addable WITHOUT a Go rebuild —
killing the stale-`bin/dashboard` deployment trap. Mass migration of the
suite is TASK-077.

## Background
Verified engine anatomy (csip-tls-test/cmd/dashboard) — line/length refs
are hints; re-verify by grep at execution time; symbol names are
authoritative:
- `mayhem.go` (3,123 lines) holds the driver + curated scenario literals;
  `mayhem_world.go` (468) worldScenarios; `mqtt_scenarios.go` (114) MQTT
  chaos; `matrix.go` matrix mode; `invariants.go` (380) the INV-* audit.
- `mayScenario` struct (mayhem.go:189-203): `ID, Name, Category,
  Hypothesis, Expected, HoldS, Fix` + four FUNC fields: `setup(d) →
  (*activeConstraint, error)`, `perTick(d, i)`, `evaluate(sc, cons,
  samples) → mayFinding`, `teardown(d)`. The func fields are what the
  spec format must express declaratively.
- Injector surface used by scenarios (all methods on `mayhemDriver`):
  `post(name, path, body)` → simapi (`solar|battery|meter|ev` →
  `/inject`, `/control`, plus `mqttproxy` → `/fault|/inject|/reset`,
  `gridsim` → `/admin/outage|/admin/clock|/admin/malform|/admin/default`);
  `injectEnv(pvW, loadW)`; `postCap(typ, limW, holdS, desc)` /
  `postCapProg` / `postConnect` / `postControl` / `deleteControls(prog)`;
  `suppressDefault()` (mayhem_world.go:66-72, returns a restore func);
  SSH exec for hub-side actions (mayhem_world.go:96-103, hub-restart
  pattern). Sampling/oracles read `meterW()/solarSim()/evSim()/
  batterySim()/hubState()/reportedCannotComply()`.
- Oracles are named funcs: `diagnoseConstraint`, `diagnoseRecovery`,
  `diagnoseMalform`, plus per-scenario closures. **Boundary decision
  (already made by the brief): oracles/diagnosers STAY IN GO; scenarios
  are data.** Closured evaluate funcs must be replaced by named,
  parameterized oracles during migration (077) — the spec references them
  by name.
- The trap this kills (D8): scenarios require a Go rebuild + redeploy;
  the csip-dashboard unit execs `bin/dashboard`, so an un-rebuilt binary
  silently runs old scenarios — the 2026-07-03 stale-binary incident
  burned a validation cycle.
- Runner: `scripts/mayhem.py` (`--list/--only/--json/--matrix/--chaos`);
  dashboard `/api/qa/*` (`handleStart/Status/Scenarios/Abort`,
  mayhem.go:215-311).

## Why this task exists
D8 · R6 · item 19: "3,123-line scenario/driver/diagnosis monolith;
scenarios require Go rebuild + binary redeploy → slow iteration;
deployment traps."

## Architecture review sections
D8 · R6 · item 19 · §13 (tribal deploy knowledge) · 06 §Mayhem
(scenarios-as-data removes the rebuild-redeploy trap) · 08 RSK-13.

## Prerequisites
None (Track F, any time after P0). Coordinate with TASK-065 if its two
new scenarios land first (write them as specs if this task beats them).

## Files
- **Read first:** cmd/dashboard/mayhem.go (driver + scenario literals +
  run loop :327-440), mayhem_world.go, mqtt_scenarios.go, invariants.go,
  matrix.go, scripts/mayhem.py, cmd/dashboard/main.go (flags).
- **Modify:** cmd/dashboard/mayhem.go (scenario loading path:
  `scenarios()` gains "append specs from dir"), main.go (`-scenario-dir`
  flag, default `qa/scenarios` relative to working dir), scripts/mayhem.py
  only if listing needs a source tag.
- **Create:** `cmd/dashboard/scenariospec.go` (schema + decode +
  compile-to-mayScenario) + `scenariospec_test.go`;
  `qa/scenarios/` directory + `qa/scenarios/README.md` (schema doc) +
  one pilot spec (`export-cap-full-battery.json` — the simplest
  constraint scenario).

## Blast radius
Dashboard binary (bench repo only; no product code). The engine's run
loop is untouched — specs COMPILE INTO `mayScenario` values, so verdicts,
sampling, invariant audit, and the API are identical by construction.

## Implementation strategy
Interpret, don't replace: a spec decodes into the existing `mayScenario`
struct with generated closures. JSON via stdlib (no new dependency —
decision: JSON over YAML to keep the dashboard dependency-free; comments
live in a `"notes"` field). The action vocabulary mirrors the driver
methods 1:1 so the compiler is a thin switch, and anything the vocabulary
can't express stays a Go scenario until the vocabulary grows (077 will
force the remaining verbs out).

## Detailed steps
1. Schema (`scenariospec.go`), versioned `{"spec_v": 1}`:
   ```json
   {
     "spec_v": 1,
     "id": "...", "name": "...", "category": "...",
     "hypothesis": "...", "expected": "...", "fix": "...",
     "hold_s": 90,
     "setup":   [ {"action": "...", ...}, ... ],
     "per_tick":[ {"action": "...", ...},
                  {"at_tick": 15, "action": "..."} ],
     "teardown":[ ... ],
     "constraint": {"type": "exportCap", "limit_w": 0, "hold_s": 90,
                    "desc": "..."},
     "oracle":  {"name": "diagnoseConstraint", "params": {...}},
     "expected_verdicts": ["PASS", "DEGRADED"]
   }
   ```
   Action vocabulary v1 (mirror driver methods): `sim_post {target,path,
   body}`, `inject_env {pv_w, load_w}`, `post_cap`/`post_connect`/
   `post_control`, `delete_controls {program}`, `suppress_default`,
   `gridsim_admin {path, body}`, `mqtt_fault/mqtt_inject/mqtt_reset`,
   `ssh_hub {command}` (marked privileged), `sleep_s`. `per_tick` entries
   without `at_tick` run every tick; with `at_tick` run once.
2. Oracle registry: `map[string]func(params) evaluateFn` seeded with
   `diagnoseConstraint`, `diagnoseRecovery`, `diagnoseMalform`; params
   decoded per oracle (unknown oracle/params = load-time error, never
   runtime surprise). `expected_verdicts` implements the
   "expected-FAIL pins the gap" pattern (06 §4.5) as data.
3. Compiler: spec → `mayScenario{setup: composed actions returning the
   constraint from post_cap/post_connect, perTick, evaluate: registry
   lookup, teardown: reverse-order + auto-restore of suppress_default}`.
   Compile-time validation: every action verb known, targets known,
   `at_tick < hold_s`, constraint present when the oracle needs one.
4. Loading: `scenarios()` appends compiled specs from `-scenario-dir`
   (each `*.json`); ID collision with a Go scenario = load error (until
   077 deletes the twin, the spec file must not shadow silently);
   `/api/qa/scenarios` and `mayhem.py --list` tag source (`go|spec`).
5. Pilot: write `export-cap-full-battery.json` reproducing the Go literal
   (mayhem.go:2321-2334: battery full inject via setup? — read the
   literal: setup injects SoC 100 via the armCap-like block, injectEnv
   pvHigh/loadLow, postCap exportCap 0; oracle diagnoseConstraint).
   Handle `d.pvHighW` (driver-derived nameplate): expose as action value
   `"pv_w": "high"` sentinel resolved by the compiler.
6. Parity: run the pilot from spec with the Go twin disabled-by-flag
   (temporary `-prefer-spec id` toggle or rename) ×3; identical verdicts
   and same-shaped findings. Keep the Go literal (077 deletes it).
7. Rebuild-trap note: `qa/scenarios/README.md` states specs load at RUN
   start (re-read per run — verify the load point lands in
   `handleStart`, not process start, so editing a spec needs NO
   restart); document that engine/oracle changes still need
   `go build -o bin/dashboard ./cmd/dashboard` + unit restart.
8. `make test-fast` additions: schema decode/validation/compiler tests
   with golden spec files; a compile-all test over qa/scenarios/.

## Testing changes
scenariospec_test.go (decode, validation errors, compiler output,
oracle registry); compile-all test; pilot parity ×3 on the bench.
Run: `make test-fast`; `python3 scripts/mayhem.py --only
export-cap-full-battery --dashboard http://69.0.0.20:8080`.

## Documentation changes
- qa/scenarios/README.md (schema reference + authoring guide + the
  no-rebuild boundary).
- csip-tls-test CLAUDE.md Mayhem section: spec dir + boundary ("oracles
  are code, scenarios are data").
- docs/QA_FAULT_INJECTION.md if it catalogs injectors (verify; update).

## Common mistakes to avoid
- Inventing a scripting language (conditionals/loops in JSON) — the
  vocabulary mirrors driver verbs; logic belongs in oracles (Go). If a
  scenario needs more, it stays Go.
- Loading specs at process start (recreates a flavor of the stale-binary
  trap for specs; load per run).
- Silent ID shadowing between spec and Go definitions.
- Letting `ssh_hub` run arbitrary commands from a spec without marking it
  (bench is trusted, but the README must flag it; INCONCLUSIVE-without-SSH
  precedent from hub-restart applies to spec scenarios too).
- Breaking `--matrix`/`--chaos` modes (they build scenarios differently —
  matrixScenarios(); leave untouched).

## Things that must NOT change
- Verdict machinery: run loop, sampling cadence, invariant audit
  (`escalateForAudit`), report format, `/api/qa/*` shapes (mayhem.py
  compatibility).
- Existing Go scenarios' behavior (all still load and run unchanged).
- The 10×-solo stability rule for anything NEW (RSK-13) — pilot is a
  ported twin, so ×3 parity suffices.
- Bench-restore guarantees (`restoreBench`, teardown ordering).

## Acceptance criteria
- [ ] Schema documented; loader validates and rejects bad specs with
  actionable errors.
- [ ] Pilot spec ×3 verdict-parity with its Go twin (evidence).
- [ ] Editing a spec between runs takes effect with NO rebuild/restart
  (demonstrated in PR).
- [ ] `mayhem.py --list` shows source tags; all Go scenarios unaffected
  (one full campaign green).
- [ ] `make test-fast` green with the new tests.

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) green
- [ ] `go test ./tests/` green (untouched — sanity)
- [ ] Mayhem: full FAST campaign (loader touches scenarios(); prove
  no-op for Go set)
- [ ] Dashboard rebuilt to `bin/dashboard` + unit restarted (the trap
  this task documents — don't fall in it while fixing it)

## Mayhem scenarios affected
export-cap-full-battery gains a spec twin (Go original still
authoritative until 077). All others: none.

## Conformance implications
None.

## Suggested commit message
`feat(qa): scenario-spec schema + interpreter (R6) — pilot export-cap-full-battery, no-rebuild authoring`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Mayhem scenarios-as-data: schema + engine (R6)
**Description:** JSON specs compile to mayScenario at run start; action
vocabulary mirrors driver verbs; oracle registry (oracles stay Go);
pilot parity ×3; full-campaign no-op proof. Risk: low (additive loader).
Rollback: remove -scenario-dir contents.

## Code review checklist
- Vocabulary↔driver-method 1:1 audit (no dead verbs, no missing ones the
  pilot needed).
- Load-per-run verified.
- Validation errors name the file + field.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-077 (mass migration + Go-literal deletion), backlog: spec-driven
matrix cells (07 deferred "matrix/chaos cells for new faults").
