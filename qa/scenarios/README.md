# Mayhem scenario specs (TASK-076)

This directory holds **declarative Mayhem scenarios** — JSON files that the
dashboard's Mayhem engine (`cmd/dashboard/mayhem.go` + `scenariospec.go`)
compiles into the same `mayScenario` value a hand-written Go literal in
`scenarios()`/`worldScenarios()`/`mqttScenarios()` produces. A spec here is
**data**, not code: adding or editing one takes effect on the very next
`POST /api/qa/start` with **no `go build`, no dashboard binary swap, no
`systemctl restart csip-dashboard`.**

That is the entire point. The 2026-07-03 stale-`bin/dashboard` incident burned
a validation cycle because a scenario change needed a rebuild+redeploy that got
skipped, and the running binary silently kept executing the old scenario. A
spec file cannot go stale that way: `scenarios()` reads this directory fresh,
every run (see "Why per-run loading matters" below).

## The boundary: oracles are code, scenarios are data

**Diagnosers (`diagnose*` funcs in `mayhem.go`/`mayhem_world.go`) stay in Go**
and are looked up by name from `oracleRegistry` (`scenariospec.go`). A spec can
**select** an oracle and pass it parameters (e.g. `diagnoseSurvival` takes a
`label`); it can never define new pass/fail *logic*. If a scenario needs a
judgment call the registered oracles don't make, that judgment is written as a
new Go function and registered — the scenario itself still ships as data. This
is deliberate: a spec-authoring model must never accidentally become a rules
engine that has to be independently code-reviewed for correctness the way a Go
diagnoser is.

Registered so far (see `oracleRegistry` for the authoritative list):
`diagnoseConstraint`, `diagnoseConverge`, `diagnoseStale`, `diagnoseRecovery`,
`diagnoseSOC`, `diagnoseDisconnect`, `diagnoseMalform`, `diagnoseSurvival`
(parameterized: `{"label": "..."}`). TASK-077 registers the rest as it
migrates each remaining Go scenario family.

## Why JSON, not a scripting language

The action vocabulary (below) mirrors `mayhemDriver`'s own methods 1:1 —
`sim_post` ↔ `d.post`, `post_cap` ↔ `d.postCap`, and so on. There is
deliberately **no conditional, loop, or expression syntax**. A scenario that
needs branching logic in its setup/perTick (not just "always do these N
things, optionally once at tick K") does not fit the vocabulary and **stays a
hand-written Go scenario** — that's a feature, not a gap: it keeps a spec file
auditable by inspection (a smaller model, or a human, can read the JSON and
know exactly what bench calls it makes, in what order, with what bodies) and
keeps the interpreter itself simple enough that trusting it doesn't require
re-reviewing a mini scripting-language implementation.

JSON over YAML: the dashboard binary is dependency-free today (`encoding/json`
is stdlib; a YAML parser would be the first non-stdlib, non-vendored
dependency in `cmd/dashboard`). JSON has no comments, so authoring notes live
in the `"notes"` field.

## Why per-run loading matters (read this before "fixing" it)

`d.scenarios()` is called **fresh inside `handleStart`, on every
`POST /api/qa/start`** — never once at process start. It reads
`-scenario-dir` (default `qa/scenarios`, set in `main.go`) from disk on every
call. Do not "optimize" this into a load-once-at-boot cache; that would
recreate a milder version of the exact stale-binary trap TASK-076 exists to
kill, just for specs instead of Go code.

**Engine or oracle changes still need a rebuild.** Only the JSON data path is
rebuild-free. If you change `scenariospec.go`, any `diagnose*` function, or
`mayhem.go`'s run loop, you still need:

```bash
go build -o bin/dashboard ./cmd/dashboard
systemctl --user restart csip-dashboard   # or whatever your unit is named — see docs/BENCH.md
```

## Schema (`spec_v: 1`)

```jsonc
{
  "spec_v": 1,
  "id": "my-scenario",                // unique across ALL scenarios, Go and spec
  "name": "Human-readable title",
  "category": "Grid compliance (INV-EXPORT)",
  "hypothesis": "The real-world fault this represents.",
  "expected": "What a correct hub does.",
  "fix": "Where in the product to look if it doesn't.",
  "hold_s": 100,                      // sampling window, seconds
  "extended": false,                  // RSK-12: long-running, excluded from a default/full run
  "notes": "JSON has no comments; authoring notes go here.",

  "setup":    [ /* scenarioAction, run once in order at scenario start */ ],
  "per_tick": [ /* scenarioAction, run every hold tick unless at_tick is set */ ],
  "teardown": [ /* scenarioAction, run once after the hold ends */ ],

  // Sugar for "one more constraint-producing action, appended to the end of
  // setup" — the common single-cap/disconnect case. Omit entirely for a
  // scenario with no constraint (an oracle that only reads samples, e.g.
  // diagnoseRecovery), or for a scenario that posts MULTIPLE constraints
  // (write them directly in "setup" instead — see "Multiple constraints" below).
  "constraint": {
    "type": "exportCap",              // exportCap | importCap | genLimit | connect
    "limit_w": 0,
    "program": 0,                     // optional; non-zero ⇒ post_cap_prog (primacy scenarios)
    "hold_s": 100,
    "desc": "mayhem: zero export cap",
    "connect": false                  // required, type=="connect" only
  },

  "oracle": { "name": "diagnoseConstraint", "params": {} },
  "expected_verdicts": ["PASS", "DEGRADED"]   // documentation only, see below
}
```

`expected_verdicts` implements the "expected-FAIL pins the gap" pattern
(`docs/refactor/06_TESTING_STRATEGY.md` §4.5) as data: it documents which
verdicts are acceptable outcomes for this scenario. **The interpreter does not
enforce it today** — it is validated (must be one of `PASS|DEGRADED|FAIL|
BLIND|INCONCLUSIVE`) and carried onto the compiled scenario for a future CI
comparison, not compared against the actual verdict at run time.

## Action vocabulary v1

Every verb below maps to exactly one `mayhemDriver` method — this is why the
compiler is a thin switch (`compileStepAction`/`compileConstraintAction` in
`scenariospec.go`), and why the vocabulary can only grow by adding a case that
mirrors an existing (or new) driver method, never by adding control flow.

| Action | Fields | Driver call | Where valid |
|---|---|---|---|
| `sim_post` | `target, path, body` | `d.post(target, path, body)` | setup/per_tick/teardown |
| `gridsim_admin` | `path, body` | `d.post("gridsim", path, body)` — sugar for `sim_post{target:"gridsim"}` | setup/per_tick/teardown |
| `inject_env` | `pv_w, load_w` | `d.injectEnv(pvW, loadW)` | setup/per_tick/teardown |
| `post_cap` | `typ, lim_w, hold_s, desc` | `d.postCap(...)` — **constraint-producing** | setup only |
| `post_cap_prog` | `program, typ, lim_w, hold_s, desc` | `d.postCapProg(...)` — **constraint-producing** | setup only |
| `post_connect` | `connect, hold_s, desc` | `d.postConnect(...)` — **constraint-producing** | setup only |
| `post_control` | `body, typ, lim_w` | `d.postControl(body)` + author-declared constraint — **constraint-producing** | setup only |
| `delete_controls` | `program` | `d.deleteControls(program)` | setup/per_tick/teardown |
| `suppress_default` | — | `d.suppressDefault()`; **auto-restored at the END of teardown** | setup only |
| `mqtt_fault` | `mode, latency_ms, duration_s` | `d.mqttFault(...)` | setup/per_tick/teardown |
| `mqtt_inject` | `topic, payload, retain` | `d.mqttInject(...)` | setup/per_tick/teardown |
| `mqtt_reset` | — | `d.mqttReset()` | setup/per_tick/teardown |
| `ssh_hub` | `command` | `d.hubSSH(command)` — **PRIVILEGED** | setup/per_tick/teardown |
| `sleep_s` | `seconds` | `time.Sleep` | setup/teardown only (never per_tick — it would block the sampling cadence) |

`per_tick` entries: no `at_tick` ⇒ runs every tick; `at_tick: N` ⇒ runs
**exactly once**, when the tick index equals `N`. **Caveat:** ticks are
~wall-seconds only at the default 1000 ms sample interval
(`mayDefaultSampleMs`) — the same assumption the hand-written Go scenarios
make with `if i == 15 { ... }`. `at_tick` must satisfy `0 <= at_tick <
hold_s`.

### `pv_w`'s "high" sentinel

`inject_env`'s `pv_w` is either a number, or the string `"high"`, which
resolves at run time to `d.pvHighW` — the nameplate-aware "full sun" setpoint
computed in `baseline()` (capped just under the inverter's nameplate so the
sim's reported potential stays physically achievable). Use `"high"` for any
scenario that wants "the PV is producing everything it can right now."

### Multiple constraints (e.g. a primacy conflict)

`post_cap`/`post_cap_prog`/`post_connect`/`post_control` can each appear
directly in `setup` (instead of using the top-level `"constraint"` sugar).
When more than one constraint-producing action runs, **the last one's result
is what the run loop judges against** — exactly mirroring a Go scenario like
`conflicting-primacy`, which posts a low-primacy cap and then the
high-primacy one that must win, returning only the second call's result.

### Suppressing the default export cap

`suppress_default` clears the bench's program-0 `DefaultDERControl` for the
scenario's duration so "the event released" unambiguously means
"unconstrained" (see `diagnoseRecovery`'s ≥95%-of-potential bar, and the
`suppressDefault` doc comment in `mayhem_world.go`). It only ever belongs in
`setup`; **you never write a matching teardown action for it** — the
compiler captures the restore closure and calls it automatically, **after**
every explicit teardown action runs (so a scenario's own cleanup — e.g.
`delete_controls` — happens first, then the default is restored last,
mirroring `wan-outage-expiry`'s Go teardown ordering).

### `ssh_hub` is privileged

`ssh_hub` runs an arbitrary command on the hub Pi over SSH
(`BatchMode=yes`, 4 s connect timeout — same as every other SSH-driven
scenario). The bench is a trusted environment, but a spec author must still
see this called out: a spec that runs `ssh_hub` is doing something no other
verb can (arbitrary remote execution), and — per the existing hub-restart
precedent — a scenario that depends on SSH should expect **INCONCLUSIVE**,
not a misleading verdict, when SSH is unavailable (that's automatic: an error
from any setup action degrades the scenario to INCONCLUSIVE via the normal
run-loop path, same as a Go scenario's `setup` returning an error).

## ID collisions are load errors, never silent shadowing

If a spec's `"id"` matches an existing Go scenario's ID (or another spec's),
`loadSpecScenarios` logs a clear error naming the file and the colliding ID,
and **excludes that one spec** from the run — every other scenario, Go or
spec, is unaffected. This is why `export-cap-full-battery.json` in this very
directory does not appear in a live campaign today: its ID intentionally
matches the still-present Go literal in `mayhem.go` (kept until TASK-077
deletes it), so every run logs the collision and the Go original keeps
running the curated suite unchanged. It becomes the live scenario the moment
077 removes the Go twin — no file change required.

## Compile-time validation

A spec is rejected at **load time**, with an error naming the file and the
failing field/index, if: `spec_v` isn't `1`; a required field is blank;
`hold_s <= 0`; an action verb or `sim_post` target isn't recognised;
`at_tick` is used outside `per_tick`, or falls outside `[0, hold_s)`;
`suppress_default`/a constraint-producing verb/`sleep_s` appears somewhere
it isn't valid; the named oracle isn't registered, or its params don't
decode; or an oracle that needs a constraint (`diagnoseConstraint` and
friends — see `oracleRegistry`'s `requiresConstraint`) never gets one from
`setup`/`"constraint"`. See `cmd/dashboard/scenariospec_test.go` for the full
table of rejected inputs.

## Testing

- `go test ./cmd/dashboard/...` — schema decode/validation, the compiler
  (action-by-action and end-to-end against fake HTTP backends), the oracle
  registry, ID-collision handling, and a compile-all pass over every file in
  this directory (a broken spec here fails CI, not a live campaign).
- `python3 scripts/mayhem.py --list` shows each scenario's source
  (`[go]`/`[spec]`) alongside its `[extended]` tag.

## Worked example

`export-cap-full-battery.json` in this directory is a JSON twin of the Go
literal `scenarios()` builds for ID `export-cap-full-battery`
(`cmd/dashboard/mayhem.go`) — the pilot proving the schema end-to-end.
`cmd/dashboard/scenariospec_test.go` also carries two more proofs inline
(not shipped as files, since their IDs would collide with their own still-
present Go twins the same way): a `post_connect`/`delete_controls` twin of
`grid-disconnect`, and a `gridsim_admin`-at-tick / parameterized-oracle twin
of `wan-outage-hold`. Read those three before writing a new spec — between
them they exercise every verb this task's pilot needed.
