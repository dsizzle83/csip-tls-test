# Aggregator control campaigns (`camp_v: 1`, T06.6/T06.7)

This directory holds **declarative control campaigns** for the Secure SunSpec
Modbus (mbaps) aggregator emulator (`internal/aggregator`). A campaign is a JSON
file the headless engine (`internal/aggregator/engine.go`) loads and runs: it
connects as a role, drives the gateway's northbound mbaps `:802` server through a
sequence of steps (discover, poll, typed control writes, readback verification,
role-denial probes), records every observation, and hands the finished evidence
to a **named oracle** for a single verdict.

It is the **sibling** of the dashboard's Mayhem scenario family
(`qa/scenarios/*.json`, `spec_v: 1`) — same spirit, separate engine (PN-3). Mayhem
drives the hub over CSIP with a hostile-QA vocabulary; this family drives the
gateway over mbaps with a control/readback/denial vocabulary. The two never share
a driver.

## The boundary: oracles are code, campaigns are data

**Oracles (`convergeWithinSLA`, `denyExpected`, `reversionOnExpiry`) stay in Go**
(`internal/aggregator/oracle.go`, `readback.go`) and are looked up by name from
`oracleRegistry`. A campaign can **select** an oracle and (where supported) pass
it params; it can never define pass/fail logic. A judgment the registered oracles
don't make is written as a new Go oracle and registered — the campaign still ships
as data. This is deliberate, and identical to the Mayhem rule: a campaign-authoring
model must never accidentally become a rules engine that needs independent code
review the way a Go oracle does.

Every observation the engine records (`RunState` — session facts, telemetry
samples, control writes, denial probes) is **verdict-free**. The verdict lives in
a separate layer (`verdict.go` / `report.go`): the oracle reads the run and the
per-step results and returns exactly one `PASS | DEGRADED | FAIL | BLIND |
INCONCLUSIVE`.

## Schema

```jsonc
{
  "camp_v": 1,
  "id": "curtail-solar-50",           // unique across all campaigns in this dir
  "name": "Human-readable title",
  "role": "GridServiceSunSpec",       // session role to connect as (one of the 5 bench roles)
  "target": "gateway",                // "gateway" (:802) or "device" (loopback mbapsdev)
  "hypothesis": "The real-world need this represents.",
  "expected": "What a correct gateway does.",
  "fix": "Where in the product to look if it doesn't.",
  "notes": "JSON has no comments; authoring notes go here.",
  "steps": [ /* the action vocabulary below, run in order */ ],
  "oracle": { "name": "convergeWithinSLA" },      // + optional "params"
  "expected_verdicts": ["PASS"]                   // acceptable outcomes; the runner
                                                  // exits non-zero on a surprise
}
```

## Action vocabulary v1

Each verb maps to exactly one engine driver method — this is why the interpreter
is a thin dispatch and why the vocabulary can only grow by mirroring a primitive,
never by adding conditionals or loops. A campaign needing real logic stays a Go
test.

| Verb | Fields | Effect |
|---|---|---|
| `connect_as` | `role` | Switch the session to another role mid-campaign. |
| `discover` | `units` (list or omit) | Walk the per-device unit map; inventory Model 1 + model chain. |
| `poll` | `units` (`"*"` or list), `period_s` | Start a background telemetry loop into the run report. |
| `write_point` | `unit, model, point, value` (+`win_tms, rvrt_tms`) | Typed, scale-correct control write; reversion timers write the `<point>RvrtTms` companion. |
| `write_multi` | `unit, addr, values` | Raw FC16 register write (escape hatch for a point the typed writer can't address). |
| `readback` | `unit, model, point, expect, sla_s` (+`tol, phase`) | Poll the echo point until it converges to `expect` within `sla_s`. |
| `expect_exception` | `unit, model, point, value` (+`expect_code`) | Attempt a write and assert the gateway answers with `expect_code` (default 01). |
| `disconnect` | — | Close the current session. |
| `resume` | — | Re-establish the session (reconnect). |
| `sleep_s` | `seconds` | Wait (cancellable) — e.g. a hold window. |
| `sim_fault` | `target, fault` | Arm/clear a fault on a named sim via its simapi (`{"kind":"drop_session"}`). |

`units` is `"*"` (everything discovered so far this campaign) or an explicit list
— a small number-or-`"*"` union, never an expression. `readback.phase` (`"hold"`
/ `"revert"`) tags a readback for the `reversionOnExpiry` oracle.

**Reserved for T06.8** (TLS-fault probes): `renegotiate`. It is intentionally NOT
accepted here yet — a campaign using it fails at load — because its oracle bodies
(the renegotiation-refusal judge, `resumeAfterDrop`) belong to that task.

## Oracles

| Oracle | Verdict logic |
|---|---|
| `convergeWithinSLA` | Every `readback` converged to its commanded value within its SLA ⇒ PASS (DEGRADED if any only just made it; FAIL if any never converged; BLIND if a target never returned a value). |
| `denyExpected` | Every `expect_exception` probe answered with its expected code and nothing was wrongly accepted ⇒ PASS (FAIL on an accepted write or a wrong code; INCONCLUSIVE if a probe hit a transport error). |
| `reversionOnExpiry` | A `phase:"hold"` readback held the ceiling, then a `phase:"revert"` readback converged to the safe default ⇒ PASS; a revert readback stuck at the commanded value ⇒ FAIL (stuck curtailment — a safety regression). |

## Load-time validation

A campaign is rejected at **load** (with an error naming the offending field), and
excluded without affecting any other file, if: `camp_v` isn't `1`; `id`/`name` is
blank; `role` isn't a bench role; `target` isn't `gateway`/`device`; there are no
steps; a verb is unknown; a `write_point`/`readback`/`expect_exception` names a
model with no fixed-shape layout or a point not in it; `sla_s`/`period_s`/`seconds`
is `<= 0`; a `unit` is 0; the named oracle isn't registered or its params don't
decode; or an `id` collides with another file. An id collision is a load error,
never a silent shadow — the same guard the Mayhem loader uses.

Campaigns load fresh from this directory on every batch run, so adding or editing
one takes effect with no rebuild (the same stale-binary trap the Mayhem
scenarios-as-data work closed).

## Testing

- `go test ./internal/aggregator/...` — schema decode/reject table, the oracle
  registry + decision tables, and a **compile-all pass over every file in this
  directory** (a broken campaign here fails CI, not a live run).
- `go test -tags integration ./internal/aggregator/...` — the engine runs
  `curtail-solar-50` (readback-verify) and `role-denial-readonly` end to end
  against a loopback authz-enforcing mbaps server and asserts the oracle verdicts.

## Files

- `curtail-solar-50.json` — GridService curtail→verify→release (`convergeWithinSLA`). Runs hermetically + live.
- `role-denial-readonly.json` — ReadOnly + LexaVolt write denial (`denyExpected`). Runs hermetically + live.
- `battery-hold-dispatch.json` — GridService battery WSet hold→dispatch (`convergeWithinSLA`). Live/battery; validated at load.
- `ramp-limit-reversion.json` — GridService reversion-on-expiry (`reversionOnExpiry`). Live-bench; oracle unit-tested on synthetic evidence.
