# TASK-080 survey — CSIP curve functions (volt-var / volt-watt) scope

*Evidence for AD-010. Every cell below is grep/read-verified against the
tree as of 2026-07-06 (lexa-proto, lexa-hub, csip-tls-test); no cell is
inferred from the architecture review's `[Likely]` tag without independent
confirmation. `lexa-proto` is the shared-module home per AD-003(g) — this
survey cites it, not the vendored copies, as the canonical location.*

## 1. Layer × capability table

| Layer | Capability | Status | Evidence |
|---|---|---|---|
| `csipmodel` decode | Scalar `DERControlBase` (no curve fields) | EXISTS | `lexa-proto/csipmodel/resources.go:269-284` |
| `csipmodel` decode | `ExtendedDERControlBase` — adds `OpModVoltVar`/`OpModVoltWatt`/`OpModFreqWatt`/`OpModWattPF` + 10 ride-through `CurveLink` fields | EXISTS | `lexa-proto/csipmodel/der.go:219-263` |
| `csipmodel` decode | `DERCurve`/`DERCurveData`/`DERCurveList` (piecewise curve resource incl. `autonomousVRefEnable`, ramp times, axis multipliers) | EXISTS | `lexa-proto/csipmodel/der.go:104-169` |
| `csipmodel` decode | `DERCapabilityFull.ModesSupported` bitmask (client's declared capability) | EXISTS (type only) | `lexa-proto/csipmodel/der.go:316-317` |
| Walker fetch | `ExtendedDERControlList` / `ExtendedDefaultDERControl` (curve-linked events + default) fetched **first**, always | EXISTS | `lexa-hub/internal/northbound/discovery/walker.go:250-268`, `fetchExtendedDERControlList` :397-400, `fetchExtendedDefaultDERControl` :402-405 |
| Walker fetch | `DERCurveList` fetched per program, hrefs indexed into `ps.Curves map[string]DERCurve` | EXISTS | `walker.go:281-293`, `fetchDERCurveList` :392-395 |
| Walker → scheduler bridge | Scalar-only "simple" copy built field-by-field from the Extended fetch, **dropping every curve field on the floor** (deliberate allowlist copy, not a struct embed) | **THE FIRST DROP POINT** | `extendedListToSimple` `walker.go:470-506`, `extendedDefaultToSimple` `walker.go:445-468` (comments: "the scheduler ... only touches scalar modes") |
| Curve resolution | `resolveCurves()` looks up all 14 curve-linked hrefs against `ps.Curves`, builds a `ResolvedCurves` struct with the actual `*DERCurve` objects | EXISTS | `lexa-hub/internal/northbound/schedule/schedule.go:369-396` |
| Curve resolution consumer | `schedule.Build()` attaches `ResolvedCurves` to each `ScheduleSlot` — but this builds the **24h informational schedule only** | EXISTS, informational-only | `schedule.go:60-75` (`ScheduleSlot.Extended`/`.Curves` fields), `Build()` :94-143 |
| Curve resolution sink | `curveSummary()`/`countProgramsWithCurves()` publish curve **metadata** into `bus.DERScheduleMsg` for the dashboard Schedule tab | EXISTS, display-only | `lexa-hub/cmd/northbound/main.go:612-620` (count), `:695-712` (per-slot summary fields), `:753+` (`curveSummary`) |
| Real-time scheduler | `Scheduler.ActiveControl.Base` is the **scalar** `model.DERControlBase` — structurally cannot carry a curve field | MISSING (structural) | `lexa-hub/internal/northbound/scheduler/scheduler.go:48-59` |
| Real-time scheduler | `resolve()`/`activeEvent()` read `ps.Controls.DERControl`/`ps.DefaultControl` exclusively — **never** `ps.ExtendedControls`, `ps.ExtendedDefault`, or `ps.Curves` | MISSING | `scheduler.go:158-180` (`resolve`), `:333-378` (`activeEvent`) — zero references to `Extended*`/`Curves` anywhere in the file (grep-confirmed) |
| Bus wire schema | `bus.ActiveControl` fields: `Connect`/`ExpLimW`/`ImpLimW`/`MaxLimW`/`FixedW`/`ClockOffset`/`ValidUntil` — no curve field, no curve-ref field | MISSING | `lexa-hub/internal/bus/messages.go:46-58` |
| Scheduler→bus translation | `toActiveControl()` copies only the five scalar fields | MISSING (nothing to copy — `ac.Base` has no curve fields) | `cmd/northbound/main.go:905-935` |
| Hub-side actuation | `cmd/hub` device actuators / lexa-modbus control applicator consume `bus.ActiveControl` only | MISSING (no curve data ever arrives) | (no code reference needed — upstream schema has no such field) |
| `derbase.ApplyControl` (the CSIP→SunSpec dispatcher every consumer calls) | Enumerates `OpModEnergize`/`OpModConnect`/`OpModFixedPFInjectW`/`OpModFixedPFAbsorbW`/`OpModFixedVar`/`OpModFixedW`/ceiling triple/import pair — **zero** reference to `OpModVoltVar`/`OpModVoltWatt`/`OpModFreqWatt`/`OpModWattPF`/any trip `CurveLink`, and its parameter type (`model.DERControlBase`) is the scalar one, so it cannot see curve fields even if it wanted to | MISSING | `lexa-proto/derbase/derbase.go:207-262` (grep for `OpModVoltVar\|OpModVoltWatt\|CurveLink\|DERCurve` in this file: zero hits outside the package doc comment) |
| `derbase` write paths | `ReadVoltVar`/`WriteVoltVar` (M705), `ReadVoltWatt`/`WriteVoltWatt` (M706), voltage/freq trip read/write (M707-710), `adoptCurve` §3.1.2/§3.3 handshake (staging write → `AdptCrvReq=2` → poll `AdptCrvRslt` → `Ena=1`) | **EXISTS, tested** | `derbase.go:432-450` (`adoptCurve`), `:486-509` (VoltVar), `:511-534` (VoltWatt), `:536-566` (trip sets); capability probe `Has705`/`Has706`/… `derbase.go:66-79` |
| `derbase` test coverage | `TestCSIP_VoltVarAdoptWorkflow` proves the adopt handshake against a **synthetic in-memory register map** (`memDev`), not a real or simulated device | EXISTS, unit-test-only | `derbase_csip_test.go:52-90` (`newCSIPDevice`/`memDev`), `:205-236` (the test) |
| Bench sims — SunSpec model coverage | batsim (`sim/southbound/battery.go`) implements models 1/120/121/103/123/802 only | MISSING 704-712 entirely | `sim/southbound/battery.go:5-13` (register-layout comment); grep for `705\|706\|VoltVar\|VoltWatt` across `sim/southbound/` and `sim/modsim-conformance/`: **zero hits** |
| Bench sims — 704 (the model `ApplyControl` itself needs for anything beyond legacy 123) | Not present either — same grep | MISSING | (same grep as above; battery has no M704 base at all) |
| Mayhem/QA | `curve-attack` scenario: server serves an **empty** `DERCurveList` while an export cap is active — discovery robustness only | EXISTS, narrow scope | `cmd/dashboard/mayhem.go:2769-2787`; its own `Expected` text: *"the hub discovers DER curves but does not yet consume them for control"* (self-documented gap already in the codebase) |
| Mayhem/QA | Scenario serving an **active** `DERControl`/`DefaultDERControl` with a populated `opModVoltVar`/etc. and asserting hub behavior | MISSING | grep of `mayhem.go`/`mayhem_world.go` for a curve-bearing-control scenario: none found |
| Conformance | `CONFORMANCE_REPORT.md` mentions curve functions, VoltVar/VoltWatt, or any ADV-group CSIP test ID | MISSING (no claim made either way today) | grep of `CONFORMANCE_REPORT.md`: zero hits |
| Conformance | Hub ever POSTs/asserts `DERCapabilityFull.ModesSupported` at runtime (a live capability claim a lab could hold it to) | MISSING (unused) | grep across `lexa-hub` (excl. vendor/tests): only a read-relay for the dashboard, `cmd/northbound/main.go:721`; no POST site found |

## 2. Today's behavior trace — a curve-bearing control, end to end (verified, not assumed)

Scenario: the utility's DERProgram serves a `DERControl` (or `DefaultDERControl`)
whose `DERControlBase` sets `opModVoltVar` (an href to a `DERCurve`), possibly
alongside an ordinary `opModExpLimW` cap in the same control.

1. **Fetch.** The walker's step 6a/6b *always* fetches the Extended (curve-
   capable) variant first (`fetchExtendedDefaultDERControl`/
   `fetchExtendedDERControlList`), so Go's `encoding/xml` correctly populates
   `ExtendedDERControlBase.OpModVoltVar` with the `CurveLink`. Step 6d fetches
   the program's `DERCurveList` and indexes it by href into `ps.Curves`. All
   of this succeeds — nothing is dropped by the HTTP/XML layer.
2. **The drop.** `extendedListToSimple`/`extendedDefaultToSimple` immediately
   build the scalar-only `ps.Controls`/`ps.DefaultControl` the scheduler
   consumes, by copying named fields one at a time. `OpModVoltVar` (and every
   other curve-linked field) is not in that copy list — not because of an
   error, but because the destination type (`model.DERControlBase`,
   `resources.go:269`) has no such field to receive it. No log line, no
   error return, no metric increments here.
3. **Scheduler.** `activeEvent()`/`resolve()` operate only on the scalar
   copies, so the winning `ActiveControl` for this window carries the
   ordinary `OpModExpLimW` (correctly enforced) and simply has no
   representation of the curve intent at all — not "nil because ignored",
   but "the type never had a place to put it."
4. **Bus + hub.** `toActiveControl` → `bus.ActiveControl` → hub actuators →
   `lexa-modbus` → `derbase.ApplyControl` all faithfully apply the scalar
   cap. The curve-linked mode never influences a register write, an adopt
   handshake, or any device state.
5. **In parallel, on a separate path:** `schedule.Build()` (called every walk
   right after the control publish, `cmd/northbound/main.go:581-582`) *does*
   resolve `opModVoltVar`'s href against `ps.Curves` via `resolveCurves()`
   and attaches the real `DERCurve` object to the same window's
   `ScheduleSlot.Curves.VoltVar`. This flows into `bus.DERScheduleMsg` as
   `DERCurveSummary` metadata for the dashboard's Schedule tab
   (`curveSummary()`, `cmd/northbound/main.go:753+`) — visible to an
   operator looking at the UI, consumed by no actuation code anywhere.
6. **No alarm.** The only related telemetry, `countProgramsWithCurves`
   (`main.go:612`), is a `slog.Debug`-level per-walk count of how many
   *programs* merely have a non-empty curve map — it says nothing about
   whether the control **currently being enforced** referenced a curve mode
   that got silently dropped.

**Conclusion: the "acknowledged and ignored" framing is TRUE, with a useful
nuance for the conformance statement** — the curve is not merely dropped
into a void; it is fetched, resolved, and even *displayed* to the operator
on the dashboard. It is only ever inert with respect to device actuation,
and nothing distinguishes (for an operator or an alarm) "a program has
curves nobody asked to enforce right now" from "the control we are
*currently enforcing* just tried to set a curve mode we can't apply." The
hub does **not** crash, zero-value, or misbehave on a curve-bearing
control — the scenario gap noted below is real, but there is no live bug
to file: the scalar portions of the SAME control (e.g., a concurrent
`opModExpLimW`) are applied correctly and safely regardless of whatever
curve-linked fields ride alongside them.

## 3. The gap, enumerated (what's missing between "derbase can write a
   curve" and "CSIP curve → device")

1. **Scheduler curve resolution in the real-time path.** `resolve()`/
   `activeEvent()` must read `ps.ExtendedControls`/`ps.ExtendedDefault` +
   `ps.Curves` (or the scheduler needs a curve-aware sibling to
   `ActiveControl`), duplicating or refactoring `schedule.go`'s
   `resolveCurves()` into a path both the informational schedule and the
   real dispatch share. Must integrate with `failClosed`'s `lastGood`/
   `Held` semantics — those `*ActiveControl` copies would now need to carry
   curve state through a hold, and `plausibleControl()` needs a curve-aware
   validity check (are the curve's points monotonic in X, in bounds, non-
   degenerate?) so a malformed curve is rejected the same way an implausible
   `ExpLimW` is today. **Estimate: M.**
2. **Curve fetch/cache is mostly already built** — `walker.go` step 6d
   already produces `ps.Curves`; this hop is "make it a first-class input
   to dispatch," not "build it from nothing." **Estimate: S.**
3. **Bus schema: a versioned curve payload** (AD-006 discipline) —
   `bus.ActiveControl` (or a new sibling topic) needs a field carrying the
   resolved curve (points, `vRef`, deadband/ramp params). Needs the same
   `Finite()`-style defense-in-depth the NaN-hardening pass added for
   scalar limits (TASK-055) extended to point arrays, plus a size cap (a
   curve is attacker-shaped array data reaching the bus over MQTT, the same
   hostile-boundary posture as the fuzzed XML/bus-JSON parsers, TASK-047/048).
   **Estimate: M.**
4. **lexa-modbus / reconciler-side adopt orchestration.** The AD-002/AD-013
   reconciler's per-device converge loop needs a curve-diff detector (only
   re-adopt when the payload changed — mirroring the change-detected
   dedupe TASK-040 already applies to other writes), a call into
   `derbase`'s `adoptCurve` workflow, and a new CannotComply hop on
   `AdptCrvRslt == FAILED`. This is new state inside the same convergence
   machinery the review already named the program's dominant defect class
   (W2) and that P2 just finished collapsing from four mechanisms to one —
   adding a sixth axis of "what must converge" here is the single highest-
   risk hop in this list. **Estimate: L.**
5. **Adopt retry/timeout handling.** `pollAdoptResult` already has a
   documented best-effort escape hatch ("device may not update the result
   point" — `derbase.go` `pollAdoptResult`, returns `nil` on timeout rather
   than erroring); the reconciler needs its own retry/backoff distinct from
   scalar-write retry, since a curve write is a multi-register transaction
   with a partial-write hazard on a comms drop mid-handshake.
   **Estimate: M.**
6. **Readback/verify.** `ReadVoltVar`/`ReadVoltWatt` exist; wiring them into
   a periodic verify-against-desired loop (does the active curve — index 0
   — still match what was last adopted, accounting for `DefaultRvrtTms`
   auto-revert on comms loss) is new. **Estimate: S–M.**
7. **Bench sim support.** batsim/modsim/metersim implement none of models
   704-710 today (only legacy 1/120/121/103/123/802) — closed-loop curve
   dispatch cannot be validated on hardware-in-the-loop at all until three
   device sims gain new register banks + simapi inject/state plumbing for
   each. **Estimate: L.**
8. **modsim-conformance additions.** New per-device-type adopt-handshake
   assertions. **Estimate: M.**
9. **New Mayhem scenarios** (task step 3): curve-adopt-under-churn (comms
   flake mid-handshake), adopt-reject (device returns `AdptFailed`),
   curve+cap interaction (does a ceiling and a Q(V) curve fight — a new
   arbitration question for the in-flight P5 constraint controller,
   TASK-058). Given GAP-14's finding that decision-string oracles don't
   survive refactors, these need proper plan/state assertions from day one.
   **Estimate: L** (3+ scenarios, each a new oracle design).
10. **Conformance suite additions.** The curve-related ADV test group (CSIP
    Conformance Test Procedures v1.3) plus actually asserting
    `DERCapabilityFull.ModesSupported`'s VoltVar/VoltWatt bits at
    registration (unused today — see table above), so certification claims
    match declared capability. **Estimate: M.**

**Tally: 2×S, 5×M, 3×L.** This is the majority of the work by a wide margin
— the derbase write paths (already done, tested) are the easy 10% of the
total bill, exactly as the task file warned. Realistic cost: several
engineer-weeks spanning the northbound scheduler, bus schema, the reconciler
(mid-stabilization from P2/AD-002/AD-013), three device sims, Mayhem, and
the conformance suite — not a single-task or single-phase add-on.

## 4. Market / certification questions (asked, unanswered as of 2026-07-06)

No project-owner input was available in this session (docs-only worktree,
no live owner channel). Recorded as open, with an explicit trigger below —
this AD is conditional on these, not silent about needing them.

1. **Do any target utility programs or signed pilot LOIs contractually
   require live, utility-updatable volt-var/volt-watt curve dispatch via
   CSIP**, or do they accept device-local/commissioning-time default curves
   satisfying IEEE 1547-2018's autonomous-operation requirement (the "many
   DERMS programs run fixed default curves" pattern this task's background
   already names as acceptable)?
2. **Is the V1.0 certification-lab engagement (IEEE 1547.1 / CSIP test
   procedures) scoped to include the curve-linked ADV test group**, or can
   the DUT's declared `ModesSupported` bitmask legitimately omit
   VoltVar/VoltWatt/FreqWatt/WattPF/ride-through bits this cycle — making
   those tests N/A rather than FAIL? (This repo's own conformance evidence
   matrix, `CONFORMANCE_REPORT.md` §1, is structured around what the client
   claims/exercises per test ID; nothing in-repo establishes curve dispatch
   as a hard prerequisite for a passing baseline CSIP client conformance
   run — but only the lab's actual test plan can confirm this for real.)
3. **Does any signed pilot/LOI contract mention volt-var, volt-watt, or
   "smart inverter functions" in language that binds V1.0 delivery**, and
   if so, what's the revisit deadline?

**Recorded as unanswered as of 2026-07-06.** Trigger for revisiting AD-010:
before signing any pilot/LOI whose contract language references curve-linked
DER function sets, or before finalizing the certification lab's test scope
for the V1.0 engagement — whichever comes first. The owner must answer
these before either event, not after.

## 5. Decision matrix

| Option | Cost | Benefit | Risk |
|---|---|---|---|
| **Implement now** | Weeks of work across 5 lexa-hub subsystems + 3 device sims + Mayhem + conformance (§3 tally: 2S/5M/3L) | Supports utility programs requiring live curve dispatch (rare for an early pilot fleet per the task's own decision context) | High — lands a 6th convergence axis inside the reconciler the moment P2 finished collapsing four mechanisms into one (AD-002); intersects the in-flight P5 constraint-controller rewrite (TASK-058) before that framework has even landed its first real migration (TASK-060) |
| **Implement-partial** (write curve once when first resolved, never re-verify/retry/readback) | Looks cheap (skip hops 4-6's retry/verify machinery) | None durable | **Rejected.** Worst option: an unverified curve write is exactly the class of confidently-wrong dispatch the review's W2 finding is about — nothing polls `AdptCrvRslt` on an ongoing basis, so a failed/partial adopt produces silent misbehavior with no CannotComply signal, strictly worse than today's honest inertness (nothing is ever silently miscommanded, because nothing is commanded at all) |
| **De-scope, autonomous default curves** | Near-zero (no behavior change from what the code already does; the only recommended addition is an S-effort ignored-curve-field alarm, backlog, not required this task) | Ships V1.0 on schedule; devices keep vendor/commissioned curves satisfying IEEE 1547-2018 on their own; hub's honest current behavior (fetch + display, never enforce) becomes a *written, deliberate* claim instead of an accidental one | Low — excludes certification/sales claims for programs requiring live dispatch; explicit conformance-statement language and a dated revisit trigger close the "silence" risk AD-010 exists to prevent |

**Recommendation: DE-SCOPE for V1.0.** The investigation found no evidence
curves are "trivially wireable" (§3's tally says the opposite) and no
in-repo evidence of a certification hard-requirement (§4 Q2 is unanswered
but nothing here contradicts the task's own framing that de-scope is
acceptable). De-scoping matches what the code already, honestly does today
— it requires no behavior change, only a written claim and (recommended,
not required) one small alarm.
