# 03 — Refactor Phases

*Each phase leaves the project releasable: it compiles, passes all existing
tests, and passes a full Mayhem campaign at its exit gate. Task details:
`tasks/TASK-*.md`; ordering and blocking: `04_DEPENDENCY_GRAPH.md`.*

Verdict-rate baseline to defend throughout: **V6 = 0.6 FAIL/cycle, 0 BLIND**
(legacy-42 subset ≈ 0), with remaining DEGRADEDs accepted-by-design
(documented in `docs/QA_REPORT_V5_20260703.md` and the V6 notes).

---

## Phase 0 — Foundations ("stop the bleeding")

**Tasks:** TASK-001 … TASK-018 · **Duration:** ~5 weeks · **Effort:** ~90 h

**Purpose.** Convert tribal process into institutional process before any
structural change. Nothing here intentionally changes runtime behavior
except where stated (auth, watchdogs).

**Expected outcome.** Zero uncommitted work; CI (build, `-race` tests,
conformance smoke, `govulncheck`, lockstep-divergence gate) on every PR in
both repos; systemd watchdogs + `sd_notify`; journald/flash budgets; broker
credentials + ACLs; authenticated lexa-api; refreshed toolchain and
dependencies; monolith `csip-tls-test/cmd/hub` + forks + deprecated GUI
deleted (−5k LOC); dead `SetCSIPPrograms` path removed; bus message
version/schema envelope introduced; stock-timing Mayhem campaign baselined.

**Dependencies.** None. Start immediately.

**Technical debt removed.** D1, D2, D3, D5, D7, D10; Top-20 items 1, 2, 5,
6 (partial: broker+API), 8, 11, 15 (partial: dead path), 18.

**Engineering risks.**
- Dependency refresh (paho, x/crypto, Go 1.22+) can subtly change MQTT
  reconnect or TLS behavior → gate with full Mayhem campaign + the
  mqtt-broker-restart/latency scenarios specifically.
- Deleting the monolith may break stray imports/scripts → grep-audit task
  includes a build of every binary and `scripts/*.sh` reference sweep.
- Watchdog too aggressive → a wedged-but-recovering service flaps; choose
  `WatchdogSec` ≥ 4× tick, soak on bench for 48 h before calling done.
- Broker ACLs: a missed topic permission silently drops a control path →
  Mayhem full campaign is the gate; ACL file mirrors `internal/bus/topics`.

**Rollback strategy.** Pure-process items (CI, commits) need none. Auth and
watchdog changes ship as config/unit-file changes, revertible per service
by git revert + redeploy (`deploy-hub-pi.sh` takes no on-target backups —
adding one is backlogged). Dependency refresh is one revertible commit per
repo.

**Exit criteria.**
- CI green on both repos, required for merge; branch protection on `main`.
- `git status` clean in both repos; review finding D10 closed.
- Full FAST campaign ≤ baseline; first STOCK campaign recorded and triaged
  (STOCK failures become tracked findings, not phase blockers, unless they
  reveal safety regressions).
- Bench services all running with `WatchdogSec` + ACL'd broker.

---

## Phase 1 — Shared protocol modules (R2)

**Tasks:** TASK-019 … TASK-024 · **Duration:** ~5 weeks (parallel with early
Phase 2) · **Effort:** ~70 h

**Purpose.** Kill the MTR-4 divergence bug class permanently: one
`sunspec`/`derbase`-layout codec, one `ocppserver`, one 2030.5 model, shared
by product and sims via a versioned module (`go.work` during development).

**Expected outcome.** New shared module(s) under `~/projects/lexa-proto`
(name decided in TASK-019's ADR); both repos import it; the in-repo
duplicates and the already-diverged sim fork are deleted; CI enforces both
repos pin the same module version.

**Dependencies.** P0 CI (the divergence gate lands there first as a raw
diff check, upgraded here to version pinning).

**Technical debt removed.** D4; Top-20 item 4. Kills the W3 weakness.

**Engineering risks.**
- The forks have *already diverged* (`der1547.go`, `models.go`, `reader.go`;
  `layout.go`/`derlayout.go` product-only). Reconciliation must be a
  reviewed, field-by-field merge with the product side as authority —
  differences may encode real fixes on either side. This is the riskiest
  step of the phase; it gets its own task and a bench validation pass
  against all three sims (self-confirmation caveat noted; golden fixtures
  arrive in P6).
- Module extraction can silently change build flags (CGo taint) — shared
  modules must remain `CGO_ENABLED=0`-clean.

**Rollback strategy.** Extraction is mechanical (`git mv` + import rewrite);
each consumer flips in its own commit and can be reverted independently
while `go.work` keeps old and new importable.

**Exit criteria.** Both repos build from the shared module; `diff -rq`
between repos finds no duplicated protocol packages — with **one documented
exception** (TASK-082, AD-003(f)): `csip-tls-test/internal/csipref/{discovery,scheduler}`
is a deliberate, one-repo-only referee implementation of the CSIP client-side
walk/evaluate logic, kept independent of lexa-hub's own walker/scheduler for
conformance value (no lexa-hub counterpart exists to diff against — this is
not a duplicated pair, it's a single-sided reference implementation). Every
other protocol-semantics fork (SunSpec codec, derbase, OCPP CSMS, 2030.5
model) has zero duplicates; Mayhem full campaign + `sim/modsim-conformance`
(all three device types) + CSIP conformance logic tests green; MTR-4
lockstep note in both CLAUDE.md files replaced by the CI rule.

---

## Phase 2 — Device Reconciler (R1)

**Tasks:** TASK-025 … TASK-033 · **Duration:** ~10 weeks · **Effort:**
~120 h + campaign time

**Purpose.** Replace the four uncoordinated convergence mechanisms
(restore-rule re-command spam; `cmdDeduper` + watchdog + breach-reset;
`retryDevice.lastCtrl` reassert; the five-hop CannotComply chain) with one
per-device reconciler owning: write-on-diff, verify-by-readback,
reassert-on-reconnect, escalating retry, non-convergence reporting.

**Expected outcome.** Optimizer output becomes declarative: retained
per-device desired-state documents
(`{ceilingW, setpointW, connect, maxCurrentA, source, mrid, issuedAt, seq}`).
Reconcilers live in `lexa-modbus` (battery, solar, meter-adjacent checks)
and `lexa-ocpp` (EVSE). Legacy mechanisms deleted. CannotComply chain
collapses from five stateful hops to: reconciler emits non-convergence →
hub arbitrates → northbound posts.

**Dependencies.** P0 (CI + the bus envelope design from TASK-017 — the
desired-state document is the first versioned bus schema; TASK-018's full
rollout is not a blocker). P1 not strictly required but avoids doing codec
work twice.

**Migration order (fixed).** Battery first (Tier-0 interlock as safety
net) → solar → EVSE. Each device class: dual-run (reconciler consumes the
new retained desired-state topic while legacy command topics still flow;
readback-compare logged, not enforced) → flip optimizer publishing for that
class → campaign → next class. Legacy deletion only after all three classes
flip and a full campaign holds baseline.

**Technical debt removed.** D11 (chain), the W2 structural flaw; Top-20
item 3. Sets up R4.

**Engineering risks (the highest of the roadmap until P5).**
- Every legacy mechanism encodes a QA scenario. The behavior-preservation
  ledger in TASK-025 lists each guard → scenario mapping
  (e.g. breach-triggered dedupe reset ↔ the 2026-07-03 "0 W ceiling ignored
  for 30 s" finding; `lastCtrl` reassert + restore-while-dark ↔
  release-while-rebooting / curtailment-release Mode B; watchdog re-assert ↔
  export-cap-full-battery ghost). The reconciler must pass each named
  scenario **before** its legacy counterpart is deleted.
- Retained desired-state inherits the retained-message trust problem (§8.3):
  documents carry `issuedAt` + `seq` from day one; staleness policy defined
  in TASK-025 (full hardening in P3).
- Dual-run double-actuation: during dual-run the reconciler runs in
  **observe/compare mode** (logs divergence, writes nothing) until the flip.

**Rollback strategy.** Feature flag per device class in `modbus.json` /
`ocpp.json` (`"reconciler": "off" | "shadow" | "active"`). Rolling back =
set `off`, restart service; legacy path remains intact until TASK-032.
After TASK-032 (legacy deletion), rollback is git revert + redeploy —
which is why deletion is last and gated on a 10-cycle campaign.

**Exit criteria.** All devices on reconciler; legacy trio deleted; 10-cycle
FAST campaign at ≤ baseline FAIL rate with INV-HUNT clean; STOCK campaign
run; scenarios named in the preservation ledger individually PASS;
`docs/QA_FINDINGS.md` updated.

---

## Phase 3 — Time & persistence (R3 + W5)

**Tasks:** TASK-034 … TASK-043 · **Duration:** ~8 weeks · **Effort:** ~90 h

**Purpose.** One owner for utility time; nothing important dies with the
process or trusts a stale retained message.

**Expected outcome.** `utilitytime` package (offset acquisition, smoothing,
step classification, event-window evaluation, expiry policies) consumed by
walker, scheduler, hub, lexa-api, optimizer — folding `expiryConfirmTicks`,
`csipReportGraceS`, and both clock-regression guards into tested policies.
Local (hub-side) clock-step policy defined and tested. Append-only event
journal (controls adopted, dispatches, breaches, CannotComply — the
utility-facing audit record) with flash-aware rotation; guard/breach-state
snapshot so a restart mid-breach does not re-emit a duplicate CannotComply
"begin"; retained `lexa/csip/control` re-validated on startup (staleness
bound, corrupted-payload re-request path). New Mayhem scenarios land
*with* each mechanism: local-clock-step, power-cut retained rollback,
corrupted retained JSON.

**Dependencies.** P2 (the reconciler changes what state needs snapshotting;
doing persistence first would snapshot soon-to-be-deleted guards). The
`utilitytime` sub-track (TASK-034…038) only depends on P0 and can start
during late P2.

**Technical debt removed.** W4, W5; §8.3, §8.4 risks; Top-20 items 7, 9, 12
(partial).

**Engineering risks.**
- Time code is the most regression-prone area in QA history (the
  clock-jitter saga: four fixes, three services, three days). Mitigation:
  the scheduler's `failclosed_test.go` suite + clock-jitter /
  clock-jump-forward scenarios are the gate for every migration task;
  migrate one consumer per task, never two.
- The default-fallback guard (2026-07-03: hold a still-served unexpired
  event over a resolved DefaultDERControl) is subtle and load-bearing —
  it must be ported into `utilitytime`/scheduler policy verbatim with its
  four tests.
- Journal writes on SD/eMMC: budget writes (batched, size-capped, rotated);
  disk-full scenario (P4) validates behavior when the partition fills.

**Rollback strategy.** `utilitytime` migrations are per-consumer commits.
Journal/snapshot are additive (write-only) until the restore path flips on
via config; restore-on-start ships behind a flag defaulting off for one
campaign cycle.

**Exit criteria.** One time abstraction, five consumers, zero local
grace/debounce constants outside it; power-cut rollback and
corrupted-retained scenarios PASS; restart mid-breach emits no duplicate
CannotComply; journal survives and rotates; full campaign ≤ baseline.

---

## Phase 4 — Observability & QA depth (parallel with P2/P3)

**Tasks:** TASK-044 … TASK-055 · **Duration:** weeks 16–24, parallel ·
**Effort:** ~90 h

**Purpose.** See the system (metrics, structured logs, heartbeat alerting),
bound the tick (async actuator publishes), and close the §9 blind-spot
families that don't require new product mechanisms.

**Expected outcome.** Prometheus `/metrics` on all six services + scrape
config; structured logging with rate caps; plan-heartbeat stall alerting
(consuming the retained `lexa/hub/plan` topic that already exists);
actuator publishes decoupled from the tick (fire-with-timeout,
check-later); fuzzers for `tlsclient.readResponse`, XML decode, bus JSON in
CI; new Mayhem scenarios: duplicate MQTT client ID, disk-full, MQTT
storm/backpressure, `tc netem` packet chaos; generative int16/scale-factor
boundary sweep; guard-threshold dither sweeps; `"NaN"`-string bus JSON
robustness.

**Dependencies.** P0 (CI hosts the fuzzers). Scenario tasks touching
retained-state semantics (power-cut, corrupted-retained) live in P3 with
their mechanisms; the rest are independent of P2/P3 and are the main
parallel track.

**Technical debt removed.** Top-20 items 10, 12 (rest), 14, 20 (setup);
§11 sync-publish risk; §9 identity/value/load families.

**Engineering risks.** Low. Chief hazard: new scenarios producing noisy
verdicts → each new scenario runs 10× solo for verdict stability before
joining the curated set (established Mayhem practice).

**Rollback strategy.** All additive; metrics/logging behind config.

**Exit criteria.** Metrics scraped from all services on the bench; one
full campaign including the new scenarios with stable verdicts; fuzzers
running ≥15 min in nightly CI with zero crashes; tick-overrun counter
exposed and zero under mqtt-latency scenario in FAST mode.

---

## Phase 5 — Optimizer split (R4)

**Tasks:** TASK-056 … TASK-067 · **Duration:** ~12 weeks · **Effort:**
~130 h + campaigns

**Purpose.** Split `optimizer.go` (2,329 lines, 9+ inter-tick guard sites)
into a small formally-testable **constraint controller** (caps, convergence,
CannotComply) above an **economic layer** (TOU, self-consumption,
plan-following), consuming a per-device **plant model** (ramp rate, control
latency, taper) instead of bench-calibrated globals. Multi-device
assumptions (first-EVSE, single-inverter nameplate split, single
`plan.Breach`) removed. Engine state consolidation (R7 remainder).

**Expected outcome.** No orchestrator file >600 lines; guard state
consolidated into one `session` struct per constraint; plant-model
parameters in `modbus.json`-style device config (discovered where
possible); decision-string tests replaced by behavioral/invariant tests;
second inverter + second EVSE on the bench with multi-device Mayhem
scenarios; engine mutexes collapsed to one state struct with single writer.

**Dependencies.** **Hard: P2** (reconciler removes actuation/dedupe
responsibilities from the optimizer — splitting before that means splitting
code that is about to shrink). P3 `utilitytime` (TOU/expiry consumers).
TASK-056 (behavioral tests) blocks all migration tasks.

**Technical debt removed.** W1, D6, §8.1, §8.5; Top-20 items 13, 15 (rest),
16-adjacent.

**Engineering risks (highest of the roadmap).**
- The cascade's *ordering* is semantics: Rules 1→6 + restore + safety
  backstop resolve conflicts implicitly. The constraint controller makes
  priority explicit (safety > compliance > economics); shadow-mode
  (TASK-059) runs both stacks per tick on live bench input and diffs
  decisions for ≥1 week of bench time before any flip.
- Bench-calibrated constants (`socStepEstimate` "20× demo",
  `maxDropW=1500/maxRiseW=500`, `filterAlpha=0.4`) hide the real plant
  model. Converting them to parameters must reproduce identical FAST-bench
  behavior with the bench's plant-model file before any generalization.
- Guard×guard interactions are the dominant historical defect class — the
  per-constraint `session` consolidation is done one constraint at a time,
  full campaign each.

**Rollback strategy.** Old cascade remains the active path during
shadow-mode; flip is per-constraint behind config; final deletion
(TASK-066) gated on 10-cycle FAST + STOCK campaigns and only after M4
sign-off. Until then a git revert restores any single constraint migration.

**Exit criteria.** Shadow-mode diff rate ~0 on accepted scenarios; 10-cycle
FAST and STOCK campaigns ≤ baseline; multi-device scenarios PASS;
`optimizer.go` gone or <600 lines; every plant-model parameter documented
with units and provenance; behavioral test suite is the only orchestrator
test surface.

---

## Phase 6 — Commercialization surface

**Tasks:** TASK-068 … TASK-081 · **Duration:** ~14 weeks (much of it lead
time) · **Effort:** ~110 h

**Purpose.** Everything a paying utility deployment needs that isn't
control-loop code: cert lifecycle, OCPP security, northbound decomposition
and HTTP-client hardening, server-poll-rate compliance, multi-vendor
validation with golden fixtures, scenarios-as-data, 30-day soak,
DST/timezone tests, CSIP curve-function scope decision, V1.0 release gate.

**Dependencies.** P5 for multi-vendor plant-model work; P4 fuzz corpus
feeds the HTTP-client decision (TASK-069); everything else parallelizes.
Long-lead items (vendor hardware, conformance-lab slot) should be
*ordered* during P2–P3.

**Technical debt removed.** D8, D9, D12; Top-20 items 16, 17, 19, 20;
review §10.2/.5, §12 walker findings; W7 remainder (OCPP profile).

**Engineering risks.**
- wolfSSL reconnect churn under cert rotation (§8.6) — the rotation task
  includes a reconnect-storm soak before it's called done.
- Golden vendor fixtures may reveal bilateral codec misunderstandings
  (self-confirmation blind spot) — treat findings as P1 bugs against the
  shared module; this is the point of the exercise.
- Hand-rolled HTTP parser replacement touches the utility-facing boundary —
  decision (shim vs. harden) recorded in 02, gated by fuzz corpus results,
  dual-run against gridsim conformance suite.

**Rollback strategy.** Additive/operational items roll back by config.
The HTTP transport change dual-runs (old fetcher vs. shim) against
conformance before flip.

**Exit criteria.** `09_RELEASE_CHECKLIST.md` fully green — that checklist
*is* this phase's definition of done, including regenerated conformance
evidence (`scripts/run-conformance.sh`) and the M5 campaigns/soak.
