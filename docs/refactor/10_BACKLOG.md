# 10 — Backlog (valuable, not on the critical path)

*Things V1.0 does not need but V1.x/V2 will. Reviewed at phase boundaries;
promote by giving an item a TASK number and a row in 04.*

## Fleet-scale architecture (review §12, §15 due-diligence)
- **Measurement batching:** per-poll-cycle batched measurement messages
  instead of topic-per-device JSON (wrong at hundreds of devices).
- **Topic-scheme v2:** device groups/sites; wildcard ACL design.
- **Poll-loop scaling:** goroutine-per-device policy, `registries sync.Map`
  deletion path (latent leak noted in §11).
- **Fleet management plane:** remote config, remote journal export, OTA
  update strategy for the SOM (a utility will ask at the second site).

## Control & optimization
- **Plant-model discovery:** commissioning-time probe (step a setpoint,
  measure ramp/lag/taper) to auto-fill what TASK-057 configures by hand.
- **Derived socStep (retire the `SOCStepPctPerTickOverride` legacy debt).**
  TASK-064 kept the legacy `socStepEstimate = 1.0 %/tick` as an explicit
  `BatteryPlant.SOCStepPctPerTickOverride` (preserve-first — the derived value
  ≈0.42 %/tick for the bench pack is a real behaviour change the identical-behaviour
  task forbade). Physically it is `MaxChargeW × tickSeconds ÷ (CapacityKWh × 36000)`
  from live `BatteryMetrics` + `BatteryPlant.CapacityKWh` + the engine cadence. After
  real-pack calibration (or the discovery probe above), compute it from the pack
  energy and DROP the override so the SOC-taper handoff tracks the real pack instead
  of the 20×-demo overestimate. Debt marker lives on the field (05 §6); the export
  constraint reads `bp.SOCStepPctPerTickOverride` — swap that one read for the derived
  formula and re-run the golden on-cap parity. Behaviour change → needs its own soak.
- **Volt-var / volt-watt closed-loop CSIP curve dispatch** — de-scoped for
  V1.0 by AD-010 (2026-07-06, TASK-080; survey:
  `docs/refactor/adr-inputs/curve-functions-survey.md`). `derbase` write
  paths already exist and are tested (M705/706 + §3.1.2 adopt handshake) —
  that is the easy ~10% of the bill. Promote to a TASK-0NN (04 owns the ID
  space) only once a market/certification answer requires it (AD-010's
  revisit trigger: before signing a pilot/LOI referencing curve-linked DER
  function sets, or before the certification lab's test scope is
  finalized). Missing-pieces list, with effort estimates, for whoever
  schedules this:
  1. **(S)** Curve fetch/cache is mostly built already — `walker.go` step
     6d already produces `ps.Curves`; make it a first-class dispatch input
     rather than display-only.
  2. **(M)** Scheduler curve resolution in the real-time path:
     `Scheduler.resolve`/`activeEvent` must read `ps.ExtendedControls`/
     `ps.ExtendedDefault`/`ps.Curves` (today they read only the scalar
     `ps.Controls`/`ps.DefaultControl`); `failClosed`'s `lastGood`/`Held`
     copies need to carry curve state through a hold;
     `plausibleControl()` needs a curve-aware validity check (monotonic
     X-values, in-bounds, non-degenerate).
  3. **(M)** Bus schema: a versioned curve payload on `bus.ActiveControl`
     (or a sibling topic) per AD-006's discipline, with `Finite()`-style
     defense-in-depth extended to point arrays (TASK-055 precedent) and a
     size cap (attacker-shaped array data reaching the bus, per
     TASK-047/048's hostile-boundary posture).
  4. **(L, highest-risk hop)** lexa-modbus / reconciler-side adopt
     orchestration: a curve-diff detector (change-detected re-adopt only,
     mirroring TASK-040's dedupe discipline), a call into `derbase`'s
     `adoptCurve` workflow, and a new CannotComply hop on
     `AdptCrvRslt == FAILED` — a sixth axis inside the convergence
     machinery AD-002/AD-013 just finished collapsing from four
     mechanisms to one. Sequence after the P5 constraint-controller
     migration (TASK-060+) has stabilized, not concurrently with it.
  5. **(M)** Adopt retry/timeout handling distinct from scalar-write
     retry (`pollAdoptResult`'s existing best-effort timeout path needs a
     reconciler-level backoff/retry policy on top of it).
  6. **(S-M)** Readback/verify: wire `ReadVoltVar`/`ReadVoltWatt` into a
     periodic verify-against-desired loop, accounting for
     `DefaultRvrtTms` auto-revert on comms loss.
  7. **(L)** Bench sim support: batsim/modsim/metersim implement none of
     SunSpec models 704-710 today (only legacy 1/120/121/103/123/802) —
     needed before closed-loop dispatch can be validated on
     hardware-in-the-loop at all.
  8. **(M)** `modsim-conformance` per-device-type adopt-handshake
     assertions.
  9. **(L)** New Mayhem scenarios: curve-adopt-under-churn, adopt-reject
     (`AdptFailed`), curve+cap interaction with the P5 constraint
     controller — proper plan/state oracles per GAP-14, not
     decision-string assertions.
  10. **(M)** Conformance suite: the curve-related ADV test group (CSIP
      Conformance Test Procedures v1.3) plus actually asserting
      `DERCapabilityFull.ModesSupported`'s relevant bits at registration
      (unused today).

  Tally: 2×S, 5×M, 3×L — several engineer-weeks, not a single-task add-on.
- **Ignored-curve-field alarm (S effort, recommended companion to the
  de-scope, not required for V1.0):** today a curve-bearing
  active/default control is silently dropped to its scalar-only
  representation at `extendedListToSimple`/`extendedDefaultToSimple`
  (`internal/northbound/discovery/walker.go:445-506`) with no log/metric
  distinguishing it from the existing per-walk `countProgramsWithCurves`
  debug count (which only counts programs that merely *have* a curve map,
  not whether the control currently being enforced referenced one). Add a
  log line + metric when the winning `ActiveControl`'s source event/default
  carried a non-empty curve-linked field, so "silently ignored" becomes
  "flagged and ignored" ahead of full implementation.
- **Energy-balance estimator** (would make meter magnitude-drift detectable
  — currently deferred as undetectable in principle, QA_GAPS §4).
- **DP planner revisit:** only if P5 shadow diffs implicate it (AD-007).
- **Multi-site / multi-meter topologies** (second meter appearing is an
  identity-family QA gap; product semantics undefined today).
- **`OptimalChargeWindow` candidate-start generation on a 25-hour fall-back
  day (GAP-05, TASK-079 KNOWN-GAP):** the outer loop tries 24 distinct local
  hour LABELS (0-23) as candidate window starts; on the DST fall-back day
  the repeated local hour (e.g. 01:00 America/Los_Angeles, occurring PDT
  then PST) is ambiguous under `time.Date`, which deterministically resolves
  it to one specific instant — so the *second* occurrence of that hour can
  never itself be a candidate window START (it's still reachable as an
  interior hour of a window that starts earlier, and every schedule we
  could construct prices both occurrences identically since TOU tariffs are
  hour-of-day keyed, so this has never been observed to misprice anything).
  A real fix means walking real instants instead of hour labels for
  candidate generation — bigger than TASK-079's inline-fix blast radius.
  Pinned as `TestTOU_OptimalChargeWindow_DSTBack_RepeatedHourStartAnchor` in
  lexa-hub `internal/orchestrator/costmodel_test.go`. Not urgent:
  `OptimalChargeWindow` has no production caller today.

## Test bench & QA
- **OCPP lifecycle-reorder injector** for evsim (out-of-order
  TransactionEvents, boot-mid-transaction) — next time evsim is opened.
  TASK-074 touched evsim's CSMS-connection flags (SP2 enablement) but not
  its TransactionEvent send path, so this is still open; noted here per
  that task's "revisit when evsim is next touched" trigger.
- **OCPP Security Profile 3 (mTLS)** for the CSMS/evsim link — AD-008 scopes
  TASK-074 to "≥2"; profile 3 would add a charger-presented client cert
  (mutual TLS) on top of the profile-2 TLS+BasicAuth landed there. Evaluate
  whether the incremental identity assurance is worth a second cert-issuance
  flow on the EV link once profile 2 has bench mileage.
- **Matrix/chaos cells for the 2026-07 fault families** (outage, invert,
  netem) once first campaigns show which pairings interact.
- **Second gridsim instance** → DNS-SD flap / wrong-server scenarios.
- **Backward server-clock jump oracle research** (deferred for lack of a
  defensible pass/fail definition).
- **Wedge detection** via hub heartbeat counter in `/status` (the retained
  `lexa/hub/plan` timestamp now exists — build the harness check when
  false-positive risk is characterized).
- **Sim GUI replacement parity audit:** confirm no remaining consumer of
  removed legacy surfaces (post TASK-011).

## Platform & operations
- **On-target deploy backups:** `deploy-hub-pi.sh` currently takes no
  backup before overwriting binaries/configs; add a backup+rollback step
  (until then, rollback = git revert + redeploy).
- **Conditional GET / If-Modified-Since on the northbound walk:** descoped
  from TASK-071 with evidence — gridsim has no 304 support; revisit when a
  real utility server offers it (poll-rate honoring ships in 071).
- **SQLite (or similar) for structured telemetry retention** — revisit
  AD-005 once journal requirements from a real utility contract exist.
- **A/B partition OS updates** on the ConnectCore SOM; watchdog-driven
  boot fallback.
- **Mosquitto bridge/TLS for off-box telemetry** (currently everything is
  localhost-only by design).
- **Metrics long-term storage + fleet dashboards** (bench scrape is P4;
  fleet is not).
- **DevKit return runbook execution** (`lexa-hub/DEVKIT.md`) — repoint
  bench services from hub-Pi 69.0.0.1 back to 69.0.0.2 when hardware returns.
- **lexa-proto hosted-flip** (AD-003(f) checklist): rename the module path
  to `github.com/dsizzle83/lexa-proto`, host it under `dsizzle83`, drop the
  `replace` + `vendor/lexa-proto/` interim vendoring (AD-003(e)) from both
  consumers, and swap `scripts/check-proto-pin.sh`'s ground truth from
  `proto.pin` files to `go.mod` `require` lines. **Human-dependency note:**
  same blocker as `LEXA_HUB_RO_TOKEN`/`CSIP_TLS_TEST_RO_TOKEN` and AD-012
  branch protection — needs a human to create the `dsizzle83/lexa-proto`
  GitHub repo and a fetch credential (PAT-based git credential rewrite or
  SSH deploy-key `insteadOf`) in an environment with `gh`/API auth, which
  this execution environment does not have. Not on the critical path: the
  interim vendoring keeps both repos building and CI-gated today; do this
  when the hosting gap closes, not before.

## Documentation & product
- **Utility-facing compliance report generator** from the event journal
  (journal schema in TASK-039 should anticipate it).
- **Product security whitepaper** (transport crypto, authz model, cert
  lifecycle) for utility procurement questionnaires.
- **Acquisition data room hygiene:** keep campaign evidence, conformance
  reports, and this doc set export-ready (the review was explicitly
  acquisition-flavored).
- lexa-hub integration-tagged tlsclient tests (client_test.go/fetcher_test.go) reference helpers that never existed there (startInProcessServer etc.) — never compiled; port csip-tls-test helpers_test.go or delete the tagged files (TASK-047 finding).
- Ungated Time.CurrentTime + bench csipref scheduler lacks any plausibility gate (TASK-048 findings) — follow-up hardening candidates.
- Ungated Time.CurrentTime + bench csipref scheduler lacks any plausibility gate (TASK-048 findings) — follow-up hardening candidates.
- cmd/telemetry postMeasurements computes serverNow inline for MUP timestamps (6th site, TASK-036 finding) — migrate to utilitytime when telemetry is next touched.
- TASK-041 northbound snapshot half: persist responseTracker.alerted/posted so a NB restart mid-episode does not re-post CannotComply begin (hub half done in 041).
- battery-charge-disabled export-detection latency (~9s vs ~11s window) → adaptive detection window from TASK-057 plant-model controlLatencyS in TASK-064 (R4).
- cmd/hub/state.go is 865 lines (over the 600 soft cap, 05 §1) — split the SystemState reader; deferred from TASK-042 (unscoped refactor).
