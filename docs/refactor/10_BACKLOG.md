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
- **Volt-var / volt-watt closed-loop dispatch** if AD-010 de-scopes it for
  V1.0 (derbase write paths already exist).
- **Energy-balance estimator** (would make meter magnitude-drift detectable
  — currently deferred as undetectable in principle, QA_GAPS §4).
- **DP planner revisit:** only if P5 shadow diffs implicate it (AD-007).
- **Multi-site / multi-meter topologies** (second meter appearing is an
  identity-family QA gap; product semantics undefined today).

## Test bench & QA
- **OCPP lifecycle-reorder injector** for evsim (out-of-order
  TransactionEvents, boot-mid-transaction) — next time evsim is opened.
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
