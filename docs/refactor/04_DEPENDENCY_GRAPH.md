# 04 — Dependency Graph & Task Inventory

*Single source of truth for task IDs, ordering, and blocking relationships.
One row per task file in `tasks/`. "Blocks" lists direct dependents only.*

Effort: S ≈ 2–3 h, M ≈ 4–6 h, L ≈ 6–8 h. Risk: how likely the task is to
regress protected behavior (not how hard it is).

---

## 1. Task inventory

### Phase 0 — Foundations

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 001 | Commit residual work; branch/PR workflow; hosting decision | both | S | low | — |
| 002 | CI pipeline: lexa-hub (build, vet, `-race` tests) | hub | M | low | 001 |
| 003 | CI pipeline: csip-tls-test (build, test-fast, conformance logic) | test | M | low | 001 |
| 004 | CI lockstep-divergence gate (shared-package diff) | both | S | low | 002,003 |
| 005 | `govulncheck` + dependency audit in CI | both | S | low | 002,003 |
| 006 | Toolchain/dependency refresh (Go ≥1.22, x/crypto, x/net, paho) | both | L | med | 002,003,005 |
| 007 | systemd `WatchdogSec` + `sd_notify` for lexa-hub | hub | M | med | — |
| 008 | Watchdogs for the other five services | hub | M | med | 007 |
| 009 | journald rate/size caps + flash wear budget | hub | S | low | — |
| 010 | Delete monolith `cmd/hub` + forked orchestrator/bridge/adapters + `sim/orchestrator` + `battery/metrics.go` (bench `internal/csip`/`tlsclient`/southbound drivers STAY — live sim/conformance deps; see TASK-010 keep-list and TASK-082) | test | M | low | 003 |
| 011 | Delete `gui/sim_gui.py`, `sim_*.txt`; doc cleanup | test | S | low | — |
| 012 | Delete `SetCSIPPrograms`/`e.sched` dead dual path | hub | M | med | 002 |
| 013 | Mosquitto per-service credentials + ACLs | hub | L | med | — |
| 014 | lexa-api auth (token+TLS) + migrate consumers (dashboard, metersim, mayhem) | both | L | med | 013 |
| 015 | Stock-timing Mayhem release gate (script + first STOCK baseline) | test | M | low | — |
| 016 | QoS doc/code alignment (D5): per-topic QoS policy | hub | S | low | — |
| 017 | Bus message envelope: `v` field + schema-check design (shared types) | hub | M | low | 002 |
| 018 | Bus envelope rollout: all publishers/subscribers, reject-and-alarm | both | L | med | 017 |

### Phase 1 — Shared protocol modules (R2)

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 019 | Module-extraction ADR + `lexa-proto` skeleton + `go.work` | new | M | low | 001 |
| 020 | Reconcile + extract `sunspec`/derbase layouts; lexa-hub consumes | hub,new | L | **high** | 019 |
| 021 | Sims consume shared sunspec; delete sim fork; bench validation | test | L | med | 020 |
| 022 | Extract `ocppserver` into shared module; both repos consume | both | M | med | 019 |
| 023 | Extract 2030.5 CSIP model into shared module | both | L | med | 019 |
| 024 | CI: shared-module version-pinning gate (replaces raw diff in 004) | both | S | low | 020–023 |

### Phase 2 — Device Reconciler (R1)

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 025 | Desired-state schema ADR + bus types + behavior-preservation ledger | hub | L | low | 017 |
| 026 | Reconciler core library (pure logic + unit tests) | hub | L | low | 025 |
| 027 | Battery reconciler in lexa-modbus: shadow mode (observe/compare) | hub | L | med | 026 |
| 028 | Flip battery: optimizer publishes desired state; campaign | hub | L | **high** | 027 |
| 029 | Migrate solar/inverter to reconciler (shadow → flip) | hub | L | **high** | 028 |
| 030 | Migrate EVSE reconciler into lexa-ocpp (shadow → flip) | hub | L | **high** | 028 |
| 031 | Non-convergence → CannotComply chain collapse (5 hops → 3) | hub | L | med | 028 |
| 032 | Delete legacy: `cmdDeduper`, restore re-command spam, `lastCtrl`, breach-reset | hub | L | **high** | 029,030,031 |
| 033 | Mayhem reconciler updates + 10-cycle sign-off campaign | test | M | low | 032 |

### Phase 3 — Time & persistence (R3 + W5)

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 034 | `utilitytime` package core (offset, smoothing, step classification, windows) | hub | L | low | — |
| 035 | Migrate walker + scheduler onto `utilitytime` (guards ported verbatim) | hub | L | **high** | 034 |
| 036 | Migrate hub `expiryConfirmTicks`, api `csipReportGraceS`, optimizer TOU | hub | L | med | 035 |
| 037 | Local (hub-side) clock-step policy + implementation | hub | M | med | 034,035,036 |
| 038 | Mayhem: local clock-step scenario | test | M | low | 037 |
| 039 | Event journal: schema + append-only writer + flash-aware rotation | hub | L | low | — |
| 040 | Journal integration: adoptions, dispatches, breaches, CannotComply | hub | M | med | 039, 031 |
| 041 | Guard/breach-state snapshot + restore-on-start (flagged) | hub | L | med | 040 |
| 042 | Retained-control trust hardening (staleness bound, corrupt→re-request) | hub | M | med | 034 |
| 043 | Mayhem: power-cut retained rollback + corrupted-retained scenarios | test | L | low | 042 |

### Phase 4 — Observability & QA depth (parallel track)

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 044 | Prometheus `/metrics` on all six services + bench scrape | hub | L | low | — |
| 045 | Structured logging + plan-heartbeat stall alerting | hub | M | low | 044 |
| 046 | Async actuator publishes; tick time budget + overrun counter | hub | L | med | — |
| 047 | Fuzz `tlsclient.readResponse` + response size caps | hub | L | med | 002 |
| 048 | Fuzz XML decode + bus JSON decode (both repos, CI nightly) | both | M | low | 002,003 |
| 049 | Mayhem: duplicate MQTT client-ID scenario | test | M | low | — |
| 050 | Mayhem: disk-full scenario | test | M | low | — |
| 051 | Mayhem: MQTT storm / backpressure scenario | test | M | low | — |
| 052 | Bench `tc netem` packet-chaos harness + scenarios | test | L | low | — |
| 053 | Generative int16/scale-factor boundary sweep test | both | L | med | 021 |
| 054 | Guard-threshold dither sweeps (SoC@reserve, export@breach) | test | M | low | — |
| 055 | `"NaN"`-string bus JSON robustness + test | hub | S | low | 018 |

### Phase 5 — Optimizer split (R4)

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 056 | Convert decision-string tests → behavioral/invariant tests | hub | L | low | 033 |
| 057 | Plant-model types + per-device config schema (ramp, latency, taper) | hub | L | low | 033 |
| 058 | Constraint-controller package skeleton (priority: safety>compliance>economics) | hub | L | low | 056,057 |
| 059 | Shadow-mode dual-run harness (old cascade vs new stack, decision diff) | hub | L | med | 058 |
| 060 | Migrate export-limit constraint (+ its convergence session) | hub | L | **high** | 059 |
| 061 | Migrate import + generation constraints | hub | L | **high** | 060 |
| 062 | Per-constraint `session` structs: consolidate remaining guard state | hub | L | **high** | 061 |
| 063 | Economic layer isolation (TOU/self-consumption/planner below constraints) | hub | L | med | 062 |
| 064 | Bench constants → plant-model parameters (identical-behavior proof) | hub | L | **high** | 057,063 |
| 065 | Bench: second inverter + second EVSE; multi-device scenarios; multi-breach | both | L | med | 062,018 |
| 066 | Delete legacy cascade; enforce <600-line orchestrator files | hub | M | **high** | 063,064,065 |
| 067 | Engine state consolidation: one state struct, single writer (R7 rest) | hub | M | med | 066 |

### Phase 6 — Commercialization

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 068 | Northbound decomposition: walk/publishers/responses/flow-reservations packages | hub | L | med | — |
| 069 | HTTP client: `net.Conn` shim under `http.Transport` vs hardened parser (ADR + impl) | hub | L | **high** | 047,068 |
| 070 | Context propagation walker-deep | hub | M | low | 068 |
| 071 | Honor server-advertised poll intervals; conditional walk | hub | M | med | 068 |
| 072 | Cert expiry monitoring + alerting | hub | M | low | 044 |
| 073 | Cert rotation without control interruption + reconnect-churn soak | hub | L | **high** | 072 |
| 074 | OCPP security profile 2 (TLS + BasicAuth); evsim counterpart | both | L | med | 022 |
| 075 | Golden vendor register fixtures + third-party SunSpec referee | both | L | med | 021 |
| 076 | Mayhem scenarios-as-data: spec schema + engine (R6) | test | L | low | — |
| 077 | Migrate 51 scenarios to declarative specs | test | L | med | 076 |
| 078 | 30-day soak rig: RSS/fd/goroutine trends + chaos background | test | L | low | 044,052,008 |
| 079 | DST / timezone / leap-smear TOU boundary tests | hub | M | med | 036 |
| 080 | CSIP curve-functions scope ADR (volt-var/volt-watt: implement or de-scope) | hub | M | low | — |
| 081 | V1.0 release-gate execution (checklist, conformance evidence, campaigns) | both | L | low | all |

### Phase 1 addendum

| ID | Title | Repo(s) | Effort | Risk | Depends on |
|---|---|---|---|---|---|
| 082 | Bench fork endgame: re-point `sim/modsim-client` + southbound driver forks to `lexa-proto`; delete bench `derbase`; AD on the bench `csip/{discovery,scheduler}` forks (keep-as-referee or extract) | test | L | med | 020,021,023 |

**82 tasks · ~495 h summed task effort** (campaign/soak wall-clock excluded;
`01` §8's ~700 h additionally includes campaign attendance, deploys, and
triage overhead — the two figures measure different things and are both
correct).

---

## 2. Critical path

```
001 → 002/003 → 017 → 025 → 026 → 027 → 028 → 029/030 → 031 → 032 → 033
    → 056/057 → 058 → 059 → 060 → 061 → 062 → 063/064/065 → 066 → 067
    → 081
```

That is: process foundations → bus envelope → Reconciler (battery → all →
delete legacy) → optimizer split (shadow → per-constraint → delete) →
release gate. Everything else hangs off this spine.

## 3. Safe parallelization

- **Track A (critical path):** as above — one engineer/agent owns it end
  to end; it serializes on Mayhem campaigns.
- **Track B (P0 operational):** 007–009, 013–016 are independent of Track A
  and largely of each other (exceptions: 008 depends on 007; 013→014).
- **Track C (shared modules):** 019–024 parallel to P2 shadow work; merge
  before 029 to avoid codec double-touch.
- **Track D (P4 observability/QA):** 044–055 all parallel; only 053 waits
  on the shared sunspec module, 055 on the envelope.
- **Track E (P3 time):** 034–038 can start during late P2; 039–043 wait for
  031.
- **Track F (P6 long-lead):** order vendor hardware + conformance-lab slot
  during P2; 068/070/071/076/080 any time after P0.

**Never parallelize:** two tasks that both touch `internal/orchestrator`
or the scheduler in the same window — campaign attribution becomes
impossible. The critical path serializes those by construction; note that
**063 → 064 → 065 also serialize** (all three touch the orchestrator)
even though the §2 diagram draws them as one bundle.

## 4. Highest-risk dependencies

1. **028→032 (reconciler flips → legacy deletion).** Deleting the legacy
   convergence trio before every preservation-ledger scenario passes on the
   reconciler is the single most dangerous move available. Gate: 10-cycle
   campaign per flip.
2. **020 (sunspec fork reconciliation).** Already-diverged code where either
   side may hold the real fix; a wrong merge misreads hardware (MTR-4
   recurrence) *bilaterally invisibly* until 075's golden fixtures.
3. **059→066 (shadow → delete cascade).** Ordering semantics of Rules 1→6
   are implicit; shadow-diff must run ≥1 week bench time including one full
   campaign before each flip.
4. **006 (dependency refresh)** early and alone: paho upgrade changes
   reconnect semantics under the very scenarios (broker restart/latency)
   that protect everything else. Do it before 025+, never during P2.
5. **073 (cert rotation)** exercises wolfSSL free/reconnect paths (§8.6
   segfault risk) — soak on bench, never first on a customer SOM.

## 5. Review-item traceability

| Review item | Tasks |
|---|---|
| W1 / R4 / D6 / §8.1 / item 13 | 056–067 |
| W2 / R1 / D11 / item 3 | 025–033 |
| W3 / R2 / D1 / D4 / items 4 | 010, 019–024, 082 |
| §14 item 2 (CI both repos) | 002, 003 |
| W3 CI gate (P0 half) | 004 |
| W4 / R3 / item 7 | 034–038, 079 |
| W5 / §8.3 / item 9 | 039–043 |
| W6 / D3 / item 15 | 012, 067 |
| W7 / §10.1 / item 6 | 013, 014, 074 |
| D2 | 011 |
| D5 | 016 |
| D7 / §10.4 / item 8 | 005, 006 |
| D8 / R6 / item 19 | 076, 077 |
| D9 / §10.2 / R5 / item 17 | 047, 068–071 |
| D10 / item 1 | 001 |
| D12 / R5 | 068, 070 |
| §8.4 (local clock) / §9 time family | 037, 038, 079 |
| §8.5 (single-device) | 065 |
| §8.6 (wolfSSL churn) | 073 |
| §9 self-confirmation / item 16 | 075 |
| §9 persistence family / item 12 | 042, 043, 050 |
| §9 identity family | 049 (MQTT client-ID member; duplicate Modbus unit-ID and second-meter members deferred — see 07 §deferred + 10_BACKLOG) |
| §9 value-domain family | 053, 054, 055 |
| §9 load/duration family / item 20 | 051, 052, 078 |
| §9 tests-verify-implementation | 056 |
| §11 watchdog / item 5 | 007, 008 |
| §11 sync publish waits | 046 |
| §11 flash wear | 009, 039 |
| §12 walker poll rates | 071 |
| §13 stock-timing hole / item 11 | 015, 081 |
| §10.3 XML robustness | 048 |
| §10.5 cert lifecycle | 072, 073 |
| §10.6 crash-only design doc | 045 (documented), 041 |
| item 14 (metrics/alerts) | 044, 045 |
| item 18 (bus versioning) | 017, 018, 055 |
| §15 curve-function scope | 080 |

No review recommendation is unassigned. De-scopes are recorded in
`07_QA_GAP_PLAN.md` §"Explicitly deferred" and `10_BACKLOG.md` (both count
as the program's de-scope record); *structural* de-scopes (changes to what
V1.0 claims to be) additionally require an AD in
`02_ARCHITECTURE_DECISIONS.md`.
