# 01 — Implementation Gameplan: LEXA DERMS V1.0

*Master engineering roadmap. Derived from `ARCHITECTURE_REVIEW.MD` (2026-07-04).
Owner: Principal Engineer. Status: ACTIVE. Update the status table in
`00_MASTER_INDEX.md` as phases complete.*

---

## 1. Overall vision

Turn the LEXA DERMS edge gateway from a **well-shaped, QA-hardened prototype**
into a **commercially deployable product** a utility can depend on, in roughly
12 months, without ever breaking the behaviors the Mayhem QA arc paid for.

The end state (V1.0):

- The six-service distributed topology, unchanged (ADR-0001 stands).
- One explicit **Device Reconciler** owning desired-state convergence per
  device, replacing today's four overlapping ad-hoc mechanisms (review W2/R1).
- One shared, versioned protocol codebase (`sunspec`, `ocppserver`, CSIP
  model) consumed by both product and test bench — the lockstep rule enforced
  by CI, not by a CLAUDE.md sentence (W3/R2).
- One `utilitytime` abstraction owning server-clock offset, step
  classification, event windows, and expiry (W4/R3).
- A split optimizer: a small, formally-testable **constraint controller**
  (caps, convergence, CannotComply) over an **economic layer** (TOU,
  self-consumption), parameterized by a per-device plant model instead of
  bench-calibrated constants (W1/R4).
- Persistence: an append-only compliance event journal + guard-state
  snapshots; restart-safe breach episodes; retained-message trust hardened
  (W5).
- Production operational posture: CI on every PR, systemd watchdogs,
  Prometheus metrics, structured logs, broker ACLs, authenticated APIs, OCPP
  security profile ≥2, cert lifecycle management (review §10, §11).
- Mayhem grown to cover the §9 blind-spot families (persistence/restart,
  local time, identity/topology, value-domain, load/duration), run in **stock
  timing** as a release gate.

## 2. Architectural goals

1. **One owner per concept.** Desired state → Reconciler. Utility time →
   `utilitytime`. Compliance enforcement → constraint controller. Protocol
   codecs → shared modules. Every W1–W7 weakness is a concept with 2–5 owners
   today.
2. **Declarative over imperative actuation.** The optimizer publishes *what
   should be true* (retained desired-state documents); reconcilers next to
   the hardware make it true and report non-convergence.
3. **Safety layering stays intact.** Tier-0 edge interlock (lexa-modbus) →
   Tier-1 fast protection loop (lexa-hub) → Tier-2 economics, per ADR-0001.
   Nothing in this roadmap weakens a tier.
4. **The product ships what QA tested.** Stock-timing campaigns become a
   release gate; wall-clock-denominated thresholds everywhere (already begun
   with `scaleTicks`).
5. **Boring, auditable operations.** Everything a utility's lawyers or a
   due-diligence team asks for — event records, cert lifecycle, CVE process,
   CI history — exists and is machine-produced.

## 3. Migration philosophy

- **Never a flag-day rewrite.** Every structural change follows the ratchet:
  *introduce abstraction → implement new → dual-run/shadow → validate with
  Mayhem → migrate callers → delete legacy → update docs.*
- **Mayhem is the regression oracle.** Full campaign (51+ scenarios) at every
  phase boundary and after any change touching `internal/orchestrator`,
  the scheduler, actuation, or southbound reconnect paths. The verdict
  history (V3 5.0 → V6 0.6 FAIL/cycle) is the baseline; a phase that raises
  the FAIL rate does not merge.
- **Device-by-device, battery first.** The battery has the Tier-0 interlock
  as an independent safety net, so it absorbs migration risk best.
- **Preserve hardened behavior by name.** Every guard being replaced is
  listed in the replacing task's "behavior to preserve" section with the QA
  scenario that created it. Deleting a guard without naming its scenario is a
  review-blocking offense (see `05_ENGINEERING_PRINCIPLES.md`).
- **Every phase leaves the project releasable**: compiles, passes
  `make test-fast` / `go test -race`, passes conformance logic tests, passes
  a full Mayhem campaign at its exit gate.

## 4. Guiding principles (summary — full text in 05)

- Small PRs on short-lived branches; nothing lives uncommitted overnight.
- Tasks sized 2–8 h, self-contained, executable by a smaller coding model.
- Behavioral/invariant tests over decision-string assertions.
- Lockstep changes (register maps, bus schemas) ship in one session, both
  repos, enforced by CI.
- Bench constants are debt: every new constant needs either a config knob, a
  plant-model parameter, or a comment justifying why it is universal.

## 5. Project priorities (strict order)

1. **Safety invariants** — INV-SOC, INV-CONNECT, INV-EXPORT, INV-EXPIRED,
   INV-EVMAX, INV-HUNT, INV-CONVERGE (the seven in
   `cmd/dashboard/invariants.go`), battery reserve protection, fail-closed
   CSIP.
2. **Process safety** — CI, commit discipline, watchdogs (cheap, prevents
   losing #1 work).
3. **Structural debt with active bug production** — W2 convergence (R1),
   W3 duplication (R2), W4 time (R3).
4. **Productization surface** — persistence, observability, authz, certs.
5. **Optimizer redesign (R4)** — only after R1 shrinks its responsibilities.
6. **Commercial validation** — multi-vendor, conformance lab, soak.

## 6. Risk management

Full register: `08_RISK_REGISTER.md`. The load-bearing mitigations:

- **Optimizer is radioactive** (review §8.1): until Phase 5 completes, any
  `optimizer.go` change requires a full Mayhem campaign. No exceptions.
- **Dual-run before delete**: R1 and R4 both run new-next-to-old with
  compare/shadow modes before any legacy path is removed.
- **Rollback**: every phase defines a rollback in `03_REFACTOR_PHASES.md`;
  feature flags gate new actuation paths. Note: `deploy-hub-pi.sh` takes
  **no on-target backups today**, so deploy rollback is git-revert +
  redeploy until a backup step lands (tracked in `10_BACKLOG.md`).
- **Bus factor**: every phase converts tribal knowledge (deploy gotchas,
  FAST/STOCK duality, `bin/dashboard` vs `./dashboard`) into scripts, CI, or
  docs.

## 7. Dependency graph & critical path (summary — full detail in 04)

```
P0 Foundations (CI, commit, watchdogs, authz, deps, dead code)
 ├─→ P1 Shared modules (R2)  ──┐
 ├─→ P2 Device Reconciler (R1)─┼─→ P5 Optimizer split (R4) ─→ P6 Commercialization
 └─→ P3 Time & persistence ────┤                                   (certs, OCPP sec,
      P4 Observability & QA depth (parallel with P2/P3)              multi-vendor, soak,
                                                                     conformance evidence)
```

**Critical path:** P0 → P2 (R1 Reconciler) → P5 (R4 optimizer split) → P6
multi-vendor validation. Everything else parallelizes around it.

## 8. Estimated timeline

| Phase | Calendar | Engineering effort |
|---|---|---|
| P0 Foundations | Weeks 0–5 | ~90 h |
| P1 Shared modules (R2) | Weeks 4–9 | ~70 h |
| P2 Device Reconciler (R1) | Weeks 6–16 | ~120 h + campaigns |
| P3 Time & persistence (R3, W5) | Weeks 14–22 | ~90 h |
| P4 Observability & QA depth | Weeks 16–24 (parallel) | ~90 h |
| P5 Optimizer split (R4) | Weeks 24–36 | ~130 h + campaigns |
| P6 Commercialization | Weeks 34–48 | ~110 h + lab/lead time |
| **Total** | **~11–12 months** | **~700 h focused work** |

(The ~700 h includes campaign attendance, deploys, and triage overhead;
`04` §1's ~495 h is the sum of per-task S/M/L implementation effort only.)

Calendar > effort because Mayhem campaigns (~45 min fast, hours stock,
10-cycle overnight), soak runs (weeks of wall clock), vendor hardware
lead times, and conformance-lab scheduling dominate elapsed time.

## 9. Engineering milestones

- **M0 (end P0): "Institutional process exists."** CI green on both repos,
  zero uncommitted work, watchdogs live, broker/API authenticated, monolith
  deleted, stock-timing baseline campaign recorded.
- **M1 (end P1): "One codec."** Shared `sunspec`/`ocppserver`/CSIP-model
  modules consumed by both repos; forks deleted; CI divergence gate green.
- **M2 (end P2): "One convergence mechanism."** All three device classes on
  the Reconciler; `cmdDeduper` / restore-spam / `lastCtrl` / breach-reset
  deleted; full campaign ≤ V6 baseline FAIL rate.
- **M3 (end P3+P4): "Restart-safe and observable."** Event journal +
  snapshots live; power-cut/corrupted-retained Mayhem scenarios pass;
  metrics + heartbeat alerting deployed; fuzzers in CI.
- **M4 (end P5): "Reviewable safety core."** Constraint controller ≤600-line
  files, plant-model parameters, behavioral test suite, second
  inverter/EVSE scenarios passing.
- **M5 (end P6): "V1.0 gate."** `09_RELEASE_CHECKLIST.md` fully green:
  cert lifecycle, OCPP security profile, multi-vendor fixtures, 30-day soak,
  regenerated conformance evidence.

## 10. Definition of done (project level)

V1.0 ships when:

1. Every item in `09_RELEASE_CHECKLIST.md` is checked with linked evidence.
2. Two consecutive 10-cycle Mayhem campaigns — one FAST, one STOCK — with
   0 FAIL / 0 BLIND and only accepted-by-design DEGRADEDs.
3. 30-day soak with flat RSS/fd/goroutine trends and zero watchdog fires.
4. All review items D1–D12, R1–R7, W1–W7, §9 blind spots, and Top-20 actions
   are traceable to a merged task or an explicit, documented de-scope
   (recorded in `07_QA_GAP_PLAN.md` §deferred or `10_BACKLOG.md`; structural
   de-scopes additionally get an AD in `02_ARCHITECTURE_DECISIONS.md`).
   Traceability matrix: `04_DEPENDENCY_GRAPH.md` §5.
