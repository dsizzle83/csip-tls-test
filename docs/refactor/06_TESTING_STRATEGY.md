# 06 — Testing Strategy

*Map of every test layer, what it proves, what it cannot see, and what the
roadmap adds. QA blind-spot work items are detailed in `07_QA_GAP_PLAN.md`.*

---

## 1. The test pyramid as it exists today

| Layer | Where | Runs | Proves |
|---|---|---|---|
| Unit (product) | `lexa-hub` `go test -race ./internal/...` | dev, (CI from TASK-002) | Optimizer rules, scheduler fail-closed, convergence checkers, codecs — I/O-free by design |
| Unit (bench) | `make test-fast` (<1 s), `go test ./internal/southbound/...` | after every change | Sim world model, register codecs, harness logic |
| Protocol logic | `go test ./tests/` (csip-tls-test) | dev | 2030.5 discovery, MUP, conformance logic |
| Integration | `make test-integration` (amd64 wolfSSL sysroot) | desktop | Real mTLS handshakes, cipher pinning |
| Conformance | `scripts/run-conformance.sh`, `sim/conformance`, `sim/modsim-conformance` | pre-release/demo | CSIP layers 1–3, SunSpec register behavior per device type |
| **Mayhem HIL** | `scripts/mayhem.py`, dashboard `/api/qa/*` | campaign (~45 min FAST; 10-cycle overnight) | 51 hostile scenarios + 7 cross-cutting invariants (INV-SOC, -CONNECT, -EXPIRED, -EVMAX, -HUNT, -EXPORT, -CONVERGE — `cmd/dashboard/invariants.go`); ground truth from sim `/state`, not the hub's view |
| Bench replay | `cmd/dashboard/replay.go` | ~20 h | 92-day cost/compliance against real sims with warped CSIP clock |
| Manual | run-demo skill, dashboards | demos | End-to-end sanity |

**Strengths to preserve:** invariant-based HIL verdicts; mutation-verified
safety tests; per-fix regression tests tagged with scenario IDs; ground
truth independent of the hub.

**Known weaknesses (from review §9/§13):** self-confirmation (sim and
product codecs share lineage); FAST-only campaigns while the product ships
STOCK; single-fault app-layer injection; decision-string assertions in
optimizer tests; no soak, no packet-level chaos, no restart-unclean tests.

## 2. Target state per layer

### Unit
- CI on every PR (TASK-002/003), `-race`, plus `govulncheck` (005) and
  nightly fuzz jobs (047/048).
- Orchestrator tests migrate to **behavioral assertions** (TASK-056):
  assert published desired state / measured-effect expectations /
  invariants, not decision strings — precondition for R4.
- New pure components (reconciler core 026, `utilitytime` 034, constraint
  sessions 062) arrive with exhaustive table-driven tests; time-dependent
  logic takes an injected clock.

### Integration
- Keep wolfSSL handshake suite; add reconnect-churn soak (073) and the
  HTTP client dual-run harness (069).
- Shared-module extraction (P1) must keep conformance suites green at every
  step — they are the codec regression net until golden fixtures land.

### Mayhem (the regression oracle)
- **Campaign gates:** full FAST campaign at every phase exit and for any
  radioactive-zone PR; 10-cycle campaign before each legacy deletion
  (032, 066); STOCK campaign at M0 baseline and every release (015, 081).
- **Baseline to defend:** V6 = 0.6 FAIL/cycle, 0 BLIND; accepted DEGRADEDs
  enumerated in the V5/V6 reports. A phase may not raise the FAIL rate.
- **New scenario families** (P3/P4, detail in 07): power-cut retained
  rollback, corrupted retained payload, disk-full, duplicate client ID,
  local clock step, MQTT storm, netem packet chaos, dither sweeps.
- New scenarios run 10× solo for verdict stability before joining the
  curated set; "expected-FAIL pins the gap" is an accepted pattern
  (meter-ct-inverted precedent).
- Scenarios-as-data (076/077) removes the rebuild-redeploy trap.

### Conformance
- Regenerate full evidence at M0 (post-dependency-refresh), M2, M4, and
  V1.0 (081). The suite doubles as the pre-audit for third-party
  certification (P6).

### Hardware / vendor truth
- Golden register fixtures captured from ≥2 real vendor inverters + ≥1
  EVSE, replayed byte-exact against the shared codec, plus a third-party
  SunSpec implementation as referee (075) — the only cure for
  self-confirmation.
- Second inverter + second EVSE on the bench (065) to kill single-device
  assumptions.

### Soak & load
- 30-day bench soak with RSS/fd/goroutine trend capture and background
  netem chaos (078); MQTT storm behavior vs `max_queued_messages 1000`
  (051); tick-overrun counter under broker latency (046).

## 3. Missing coverage → new tests required (summary)

| Gap (review §9/§11/§13) | New coverage | Task |
|---|---|---|
| Unclean broker death / stale retained resurrection | Mayhem power-cut scenario + staleness bound | 042, 043 |
| Corrupted retained JSON → control-less forever | re-request path + scenario | 042, 043 |
| Local clock step | `utilitytime` policy + scenario | 037, 038 |
| DST/leap over TOU boundary | timezone table tests | 079 |
| Duplicate client ID / topology errors | scenario | 049 |
| int16/scale-factor boundaries | generative sweep vs shared codec | 053 |
| Threshold dither (SoC@reserve, export@breach) | sweep scenarios | 054 |
| `"NaN"` string in bus JSON | decoder hardening + test landed (055, DONE) | 055 |
| Hostile HTTP bytes | fuzz + size caps | 047 |
| Valid-namespace garbage XML / bus JSON | fuzz landed (048, DONE); no gate widening — see finding below | 048 |
| Disk full | scenario | 050 |
| Packet loss/reorder (all faults are app-layer today) | netem harness | 052 |
| Soak / resource trends | 30-day rig | 078 |
| STOCK timing never validated | release-gate campaign | 015 |
| Sim/product self-confirmation | golden fixtures + referee | 075 |

**TASK-048 findings (fuzz landed, gates NOT widened — reported per 05 §7/§3
"do not invent assertions the code doesn't have"):**
- `Time.CurrentTime` (2030.5 `/tm`) is an unbounded int64 with no
  plausibility gate anywhere in lexa-hub's walker/scheduler; a
  namespace-valid-but-garbage value decodes cleanly and feeds
  `ClockOffset` (and therefore every `scheduler.Evaluate` `serverNow`)
  ungated. Candidate input to TASK-018/025 gate widening — see
  `07_QA_GAP_PLAN.md`.
- csip-tls-test's `internal/csipref/scheduler` (the independent referee,
  AD-003(f)) has **no** equivalent of lexa-hub's `plausibleControl`/
  `plausibleLimit`/`maxPlausibleLimitW` at all — an implausible
  `OpModXxxLimW` that the product would reject decodes and would be applied
  unfiltered by the referee. This is a real asymmetry between the twins,
  not fixed here (scheduler is out of scope for a fuzz-only task and adding
  a gate would blur the referee's deliberate independence) — filed as a W3
  finding for whoever next touches `internal/csipref/scheduler`.
- The documented CLAUDE.md/architecture-review §10.3 hazard ("root element
  missing xmlns unmarshal silently yields zero-value structs") does not
  currently reproduce as *silent* (no error) for any of today's csipmodel
  root types: encoding/xml returns a non-nil error whenever a
  namespace-qualified `XMLName` tag doesn't match, and the affected part of
  the struct stays zero. The fuzz targets in both repos assert this
  (`assertRootMatches`) as a regression tripwire against a future csipmodel
  type omitting its namespace tag — see the fuzz_test.go doc comments in
  both repos for the empirical detail.

## 4. Regression strategy going forward

1. **Every fix ships with its regression test** tagged
   `// QA <scenario/finding>` (existing culture, now enforced in review).
2. **The preservation ledger** (TASK-025) maps each legacy guard to its
   originating scenario; those scenarios individually gate the guard's
   replacement — behavior survives even when code doesn't. It now exists:
   `docs/refactor/PRESERVATION_LEDGER.md` (11 rows, AD-013).
3. **Campaign evidence is versioned:** every campaign report lands in
   `docs/` (existing `qa-mayhem-*`/`QA_REPORT_*` pattern) and phase-exit
   reports are referenced from `00_MASTER_INDEX.md` status.
4. **Verdict-drift watch:** accepted DEGRADEDs are enumerated; a new
   DEGRADED signature is a finding, not noise.
5. **Never weaken an oracle to pass a run.** Harness margins may be tuned
   only with a physical justification written into the scenario (the
   HoldS-adjustment precedents), never to mask a product gap — pin gaps
   with expected-FAIL scenarios instead.
