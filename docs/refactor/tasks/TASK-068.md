# TASK-068 — Northbound decomposition: walk / publishers / responses / flow-reservations packages

*Status: TODO · Phase: P6 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

## Objective
`cmd/northbound/main.go` (831 lines, verified) is decomposed into four
`internal/northbound/` packages — `run` (discovery loop), `publish`
(MQTT publishers), `responses` (responseTracker), `flowres`
(flowReservationManager) — by PURE MOVES with no behavior change, each
package gaining its own unit tests. `main.go` shrinks to wiring
(config, TLS fetchers, MQTT connect, signal handling).

## Background
Verified contents of cmd/northbound/main.go:
- `flowReservationManager` (:52-127): holds a dedicated
  `tlsclient.WolfSSLFetcher`, receives `bus.FlowReservationRequestMsg`
  from MQTT (`bus.TopicCSIPFRRequest`, subscribed at :192-197), POSTs
  `model.FlowReservationRequest` to the utility; `setRequestPath` fed by
  the walk (:307).
- `main()` (:128-236): config, LFDI derivation (`lfdiFromCert`, :640),
  three fetchers (discovery, responses, flow-reservation — the isolation
  comment at :179-181), MQTT subscriptions (FR requests; compliance
  alerts → `respTracker.alertCannotComply`/`clearAlerts`, :203-214),
  discovery ticker goroutine with ctx (:216-229), signal handling.
- `runDiscovery(mc, fetcher, lfdi, sched, rt, frm, cfg)` (:241-309):
  the walk (walker.Discover), clock resync, scheduler Evaluate,
  ActiveControl publish, schedule/pricing/billing/flow-reservation
  publishes, `rt.update(tree, active, superseded)`, `frm.setRequestPath`,
  plus `discoveryFailures` counter (:238-240) and the fail-closed logging.
- Publishers (:323-638): `publishSchedule`, `curveSummary`,
  `publishPricing`, `toTimeTariffMsg`, `publishBilling`,
  `publishFlowReservations`, `toActiveControl`, helpers
  (`unitValueToFloat`, `derefF64`, `apW`, `countProgramsWithCurves`).
- `responseTracker` (:662-830): `responsePoster` interface,
  `alertCannotComply`, `clearAlerts`, `terminalResponse`, `update`
  (tree × active × superseded reconciliation), `completeActive`, `set`,
  `postResponse` — five-hop CannotComply chain's northbound end (reworked
  by TASK-031; read its result first).

Existing homes: `internal/northbound/{discovery,scheduler,model,schedule,
identity,dnssd}` — the new packages sit beside them. Interfaces are
defined where consumed (05 §2): `runDiscovery` consumes a publisher and a
tracker; keep `responsePoster` with `responses`.

## Why this task exists
D12: 831-line god-file mixing four concerns — "hard to test; hard to own."
R5. Also unblocks TASK-069/070/071, which each modify one of these
concerns and should not contend over one file.

## Architecture review sections
D12 · R5 · §13 (onboarding) · 05 §1/§2 · item 17.

## Prerequisites
None (Track F: "any time after P0"). TASK-031's responseTracker rework
should be merged first if in flight — coordinate, never parallel-edit.

## Files
- **Read first:** cmd/northbound/main.go (all of it);
  internal/northbound/discovery/walker.go (Discover signature);
  internal/northbound/scheduler/scheduler.go (Evaluate/ActiveControl);
  internal/bus (message types); any main_test.go/*_test.go under
  cmd/northbound.
- **Modify:** `cmd/northbound/main.go` (shrinks to wiring).
- **Create:** `internal/northbound/run/run.go` (+test),
  `internal/northbound/publish/publish.go` (+test),
  `internal/northbound/responses/tracker.go` (+test),
  `internal/northbound/flowres/manager.go` (+test).

## Blast radius
lexa-northbound binary only (CGo service — build with the wolfSSL sysroot;
`make build-arm64` needs `/tmp/wolfssl-arm64-sysroot`, rebuilt via
`make wolfssl-arm64` after desktop reboots). No bus schema, no config, no
behavior change. Unexported symbols become exported across package lines —
keep the exported surface minimal (only what `run`/main require).

## Implementation strategy
Mechanical extraction in four commits, one package per commit, compiling
and green at each step: (1) `flowres` (most self-contained), (2)
`responses`, (3) `publish` (pure functions — easiest tests), (4) `run`
(pulls the other three together; `discoveryFailures` becomes a field, not
a package var). main.go keeps: config load, wolfssl/tlsclient setup, MQTT
connect, subscription wiring (closures now call into the packages),
ticker + signals.

## Detailed steps
1. Commit 1 — `flowres.Manager`: move type + methods verbatim; constructor
   takes `interface{ Post(...) }`-shaped fetcher (define the consumed
   interface in flowres, satisfied by `*tlsclient.WolfSSLFetcher`); move
   the MQTT-payload decode with it; unit test: handleRequest happy path +
   malformed payload (table, fake poster).
2. Commit 2 — `responses.Tracker`: move `responsePoster`, tracker, and
   `terminalResponse`; unit tests: one-CannotComply-per-episode
   (alert → clear → re-alert), terminal-status table, `update` supersede
   reconciliation (build a minimal ResourceTree fixture).
3. Commit 3 — `publish`: move all publish* + converters as FUNCTIONS
   taking `mqtt.Client` (or a narrow `Publisher` interface defined here)
   + tree/schedule inputs; unit tests assert emitted bus payloads
   (fake client capturing topic/payload/retain/qos) for schedule, pricing,
   billing, FR status, and `toActiveControl` field mapping (incl.
   ClockOffset passthrough).
4. Commit 4 — `run.Discovery`: struct {fetcher, sched, tracker, frm,
   publisher, cfg, failures int}; `RunOnce()` = old runDiscovery body;
   main's goroutine calls it. Keep log lines BYTE-IDENTICAL (operators and
   the Mayhem wan-outage diagnosers grep journals — verify: the
   wan-outage/northbound-hang scenarios read hub state via /status and
   gridsim, but the triage docs quote these lines; don't churn them).
5. main.go audit: ≤150 lines, wiring only; `wc -l` in PR.
6. Full build both arches; deploy to bench; one discovery cycle observed
   (journal shows identical walk logging); run
   `--only wan-outage-hold,wan-outage-expiry,northbound-hang,
   malformed-csip` ×1 as a smoke set.

## Testing changes
New unit tests per package as above (fixtures from
internal/northbound/model test XML where useful). Run:
`cd ~/projects/lexa-hub && make test`. Bench smoke per step 6.

## Documentation changes
- lexa-hub CLAUDE.md directory map: four new packages.
- internal/northbound/CLAUDE.md (exists — verified): add the package
  split note.

## Common mistakes to avoid
- "Improving" behavior mid-move (retry logic, log wording, publish QoS) —
  pure moves only; improvements are 069/070/071's business.
- Breaking the three-fetcher isolation (discovery vs responses vs FR each
  hold their own wolfSSL session — the :179-181 comment; do not share).
- Creating an import cycle: `run` imports publish/responses/flowres/
  discovery/scheduler — nothing imports `run` except cmd.
- Forgetting `wolfssl.Init()` stays exactly once in main() (CLAUDE.md
  invariant).
- Cross-compile: this binary is CGo; test builds with the amd64 sysroot
  (`make test-integration` in csip-tls-test exercises handshakes if
  needed).

## Things that must NOT change
- Walk order and fail-closed discipline (scheduler holds last-known-good;
  `discoveryFailures` counting semantics).
- One-CannotComply-per-episode semantics in the tracker (TASK-031
  behavior; scenario meter-ct-inverted / battery-soc-refuse depend on the
  Response flow).
- Retained ActiveControl publish (retain=true, QoS 1) — hub restart
  reseeding depends on it.
- MQTT topic names / payload shapes (byte-identical).
- Log lines quoted in QA triage docs.

## Acceptance criteria
- [ ] Four packages, each with tests; main.go ≤150 lines of wiring.
- [ ] `make test` green; arm64 + amd64 builds green.
- [ ] Bench smoke: identical walk journal lines; 4-scenario smoke set at
  accepted verdicts.
- [ ] Four commits, each compiling + green (bisectable).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests (csip-tls-test `go test ./tests/`) green —
  protocol-adjacent (walk behavior)
- [ ] Mayhem: targeted smoke set (wan-outage-hold, wan-outage-expiry,
  northbound-hang, malformed-csip); full campaign NOT required (pure move)
- [ ] `hub-replay-tune.sh fast` after deploy

## Mayhem scenarios affected
wan-outage-hold, wan-outage-expiry, northbound-hang, malformed-csip,
expired-control, conflicting-primacy — none should change verdict.

## Conformance implications
None intended; the CSIP walk/Response behavior is untouched. Conformance
logic tests are the guard.

## Suggested commit message
`refactor(northbound): extract run/publish/responses/flowres packages (pure moves, D12)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Northbound god-file decomposition (R5/D12)
**Description:** Four mechanical extraction commits, tests per package,
byte-identical behavior (journal + scenario smoke evidence). Risk: med
(CGo service, utility-facing). Rollback: revert any commit independently.

## Code review checklist
- Diff is move-shaped (git diff --color-moved review).
- Exported surface minimal; interfaces defined at consumers.
- No logic/log/QoS drift (grep-compare publish calls).

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-069 (HTTP client swap under the now-isolated fetcher seam), TASK-070
(ctx through run→walker→fetcher), TASK-071 (poll-rate logic in run).
