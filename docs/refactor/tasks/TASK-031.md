# TASK-031 — Collapse the CannotComply chain: reconciler reports → named breach-episode component → northbound

*Status: DONE (2026-07-05, lexa-hub 3e6c42b) · Phase: P2 · Effort: L (≈6–8 h) · Difficulty: high · Risk: med*

## Objective
CannotComply reporting runs through three owned stages instead of five stateful hops:
(1) breach evidence — optimizer meter-level `plan.Breach` AND reconciler non-convergence
reports (retained, episode-ID'd) — feeds (2) a named breach-episode component in
`cmd/hub` that owns episode state and arbitration and publishes edge-triggered
`ComplianceAlert`s carrying an episode ID, consumed by (3) northbound's `responseTracker`
which POSTs exactly one CannotComply per episode. The `activeBreachMRID` closure dies;
episode state becomes a named, testable struct (preparing the TASK-041 snapshot). Edge
semantics, the `Plan.Safety` guard, and post-dedupe are preserved exactly.

## Background
The five hops today (all verified):
1. Optimizer detects a meter-level breach (`recordBreach`, `optimizer.go:2192`; only one
   breach — `plan.Breach *ComplianceBreach`, `model.go:302–313`) and stamps the active
   control's mRID (`optimizer.go:374–376`).
2. `cmd/hub` plan observer closure (`main.go:103–149`) holds `activeBreachMRID` in a
   closure variable (`:98`) and calls the pure edge function `breachAlert`
   (`:238–257`): alert on onset OR mRID change, clear-alert on breach end, **nil on
   safety plans** — a fast-loop safety plan's nil Breach means "not assessed", not
   "compliant" (`model.go:315–320`; 2026-07-03 fix). It also fires `dedupeResets`
   (`:99–118`, ledger L3 — deleted by TASK-032, not here).
3. MQTT `lexa/csip/compliance/alert` (`bus.TopicCSIPComplianceAlert`, QoS 1,
   **non-retained** — §8.2: a dropped alert or a northbound restart mid-episode loses the
   edge; the utility never learns).
4. Northbound subscription (`cmd/northbound/main.go:203–213`).
5. `responseTracker` (`:666–830`): `alertCannotComply(mrid)` posts once per mRID episode
   (`alerted` map), `clearAlerts()` re-arms; posts `model.ResponseCannotComply` via HTTP.

New evidence source from TASK-026–030: reconciler `Report`s (`NonConvergedBegin/End`,
`StaleDesired`, interlock-hold) with device, mrid, seq, episode counter — device-level
"the hardware won't do what was asked", complementary to the optimizer's meter-level
"the site isn't meeting the limit". Both must merge into ONE episode stream so gridsim
sees one CannotComply per real episode, not one per source.

Arbitration rule (keep it simple and explicit): an episode begins when EITHER source
reports sustained non-compliance for the active control mRID; it ends when ALL sources
are clear. The optimizer's built-in debounces (`expOverTicks` etc., ledger L10) and the
reconciler's `ConvergeTimeout` already provide onset damping — the component must NOT add
another debounce layer (one owner per concept, 05 §1).

## Why this task exists
D11: five hops, two edge detectors, closure state — already produced three QA race
classes (mRID-agnostic latching → reject-write/enable-gate flakiness; safety-plan
spurious clear; per-tick spam risk). §8.2 rates the chain a top risk. Naming the episode
state kills the closure (05 §4: "if it has a name in a bug report, it needs a name in the
code") and is the prerequisite for persisting it (TASK-041: restart mid-breach must not
re-send a duplicate begin).

## Architecture review sections
W2 (mechanism d), D11, §8.2, R1/R7 (activeBreachMRID out of closures), §14 item 3;
02 AD-002/AD-005 (snapshot forward-prep); 08 RSK-01; ledger L5, L6.

## Prerequisites
- TASK-028 DONE (battery reports exist end-to-end). TASK-029/030 flips ideally done
  (04 lists only 028 as hard dep) — if solar/EVSE are still legacy, their evidence source
  is optimizer-only and the component must handle sources appearing later without
  redesign.

## Files
- **Read first:** `cmd/hub/main.go:90–260`, `cmd/hub/breachalert_test.go` (the edge
  contract as tests), `cmd/northbound/main.go:198–213, 666–830`,
  `internal/reconcile/report.go`, `internal/bus/messages.go:41–54` (`ComplianceAlert`),
  `internal/orchestrator/model.go:286–320`.
- **Modify (lexa-hub):** `cmd/hub/main.go` (observer body shrinks to: plan-log publish +
  component feed); `internal/bus/messages.go` (`ComplianceAlert` gains
  `EpisodeID string \`json:"episode_id,omitempty"\`` — additive);
  `cmd/northbound/main.go` (`responseTracker` keys the `alerted` map by episode ID when
  present, mrid otherwise — tolerant of old publishers during rollout);
  `cmd/modbus`/`cmd/ocpp` shells (publish their reports to MQTT if not already:
  retained `lexa/reconcile/{class}/{device}/report`, retained so the hub re-seeds after
  restart — add topic helpers to `internal/bus/topics.go`).
- **Create:** `cmd/hub/breach.go` (`type breachEpisodes struct` — the named component) +
  `cmd/hub/breach_test.go` (absorbs and extends `breachalert_test.go` cases).

## Blast radius
The compliance-reporting path end to end (hub observer, one bus schema additively, the
northbound poster). NOT touched: optimizer detection logic (L10), the dedupe-reset
mechanism (L3 — still wired until TASK-032), plan-log/heartbeat publishing, actual
Response XML/HTTP mechanics.

## Implementation strategy
Introduce the component behind the existing wire contract first (same alerts out,
closure state moved inside a struct), prove parity with the carried-over tests, then add
the reconciler-report input and episode IDs. Northbound change is tolerant/additive so
hub and northbound can deploy in either order (they restart together in practice, but
don't require it).

## Detailed steps
1. `cmd/hub/breach.go`: `breachEpisodes` struct owning `activeMRID`, `episodeID`
   (generated at onset: e.g. `mrid + "-" + issuedAt`), per-source latest evidence
   (`planBreach *ComplianceBreach`, `deviceReports map[deviceID]reconcileReport`), and a
   single method `Update(evidence) (alerts []bus.ComplianceAlert)` implementing the
   arbitration + edge rules. Port `breachAlert`'s exact semantics (incl. Safety guard and
   mRID-switch re-alert) as the plan-evidence half; `breachalert_test.go` cases move to
   `breach_test.go` and must pass against the component unchanged in meaning.
2. Rewire the observer (`main.go:103–149`): keep plan-log publish + `dedupeResets`
   exactly as-is; replace the closure edge logic with `component.Update(...)`; delete
   `activeBreachMRID` and the standalone `breachAlert` func once tests are ported.
3. Reconciler report transport: shells publish `Report`s (retained per device);
   `cmd/hub` subscribes and feeds `component.Update`. Mapping to evidence: only reports
   carrying the active control's mrid (or empty-mrid device faults during an active
   control — decide + document: empty-mrid reports log but do not open CSIP episodes)
   participate in CannotComply; `StaleDesired`/interlock-hold log-only for now.
4. `ComplianceAlert.EpisodeID` additive field; hub sets it; northbound `responseTracker`
   dedupe keys on `EpisodeID` when non-empty (fallback mrid). `clearAlerts` semantics
   unchanged.
5. Tests: component table-driven — onset/clear/mrid-switch/safety-plan parity (ported);
   reconciler-only episode (device refuses, meter fine); both-sources overlap (one
   episode, one begin, one end when both clear); northbound: duplicate begin with same
   episode ID posts once; restart-shaped replay (same retained report re-delivered) posts
   once. Mutation check (05 §8): break the Safety guard, a test must fail.
6. Bench validation, targeted:
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only battery-soc-refuse,battery-empty-import-cap,battery-charge-disabled,reject-write-curtail,enable-gate-curtail,export-cap-full-battery,ev-min-current-floor,control-churn`
   — CannotComply-bearing scenarios; verdicts at baseline, and gridsim receives exactly
   one CannotComply per episode (check gridsim admin/logs as the scenarios' diagnosers do).
7. Full FAST campaign ≤ baseline.
8. Ledger: L5, L6 → `restructured (T031)` with the new component named.

## Testing changes
Step 5 suite (component + tracker). `breachalert_test.go` retired INTO `breach_test.go`
(no coverage loss — reviewer diffs case lists). Commands: `make test`; mayhem runs above.

## Documentation changes
- Ledger L5/L6 status + component name.
- `internal/bus/topics.go` header comment: new report topic family documented.
- lexa-hub CLAUDE.md data-flow diagram: alert path updated (3 stages).
- Note for TASK-041 in the component's doc comment: which fields need snapshotting
  (episodeID, activeMRID, posted-flag) to kill the duplicate-begin-after-restart noise
  (§11 crash-recovery finding).

## Common mistakes to avoid
- Making the alert topic retained "for durability" — the ALERT is an edge; retained
  edges replay as false edges after restarts. Durability lives in the retained
  reconciler REPORTS (state, not edge) + TASK-041 snapshot.
- Adding a debounce in the component (evidence sources already debounce; a third layer
  recreates the guard×guard class).
- Dropping the mRID-switch re-alert (case `plan.Breach.MRID != prevMRID` — the
  reject-write/enable-gate fix) during the port.
- Touching `dedupeResets` — that is TASK-032's deletion, gated separately.
- Letting empty-mrid device reports open CSIP episodes (a device fault with no active
  control is not a CannotComply).

## Things that must NOT change
- **L5 edge semantics:** one alert at onset, one at clear, safety plans never clear,
  new-mRID re-alerts — ported tests prove it.
- **L6:** exactly one CannotComply POST per episode; `clearAlerts` re-arm.
- Plan-log/heartbeat publish on every pass (`bus.TopicHubPlan` retained — lexa-api and
  QA introspection depend on it).
- Optimizer detection thresholds/counters (L10) — zero optimizer edits.
- Wire: `Response` XML + posting mechanics in northbound (`postResponse`) unchanged.

## Acceptance criteria
- [ ] `grep -n "activeBreachMRID" cmd/hub/` → no matches; component struct owns the state.
- [ ] Ported edge tests green; both-sources and reconciler-only episode tests green.
- [ ] Bench: one CannotComply per episode observed on the CannotComply-bearing scenario
      set; verdicts at baseline.
- [ ] Full FAST campaign ≤ 0.6 FAIL/cycle, 0 BLIND.
- [ ] Northbound tolerant of alerts without EpisodeID (mixed-version safe).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] `make test-fast` (csip-tls-test) green
- [ ] Conformance logic tests: `go test ./tests/` (Response/CannotComply logic is
      CSIP-adjacent) green
- [ ] Mayhem: targeted CannotComply set + **full campaign** (radioactive zone: cmd/hub)
- [ ] Timing re-tuned post-deploy

## Mayhem scenarios affected
`battery-soc-refuse`, `battery-empty-import-cap`, `battery-charge-disabled`,
`reject-write-curtail`, `enable-gate-curtail`, `export-cap-full-battery`,
`ev-min-current-floor`, `ev-accept-but-ignore`, `control-churn`, `perfect-storm` —
all consume/assert CannotComply behavior; verdicts must hold.

## Conformance implications
CannotComply (`ResponseType` per 2030.5) count-per-episode is observable by the utility:
must remain exactly-once. Conformance logic tests cover the Response path — run them.

## Suggested commit message
`refactor(hub): named breach-episode component; reconciler reports feed CannotComply (TASK-031)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 2: CannotComply chain 5 hops → 3, episode state named and tested
**Description:** breachEpisodes component absorbs the closure edge logic (tests ported),
merges optimizer + reconciler evidence under episode IDs; northbound dedupes by episode.
Evidence: targeted scenario set + full campaign. Rollback: revert (wire contract is
backward compatible).

## Code review checklist
- Ported test parity (case-by-case diff vs breachalert_test.go).
- No new debounce; arbitration is pure evidence-merge.
- Alert topic still non-retained; report topics retained.
- Snapshot-fields note present for TASK-041.

## Definition of done
Acceptance criteria + regression checklist; ledger L5/L6 updated; status headers (this
file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-032 (legacy deletion), TASK-040/041 (journal + snapshot of episode state),
TASK-018 (envelope on the new report schema).
