# TASK-041 — Guard/breach-state snapshot + restore-on-start (flagged)

*Status: TODO · Phase: P3 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

## Objective
Give lexa-hub a small JSON state snapshot (atomic tmp+rename) written on
breach-episode transitions and periodically-when-dirty, plus a
restore-on-start path gated behind a `hub.json` flag that defaults **off**
for one full campaign cycle. Explicit goal: a hub restart mid-breach must
NOT re-emit a duplicate CannotComply "begin" for the same episode.

## Background
Repo `~/projects/lexa-hub`. Review §11: "breach-episode state doesn't
survive, so a restart mid-breach re-sends a duplicate CannotComply 'begin'
(harmless today, protocol-noise tomorrow)". Mechanics (verified):

- The hub's breach episode lives in `activeBreachMRID` — before TASK-031 a
  closure variable in `cmd/hub/main.go:98`; after TASK-031 a named
  component (04 orders 031 → 040 → 041, so expect the component). On
  restart it resets to "": the next economic tick with `plan.Breach != nil`
  publishes a fresh `bus.ComplianceAlert{Active: true}` (`breachAlert`,
  main.go:238–257) — a duplicate "begin" on the bus.
- Northbound's `responseTracker.alerted` map (cmd/northbound/main.go:678,
  698–706) dedupes CannotComply POSTs per mRID per episode — so a duplicate
  begin only reaches the utility when northbound ALSO restarted (power blip
  restarts both; systemd `Restart=on-failure` + a crash loop does too).
  Fixing the hub side removes the bus-level duplicate; persisting
  northbound's tiny alerted set removes the utility-facing one. Both are in
  scope; both are small.
- AD-005 bounds the snapshot: "only covers state whose loss causes protocol
  noise (duplicate CannotComply begin) or safety regressions." Optimizer
  guard sessions (expGuard/impGuard/genGuard etc., optimizer.go:132+) are
  deliberately NOT snapshotted: they re-converge within a few ticks and
  restoring stale guard state across a restart is exactly the guard×guard
  interaction class W2 warns about. Document this exclusion.
- Restore trust: a stale snapshot is a stale-state hazard (same family as
  §8.3 retained-message trust). The snapshot carries `written_at` +
  `service_start_count`; restore ignores snapshots older than
  `max_age_s` (default 300).
- TASK-039/040 provide the journal; snapshot writes emit
  `snapshot_written` / restores emit `snapshot_restored` events for
  forensics.

## Why this task exists
W5 (nothing survives restart), §11 crash-recovery finding, AD-005 second
half. The reliability review explicitly calls the duplicate-begin the
protocol-noise-tomorrow item; P3's exit criteria include "restart mid-breach
emits no duplicate CannotComply".

## Architecture review sections
W5, §11 (crash recovery), §8.3 (stale-state trust — snapshot inherits it),
AD-011 (crash-only: snapshot restore is part of the re-seed path).
Roadmap: 02 AD-005; 03 Phase 3 exit criteria; 04 deps (040).

## Prerequisites
TASK-040 DONE (journal events exist; breach component named by TASK-031).
Bench FAST for validation.

## Files
- **Read first:**
  - `~/projects/lexa-hub/cmd/hub/main.go` (breach component / planObserver region)
  - `~/projects/lexa-hub/cmd/hub/config.go`
  - `~/projects/lexa-hub/cmd/northbound/main.go` (lines 666–830)
  - `~/projects/lexa-hub/internal/journal/` (event constructors)
  - `docs/refactor/02_ARCHITECTURE_DECISIONS.md` AD-005 (this repo)
- **Modify:**
  - `~/projects/lexa-hub/cmd/hub/{main.go,config.go}` (+ breach component file if TASK-031 created one)
  - `~/projects/lexa-hub/cmd/northbound/{main.go,config.go}`
  - `~/projects/lexa-hub/configs/hub.json`, `configs/northbound.json`
- **Create:**
  - `~/projects/lexa-hub/internal/snapshot/snapshot.go` (+ `snapshot_test.go`) — tiny generic atomic-JSON store, reusable by both services

## Blast radius
`cmd/hub` breach reporting path, `cmd/northbound` response dedupe, new leaf
package `internal/snapshot`. With the flag off (default), runtime behavior
is write-only (snapshot files appear; nothing reads them). Bus schema
unchanged.

## Implementation strategy
A 100-line `internal/snapshot` package: `Save(path string, v any) error`
(marshal → write `path+".tmp"` → fsync → `os.Rename`) and
`Load(path string, v any) error`. Hub snapshots
`{v:1, written_at, active_breach: {episode_id, mrid, begin_ts, alert}}` on
every breach begin/end transition and every 60 s while a breach is active;
northbound snapshots `{v:1, written_at, alerted: [mrid...], posted: {mrid:status}}`
on change (alerted/posted are small maps — the posted map also prevents
duplicate Started/Completed Responses after restart). Restore behind
`"snapshot": {"enabled": false, "path": "...", "max_age_s": 300}` — one
campaign runs with it off (write-only soak), then a follow-up config flip
turns it on (no code change).

## Detailed steps
1. Build `internal/snapshot` with tests: atomic rename (no partial file
   visible — test by concurrent reader), Load of missing/corrupt/stale file
   returns a typed error (`ErrStale`, `ErrNotExist` passthrough), version
   field checked.
2. **Hub:** config block; on breach begin/end (the TASK-031 component),
   `Save` the episode state + journal `snapshot_written`; on start with
   `enabled`, `Load` — if a fresh, valid snapshot holds an active episode,
   seed `activeBreachMRID` (and episode ID) so the first breaching tick does
   NOT publish a duplicate begin, and journal `snapshot_restored`. If the
   restored episode's breach is GONE on the first economic tick
   (plan.Breach == nil), the normal clear-edge fires
   (`ComplianceAlert{Active:false}`) — that is correct: the breach may have
   ended while dark; northbound's clearAlerts then unlatches its dedupe.
3. **Northbound:** config block; persist `alerted` + `posted` on change
   (both mutate under `rt.mu` — Save outside the lock with a copied
   snapshot); on start with `enabled`, seed the tracker so a redelivered/
   re-emitted alert POSTs nothing and completed events are not re-Started.
   Cap `posted` snapshot size (drop terminal-status entries older than 24 h
   worth of walks — the tracker itself never prunes; snapshot only what a
   restart needs: non-terminal statuses + alerted set).
4. Wire `snapshot_written` journal events (already constructed in 039's
   schema).
5. Unit tests: hub restart-mid-breach simulation — drive `breachAlert`/the
   component through begin → snapshot → new component seeded from snapshot →
   same plan.Breach — assert **no** Active=true alert emitted; then breach
   clears — assert one Active=false. Northbound: alertCannotComply after
   seeded restore posts nothing.
6. **Bench validation (flag ON temporarily on the bench):** arm
   `reject-write-curtail` conditions manually or via
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only reject-write-curtail`
   with a mid-scenario `sudo systemctl restart lexa-hub` (reuse the
   hub-restart pattern by hand over SSH); inspect gridsim's received
   Responses (gridsim admin/logs) for exactly ONE CannotComply for the
   episode. Also run `hub-restart-mid-cap` 10× — its verdict must not
   regress.
7. Ship with `enabled: false` in the example configs and on the bench;
   record in 00_MASTER_INDEX that the flag flips after one clean full
   campaign (the flip is an ops action, not a code PR).

## Testing changes
- `internal/snapshot` unit tests (atomicity, staleness, corruption).
- Hub + northbound restart-simulation unit tests (step 5).
- Bench: step 6 evidence + full FAST campaign with flag off; then the
  flag-on campaign before calling P3's exit criterion met.
- Run: `go test -race ./internal/... ./cmd/...`.

## Documentation changes
- 02 AD-005: mark snapshot half implemented; record the guard-state
  exclusion rationale (one paragraph).
- `docs/JOURNAL_FORENSICS.md` (from TASK-040): add snapshot file locations
  and the restored-episode story.
- configs examples updated.

## Common mistakes to avoid
- Restoring optimizer guard state — explicitly excluded (see Background);
  do not "complete" the snapshot with it.
- Writing the snapshot on every tick — transitions + 60 s-while-dirty only
  (flash, RSK-14).
- `os.Rename` across filesystems fails — tmp file must live in the same
  directory as the target.
- The seeded hub episode must still allow a NEW breach (different mRID) to
  alert immediately — the mRID-keyed edge logic (main.go:89–98 comment)
  must be preserved exactly.
- A snapshot older than max_age_s or with a future `written_at` (local
  clock step — see TASK-037) is discarded with a log, never trusted.
- Do not couple snapshot restore to MQTT retained re-seed ordering: restore
  runs before `eng.Start()`; the retained control arrives whenever it
  arrives. No ordering assumption.

## Things that must NOT change
Preservation ledger entries touched:
- One CannotComply POST per breach episode (northbound `alerted` guard) ↔
  reject-write/enable-gate-curtail flakiness history (main.go comments).
- mRID-keyed breach edge (a NEW mRID breaching while another is latched
  must alert) ↔ the reject-write/enable-gate "alerter latched" finding
  (cmd/hub/main.go:89–98).
- `hub-restart-mid-cap` verdict: "come back enforcing; never emit an
  un-commanded restore during shutdown/startup" — restore must not touch
  device command paths at all (it seeds reporting state only).
- Response state machine statuses/order (CORE-022/023).
- With `enabled:false`, bit-identical behavior to pre-task (plus snapshot
  files being written).

## Acceptance criteria
- [ ] Unit test proves restart-mid-breach emits no duplicate Active=true
      (hub) and no duplicate POST (northbound).
- [ ] Atomicity test: killing the writer mid-Save never leaves a corrupt
      readable snapshot (tmp+rename verified).
- [ ] Bench evidence: one CannotComply per episode across a live
      `systemctl restart lexa-hub` mid-breach (gridsim response log
      excerpt).
- [ ] `hub-restart-mid-cap` 10× at baseline verdict with flag ON.
- [ ] Full FAST campaign with flag OFF ≤ baseline (write-only soak).

## Regression checklist
- [ ] `go test -race ./internal/... ./cmd/...` (lexa-hub) green
- [ ] Conformance logic tests green (`go test ./tests/`) — Response dedupe touched
- [ ] Mayhem: `hub-restart-mid-cap` 10× + full FAST campaign
- [ ] `hub-replay-tune.sh fast` re-applied after deploy

## Mayhem scenarios affected
`hub-restart-mid-cap` (primary), `reject-write-curtail`/
`enable-gate-curtail` (episode accounting), `wan-outage-expiry` (no
interaction expected — verify). TASK-043's power-cut scenario will lean on
this snapshot's behavior later.

## Conformance implications
Prevents duplicate 2030.5 CannotComply/Started/Completed Responses after
client restart — strictly closer to spec-clean behavior. No format changes.

## Suggested commit message
`feat(hub,northbound): breach-episode snapshot + flagged restore — no duplicate CannotComply after restart (TASK-041)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Snapshot + flagged restore for breach/response state (TASK-041)
**Description:** AD-005 snapshot half: atomic JSON snapshots of the hub
breach episode and northbound response dedupe state; restore behind
`snapshot.enabled` (default off, one write-only campaign before flip).
Kills the §11 duplicate-CannotComply-after-restart finding. Testing: unit
restart simulations, bench restart evidence, campaigns. Rollback: flag off
(runtime) or revert.

## Code review checklist
- Restore path cannot influence device commands (grep the diff for actuator
  imports — must be none).
- Staleness + version checks on Load; discard-and-log on any doubt.
- Locks: northbound Save happens outside `rt.mu` with copied data.
- Flag default off in code AND example configs.
- Campaign + bench evidence attached.

## Definition of done
Acceptance + regression checklists green; AD-005/forensics docs updated;
status headers updated (this file + 00_MASTER_INDEX; note the pending
flag-flip campaign).

## Possible follow-up tasks
Ops: flag-flip campaign. TASK-043 (power-cut scenario exercises retained +
snapshot interplay). Backlog: EV cooldown / daily-plan persistence if field
data shows restarts hurt economics (explicitly out of AD-005 scope today).
