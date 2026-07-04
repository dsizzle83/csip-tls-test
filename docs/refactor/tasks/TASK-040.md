# TASK-040 — Journal integration: adoptions, dispatches, breaches, CannotComply

*Status: TODO · Phase: P3 · Effort: M (≈4–6 h) · Difficulty: med · Risk: med*

## Objective
Wire the `internal/journal` library (TASK-039) into the running system so
that every control adoption/release, every device dispatch that actually
publishes, every breach-episode begin/end, and every CannotComply POST is
durably recorded — with episode IDs that let an operator correlate journal
records against journald lines during incident diagnosis.

## Background
Repo `~/projects/lexa-hub`. TASK-039 provides
`journal.Open(cfg) (*Writer, error)`, `Append(Event)`, and typed
constructors for: `control_adopted`, `control_released`, `dispatch`,
`breach_begin`, `breach_end`, `cannot_comply_posted`, `service_start`.

The four emit sites (verified):
1. **Control adoption / release (hub).** `cmd/hub/state.go`:
   `onCSIPControl` (line 157) stores each retained/new `bus.ActiveControl`;
   the expiry-drop block (lines 348–371, after TASK-036 a
   `utilitytime.DebouncedExpiry`) releases with reason "expired".
   Adoption should be journaled only on *change* (Source/MRID/limits/
   ValidUntil differ from the previous message) — northbound republishes an
   identical control every walk (~5 s FAST); journaling each would blow the
   write budget.
2. **Dispatch (hub).** The event is "a device command that actually went
   out on the bus". Post-TASK-031 (pre-TASK-032) that is each actuator's
   `Apply*Command` after a successful `PublishJSON` — the post-dedupe point,
   so volume is bounded by real command changes. If TASK-032 has landed,
   the legacy actuator publishes are gone and the desired-state publish
   site (the desired-doc publisher's content-change publish) is the
   dispatch event — emit there and say so in the PR.
3. **Breach episodes (hub).** TASK-031's named breach-episode component
   (`breachEpisodes`, `cmd/hub/breach.go`) owns episode state, mints the
   episode ID at onset, and publishes edge-triggered `ComplianceAlert`s.
   Emit `breach_begin`/`breach_end` from that component's begin/resolve
   edges (inside or immediately alongside its `Update` output handling).
4. **CannotComply POST (northbound).** `responseTracker.alertCannotComply`
   → `postResponse` POSTs status `model.ResponseCannotComply`. Journal
   `cannot_comply_posted` after a successful POST (the `err == nil`
   branch), including the mRID and the episode ID carried on the alert.

Episode ID: minted by the breach-episode component at `breach_begin`
(TASK-031); `bus.ComplianceAlert` already carries
`EpisodeID string \`json:"episode_id,omitempty"\`` (added by TASK-031) —
verify it exists and is stamped on begin alerts; do not re-add it.

TASK-031/032 restructure this area — at execution time, hook whatever the
current breach-episode component and actuator publish path are; the emit
events (adoption, dispatch, breach begin/end, CannotComply post) are the
stable contract, not the symbol names.

Config: each journaling service gets a `journal` block in its JSON config
(`/etc/lexa/hub.json`, `/etc/lexa/northbound.json`; example files in
`~/projects/lexa-hub/configs/`): `{"journal": {"dir": "/var/lib/lexa/journal",
"max_bytes": 1048576, "max_files": 4}}` — absent block = journaling
disabled (nil Writer, no-op emits), so rollout is config-driven.

## Why this task exists
W5 / Top-20 item 9: the compliance/dispatch record a utility requires does
not exist; breach forensics today live only in volatile journald. Also the
"replay/diagnosis story": QA root-causing (V3→V6) worked journal-line by
journal-line; episode IDs make that mechanical.

## Architecture review sections
W5, D11 (chain fragility — journal is the evidence trail while TASK-031
collapses it), §11 crash recovery. Roadmap: 02 AD-005; 03 Phase 3;
04 deps (039, 031); 08 RSK-05 ("journal evidence (040)").

## Prerequisites
TASK-039 DONE. TASK-031 DONE (breach-episode named component). Bench FAST
for the campaign.

## Files
- **Read first:**
  - `~/projects/lexa-hub/internal/journal/` (all — TASK-039 output)
  - `~/projects/lexa-hub/cmd/hub/main.go` (lines 84–230), `cmd/hub/state.go` (onCSIPControl + expiry block), `cmd/hub/actuators.go` (all), `cmd/hub/breach.go` (TASK-031 component), `cmd/hub/config.go`
  - `~/projects/lexa-hub/cmd/northbound/main.go` (lines 240–330, 660–830) + `cmd/northbound/config.go`
  - `~/projects/lexa-hub/internal/bus/messages.go` (ComplianceAlert)
- **Modify:**
  - `~/projects/lexa-hub/cmd/hub/{main.go,state.go,actuators.go,breach.go,config.go}`
  - `~/projects/lexa-hub/cmd/northbound/{main.go,config.go}`
  - `~/projects/lexa-hub/configs/hub.json`, `configs/northbound.json` (example blocks)
  - `~/projects/lexa-hub/scripts/deploy-hub-pi.sh` ONLY if it must create `/var/lib/lexa/journal` (check; hub Pi units run as root per docs/BENCH.md, so `journal.Open`'s MkdirAll suffices — prefer no script change)
- **Create:** none.

## Blast radius
`cmd/hub` (actuator + state paths — **radioactive zone adjacency**, 05 §12:
`cmd/hub/actuators.go` is explicitly listed), `cmd/northbound` response
path, `internal/bus` (one additive field). Journaling must be strictly
fire-and-forget: an error from `Append` is logged (edge-triggered, the
library does this) and never alters control flow.

## Implementation strategy
One commit per service. Hub: construct the Writer in `main()` from config
(nil if absent), pass it to the reader (adoption/release), the actuators
(dispatch), and the breach component (episodes); mint episode IDs at
`breach_begin` and stamp them onto the outgoing `ComplianceAlert`.
Northbound: construct Writer, emit `cannot_comply_posted` on successful
POST, `service_start` at boot (both services). Then deploy + campaign.

## Detailed steps
1. **Bus field.** Verify `bus.ComplianceAlert.EpisodeID` (omitempty, added
   by TASK-031) exists and is set on begin alerts by the breach-episode
   component; northbound passes it through to the journal event. If
   TASK-031's tests don't already cover it, unit-test JSON round-trip (old
   payload without the field still decodes).
2. **Hub wiring.**
   - `config.go`: add `Journal *journal.Config` (pointer = optional).
   - `main.go`: `var jw *journal.Writer` opened when configured; emit
     `service_start`. Pass `jw` into `newMQTTSystemReader` (adoption/
     release) and store on each actuator struct (dispatch) and the breach
     component (episodes). All emits guarded by `if jw != nil`.
   - `state.go`: in `onCSIPControl`, compare against previous message
     (Source, MRID, Connect, ExpLimW/ImpLimW/MaxLimW/FixedW, ValidUntil) —
     on change emit `control_adopted` (or `control_released` reason
     "cleared" when Source=="none"/""), carrying SrvT from
     `utilitytime` (TASK-037 anchored clock if present). In the expiry-drop
     branch emit `control_released` reason "expired".
   - `actuators.go`: after each successful publish, emit `dispatch` with
     device, kind, and the command values. (Post-dedupe ⇒ write volume is
     bounded by actual command changes + the 60 s watchdog re-asserts.)
3. **Northbound wiring.** `config.go` journal block; `main.go` opens Writer,
   emits `service_start`; in `postResponse`'s success path, when the status
   is CannotComply, emit `cannot_comply_posted{episode_id, mrid}` (TASK-031
   already threads the episode ID from the MQTT alert into the tracker's
   dedupe key — reuse it at the emit site; extend signatures only if the ID
   is not already in scope there).
4. **Diagnosis story** (deliverable, not prose): add
   `docs/JOURNAL_FORENSICS.md` to lexa-hub — one page: file locations,
   `jq` one-liners (`jq -r 'select(.type=="breach_begin")'`), and the
   journalctl correlation recipe: episode ID appears in both the journal
   events and the existing hub log line
   `lexa-hub: COMPLIANCE BREACH … mrid=…` (main.go:141) — add the episode ID
   to that log line so `journalctl -u lexa-hub | grep <episode_id>` works.
5. **Bench validation.** Deploy both services
   (`make build-arm64 && bash scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`,
   then `hub-replay-tune.sh fast`). Run
   `python3 scripts/mayhem.py --dashboard http://localhost:8080 --only export-cap-full-battery,reject-write-curtail,wan-outage-expiry`.
   Then SSH to the hub Pi and assert the journal contains: ≥1
   `control_adopted`, matching `control_released`, a
   `breach_begin`/`cannot_comply_posted`/`breach_end` chain sharing one
   episode ID for reject-write-curtail. Then a full FAST campaign.

## Testing changes
- `cmd/hub`: extend `actuators_test.go` (dispatch emitted only when publish
  happens — dedupe-suppressed applies emit nothing) and `state_test.go`
  (adoption emitted on change only; release on expiry) using a Writer on
  `t.TempDir()` + `journal.Scan`.
- `cmd/hub/breach_test.go` (TASK-031's suite, formerly `breachalert_test.go`):
  episode-ID minting on begin, reuse on end — extend if not already covered.
- `cmd/northbound`: unit test `alertCannotComply` journaling via a fake
  poster (the `responsePoster` interface, main.go:662).
- Run: `go test -race ./internal/... ./cmd/...`; bench steps above.

## Documentation changes
- New `~/projects/lexa-hub/docs/JOURNAL_FORENSICS.md` (step 4).
- 02 AD-005: mark "integrated (hub, northbound)".
- `configs/*.json` examples updated (step 2/3).

## Common mistakes to avoid
- Journaling the per-walk identical `ActiveControl` republish (every ~5 s)
  — must be change-detected or the 5 MiB cap rotates in hours and RSK-14
  wear returns.
- Blocking the tick on journal fsync: `Append` batches; never call `Flush`
  from the actuator path. Breach transitions MAY flush (rare, valuable).
- `cmd/hub/actuators.go` is radioactive: this PR must contain nothing else,
  and a full campaign gates the merge (05 §12).
- Do not create `/var/lib/lexa` in the repo's unit files with `User=`
  assumptions — hub Pi units run as root (BENCH.md); the SOM install path
  is `make install` — `journal.Open` MkdirAll handles both.
- Touching `alertCannotComply`: keep the tracker's one-POST-per-episode
  idempotency guard exactly (the `alerted` map, keyed by episode ID with
  mRID fallback since TASK-031) — QA relies on one POST per episode.
- Deploy gotcha: re-run `hub-replay-tune.sh fast` after deploy.

## Things that must NOT change
Preservation ledger entries touched (emit-only — behavior must be
bit-identical):
- The breach-episode component's begin/resolve edge semantics and
  one-CannotComply-per-episode dedupe (as landed by TASK-031).
- responseTracker idempotency + response state machine (CORE-022/023).
- Fail-closed publish-nothing on walk error (main.go:252–267).
- Alert remains QoS 1 non-retained via `PublishJSON` (main.go:146).

## Acceptance criteria
- [ ] All unit tests green (`go test -race ./internal/... ./cmd/...`).
- [ ] Bench evidence attached: journal excerpt showing an adoption→breach→
      CannotComply→clear chain with one episode ID, plus the matching
      journalctl grep.
- [ ] With no `journal` config block, services behave exactly as before
      (nil-writer no-op path tested).
- [ ] Full FAST campaign ≤ V6 baseline (0.6 FAIL/cycle, 0 BLIND).
- [ ] Write-volume spot check: after the 3-scenario run, journal size is
      KBs, not MBs (change-detection working).

## Regression checklist
- [ ] `go test -race ./internal/... ./cmd/...` (lexa-hub) green
- [ ] Conformance logic tests green (`go test ./tests/` in csip-tls-test) — Response path touched
- [ ] Mayhem: full FAST campaign (radioactive file touched)
- [ ] `hub-replay-tune.sh fast` re-applied after deploy

## Mayhem scenarios affected
None should change verdicts. `reject-write-curtail`,
`enable-gate-curtail`, `export-cap-full-battery` (breach chains),
`wan-outage-expiry` (release reason "expired") now leave journal evidence —
future diagnosers may consume it (backlog).

## Conformance implications
CannotComply Responses now have a durable client-side record (mRID +
timestamp) — supports future audit/certification evidence. No wire changes.

## Suggested commit message
Two commits:
`feat(hub): journal adoptions, dispatches, breach episodes (TASK-040 1/2)`
`feat(northbound): journal CannotComply posts + episode-ID passthrough (TASK-040 2/2)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Journal integration: durable control/dispatch/breach/CannotComply record (TASK-040)
**Description:** Wires TASK-039's journal into hub + northbound at four emit
sites; episode IDs correlate journal ↔ journald ↔ 2030.5 Responses.
Config-gated (absent block = off). Risk: touches actuator path (emit-only).
Testing: unit + bench evidence + full campaign attached. Rollback: remove
config block (runtime), or revert per-service commit.

## Code review checklist
- Every emit is `if jw != nil`-guarded and error-tolerant.
- Change-detection on adoption covers all control fields.
- Episode ID flows hub→bus→northbound→journal unbroken.
- No behavioral diff in dedupe/breach/response logic (read side-by-side).
- Campaign report attached.

## Definition of done
Acceptance + regression checklists green; docs added/updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-041 (snapshot uses `snapshot_written` events), TASK-050 (disk-full
exercises journal error path), backlog: compliance report generator;
Mayhem diagnosers reading journal evidence over SSH.
