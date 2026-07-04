# TASK-039 — Event journal: schema + append-only writer + flash-aware rotation

*Status: TODO · Phase: P3 · Effort: L (≈6–8 h) · Difficulty: med · Risk: low*

## Objective
Create `lexa-hub/internal/journal`: an append-only, newline-delimited-JSON
(NDJSON) event journal with size-based rotation, batched fsync, a documented
flash write budget, and a schema designed to later feed the utility-facing
compliance report. Pure library + config types only — consumer wiring is
TASK-040.

## Background
Repo `~/projects/lexa-hub`. Review W5: nothing survives a restart except
retained MQTT; there is **no dispatch/compliance/metering event log**, which
utilities will contractually require. AD-005 decides the shape: "newline-
delimited, size-rotated, fsync-batched journal on its own quota … recording
controls adopted, dispatches, breach episodes, CannotComply — doubles as the
utility-facing audit log"; SQLite explicitly rejected (flash wear, fsync
cost, new dependency). `docs/refactor/10_BACKLOG.md` lists a
"Utility-facing compliance report generator from the event journal" — the
schema here must anticipate it.

Flash context (RSK-14, review §11): the hub runs on a Pi SD card today and a
Digi SOM eMMC in production; journald already writes ~2 lines/tick
(≈50k lines/day in FAST). The journal must be write-budgeted: batched
fsyncs, bounded total size, rotation instead of growth.

Event sources that TASK-040 will wire (verify names now so the schema
fits): control adoption/expiry (`cmd/hub/state.go` `onCSIPControl` +
expiry-drop block at lines 348–371), dispatch/plan publishes
(`planObserver` in `cmd/hub/main.go:103–149`), breach episode edges
(`breachAlert`, `cmd/hub/main.go:238–257`, keyed by mRID), CannotComply
POSTs (`responseTracker.alertCannotComply`/`postResponse`,
`cmd/northbound/main.go:698, 809`). Message vocabulary:
`bus.ActiveControl` (Source/MRID/limits/ValidUntil/ClockOffset/Ts),
`bus.ComplianceAlert` (MRID/LimitType/LimitW/MeasuredW/ShortfallW/Reason/
Active/Ts) — `internal/bus/messages.go:28–54`.

## Why this task exists
W5 / Top-20 item 9: no persistence, no audit record. A utility's lawyers
will subpoena the dispatch/compliance record; today it dies with the
process and journald rotation.

## Architecture review sections
W5, §11 (flash wear), §15 months 4–6. Roadmap: 02 AD-005; 03 Phase 3;
08 RSK-14; 10_BACKLOG (compliance report generator).

## Prerequisites
None (04 row 039: no dependencies). TASK-009 (journald caps/wear budget) is
complementary, not blocking.

## Files
- **Read first:**
  - `docs/refactor/02_ARCHITECTURE_DECISIONS.md` AD-005 (this repo)
  - `~/projects/lexa-hub/internal/bus/messages.go` (ActiveControl, ComplianceAlert)
  - `~/projects/lexa-hub/cmd/hub/main.go` (lines 84–150), `cmd/hub/state.go` (lines 348–371)
  - `~/projects/lexa-hub/cmd/northbound/main.go` (lines 666–830)
  - `docs/refactor/08_RISK_REGISTER.md` RSK-14
- **Modify:** none.
- **Create:**
  - `~/projects/lexa-hub/internal/journal/journal.go` (writer, rotation, fsync batching)
  - `~/projects/lexa-hub/internal/journal/schema.go` (event types)
  - `~/projects/lexa-hub/internal/journal/reader.go` (scan/verify helper — needed by tests, the compliance generator, and TASK-041's diagnosis story)
  - `~/projects/lexa-hub/internal/journal/journal_test.go`, `schema_test.go`

## Blast radius
None at runtime (new leaf package, zero consumers). The schema becomes a
compatibility surface the moment TASK-040 ships — design fields as
append-only (new fields OK, renames not).

## Implementation strategy
A `Writer` owning one open file + a size counter; `Append(Event)` marshals
one JSON object per line; fsync policy is batched (flush+fsync when either
`FlushEvery` events or `FlushInterval` elapsed since first unflushed write —
time-based flushing runs on the caller's Append path via lazy check PLUS an
optional background ticker owned by the caller, keeping the library
goroutine-free by default). Rotation: when the active file would exceed
`MaxBytes`, close, rename to `<name>.1` (shifting `.1`→`.2` … up to
`MaxFiles`), open fresh. Crash tolerance: the reader skips a truncated final
line (partial write from power cut) without failing.

## Detailed steps
1. `schema.go` — envelope + event types:
   ```go
   type Event struct {
       V    int             `json:"v"`    // schema version, 1
       Ts   int64           `json:"ts"`   // local Unix seconds (wall; observability)
       SrvT int64           `json:"srv_t,omitempty"` // server time when known (utilitytime)
       Seq  uint64          `json:"seq"`  // per-writer monotonic
       Type string          `json:"type"`
       Svc  string          `json:"svc"`  // "hub" | "northbound" | ...
       Data json.RawMessage `json:"data,omitempty"`
   }
   ```
   Typed payloads with constructors (`schema_test.go` locks JSON shapes):
   - `control_adopted` {source, mrid, limits (exp/imp/max/fixed W ptrs), valid_until, clock_offset}
   - `control_released` {mrid, reason: "expired" | "cleared" | "replaced"}
   - `dispatch` {device, kind: "battery"|"solar"|"evse", setpoint_w/ceiling_w/max_current_a, connect}
   - `breach_begin` / `breach_end` {episode_id, mrid, limit_type, limit_w, measured_w, shortfall_w, reason}
     — `episode_id = mrid + "/" + beginTs` (the journalctl-correlation key
     TASK-040's diagnosis story uses)
   - `cannot_comply_posted` {episode_id, mrid, http_status}
   - `service_start` {version, config_hash}
   - `snapshot_written` / `snapshot_restored` {path, breach_episode} (for TASK-041)
2. `journal.go` — `Config{Dir, Name, MaxBytes (default 1<<20), MaxFiles
   (default 4), FlushEvery (default 32), FlushInterval (default 5s), Now
   func() time.Time}`; `Open(cfg) (*Writer, error)` (creates Dir 0755, file
   0644, resumes Seq by scanning the tail of the newest file);
   `(*Writer).Append(e Event) error` (never blocks on fsync unless batch
   boundary); `(*Writer).Flush() error`; `(*Writer).Close() error`.
   Concurrency: single mutex; Append is safe from multiple goroutines
   (planObserver + subscription callbacks will both call it in TASK-040).
   Errors: an Append that cannot write (disk full) increments an internal
   dropped-counter, logs edge-triggered (first failure + recovery), and
   returns the error — callers must never crash on journal failure
   (crash-only ≠ crash-on-log; AD-011).
3. `reader.go` — `Scan(dir, name, fn func(Event) error) error` iterating
   rotated files oldest→newest, tolerating a truncated last line (return
   count of skipped partials).
4. Write budget doc (package comment): at defaults and FAST worst case
   (3 s tick, dispatch×3 devices/tick worst case + plan events NOT journaled
   — dispatches only on change post-dedupe): estimate ≈ line size (~200 B) ×
   events/day; state the ceiling `MaxBytes×(MaxFiles+1)` = 5 MiB, fsyncs/day
   at FlushEvery/FlushInterval; cite RSK-14. Numbers must be in the comment,
   not hand-waved.
5. Tests:
   - Append→Scan round-trip, Seq monotonic across reopen.
   - Rotation at MaxBytes (shift chain, MaxFiles honored, oldest deleted).
   - Truncated-final-line tolerance (write partial bytes, reopen, Scan).
   - Disk-full behavior via a tiny `MaxBytes` tmpfs? Not portable — instead
     inject failure with a Writer opened on a closed file / read-only dir;
     assert edge-triggered logging + error return + recovery after chmod.
   - Fsync batching: with injected `Now`, assert flush at FlushEvery and at
     FlushInterval boundaries (observe via file size on disk before/after).
6. `go test -race ./internal/journal/` and full `go test -race ./internal/...`.

## Testing changes
New package tests as above. Run:
`cd ~/projects/lexa-hub && go test -race ./internal/journal/`.

## Documentation changes
- 02 AD-005: append "implemented (library)" note with schema version 1 and
  the write-budget numbers.
- Do not update CLAUDE.md yet (no runtime behavior until TASK-040).

## Common mistakes to avoid
- No goroutines/tickers inside the library by default (testability;
  ownership rules 05 §4) — time-based flush is checked lazily on Append;
  document that a caller wanting hard real-time flush adds its own ticker
  calling `Flush()`.
- `os.File.Sync()` per Append would murder the SD card — that is exactly
  what batching exists to avoid; never "simplify" to sync-per-write.
- Rotation must rename-then-create, never copy (copy doubles writes and
  breaks tail-readers).
- Resume-Seq scan must bound its read (tail of newest file only), not read
  the whole journal at startup.
- Do not journal per-tick steady state (plan logs are already on
  `lexa/hub/plan`); journal **transitions** only (05 §9) — the schema has no
  "tick" event on purpose.
- Keep the package importable by `CGO_ENABLED=0` services (stdlib only).

## Things that must NOT change
Nothing at runtime (no consumers). Protected design constraints: AD-005
(journal is the *record*, retained MQTT stays the *bus* recovery mechanism —
this library must not grow restore-state semantics; that is TASK-041's
snapshot); AD-011 (journal failure must never panic or wedge a caller).

## Acceptance criteria
- [ ] `go test -race ./internal/journal/` green; coverage ≥ 90%.
- [ ] Rotation, truncated-tail tolerance, and fsync batching each proven by
      a test.
- [ ] Package comment contains the write budget with arithmetic (bytes/event,
      events/day worst case, total cap, fsyncs/day).
- [ ] Zero consumers: `grep -rn "internal/journal" ~/projects/lexa-hub --include=*.go | grep -v internal/journal` empty.
- [ ] Schema constructors emit stable JSON (golden strings in schema_test.go).

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: none (no protocol surface)
- [ ] Mayhem: none (no runtime change)

## Mayhem scenarios affected
None yet. TASK-050 (disk-full) will exercise the disk-full error path;
TASK-043 uses journal evidence (via TASK-040 wiring) in diagnosis.

## Conformance implications
None now. The `control_adopted`/`cannot_comply_posted` records are the raw
material for utility compliance evidence (2030.5 Response history) — keep
mRIDs verbatim as received.

## Suggested commit message
`feat(journal): append-only NDJSON event journal with rotation + batched fsync (TASK-039)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** journal: flash-aware append-only event journal library (TASK-039)
**Description:** Implements AD-005's journal half as a pure library: NDJSON
schema v1 (controls/dispatches/breach episodes/CannotComply), size rotation,
batched fsync, crash-tolerant reader, documented write budget (RSK-14).
No consumers (wiring = TASK-040). Rollback: revert; nothing imports it.

## Code review checklist
- fsync batching logic correct at both boundaries; no sync-per-write.
- Rotation shift chain has no off-by-one at MaxFiles.
- Error paths return, log edge-triggered, never panic.
- Schema fields snake_case, append-only-friendly, mRID passthrough.
- Write-budget arithmetic checks out.

## Definition of done
Acceptance + regression checklists green; AD-005 note added; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-040 (integration), TASK-041 (snapshot), TASK-050 (disk-full scenario),
backlog: compliance report generator (10_BACKLOG).
