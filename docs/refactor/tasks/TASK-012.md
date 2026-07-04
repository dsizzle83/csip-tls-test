# TASK-012 — Delete `SetCSIPPrograms`/`e.sched` dead dual path

*Status: TODO · Phase: P0 · Effort: M (≈4–5 h + campaign) · Difficulty: med · Risk: med*

## Objective
The engine's unused second CSIP-resolution path is gone: `SetCSIPPrograms`,
`hasDisconnectControl`, the `programs`/`clockOffset`/`sched`/`csipMu` state, and the
dual-source block inside `tick()` are deleted from
`lexa-hub/internal/orchestrator/engine.go`; `Wake()` and the bus-driven (reader) path
are preserved bit-for-bit; a full Mayhem campaign proves nothing moved.

## Background
Verified in `/home/dmitri/projects/lexa-hub/internal/orchestrator/engine.go`:
- `SetCSIPPrograms(programs []discovery.ProgramState, clockOffset int64)` — lines
  198–213. Stores into `e.programs`/`e.clockOffset` under `e.csipMu`, and calls
  `e.Wake()` when `hasDisconnectControl(programs)`.
- Engine fields (lines ~48–52): `csipMu sync.RWMutex`, `programs`, `clockOffset`,
  `sched *scheduler.Scheduler` (constructed at line ~124 `sched: scheduler.New()`).
- `tick()` (line 496): step-2 block (lines ~504–529) snapshots programs under `csipMu`
  and, **only when `len(programs) > 0`**, overwrites `state.ClockOffset` and evaluates
  `e.sched.Evaluate(programs, serverNow)` → `state.CSIPControl =
  FromActiveControl(active)`. The long comment there ("Wire a deployment to exactly one
  source … never both", and "do NOT overwrite the reader's offset") is the review's W6
  split-brain warning in code form.
- `hasDisconnectControl` — lines 626–645.
- **Callers (verified):** production wires only the MQTT reader —
  `cmd/hub/state.go`'s `MQTTSystemReader` fills `state.CSIPControl`/`state.ClockOffset`
  from the retained `lexa/csip/control`. `SetCSIPPrograms` is called by **nothing**
  outside `internal/orchestrator/engine_test.go`. `hasDisconnectControl` has no other
  callers. `Wake()` IS live: `cmd/hub/main.go:171` calls it on an OpModConnect=false
  control (and Tier-1 wake generalization per ADR-0001 depends on it) — **keep**.
- Doc references: `internal/orchestrator/model.go` line 9 has an architecture comment
  mentioning SetCSIPPrograms; engine.go's type-comment (line 28) and field comment
  (line 48) mention it.

This is the radioactive zone (05 §12): one-per-PR, full-campaign-gated, never merged
same-day.

## Why this task exists
Review W6/D3: "a dead scheduler evaluation site inside `tick()`, with its own mutex, is
exactly where a future engineer creates a split-brain control source." R7's first slice;
also simplifies TASK-067 (engine state consolidation) later.

## Architecture review sections
W6, D3, R7, §14 item 15 (partial). Roadmap: 03 P0 ("dead SetCSIPPrograms path removed");
05 §12 (radioactive rules).

## Prerequisites
TASK-002 (CI). Bench in FAST for the campaign. Do not batch with any other
orchestrator/scheduler change (05 §12).

## Files
- **Read first:** `internal/orchestrator/engine.go` (whole file, 670 lines),
  `internal/orchestrator/engine_test.go` (which tests use the deleted API),
  `internal/orchestrator/model.go` (comment), `cmd/hub/state.go` (the live CSIP source),
  `cmd/hub/main.go:166-175` (Wake caller).
- **Modify:** `engine.go`, `engine_test.go`, `model.go` (comment only).
- **Create:** nothing.

## Blast radius
`internal/orchestrator` public API shrinks by one method (`SetCSIPPrograms`) — no
compile-time consumer outside its own tests. `tick()` loses its step-2 dual-source
block; the reader-driven path (`state.CSIPControl`/`state.ClockOffset` as supplied by
`ReadSystemState`) becomes the only source, which is already the production reality.
Engine drops one mutex + three fields + the `scheduler`/`discovery` imports if nothing
else uses them.

## Implementation strategy
Pure deletion with compiler-verified fallout: remove the method, the helper, the fields,
and the tick block; migrate/delete the engine tests that used the API; keep `Wake()`
and every comment about the reader path's clock-offset ownership. Full FAST campaign as
the gate because `tick()` is the control loop's heart even when the deleted branch is
provably dead.

## Detailed steps
1. Re-verify deadness:
   `grep -rn "SetCSIPPrograms\|hasDisconnectControl" --include="*.go" ~/projects/lexa-hub`
   → only engine.go, engine_test.go, model.go-comment. Abort and re-scope if anything
   else appears.
2. `engine.go` deletions:
   - `SetCSIPPrograms` (198–213) and `hasDisconnectControl` (626–645).
   - Fields `csipMu`, `programs`, `clockOffset`, `sched` + the `sched: scheduler.New()`
     construction and the "CSIP state" field-comment block.
   - In `tick()`: the csipMu snapshot and the whole `if len(programs) > 0 { ... }`
     block (lines ~504–529). **Preserve** step 3 onward exactly — note `serverTime :=
     state.Timestamp.Add(time.Duration(state.ClockOffset) * time.Second)` (line ~539)
     consumes the READER's offset and must be untouched.
   - Update the Engine type comment (line 28) and the run()/Wake comments that name
     SetCSIPPrograms; Wake's comment already describes the MQTT-handler use — keep.
   - Remove now-unused imports (`scheduler`, `discovery`) **iff** the compiler agrees —
     check remaining uses first (e.g. `FromActiveControl` lives where? it converts
     scheduler.ActiveControl — if it becomes unused in this package, delete it too;
     verify `cmd/hub` doesn't import it).
3. `engine_test.go`: rewrite tests that drove the engine via `SetCSIPPrograms` to drive
   it via a stub `SystemReader` that fills `state.CSIPControl` (the production shape).
   A test that only exercised the deleted plumbing is deleted; a test that asserted
   behavior (e.g. disconnect wakes the loop) is preserved by re-expressing it through
   the reader + `Wake()` path (cmd/hub's subscribe handler is the live wake site — the
   orchestrator-level test can call `Wake()` directly).
4. `model.go` line 9: fix the dataflow comment to describe the reader-driven source.
5. `go build ./... && go test -race ./internal/...` — green, plus
   `go vet ./internal/orchestrator/`.
6. Deploy to the hub Pi (`make build-arm64`, `deploy-hub-pi.sh`, then
   `hub-replay-tune.sh fast`) and run a **full FAST campaign**:
   `python3 scripts/mayhem.py --dashboard http://localhost:8080`. Gate: ≤ V6 baseline
   (0.6 FAIL/cycle, 0 BLIND), no new DEGRADED signatures.
7. Merge no earlier than the day after writing (05 §12), campaign report attached.

## Testing changes
- Reworked `engine_test.go` (reader-driven equivalents; disconnect-wake preserved).
- Run: `go test -race ./internal/orchestrator/` and full `make test`.

## Documentation changes
- `model.go`/`engine.go` comments (in-code docs).
- 00_MASTER_INDEX status. lexa-hub CLAUDE.md needs no change (it never documented the
  dual path).

## Common mistakes to avoid
- Deleting `Wake()`/`urgentWake` — live (cmd/hub:171; Tier-1 depends on the mechanism).
- Touching the tick's step-3 clock-offset line or the "do NOT overwrite the reader's
  offset" semantics — that comment block guards a real QA class (replay clock-warp,
  TOU under offset). The deletion removes the dual branch, not the reader path.
- Batching this with ANY other optimizer/scheduler/actuator change — campaign
  attribution (05 §12).
- Silently deleting behavioral tests instead of re-expressing them via the reader.
- Forgetting `hub-replay-tune.sh fast` after the deploy.

## Things that must NOT change
- Reader-driven CSIP control flow: retained `lexa/csip/control` → `MQTTSystemReader` →
  `state.CSIPControl` (+ `state.ClockOffset`); serverNow/TOU math in tick step 3.
- `Wake()` semantics (non-blocking, coalescing) and the cmd/hub disconnect-wake wiring —
  backs the cease-to-energize latency behavior (`grid-disconnect` scenario).
- Plan observer ordering (observer → executePlan) — TASK-007's watchdog and the breach
  alert edge logic ride it.
- Everything in `optimizer.go` — zero edits.

## Acceptance criteria
- [ ] `grep -rn "SetCSIPPrograms\|hasDisconnectControl\|e\.sched" --include="*.go"` in lexa-hub → empty.
- [ ] Engine has no `csipMu`/`programs`/`clockOffset`/`sched` fields; `tick()` has no dual-source branch.
- [ ] `go test -race ./internal/...` green with reworked engine tests.
- [ ] Full FAST campaign ≤ V6 baseline; report referenced in the PR.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green
- [ ] Conformance logic tests: unaffected (no protocol change)
- [ ] Mayhem: **full campaign** (radioactive zone) — plus eyeball `grid-disconnect`, `clock-jitter`, `clock-jump-forward` verdicts specifically
- [ ] Hub redeployed + FAST re-tuned; all services active

## Mayhem scenarios affected
None expected — the deleted path never executed in production wiring. Watch
`grid-disconnect` (Wake path), `clock-jitter`/`clock-jump-forward` (offset ownership)
for any drift; a change there means the deletion touched something live — revert.

## Conformance implications
None (scheduler §12.3 evaluation lives in northbound; the deleted engine-side evaluation
was never wired).

## Suggested commit message
`refactor(orchestrator): delete dead SetCSIPPrograms dual-source path (W6/D3, R7 slice 1)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Remove the engine's dead CSIP dual-resolution path
**Description:** Deletes SetCSIPPrograms/e.sched/hasDisconnectControl + tick's dual
branch; Wake() and the reader path preserved verbatim; engine tests re-expressed via a
reader stub. Full FAST campaign attached (≤ V6 baseline). Rollback: single revert.

## Code review checklist
- Diff is pure deletion + test rework + comments; no logic edits in surviving lines.
- Reader-offset comment/semantics intact (reviewer reads tick() before/after).
- Campaign report attached; merged ≥1 day after authoring (05 §12).

## Definition of done
Acceptance criteria + regression checklist + campaign evidence + status headers updated.

## Possible follow-up tasks
TASK-067 (collapse remaining engine mutexes into one state struct — R7 remainder);
TASK-025+ (the reconciler makes the engine's actuation half declarative).
