# TASK-021 — Sims consume the shared sunspec codec; delete the bench fork; bench validation

*Status: DONE (2026-07-05, pending-sha — see final addendum commit) · Phase: P1 · Effort: L (≈6–8 h) · Difficulty: med · Risk: med*

## Objective
`csip-tls-test` no longer contains a SunSpec codec: every bench consumer imports
`lexa-proto/sunspec` (and `lexa-proto/modbus`), the forked
`internal/southbound/{sunspec,modbus}` packages are deleted (plus `derbase` if orphaned),
sims are rebuilt and redeployed to the Pis **in the same session as a hub deploy**
(MTR-4), and a full Mayhem campaign holds the baseline.

## Background
After TASK-020, the product consumes `lexa-proto/sunspec`; the bench still compiles its
older fork. Verified bench importers of `csip-tls-test/internal/southbound/sunspec`:

- **Live (must be re-pointed):**
  - `sim/southbound/{battery.go,meter.go,sim.go,solar.go}` (+ `battery_test.go`,
    `solar_test.go`, `faults_test.go`) — the register-level world model all four device
    sims share; it uses codec constants/offsets to lay out the registers the sims serve.
  - `sim/modsim-conformance/main.go` — the Modbus conformance runner
    (`-device inverter|battery|meter`).
  - `tests/modbus_conformance_test.go` — conformance logic tests (`go test ./tests/`).
  - `internal/southbound/derbase/derbase.go` (bench fork) — itself imported by the bench's
    `internal/southbound/{battery,inverter}` driver forks.
- **Monolith-orbit (deleted by TASK-010, else re-point):** the bench driver forks
  `internal/southbound/{battery,inverter,meter,registry,device}` are imported only by
  `cmd/hub` (obsolete monolith), `internal/bridge`, `internal/orchestrator/adapters`,
  `sim/orchestrator/main.go`, and `sim/modsim-client/main.go` (a Pi-side Modbus
  validation CLI).

The bench fork is the OLD codec generation (hand-rolled structs, `der1547.go` 948 lines);
the shared module carries the product's layout-engine generation. The sims' world model
must move onto the shared generation — this is exactly where a semantic disagreement
missed by TASK-020's disposition would surface as sims and hub disagreeing about register
meaning. That is a *feature*: it is the last chance to catch it before the fork is gone.

Note: `sim/southbound/battery.go`/`battery_test.go` had uncommitted QA-arc changes
(batsim `Ena` handling, 2026-07-03); TASK-001 committed them — verify before starting
(`git log -1 -- sim/southbound/battery.go`).

## Why this task exists
W3/D4: as long as the bench fork exists, every register-map change must be made twice and
CI cannot prove they match. Deleting the fork (not just deprecating it) is what kills the
MTR-4 class. Bench validation ×3 device types is the RSK-02 backstop for the whole phase.

## Architecture review sections
W3, D4, R2, §9 self-confirmation, §14 item 4; 02 AD-003; 08 RSK-02/16; 07 GAP-07/13.

## Prerequisites
- TASK-020 DONE (shared codec exists; disposition doc available).
- TASK-010 status known (determines whether the monolith-orbit importers still exist).
- Bench in FAST mode; hub deployable from lexa-hub HEAD.

## Files
- **Read first:** `docs/refactor/notes/TASK-020-sunspec-disposition.md`;
  `sim/southbound/sim.go` (world-model structure); `sim/southbound/battery.go`
  (`M123_WMaxLimPct_Ena` usage — codec constants the world model depends on);
  `tests/modbus_conformance_test.go`.
- **Modify:** all importers listed above (import rewrites; API deltas where the old
  fork's identifiers don't exist in the shared codec); `go.mod` (require lexa-proto).
- **Create:** nothing new (notes appended to the TASK-020 disposition doc).
- **Delete:** `internal/southbound/sunspec/`, `internal/southbound/modbus/`;
  `internal/southbound/derbase/` and the driver forks
  `internal/southbound/{battery,inverter,meter,registry,device}/` **only if** unreferenced
  after TASK-010 (verify with `grep -rl`), otherwise re-point them here — leftover fork
  disposal is TASK-082 (P1 addendum).

## Blast radius
Every device sim's register image (modsim, batsim, metersim — and metersim is the MTR-4
named pair with lexa-modbus), the conformance runner, and the conformance logic tests.
The hub side is untouched but interop-exposed. Dashboards/Mayhem drive the sims via
simapi, so scenario mechanics are indirectly exposed to any register-layout delta.

## Implementation strategy
Map importers → rewrite in dependency order (world model first, then runners/tests) →
build all sim binaries → delete fork → deploy sims AND hub same session → conformance ×3
→ full campaign. The old fork's identifiers may differ from the shared codec's
(generation gap); where an identifier vanished, consult the disposition doc for its
shared-codec equivalent rather than re-adding legacy names to the module.

## Detailed steps
1. Confirm prerequisites: TASK-020 disposition doc exists; `git status` clean;
   `grep -rl "csip-tls-test/internal/southbound/sunspec" --include="*.go" .` matches the
   Background list (investigate any newcomer).
2. Rewrite `sim/southbound/*` imports to `lexa-proto/sunspec`. Fix compile errors using
   the disposition doc's identifier mapping (e.g. model-123 point constants like
   `M123_WMaxLimPct_Ena` — verify the shared codec exports an equivalent; if the shared
   generation expresses it via the layout engine, add a thin constants shim *inside
   `sim/southbound`*, never by re-adding legacy API to lexa-proto).
3. `make test-fast` and `go test ./sim/southbound/...` — the world-model unit tests
   (incl. fault-injection tests) must pass unchanged. Any assertion change = a semantic
   codec delta → stop, take it back to the TASK-020 disposition table.
4. Rewrite `sim/modsim-conformance/main.go` and `tests/modbus_conformance_test.go`;
   `go test ./tests/` green.
5. Handle the monolith-orbit importers: if TASK-010 is DONE they are gone; otherwise
   rewrite the bench `derbase`+driver forks' sunspec imports mechanically (do not port
   logic — their disposal is TASK-082, P1 addendum) or, if trivially orphaned already,
   delete them now with `git rm` in their own commit.
6. Delete `internal/southbound/sunspec` and `internal/southbound/modbus`. Repo-wide
   `go build ./...` green. `diff -rq` between the two repos now finds no `sunspec` twin.
7. Build sims (`make build`, plus arm64 cross-build used by
   `scripts/update-sim-pis.sh`) and rebuild the hub from lexa-hub HEAD (`make build-arm64`).
8. **Same-session deploy (MTR-4):** `bash scripts/update-sim-pis.sh 69.0.0.1 dmitri` and
   `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`; then
   `bash scripts/hub-replay-tune.sh fast`. Sanity: `curl -s http://69.0.0.{10,11,12}:60{20,21,22}/state`
   and `curl -s http://69.0.0.1:9100/status` agree on W/SoC.
9. Conformance ×3: `bin/modsim-conformance -server 69.0.0.10:5020 -device inverter`,
   `-server 69.0.0.11:5021 -device battery`, `-server 69.0.0.12:5022 -device meter`.
10. Full FAST Mayhem campaign; compare to V6 baseline. Rebuild `bin/dashboard`
    (`go build -o bin/dashboard ./cmd/dashboard`) before restarting the dashboard unit —
    it execs `bin/dashboard`, not `./dashboard` (D8 stale-binary trap).

## Testing changes
No new tests. Existing suites are the oracle: `make test-fast`,
`go test ./internal/southbound/...` (until deletion), `go test ./sim/southbound/...`,
`go test ./tests/`, conformance runner ×3, full campaign.

## Documentation changes
- Append the sim-side identifier mapping to `docs/refactor/notes/TASK-020-sunspec-disposition.md`.
- `internal/southbound/CLAUDE.md` (bench): delete or update — the package it documents is
  gone/shrunk.
- Root `CLAUDE.md` directory map: `internal/southbound/` line updated. Leave the
  "Lockstep rule" paragraph for TASK-024.

## Common mistakes to avoid
- Deploying sims without the hub (or vice versa): the deploy gotcha that MTR-4 exists to
  prevent. Same session, always.
- Re-adding legacy identifiers to lexa-proto to make the sims compile — shims live on the
  sim side; the module API is the product generation.
- `pkill -f` over SSH to bounce sims — it can kill your own session; use
  `systemctl --user restart <sim>` (the update script does this correctly).
- Forgetting the dashboard runs from `bin/dashboard` (stale-binary incident 2026-07-03).
- Treating a green campaign as proof of codec correctness — sims and product now share
  ONE codec, so a shared misunderstanding is invisible by construction (RSK-16). Note it;
  TASK-075 addresses it.

## Things that must NOT change
- Sim register images as observed on the wire: `bad_scale` fault mechanics
  (corrupts W_SF on the read path only, `/state` stays truthful — QA_FINDINGS §3),
  0x8000 N/A sentinels, batsim `Ena`/`Conn`/`WMaxLimPct` register behavior
  (QA 2026-07-03 batsim Ena fix — pinned by `export-cap-full-battery`'s choreography).
- Conformance runner behavior/flags (`-device inverter|battery|meter`).
- Ground-truth independence: Mayhem verdicts read sim `/state`, which must keep bypassing
  the codec fault layer.

## Acceptance criteria
- [x] `grep -r "csip-tls-test/internal/southbound/sunspec" --include="*.go" .` → no matches;
      directory deleted. (Also `internal/southbound/modbus` deleted.)
- [x] `make test-fast`, `go test ./sim/southbound/...`, `go test ./tests/` green (also verified
      under `GOWORK=off go test -mod=vendor` — vendor/lexa-proto/{sunspec,modbus} added, AD-003(e)).
- [x] Conformance ×3 device types PASS against live redeployed sims: inverter 19/19,
      battery 22/22, meter 9/9 (one transient MTR-006 timing flake on first run,
      confirmed by immediate re-run — not codec-related, register offsets untouched).
- [x] Same-session hub+sims deploy recorded: lexa-hub `make build-arm64` +
      `deploy-hub-pi.sh 69.0.0.1 dmitri --enable-api-auth --enable-mqtt-acl` (all 6 services
      active) + `hub-replay-tune.sh fast` + `mqtt-chaos.sh deploy` (re-established after the
      hub deploy reset configs) + `update-sim-pis.sh 69.0.0.1 dmitri` (all 4 sims active), one
      session, 2026-07-05. Live gridsim->hub discovery walk verified: posted
      `DERC-SP-ADMIN-1783262982` via gridsim admin, hub adopted it within one discovery tick
      (journal: `discovery OK ... source=event mrid=DERC-SP-ADMIN...`, `response posted:
      Received/Started`, orchestrator ticks show `csip=event(...)`); control deleted afterward
      to restore bench default.
- [x] Full FAST campaign ≤ 0.6 FAIL/cycle, 0 BLIND: **34 PASS / 17 DEGRADED / 0 FAIL / 0 BLIND
      / 0 INCONCLUSIVE** (51/51), within the 32-35P/16-19D/0F band. Targeted register-codec
      set (`solar-bad-scale, battery-wrong-sign, meter-ct-inverted, export-cap-full-battery`)
      ran first: 3 PASS / 1 DEGRADED (battery-wrong-sign — hub correctly posted CannotComply,
      expected outcome for a deliberately-injected wrong-sign fault) / 0 FAIL / 0 BLIND.

## Regression checklist
- [x] `make test-fast` (csip-tls-test) green. (lexa-hub untouched by this task — no product
      code changed, only its Pi deploy was re-run as the MTR-4 lockstep partner.)
- [x] Conformance logic tests green (`go test ./tests/`) — protocol-adjacent: yes (23/23,
      incl. the 701/702/713/704-path adaptations)
- [x] Mayhem: **full campaign** — 34P/17D/0F/0BLIND (see above)
- [x] `hub-replay-tune.sh fast` re-run post-deploy

## Mayhem scenarios affected
None intended. Watch `solar-bad-scale`, `nan-sentinel`, `battery-nan-sentinel`,
`export-cap-full-battery` (batsim Ena choreography), `modbus-exception`, `stale-meter`.

## Conformance implications
This task's conformance runs ARE the evidence that sims still implement SunSpec
correctly on the shared codec. Archive runner output with the PR.

## Suggested commit message
`refactor(southbound): sims consume lexa-proto/sunspec; delete bench codec fork (TASK-021)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Phase 1: bench consumes shared SunSpec codec; fork deleted
**Description:** Import rewrites (world model, conformance runner, tests), fork deletion,
same-session hub+sim deploy, conformance ×3 + full campaign evidence attached. Rollback:
revert; go.work keeps the module importable, and the fork returns via git revert.

## Code review checklist
- No logic edits mixed into import rewrites; shims (if any) live in `sim/southbound`.
- Deletion commit separate from rewrite commits.
- Deploy evidence shows hub and sims same session.
- Campaign + conformance outputs attached.

## Definition of done
Acceptance criteria + regression checklist; docs updated; status headers (this file +
00_MASTER_INDEX) updated.

## Implementation notes (2026-07-05)

**Scope reality-check on step 5 (monolith-orbit importers).** The task's Background assumed
"if TASK-010 is DONE they are gone" for the driver forks (`internal/southbound/{battery,
inverter,meter,registry,device}` + `derbase`). TASK-010 (DONE) explicitly kept these — its own
"Keep list" says "`internal/southbound/` everything else" — because `sim/modsim-client/main.go`
(a live, Makefile-referenced Pi-side Modbus validation CLI) still imports them. So they needed
real repointing, not just verifying absence.

**Generation-gap fallout (anticipated by the disposition doc, materialized here).** Legacy
models (103/120/121/122/123/802/201-203) were a pure import-path swap everywhere — zero
identifier/behavior changes, confirmed by unchanged unit test assertions. The IEEE 1547-2018
models (701-712) are where the two codec generations structurally diverge (hand-rolled offsets
vs. declarative layout engine — disposition doc §2b/§2c), and that surfaced in three places
that had to touch 701-712: `sim/modsim-conformance/main.go`, `tests/modbus_conformance_test.go`,
and `internal/southbound/derbase`. Disposition:
- **Read paths** (measurements, nameplate, SoC/SoH/WHRtg): mechanical swap to the shared codec's
  typed decoders (`sunspec.Parse701/702/713`, `derbase.M701St*` constants shim for the one enum
  the shared codec doesn't symbolize). Same registers, same values, verified by unchanged
  conformance-suite pass counts.
- **The three M704 write paths `ApplyControl` actually calls** (`SetPowerFactor704`,
  `SetConstantVar704`, `SetWMaxLimPct704`) plus the M703 `SetEnterServiceBool` path: adapted to
  the shared layout engine's named-field `View` (`L704.View(regs).SetFloat(...)`) since no
  monolithic-struct M704 encoder exists in this generation (`Parse704` is read-only, by design).
  Read-modify-write-whole-model semantics preserved exactly.
- **The wider M702/705-712 read/write surface** (`SetEnterService`/`ReadEnterService` full-struct,
  `SetDERCtlAC`/`ReadDERCtlAC`, `ReadDERCapacity`, all of `Read/WriteVoltVar/VoltWatt/
  VoltageTripLV/HV/FreqTripLF/HF/FreqDroop/WattVar`, `battery.ReadStorageCapacity`): had zero
  callers beyond their own pass-through wrappers and zero test coverage (verified before
  touching anything). Deleted rather than re-implemented — the shared codec's curve-adopt write
  handshake is a different protocol (staged index + `AdptCrvReq=2` + poll + `Ena=1`, vs. this
  fork's single write + `AdptCrvReq=1`) and the bench M713 layout is a structurally different,
  non-spec field set (disposition doc §2c S3/S5) — reimplementing either would be writing new
  logic against an unexercised spec, which the brief's "do not port logic" instruction and the
  disposition doc's own risk posture (RSK-02, defer design calls) both rule out. Full disposal
  of this fork (design decision on what if anything replaces it) is TASK-082's job, not this
  task's. See `docs/refactor/notes/TASK-020-sunspec-disposition.md` §6 for the full mapping
  table and reasoning.

**Lockstep gate (`scripts/ci/lockstep-check.sh`) — fixed beyond the allowlist.** Running the
gate (as the task requires) revealed it was already broken before this task touched anything:
lexa-hub deleted its own `internal/southbound/sunspec` in TASK-020 and `internal/ocppserver` in
TASK-022, but the script hard-errors if either tracked tree is missing on *either* side, with no
handling for "retired from both repos" (the actual end state AD-003 is driving toward). Patched
the tree-existence check to treat both-sides-missing as in-lockstep-by-retirement while still
failing on an asymmetric one-side-only removal (a real bug class). This is a minimal, targeted
fix, not the full TASK-024 gate retirement — flagged here since the task text only mentioned the
allowlist, not the script, but the gate cannot "still pass" without it.

**AD-003(e) vendor delta.** New `lexa-proto/sunspec` and `lexa-proto/modbus` imports required
`GOWORK=off go mod vendor`; `vendor/lexa-proto/{sunspec,modbus}/` and `vendor/modules.txt` are
part of this change. Verified `GOWORK=off go build -mod=vendor ./...` and the southbound/tests
suites green in vendor mode too.

## Possible follow-up tasks
TASK-024 (pin gate + CLAUDE.md prose swap), TASK-053 (int16/scale generative sweep now
has one codec to target), TASK-075 (golden fixtures/referee), TASK-082 (leftover fork
disposal: driver forks, bench derbase, csip discovery/scheduler fork decision).
