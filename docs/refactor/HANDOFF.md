# LEXA DERMS V1.0 Refactor — HANDOFF

*Written 2026-07-06 by the Principal (Fable) for the successor model. Read
this first, then `docs/refactor/00_MASTER_INDEX.md`. This is the "resume
without prior context" document.*

> **AUDIT ADDENDUM 2026-07-07 (independent post-refactor audit).** An
> independent engineering audit (7 parallel code reviews + first-hand
> verification) scrutinised the frozen V1RC build. It **confirms** the
> structural wins in §2 but found a small set of correctness/safety/security
> defects that are the real V1.0 blockers. **Corrections to this doc are
> inline below (flagged `[AUDIT]`); the sequenced next-sprint execution plan
> is the new §8 — read it before picking up work.** Net: the program is a
> *release candidate*, not V1.0; the gap is a 3–6 week punch list, not a
> redesign.

## 1. Where the program is

The program executes `ARCHITECTURE_REVIEW.MD` via 82 task files in
`docs/refactor/tasks/`. Milestones M0–M2 are **complete and merged**; M3
(P3+P4) is ~95%; M4 (P5 optimizer split) has its **architecture proven in
shadow**; M5 (P6) has most implementables merged. ~70 of 82 tasks done.

**Three repos** (all on `main`, keep them synced):
- `~/projects/lexa-hub` — the product. Hosted: `origin` (GitHub dsizzle83).
- `~/projects/csip-tls-test` — test bench + Mayhem QA. Hosted: `origin`.
- `~/projects/lexa-proto` — shared codec (sunspec/ocppserver/csipmodel/
  derbase). **UNHOSTED by design** (local-only; consumers vendor it +
  pin via `proto.pin`). Hosting it is a human task (AD-003(f)).

## 2. What "done" means here — the crown-jewel facts

- **Reconciler (R1/M2):** all 3 device classes (battery/solar/EVSE) run
  under one Device Reconciler on the bench; 4 convergence mechanisms →
  1; legacy machinery deleted (−957 LOC). 10-cycle soak 0.1 FAIL/cyc.
  `[AUDIT]` Honest count is "4 → 2 + a reporting chain" (`applyRestoreRule`
  survives as intent source). Two confirmed defects in the *new* single path
  — a restart/staleness fail-open (solar can seed RESTORE over an active cap)
  and device-level non-convergence never reaching CannotComply (empty MRID).
  Both masked on the bench by FAST-mode content churn. → §8 WS-2/WS-4.
- **Constraint controller (R4/P5):** the compliance layer (export/import/
  gen constraints) reproduces the legacy cascade at **0 shadow divergence**
  on hardware. IT IS IN SHADOW — `constraint_shadow=true`, legacy cascade
  is still authoritative. See §4 for how to make it live.
- **Utility time (W4):** one `internal/utilitytime` owner. **Shared codec
  (W3):** one `lexa-proto`, CI-pinned. **Security (W7):** broker ACLs +
  API bearer-token + OCPP SP2 all implemented (SP2 flip runbook in
  BENCH.md). **Persistence (W5):** journal + breach snapshot.
  `[AUDIT]` Security *mechanisms* are well-built but ship **OFF by default**:
  the shipped `configs/*.json` leave MQTT anonymous, `lexa-api` unauthenticated
  on `:9100` (0.0.0.0), and OCPP plaintext/no-auth — the last directly
  contradicts the CLAUDE.md "OCPP SP2 is the product default" invariant
  (`cmd/ocpp/config.go` fail-louds on `reconciler` but not the SP2 fields).
  Snapshot restore also ships `enabled:false`. → §8 WS-1/WS-4.

## 3. The RESIDUAL — what is NOT done and exactly why (with runbooks)

### Genuinely blocked (external/time — a bigger model cannot shortcut these)
- **Constraint shadow→active flips + TASK-066 (delete cascade):** the
  constraint controller is proven in shadow but must NOT be flipped to
  authoritative without the ≥1-week clean-shadow soak (03 §P5). RUNBOOK:
  keep `constraint_shadow=true` on the bench for ≥1 week, run daily
  campaigns, confirm `lexa_constraint_shadow_divergence_total` stays ~0
  (triage the one known latent export-axis boundary divergence 061 found);
  THEN set the constraint stack authoritative per each constraint (config
  flip per axis, FIX-F single-author suppression must land first — see
  TASK-060/062/063 notes), run a full + STOCK campaign per flip; only
  after all axes flip clean does TASK-066 delete the legacy cascade.
- **TASK-075 golden vendor fixtures:** needs ≥2 real vendor inverters +
  1 EVSE on the bench to capture byte-exact register images. Cannot be
  fabricated. Order hardware; capture procedure is in TASK-075.
- **TASK-078 30-day soak:** 30 days wall-clock. Rig + runbook exist
  (`scripts/cert-churn-soak.sh` sibling; TASK-078). Start it; report at 30d.
- **TASK-073 cert-rotation 24h churn soak:** code done + `scripts/
  cert-churn-soak.sh`; run the 24h churn on the bench watching for
  segfault/fd-leak (§8.6).

### Implementable — status at handoff
- **062 session consolidation: DONE** (all guard state in typed constraint
  Sessions incl. BatterySafetySession w/ Evaluate + arbiter-bypassing
  EvaluateFast; DefaultOptimizer has no undocumented inter-tick state).
  Left ≤1-tick wrong-direction lag for 063 (economic-tick reads this-tick
  plan; pre-arbitration constraint reads last-committed — reserve/critical
  paths are bit-faithful). SHADOW.
- **067 engine consolidation: DONE** (5 mutexes → 1 engineState, single
  writer, atomic pointers + bounded cmdCh; engine_test.go unchanged, -race
  clean; Wake/EvaluateSafety preserved). RADIOACTIVE — needs the FAST
  campaign gate before it's trusted live (batched at the next bench wave).
- **071 poll-rate: DONE** (honor advertised pollRate in STOCK, FAST bench
  keeps override; AD-014). Backlog refinement: per-class scheduling (honor
  mode currently uses the most-conservative class, ~900s — a control-heavy
  utility may want DERControlList's faster rate; the original pollsched.go
  design does this).
- **076 scenarios-as-data engine: DONE** (spec_v:1 JSON + compiler + oracle
  registry; scenarios addable WITHOUT a Go rebuild — this is your tool for
  adding QA cheaply). 077 migrates the Go scenarios to specs.
  `[AUDIT 2026-07-07]` **077 is DONE + MERGED** (`csip-tls-test@4195d4e`),
  not "next": 24 specs live in `qa/scenarios/*.json`, their Go twins deleted;
  **34 Go `ID:` literals remain** (the retained-in-Go family per
  `docs/qa-spec-migration.md`), NOT ~60.
- **063 economic-layer isolation: DONE + MERGED.** Full constraint stack
  (safety+compliance+economics) now runs in the SHADOW wrapper; economics
  are PointDemand proposals clamped under compliance by a STRUCTURAL arbiter
  tier-fold (fixed a real 058 bug: economics could override a compliance cap
  via global-min). Golden full-stack shadow parity = 0 divergence OFF-CAP.
  Closed 062's ≤1-tick safety lag (post-arbitration safety). ON-CAP
  divergence characterized in `docs/refactor/notes/TASK-063-seam-review.md`
  → owned by 064. SHADOW (legacy cascade still authoritative).
- **064 constants→plant: DONE + MERGED.** Bench constants → 057 plant-model
  params (identical bench behavior; `docs/refactor/notes/TASK-064-plant-
  parameters.md` has the swap map). evSafeCount now has ONE owner
  (EVImportCooldown). Off-cap 0 divergence, compliance ceiling bit-faithful
  on-cap; the residual (economics EV-current axis) is irreducible in a
  layered design and vanishes at the flip. **STOCK caveat:** the inverter
  ramp is now per-wall-second (bit-identical at FAST 3s, cadence-correct at
  STOCK 15s) — needs a STOCK spot-check at the flip gate.

**R4 CONSTRAINT CONTROLLER: architecturally COMPLETE in shadow (058–064).**
Safety+compliance+economics reproduce the live cascade at 0/bit-faithful
divergence. What remains is ONLY the soak-gated flip + 065 (multi-device)
+ 066 (delete cascade). The god-file (`optimizer.go` ~2289 lines) stays
LIVE until the flip — that release-checklist box is correctly still OPEN.
- **065 multi-device: NOT STARTED** — 2nd sim instance (modsim/evsim on a
  free port), breach-list + per-device sessions, nameplate-share split.
- **077 scenario migration: DONE + MERGED** `[AUDIT 2026-07-07 correction —
  this line previously read "NOT STARTED", which was already false when this
  doc was finalised]`. 24 scenarios migrated to `qa/scenarios/*.json` + Go
  twins deleted (`4195d4e`); 34 Go literals deliberately retained (per-tick
  computed / malformed-delayed-fault / `mayhem_world.go` / `mqtt_scenarios.go`
  families — see `docs/qa-spec-migration.md`). Remaining migration is
  OPTIONAL backlog, not a V1.0 gate.

**How to finish the constraint stack (the R4 endgame for a successor):**
062+063+064 complete the SHADOW controller; then the flip sequence in §3
(soak → per-axis active flip → 066 delete cascade) makes it live. Do NOT
flip without the soak. The 057 adaptive detection window is what removes
the battery-charge-disabled boundary flake once active.

## 4. HOW TO WORK HERE — process discipline (learned the hard way)

1. **ONE agent per repo working tree.** A bench/deploy agent owns the
   MAIN checkout of a repo exclusively; every other concurrent agent uses
   `git worktree add`. Two agents in one checkout WILL corrupt each other
   (happened twice; recovered both times, but don't).
2. **Be ON `main` before merging to main.** Committing merges while the
   checkout is on a `task/*` branch leaves the local `main` ref behind
   `origin/main` (pushes go to remote main via `HEAD:main` but local main
   stagnates). Always `git checkout main`, verify `git branch --show-current`,
   then merge. Push with `git push origin HEAD:main` and CHECK the output
   (don't `-q ... 2>/dev/null` — refusals matter).
3. **Merge the agent's `task/NNN-*` branch, NOT `worktree-agent-<id>`.**
   The auto-created worktree branch sits at the base commit; the agent's
   work is on `task/NNN`. Verify content landed after merging.
4. **Never `rm -rf` a shared worktree parent** (e.g. `~/projects/lexa-hub-wt`)
   — it deletes other agents' worktrees. Use `git worktree remove <exact-path>`.
5. **Union-merge conflicts drop braces.** After resolving a `<<<<<<<`
   conflict by stripping markers, ALWAYS build — a lost `}` compiles-fails.
6. **QA gating (per deadline amendment, 05 §12):** full 51-scenario campaign
   for reconciler flips / legacy deletion / optimizer-constraint FLIPS
   (active, not shadow) / phase exits. Everything else: unit tests + a
   targeted `--only` subset; batch a subset campaign at wave boundaries.
   Shadow/additive/unwired code needs NO campaign (cite 05 §12 exception).
7. **Agents stall on monitor-and-exit.** If an agent arms a Monitor/
   background wait and ends its turn, it won't reliably resume — re-send it
   a "poll synchronously in a bounded foreground loop" message. Every
   long-campaign agent hit this.

## 5. BENCH — state + gotchas (full topology: docs/BENCH.md)

- hub Pi 69.0.0.1 (root, passwordless sudo, ssh dmitri@); sims .10/.11/.12/
  .14; desktop 69.0.0.20 (gridsim :11111/:11112, dashboard :8080).
- Current state: FAST (engine 3s/poll 2s), all reconcilers ACTIVE,
  `constraint_shadow=true`, broker ACL + API auth ON, mqttproxy on :1882.
- **`deploy-hub-pi.sh` RESETS timing to STOCK + overwrites configs +
  resets metrics_addr/reconciler/mqttproxy Pi-side enables** — after ANY
  hub deploy re-run `scripts/hub-replay-tune.sh fast` AND re-set the
  reconciler/constraint_shadow/metrics_addr configs. The security flips
  are opt-in flags: `--enable-api-auth --enable-mqtt-acl [--enable-ocpp-sp2]`.
- **mosquitto passwd MUST be `root:mosquitto 0640`** (the privilege-dropped
  broker reads it) — NOT root:root 0600 (I got this wrong once; strace-proven).
- **ACL'd broker DROPS unauthorized publishes silently (PUBACK still
  arrives!)** — verify delivery by SUBSCRIPTION, never publish success.
  `lexa/desired/*` grants are per-class in mosquitto-lexa.acl.
- `csip-dashboard` unit execs `bin/dashboard` — `go build -o bin/dashboard
  ./cmd/dashboard` before restarting it.
- QA baselines to defend: FAST ~34P/16D/0F/0B; STOCK M0 0.8F/cyc; M2 soak
  0.1F/cyc. `battery-charge-disabled` is a known ~1/10 oracle-boundary
  flake (export-detection latency; designed out by 057 plant model + the
  R4 adaptive window when the constraints flip active — NOT a regression).

## 6. Human action items (need credentials/hardware I don't have)
- Enable GitHub branch protection on both repos (AD-012 has the command).
- Create `LEXA_HUB_RO_TOKEN` + `CSIP_TLS_TEST_RO_TOKEN` PAT secrets for the
  cross-repo CI lockstep/pin gates.
- Host `dsizzle83/lexa-proto` + run the hosted-flip checklist (AD-003(f)).
- Order vendor hardware for TASK-075.

## 7. Key decisions (docs/refactor/02_ARCHITECTURE_DECISIONS.md)
AD-001 distributed topology · AD-002 reconciler · AD-003 shared module +
(e) vendoring + (f) hosted-flip + (g/h) fork disposal · AD-004 utilitytime
· AD-005 journal · AD-006 bus envelope · AD-007 constraint controller +
plant model · AD-008 security · AD-009 keep+harden httpwire (chunked
added; net.Conn shim backlogged) · AD-010 curve functions DE-SCOPED for
V1.0 · AD-012 GitHub hosting · AD-013 desired-state schema.

## 8. NEXT SPRINT — V1.0 punch list (from the 2026-07-07 independent audit)

The V1RC gate correctly stopped at **conditionally ready**. This section is
the execution plan to get from RC to a defensible `v1.0.0` tag. It is
ordered: **do the workstreams in number order** — WS-1..WS-5 are the
must-fix blockers, WS-6..WS-9 are the required gates/cleanup, WS-10+ is the
post-tag structural work. Effort is S(≤½d) / M(1–3d) / L(1–2w). Every
control-plane change is radioactive-zone (05 §12) → full campaign before
merge. Sprint exit = every ◆ box in `09_RELEASE_CHECKLIST.md` green.

**Provenance:** each item cites the confirmed finding + the file it lives in.
"Confirmed" = code-verified this audit. Do not re-litigate whether it's real;
verify the `file:line` still holds (symbols authoritative, lines are hints)
and execute.

### WS-1 — Security fail-closed by default `[Confirmed · S–M · no dep]`
The mechanisms exist and are good; only the *defaults* are wrong. This is
config + a startup guard, not new crypto.
1. **OCPP** (`lexa-hub/cmd/ocpp/config.go`): `loadConfig` fail-louds on
   `reconciler` but NOT on the SP2 fields. Add: if not an explicit bench
   profile (`OCPP_PROFILE=bench` env or `bench:true` config key), REFUSE to
   start when `cert_path`/`key_path`/`basic_auth_user`/`basic_auth_pass` are
   empty. Ship `configs/ocpp.json` with SP2 populated (placeholder paths +
   a deploy-provisioned secret), inverting the current blank default. This
   also closes the CLAUDE.md-vs-code contradiction (the invariant already
   *claims* SP2 is the product default).
2. **lexa-api** (`cmd/api/config.go`): default `listen_addr` to
   `127.0.0.1:9100` (currently `:9100` = 0.0.0.0); refuse non-loopback bind
   with an empty `api_token_file` unless `bench:true`.
3. **MQTT** (`scripts/deploy-hub-pi.sh`): make `--enable-mqtt-acl` +
   `--enable-api-auth` the DEFAULT; add an explicit `--bench-insecure` opt-out
   for the air-gapped LAN. Broker default target `allow_anonymous false`.
4. **systemd** (`systemd/*.service`): add `NoNewPrivileges=yes`,
   `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
   `RestrictAddressFamilies=AF_INET AF_UNIX` to all six units (they already
   run `User=lexa`; this bounds blast radius). Verify each still starts +
   passes the watchdog wedge test.
- **Gate:** re-run the 09 Security ◆ boxes against the SHIPPED config (not the
  flag-enabled one). Add a test asserting a product-profile start with blank
  creds FAILS. Update CLAUDE.md if any default text changes.

### WS-2 — Desired-doc restart/staleness fail-open `[Confirmed × 2 audits · M · no dep]`
Root cause: hub re-stamps `IssuedAt` only on content change
(`cmd/hub/desired.go` ~242/407/528, `desiredContentEqual` gate), but the
reconciler hard-rejects any doc older than `StaleAfter`=300s
(`internal/reconcile/reconcile.go:203`). A `lexa-modbus` restart >5 min after
the last optimizer change ⇒ device adopts nothing; solar's
`seedRestoreCeiling` (`cmd/modbus/reconcile_solar.go:132`) then installs the
RESTORE (open) ceiling as standing intent over a still-active export cap.
- **Fix (pick one, prefer A):**
  A. **Heartbeat re-stamp.** In each hub actuator, refresh `IssuedAt` (and
     re-publish retained) on a `≤StaleAfter/2` cadence even when content is
     unchanged, so the retained doc is never older than the reject bound.
     Cheapest, closes it fully. Keep `desiredContentEqual` for the
     *write-to-hardware* dedupe (don't churn the register), but decouple it
     from the *publish-freshness* decision.
  B. **Republish-on-StaleDesired.** Have the reconciler's `StaleDesired`
     report (currently suppressed when `desired==nil`, `reconcile.go:332`) reach
     the hub via the reconcile report topic and trigger a fresh publish.
     More moving parts; A is preferred.
- **Solar fail-open (independent, do regardless):** `seedRestoreCeiling` must
  NOT seed restore when the last *known* hub intent was a cap. Seed to the
  last-adopted ceiling if one exists in the retained doc; only seed restore
  for a genuinely never-commanded inverter. Fail-closed = hold the cap.
- **New QA scenario (WS-6 will need it):** `consumer-restart-after-quiescence`
  — hold static optimizer output >5 min (STOCK-realistic), restart
  `lexa-modbus`, assert the standing cap is re-adopted and NO restore write
  hits the inverter. This is the scenario whose absence hid the bug.
- **Gate:** full FAST campaign + the new scenario 10× solo; INV-EXPORT must
  hold across the restart.

### WS-3 — Mayhem sensor-availability blind spot `[Confirmed · M · no dep, but gates WS-6]`
The safety net vacuous-passes when a NON-meter probe is dead:
`breachOver` returns −1 ("no breach") on `!SolarOK`
(`cmd/dashboard/mayhem.go:~572`), but only `!GridOK` counts into
`SampleErrors` / the INCONCLUSIVE gate. A sim outage converts real breaches
into PASSes; `invSOC`/`invExport` (`cmd/dashboard/invariants.go`) share it.
- **Fix:** make probe-availability *constraint-aware*. For each oracle, count
  the probe it is actually judged from (solar for genLimit, battery for
  INV-SOC, meter for export) into a per-constraint availability tally, and
  force **BLIND** (never PASS) when the judging sensor was absent beyond a
  threshold fraction of the hold window. Same for the safety audit.
- **Run-integrity hardening (batch here, all `cmd/dashboard`):** reject a
  malformed `/api/qa/start` body (`mayhem.go:269` currently
  `_ = json.Decode`) instead of silently launching the full hostile suite;
  `recover()` the `go d.run(...)` goroutine (`mayhem.go:327`) so a diagnoser
  panic doesn't kill the dashboard mid-campaign; mark abort-truncated
  verdicts as such; make delayed-fault goroutines context-cancellable so
  teardown is last-writer-wins.
- **Gate:** unit tests for the new BLIND paths; a deliberately-killed-sim run
  must report BLIND, not PASS. **This must land before WS-6** — the release
  campaign's verdicts are only trustworthy after this.

### WS-4 — Restart-safe compliance reporting `[Confirmed · M · dep: none, pairs with WS-2]`
Three linked gaps that corrupt the utility-facing record across a restart:
1. **Snapshot ships off.** `configs/hub.json` `snapshot.enabled:false`. Flip
   to `true` for V1.0 (the write path is already atomic tmp+rename +
   validated restore, `cmd/hub/snapshot.go`). Soak it first per its rollout
   note, then default-on.
2. **Northbound responseTracker RAM-only** (the acknowledged TASK-041 NB
   half, `internal/northbound/responses/tracker.go` — `posted`/`alerted`
   maps, no persistence). A NB restart between the hub's compliance-alert
   edge (non-retained) and the POST loses the CannotComply the utility is
   owed, and re-POSTs duplicates for still-live events. Persist
   `posted`/`alerted` (small NDJSON or reuse the journal). **DECISION NEEDED
   (put an AD in 02):** is this inside the 09 "Restart safety" ◆ gate or
   backlog? The audit's read: it is inside the gate — a lost CannotComply is
   a regulatory-record defect. Currently mis-filed in `10_BACKLOG.md:180`.
3. **Device non-convergence never reaches CannotComply.** Every desired doc is
   stamped `MRID:""` (`cmd/hub/desired.go:76`), and `breach.go` drops
   empty-MRID Begins by design → the reconciler's device-level evidence
   source is inert; only the optimizer meter path reports. Either plumb the
   real controlling MRID/source into the desired doc (so an EVSE that floors
   at 6 A against a 4 A cap with no meter-visible breach IS reported), OR
   explicitly document in AD-002/CLAUDE.md that CannotComply is meter-path-only
   for V1.0. **Note:** fixing this exposes a latent second bug — a retained
   `NonConvergedBegin` outliving its episode across a reconciler restart
   re-seeds a phantom episode (`reconcile_shell.go` retained report +
   `breach.go:263`); fix both together (End-on-restart reconciliation).
- **Gate:** `hub-restart-mid-cap` + a new `northbound-restart-mid-breach`
  scenario (kill NB between alert edge and POST) must post exactly one
  CannotComply per episode; snapshot-on and snapshot-off campaigns.

### WS-5 — Resolve the optimizer honestly `[Confirmed · S now / L later · gates the god-file ◆]`
The 2,289-line `optimizer.go` is the SOLE live control core; the constraint
Stack is shadow-only and its most safety-critical paths have zero hardware
hours. For V1.0 you do NOT have to finish the flip — but you must stop
carrying it as "done" and de-risk the shadow:
1. **Now (S, ship in V1.0):** wrap the shadow candidate `Optimize` in
   `recover()` with a disable-on-panic latch (`constraint/shadow.go:254-258`
   runs inline on the live control goroutine with NO recover — a panic in
   ~4,700 lines of constraint code kills the process controlling hardware
   during the ≥1-week soak). This is the single highest-value shadow fix.
2. **Now (S):** correct the flip gate. The "confirm divergence stays ~0"
   runbook in §3 is **unsatisfiable** — TASK-063/064 notes document an
   irreducible on-cap economics/EV-current divergence. Rewrite the gate as
   **per-axis** carve-outs (0 off-cap; on-cap ≤ characterised residual per
   `notes/TASK-063-seam-review.md`) BEFORE anyone runs the soak, else it
   blocks forever or gets waved through by judgment. Also triage the one
   live battery-axis divergence 061 caught at SOC 10.57% — still open.
3. **Now (S):** before ANY flip, shadow- or at least bench-exercise the
   Stack's Tier-1 fast-safety path — `Wrapper.EvaluateSafety` delegates to
   legacy ONLY (`shadow.go:267-272`), so `Stack.EvaluateSafety`/`EvaluateFast`
   have unit tests but zero bench hours. Add a shadow-safety diff or a
   dedicated bench pass. Same for the export EV-current emission (deferred in
   shadow) and the arbiter's contradictory-cap collapse.
4. **Later (L, post-tag):** finish P5 — physically split `optimizer.go`,
   flip one axis at a time behind the corrected gate, then TASK-066 delete
   the cascade. This retires the dual-implementation maintenance tax.
- **V1.0 decision (AD in 02):** V1.0 SHIPS ON THE LEGACY CASCADE. Say so in
  the release notes; the god-file ◆ box stays OPEN and that's honest.

### WS-6 — Run the campaigns the checklist already requires `[S–M · dep: WS-1..WS-5 merged]`
The V1RC gate ran ONE FAST cycle. The ◆ boxes need: **10-cycle FAST + 10-cycle
STOCK, 0 FAIL / 0 BLIND**, DEGRADEDs ⊆ ledger. Run AFTER WS-1..WS-5 land (so
the campaign exercises the fixed system) and AFTER WS-3 (so verdicts aren't
vacuous). Also: re-confirm FINDING-A on a real redeploy (assert `lexa-api`
stays active through `power-cut-retained-rollback`) and tune the ~40s
rollback export-breach window (WS-2's freshness fix should shrink it).
STOCK is mandatory — the constraint ramp is now per-wall-second and the STOCK
dynamics have NEVER been campaigned (TASK-064 STOCK caveat).

### WS-7 — CI + process gates `[S · no dep, do early in parallel]`
- Add `gofmt -l` (fail on non-empty) + golangci-lint to BOTH repos' CI; 33
  files are currently dirty. Add `-race` to `csip-tls-test` CI (it has none;
  `cmd/dashboard` is concurrency-heavy). Give `lexa-proto` a minimal CI
  (build + `go test ./...`) — today a breaking codec change is undetected
  until a paired bump.
- Content-verify the vendor pin in CI (hash `vendor/lexa-proto` vs the pinned
  commit), not just pin-vs-pin — `check-proto-pin.sh` (a) can pass with a
  stale vendor tree, reopening MTR-4. `--verify-vendor` exists; make it CI.
- Human items unchanged (§6): branch protection, PAT secrets, lexa-proto
  hosting — still blocking the "◆ CI green" and "◆ main protected" boxes.

### WS-8 — SOM timezone safety `[Confirmed · S · no dep]`
TOU boundaries key on `t.Hour()` in the process's local zone
(`internal/orchestrator/costmodel.go`, `planner.go`) with NO `LoadLocation`/TZ
config anywhere. A Pi reimaged to UTC silently misprices and mis-times peak
discharge every evening, no alarm. Add a `tariff_zone` config + a startup
assertion that the SOM zone matches it (CLAUDE.md already documents the
requirement — TASK-079 — but nothing enforces it). Alarm on mismatch.

### WS-9 — Reliability half-failures + observability `[Confirmed · M · no dep]`
- **Alive-but-deaf:** `lexa-ocpp`/`lexa-api` gate their watchdog kick on
  `IsConnected()` (true while reconnecting) → a long broker outage leaves
  them alive doing nothing, contradicting their unit docs. Either restart on
  sustained outage or export a distinct "deaf" signal. Supervise mosquitto
  for wedges (it's `Type=simple`, unsupervised).
- **Paho resume order:** set an ordered store + bounded `SetWriteTimeout` in
  `mqttutil` so an offline-queued stale retained desired doc can't land last
  on reconnect (random `MemoryStore` order today).
- **Metrics gaps:** promote `journal` drop counters and `Engine.cmdDropped`
  (`engine_state.go:107`, log-only today) to `/metrics` — "journal silently
  dropping forensics for a week" must be diagnosable without journal archaeology.

### WS-10+ — Post-tag structural (backlog, not V1.0)
Finish P5 flip (WS-5.4); plant-model discovery probe; fleet-scale plumbing
(measurement batching, `registries sync.Map` deletion, topic-scheme v2);
multi-vendor + golden fixtures (TASK-075) + third-party conformance;
30-day soak (TASK-078 — start EARLY, a redeploy resets the window);
finish the 34-scenario Go→spec migration if desired.

### Doc-hygiene sweep (do alongside WS-7, S)
Beyond this addendum's inline fixes: normalise the ~18 stale "unmerged" task
status headers (every claimed SHA is in `main` — both repos have zero
unmerged branches); refresh the `00_MASTER_INDEX` P3 row (038/041/042/043 are
merged, not "IN PROGRESS/unmerged"); soften the index's "FINDINGS A+D FIXED +
bench-confirmed" to "fix bench-traced, RE-CONFIRM at next deploy" (restart-
safety ◆ is still OPEN); de-dupe `10_BACKLOG.md:177-178`; untrack runtime
clutter (`dashboard.log`, `text_reader.txt`, 9 stale `qa-mayhem-2026061*.md`);
resolve the single repo TODO (`lexa-hub/cmd/hub/main.go:769` milli-currency).

### Sprint sequencing summary
```
Parallel from day 1:  WS-1 (sec)  WS-3 (harness)  WS-7 (CI)  WS-8 (tz)  doc-sweep
Then (control-plane, one-at-a-time, campaign each):  WS-2 → WS-4 → WS-5(1-3) → WS-9
Gate (after the above merge):  WS-6  10-cycle FAST + STOCK, re-confirm FINDING-A
Tag v1.0.0 on legacy cascade (WS-5 AD).  WS-10+ is post-tag.
```
Blockers that are NOT in the sprint's control (start now, report later):
TASK-078 30-day soak, TASK-073 24h cert-churn soak, TASK-075 vendor hardware,
and the human items in §6. None gate the *code*; they gate the *tag*.
