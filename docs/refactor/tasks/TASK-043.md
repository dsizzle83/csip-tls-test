# TASK-043 — Mayhem: power-cut retained rollback + corrupted-retained scenarios

*Status: CODE COMPLETE, BENCH VALIDATION PENDING (2026-07-06, `task/043-powercut`) · Phase: P3 · Effort: L (≈6–8 h) · Difficulty: high · Risk: low*

**2026-07-06 update:** Both scenarios (`power-cut-retained-rollback`,
`corrupted-retained-control`) plus the broker-store manipulation helpers, the
retained-payload parser, and the custom `power-cut-retained-rollback` verdict
ladder are implemented in `cmd/dashboard/mqtt_scenarios.go` on branch
`task/043-powercut`, with pure-function unit tests in
`cmd/dashboard/mqtt_scenarios_test.go` (`go test ./cmd/dashboard/...` green;
`go build -o bin/dashboard ./cmd/dashboard` green). This was a **code-only**
session per explicit launch instructions — no bench access, no SSH, no
dashboard restart. The Acceptance criteria below that require the live bench
(10× solo verdicts, `--abort` self-restore, full campaign) are **not yet
run** and are deferred to the 081 bench gate. See `docs/QA_FINDINGS.md` §8
for the implementation writeup and the deferred-validation list.

## Objective
Add two Mayhem scenarios that prove (or pin) the retained-message trust
work: `power-cut-retained-rollback` — an unclean broker death resurrects a
superseded retained control from a stale Mosquitto store — and
`corrupted-retained-control` — a hub restarting against a truncated retained
payload while the WAN is dark must regain its control via the TASK-042
re-request path instead of running control-less. Both must be verdict-stable
10× solo; expected-FAIL-until-042 pinning is acceptable.

## Background
Repo `~/projects/csip-tls-test`. Scenario framework: `mayScenario` structs
(cmd/dashboard/mayhem.go:189–202; line refs are hints — re-verify by grep
at execution time; symbol names are authoritative) with
`setup/perTick/evaluate/teardown`;
world-fault wave lives in `cmd/dashboard/mayhem_world.go`; MQTT-bus faults
in `cmd/dashboard/mqtt_scenarios.go` drive the **on-hub mqttproxy**
(`cmd/mqttproxy`, deployed by `scripts/mqtt-chaos.sh deploy`, control API
`http://69.0.0.1:11882`): `/fault {mode: pass|down|latency}`, `/inject
{topic,payload,retain}` (hand-rolled MQTT 3.1.1 QoS-0 publisher straight to
the real broker, cmd/mqttproxy/inject.go), `/reset`. When the proxy is
absent the fault call errors → setup error → INCONCLUSIVE, never a fake
PASS (mqtt_scenarios.go:5–9). SSH to the hub Pi: `d.hubSSH(cmd)`
(mayhem_world.go:91–105; BatchMode probe → INCONCLUSIVE pattern at
mayhem_world.go:451–455; passwordless sudo on 69.0.0.1 per docs/BENCH.md).

Broker facts (lexa-hub/systemd/mosquitto-lexa.conf): distro mosquitto on
the hub Pi, `persistence true`, `persistence_location /var/lib/mosquitto/`,
`autosave_interval 60`, listener localhost-only. Unclean death =
`systemctl kill -s SIGKILL mosquitto` (bypasses the on-shutdown store
flush); a **clean stop** flushes the store — that's the tool for capturing a
point-in-time store copy.

Product behavior under test (TASK-042): stale retained adoption →
enforce-but-verify + alarm + `lexa/csip/rewalk`; corrupted retained →
alarm + rewalk; northbound answers rewalk by republishing last-good +
walking immediately. Existing related scenarios that must not regress:
`mqtt-malformed-control`, `mqtt-stale-retained` (mqtt_scenarios.go:85–117),
`wan-outage-hold`/`-expiry`, `hub-restart-mid-cap`.

Why the existing `mqtt-malformed-control` doesn't cover GAP-02: it injects
the corrupt payload while the hub is RUNNING and holding last-good in RAM,
and northbound republishes within ~5 s (FAST walk) — the harm window is the
hub-restart-against-corruption + WAN-dark combination, which nothing tests.

## Why this task exists
GAP-01: "Mosquitto autosave_interval 60 + power cut can resurrect a control
up to 60 s stale on reboot; the hub adopts it as authoritative" — zero
unclean-death coverage in the suite. GAP-02: corrupt retained + restart =
fail-open-by-omission. These are the P1 rows of 07_QA_GAP_PLAN.

## Architecture review sections
§8.3, §9 persistence/restart family, Top-20 item 12. Roadmap: 07 GAP-01/02
(validation criteria live there); 08 RSK-05; 06 §2 (10× solo,
expected-FAIL pinning precedent: `meter-ct-inverted`).

## Prerequisites
TASK-042 DONE for PASS verdicts (running earlier is allowed with
expected-FAIL pinning — state which mode in the PR). mqttproxy deployed
(`bash scripts/mqtt-chaos.sh deploy`), SSH key auth to dmitri@69.0.0.1,
bench FAST. **Post-TASK-013 note:** once broker credentials/ACLs land, the
rogue `/inject` publisher needs credentials — mqttproxy must be given them
in TASK-013's rollout; record the dependency in the scenario comment.

## Files
- **Read first:**
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (all)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (hubSSH, suppressDefault, diagnoseSurvival, armExportCap)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` (lines 40–210, 440–560, 679–1000: diagnosers; 1934 deleteControls; 2244–2312 injectEnv/postCap)
  - `~/projects/csip-tls-test/cmd/mqttproxy/{main.go,control.go,inject.go}`
  - `~/projects/lexa-hub/systemd/mosquitto-lexa.conf`
  - `docs/refactor/07_QA_GAP_PLAN.md` GAP-01/02
- **Modify:**
  - `~/projects/csip-tls-test/cmd/dashboard/mqtt_scenarios.go` (add both scenarios + broker-store helpers)
- **Create:** none.

## Blast radius
Harness only. The scenarios manipulate the live broker's store and restart
mosquitto + lexa services on the hub Pi — teardown must restore a clean
broker or every later scenario in a campaign inherits a poisoned bus.

## Implementation strategy
Both scenarios use SSH probe → INCONCLUSIVE gating (they need mosquitto
control), `suppressDefault()` where recovery is judged, and
`diagnoseSurvival`/custom ladders. Store manipulation helpers:
`brokerStoreSnapshot()` (clean stop → cp store → start),
`brokerUncleanRestore()` (SIGKILL → cp back → start). Sequence design keeps
every step observable in samples (HubAdopted/AdoptedMRID/AdoptedLimW are
sampled from the hub, mayhem.go:81–85).

## Detailed steps
1. Helpers in mqtt_scenarios.go (via `d.hubSSH`):
   ```go
   func (d *mayhemDriver) brokerSnapshot() error  // systemctl stop mosquitto && cp /var/lib/mosquitto/mosquitto.db /tmp/mayhem-store.db && systemctl start mosquitto
   func (d *mayhemDriver) brokerUncleanRollback() error // systemctl kill -s SIGKILL mosquitto && cp /tmp/mayhem-store.db /var/lib/mosquitto/mosquitto.db && systemctl start mosquitto
   func (d *mayhemDriver) brokerCleanup()         // rm -f /tmp/mayhem-store.db (best-effort)
   ```
   All with sudo; each command idempotent. (systemctl, never pkill —
   BENCH.md gotcha.)
2. **Scenario `power-cut-retained-rollback`** (Category: "Bus persistence
   (INV-EXPORT ground truth)", HoldS ≈ 110):
   - setup: SSH probe; battery full + high PV (`armExportCap` preamble but
     post the CAP later); post cap **A = 5000 W export cap** via
     `d.postCap("exportCap", 5000, 110, …)`; wait for adoption (poll
     samples ~10 s); `brokerSnapshot()` — the store now holds retained A.
     Then `d.deleteControls(0)` + post cap **B = 0 W** (the constraint the
     scenario is judged against: return `&activeConstraint{Typ:"exportCap",
     LimW: 0}`).
   - perTick: keep env injected; at tick ~30 (B adopted+settled), in this
     ORDER: **first** `gridsimOutage(gridsimOutageDown, 30, 0)` (a site
     power cut takes the WAN down at the same instant — physically
     faithful: router still booting), **then** `brokerUncleanRollback()` —
     broker dies uncleanly and comes back serving retained **A (stale,
     superseded)** — then `hubSSH("sudo systemctl restart lexa-hub")` (a
     power cut restarts the hub too — this is what makes the hub re-seed
     from the stale store). The outage MUST be armed before the rollback:
     if a northbound walk fires in between, cap B is republished over the
     resurrected A and the scenario silently no-op-passes. After the
     rollback, assert (setup-quality assertion, error ⇒ INCONCLUSIVE) that
     the retained value the bus serves is cap A — extending the existing
     A≠B check — BEFORE judging the hub.
   - evaluate: custom ladder over samples: (FAIL) hub enforces A —
     `AdoptedLimW ≈ 5000` — and true export sustains > 0 W cap past the
     settling deadline with no alarm; (DEGRADED) stale enforcement bounded:
     hub flagged staleness (post-042 alarm — observable only via bounded
     breach + recovery; keep the ladder measurement-based: breach ends
     within one walk of WAN return); (PASS) export never sustains over B's
     cap beyond `mayConvergeDeadlineS` after the WAN returns and the hub
     ends on B (`AdoptedLimW == 0` tail). Reuse `scanSamples` +
     `invExport`.
   - teardown: `gridsimOutageClear()`, `mqttReset()`, `brokerCleanup()`,
     `deleteControls(0)`; restart northbound? Not stopped — leave running.
3. **Scenario `corrupted-retained-control`** (Category: "Bus persistence
   (fail-closed survivability)", HoldS ≈ 100):
   - setup: SSH probe + mqttproxy probe (`d.mqttReset()` errors ⇒
     INCONCLUSIVE); `suppressDefault()`; armExportCap(100) with cap 0 W;
     wait adoption.
   - perTick: at tick ~15: `gridsimOutage(gridsimOutageDown, 45, 0)` (WAN
     dark — walks fail, northbound holds, fail-closed); tick ~18: inject
     truncated retained payload
     `d.mqttInject(topicCSIPControl, `+"`"+`{"source":"event","exp_lim_w":`+"`"+`, true)`;
     tick ~21: `hubSSH("sudo systemctl restart lexa-hub")` — the hub
     re-seeds from the corrupt retained value.
   - Without 042: hub runs with NO control until the WAN returns AND the
     next walk republishes (~tick 60) — sustained uncapped export = FAIL
     (pins GAP-02). With 042: hub's decode-failure alarm fires + rewalk →
     northbound republishes cached last-good **without a walk** → cap
     restored within seconds; export breach bounded → PASS/DEGRADED.
   - evaluate: `diagnoseSurvival("the corrupted retained control")`;
     teardown: `gridsimOutageClear()`, `mqttReset()`, restore default,
     `deleteControls(0)`.
4. Wire both into `mqttScenarios()`'s returned slice; rebuild
   `go build -o bin/dashboard ./cmd/dashboard`; restart csip-dashboard.
5. Validate: each scenario 10× solo
   (`python3 scripts/mayhem.py --dashboard http://localhost:8080 --only power-cut-retained-rollback` etc.);
   verify teardown left the bench clean after both completion and
   `--abort` (broker running, `/tmp/mayhem-store.db` gone, retained control
   sane: `hubSSH` + `mosquitto_sub -C 1 -t lexa/csip/control` or just run
   `export-cap-full-battery` after and see PASS). Then one full campaign.

## Testing changes
- `go test ./cmd/dashboard/` (existing harness tests; add pure-function
  tests for any new verdict ladder logic).
- HIL: 10× solo each + full campaign; `make test-fast` untouched paths.

## Documentation changes
- `docs/QA_FINDINGS.md` / gaps doc: record verdict history and whether the
  scenarios ran as expected-FAIL pins before TASK-042.
- csip-tls-test CLAUDE.md scenario count if stated.
- Comment in scenario code noting the TASK-013 credentials dependency for
  `/inject`.

## Common mistakes to avoid
- **Stale `bin/dashboard`:** the csip-dashboard unit execs `bin/dashboard`
  — rebuild before restart (D8 incident 2026-07-03).
- SIGKILLing mosquitto severs every lexa service's session at once — they
  auto-reconnect (mqttutil resubscribe replay); give the sequence 2–3 s
  between broker start and hub restart or the hub's connect-retry (5 s
  interval, 30 s timeout — mqttutil.go:85–99) skews timing. That gap is
  only race-free because the gridsim outage is armed FIRST: with the WAN
  up, a northbound walk in the gap republishes B over the resurrected A
  and the scenario no-op-passes.
- The store copy is only valid if taken via CLEAN stop (flush-on-shutdown);
  never snapshot a live store file.
- Teardown ordering: clear the gridsim outage BEFORE judging recovery
  windows; always `deleteControls(0)` so retained state converges to
  "none" before `restoreBench()` runs.
- Don't judge via hub logs; judge via ground-truth sims + sampled hub
  `/status` fields (harness discipline).
- Campaign poisoning: if the broker comes back with BOTH A and B retained
  history, only the LAST retained value per topic exists — the rollback
  design guarantees it's A; assert in setup that A≠B limits (5000 vs 0)
  and, after the rollback, that the retained value observed is A, so
  misordering is detectable before the hub is judged.
- Scenario IDs must not collide with existing ones (46 IDs today — grep
  first).

## Things that must NOT change
- Existing scenario verdicts/baselines, especially `mqtt-malformed-control`
  and `mqtt-stale-retained` (same fault family, different windows) and the
  `wan-outage-*` pair.
- Oracle margins (`mayConvergeDeadlineS`, `mayConvergeHoldS`,
  `invHuntHysteresisW`) — never tuned to make a new scenario pass (06 §4.5).
- INCONCLUSIVE-without-prereq discipline (SSH + mqttproxy probes).
- `restoreBench()` — do not add broker manipulation to the global restore;
  scenario teardown owns it.

## Acceptance criteria
- [ ] Both scenarios listed by `scripts/mayhem.py --list`.
- [ ] Missing SSH or missing mqttproxy ⇒ INCONCLUSIVE with a naming setup
      error (verified by temporarily breaking each prereq).
- [ ] 10× solo each: stable verdicts; post-042 target — rollback: PASS or
      accepted DEGRADED with bounded breach; corrupted: PASS/DEGRADED.
      Pre-042 (if run early): FAIL documented as the pin.
- [ ] After `--abort` at the worst tick (mid-rollback), the bench
      self-restores: mosquitto active, tmp store removed, a follow-up
      `export-cap-full-battery` run PASSes.
- [ ] Full campaign including both ≤ baseline FAIL rate (pins excluded per
      the accepted-FAIL ledger if pre-042).

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) green; `go test ./cmd/dashboard/` green
- [ ] Conformance logic tests: none (harness only)
- [ ] Mayhem: 10× solo each + full campaign
- [ ] `bin/dashboard` rebuilt + csip-dashboard restarted before validation

## Mayhem scenarios affected
Adds `power-cut-retained-rollback`, `corrupted-retained-control`. Watch
neighbors: `mqtt-broker-restart` (clean restart — must stay PASS),
`hub-restart-mid-cap` (shares SSH restart), `wan-outage-*`.

## Conformance implications
None (harness). Exercises the client's 2030.5 fail-closed/re-adoption
discipline end-to-end.

## Suggested commit message
`feat(mayhem): power-cut retained rollback + corrupted-retained scenarios (GAP-01/02, TASK-043)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Mayhem: unclean broker death + corrupted retained control (TASK-043)
**Description:** First unclean-death coverage in the suite: stale-store
resurrection via SIGKILL+store-rollback, and corrupt-retained + WAN-dark +
hub-restart. INCONCLUSIVE-gated on SSH/mqttproxy; abort-safe teardown.
Evidence: 10× solo verdict tables + full campaign report. Rollback: revert;
additive scenarios.

## Code review checklist
- Teardown walked through at every abort tick; broker always restored.
- Store snapshot taken via clean stop; rollback via SIGKILL only.
- Verdict ladders measurement-based (ground-truth sims), no log-grepping.
- No oracle-margin edits; IDs unique.

## Definition of done
Acceptance + regression checklists green; QA docs updated; status headers
updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-050 (disk-full — same SSH/broker family), TASK-013 follow-up (inject
credentials for mqttproxy), backlog: retained rollback variant against the
Phase-2 desired-state topics (RSK-17).
