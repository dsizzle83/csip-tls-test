# TASK-078 — 30-day soak rig: RSS/fd/goroutine trends + chaos background

*Status: TODO · Phase: P6 · Effort: L (≈6–8 h setup) · Difficulty: med · Risk: low*

## Objective
Scripted tooling exists to run and evaluate a 30-day bench soak: per-
service RSS/fd/goroutine time series scraped to CSV, weekly `tc netem`
chaos windows, a zero-watchdog-fire assertion, a weekly report template,
and a disk-space budget for the logs the soak itself produces. The rig is
started once, survives unattended operation, and its first weekly report
is produced. (The full 30-day sign-off is consumed by TASK-081.)

## Background
- GAP-12 (07): "the 92-day replay is clock-warped (~20 h wall);
  fd/goroutine/RSS leaks over weeks are invisible; `registries sync.Map`
  never deletes (latent), wolfSSL churn (§8.6) untested over time."
  Review §9 load/duration family; item 20.
- Data sources (dependencies): TASK-044 added Prometheus `/metrics` to
  all six lexa services (goroutine counts + Go runtime stats come from
  there); RSS/fd are OS-level — scrape `/proc/<pid>/status` (VmRSS) and
  `/proc/<pid>/fd` counts over SSH so the rig also works if a service's
  /metrics wedges (the wedge is a finding, not a blind spot). TASK-052
  built the netem harness (loss/reorder/delay profiles applied via SSH) —
  reuse its profiles for the weekly windows.
- Watchdogs: TASK-007/008 gave all six services `WatchdogSec` +
  `sd_notify`; `systemctl show <unit> -p NRestarts` is the fire counter.
- Topology (docs/BENCH.md): hub Pi 69.0.0.1 (six lexa services + \
  mosquitto, root units, passwordless sudo), sims on .10/.11/.12/.14
  (user units + linger), desktop .20 (gridsim + dashboard, transient
  user units that do NOT survive reboot — the rig must detect and flag a
  desktop reboot rather than silently losing gridsim). SSH `dmitri@`
  everywhere.
- Storage: Pi SD/eMMC — flash wear is a tracked risk (RSK-14; journald
  caps from TASK-009). The soak's own CSVs must live on the DESKTOP, not
  the Pis.
- Steady state during soak: normal bench operation (hub in STOCK timing —
  decide and record; STOCK is the shipped regime and 30 days of FAST is
  10× the tick count but unrepresentative latencies; recommendation:
  STOCK, since the soak validates the SHIPPING configuration — this also
  keeps the bench off the FAST/QA path) with the gridsim default program
  and sims at 1× — plus the weekly chaos windows.

## Why this task exists
GAP-12 / item 20 / 09 hard gate: "30-day soak: flat RSS/fd/goroutine,
zero watchdog fires, netem chaos windows survived." No leak class in this
system is visible in any existing test layer.

## Architecture review sections
§9 load/duration · §11 (resource hygiene, `registries sync.Map` note) ·
§8.6 · GAP-12 · item 20 · 08 RSK-14 · 09 Performance & endurance.

## Prerequisites
TASK-044 DONE (metrics), TASK-052 DONE (netem harness), TASK-007/008
DONE (watchdogs). A 30-day window where the bench is not needed for
campaigns daily (chaos windows + weekly reports coexist with occasional
QA use — document the interference rules in the runbook).

## Files
- **Read first:** docs/BENCH.md; TASK-052's netem scripts (location under
  scripts/ — verify name); systemd unit names on the hub Pi
  (deploy-hub-pi.sh installs them); TASK-044's metrics ports/paths;
  scripts/hub-replay-tune.sh (STOCK mode); RSK-14/TASK-009 journald caps.
- **Modify:** none of the product/bench services (observation-only rig).
- **Create (all in csip-tls-test):**
  `scripts/soak/soak-scrape.sh` (one sample sweep),
  `scripts/soak/soak-start.sh` / `soak-stop.sh` (desktop systemd user
  timer or long-running unit `csip-soak`),
  `scripts/soak/soak-chaos-window.sh` (wraps the 052 harness with a
  bounded schedule),
  `scripts/soak/soak-report.py` (weekly: trends, slopes, assertions),
  `docs/SOAK_RUNBOOK.md` + `docs/SOAK_REPORT_TEMPLATE.md`.

## Blast radius
Additive tooling on the desktop + read-only SSH sampling of the Pis +
scheduled netem windows (which DO perturb the LAN — that's their job).
No product code, no configs on the Pis beyond what 052 already installs.

## Implementation strategy
A desktop-resident sampler (systemd user unit + timer, but note desktop
user units are transient per BENCH.md — use `systemd --user` WITH
`loginctl enable-linger dmitri` on the desktop, and document that a
desktop reboot requires `soak-start.sh` re-run and is visible as a gap in
the CSV) samples every 5 minutes: for each service on each node — PID,
VmRSS, fd count, NRestarts, plus `/metrics` scrape (goroutines, heap) and
mosquitto queue stats if exposed. One CSV per service per week, rotated;
`soak-report.py` fits linear slopes, flags: RSS slope > threshold
(e.g. >1 MB/day sustained), fd slope > 0.5/day, goroutine slope > 0,
NRestarts delta ≠ 0, sampling gaps > 15 min. Chaos: cron-scheduled
2-hour netem window weekly (rotating profile: loss 1%, reorder, 200 ms
jitter — from 052's profiles) with window boundaries logged INTO the CSV
so trend analysis can exclude/inspect them.

## Detailed steps
1. `soak-scrape.sh`: SSH fan-out (dmitri@ hosts from a config block at
   top); per lexa service: `systemctl show -p MainPID,NRestarts <unit>`,
   `awk '/VmRSS/' /proc/$PID/status`, `ls /proc/$PID/fd | wc -l`
   (sudo needed on hub Pi root units — passwordless there; sims are user
   units, same-user readable); per sim node likewise; `curl -s
   http://<node>:<metrics-port>/metrics | grep -E 'go_goroutines|...'`;
   desktop gridsim/dashboard sampled locally; append one CSV row per
   service under `logs/soak/<week>/<service>.csv`. MUST tolerate a dead
   node (record NaN row + alert line, keep going).
2. `soak-start.sh`: installs a user timer (5 min) + verifies linger;
   writes a soak manifest (start date, bench mode, git SHAs of both
   repos, service versions) — provenance for the final report.
3. Bench-mode guard: assert STOCK at soak start (`hub-replay-tune.sh
   stock`), record it; the runbook forbids mode flips mid-soak without a
   manifest note (a FAST week and a STOCK week have different
   per-tick log volumes — trend analysis would misread it as a leak).
4. `soak-chaos-window.sh` + timer (weekly, e.g. Wed 02:00-04:00): apply
   052 profile to the LAN (per its own tooling), tag start/stop in the
   CSVs, auto-remove netem on exit AND on script trap (a stuck qdisc
   would corrupt the remaining month).
5. `soak-report.py`: reads a week of CSVs → per-service table (start/end/
   slope for RSS, fd, goroutines; restarts; gaps; chaos windows
   annotated); emits markdown following SOAK_REPORT_TEMPLATE.md; exit
   code nonzero on any flagged assertion (CI-able).
6. Disk budget: compute CSV volume (≈ 6+4 services × 12 samples/h × 30 d
   ≈ trivial MBs — but journald on the Pis grows under chaos windows;
   verify TASK-009 caps are active on every node and record limits in the
   runbook; desktop `logs/soak/` quota note).
7. Dry run: 48-hour mini-soak including one 30-minute chaos window;
   produce a report; fix sampler gaps; THEN declare the rig ready and
   start the real 30-day run (TASK-081 consumes its completion).
8. Interference rules in the runbook: campaigns/replays during a soak are
   allowed but must be logged in the manifest (they change resource
   profiles); a hub redeploy mid-soak INVALIDATES the soak (new PIDs,
   new binaries — restart the clock).

## Testing changes
No product tests. Rig self-tests: `soak-report.py` unit-tested on
synthetic CSVs (leak slope detection, gap detection, chaos annotation);
shellcheck on the scripts. Run: `python3 -m pytest scripts/soak/` (or
inline test mode), 48 h dry run per step 7.

## Documentation changes
- docs/SOAK_RUNBOOK.md (start/stop/read/interference/invalidations).
- docs/SOAK_REPORT_TEMPLATE.md.
- 08 RSK-14: soak wear telemetry noted; 09 checklist row linked.

## Common mistakes to avoid
- Sampling via `pkill`-adjacent patterns or anything that can kill a
  session over SSH — read-only commands only (the BENCH.md gotcha).
- Trusting a re-resolved PID after a silent restart (NRestarts delta is
  the truth; a PID change with NRestarts=0 means someone restarted
  manually — flag it, don't average across it).
- Running the sampler ON the hub Pi writing to its SD card (RSK-14;
  desktop pulls, Pis are passive).
- Leaving netem applied after a window crash (trap + idempotent cleanup;
  052's harness should already provide it — verify).
- FAST timing for the soak (unrepresentative; and QA campaign wall-clocks
  would collide).
- A desktop reboot silently killing the rig (linger + gap detection +
  runbook recovery step — gridsim/dashboard units die on reboot too, and
  the hub's northbound will log walk failures: expected, documented).

## Things that must NOT change
- Product/bench service code and configs (observation only).
- Journald caps (TASK-009) — the rig must not raise verbosity anywhere.
- The bench's ability to run a campaign mid-soak (with manifest note) —
  the rig must never hold locks/ports the dashboard needs.

## Acceptance criteria
- [ ] 48 h dry run: complete CSVs from all 10+ sampled services across
  4 nodes, one chaos window annotated, report generated, zero sampler-
  induced incidents.
- [ ] Report assertions demonstrably fire on synthetic leak data (test).
- [ ] Runbook: a person who is not the author starts/stops/reads the soak
  (RSK-11 bus-factor test — have the review exercise it).
- [ ] 30-day run STARTED with manifest (completion is TASK-081's gate).

## Regression checklist
- [ ] `make test-fast` (csip-tls-test) green (repo hygiene — rig code is
  script-side)
- [ ] Mayhem: none required (observation-only); one spot scenario after
  dry run to confirm bench unperturbed
- [ ] shellcheck / py tests green
- [ ] netem cleanup verified after the dry-run window

## Mayhem scenarios affected
None. (Chaos windows reuse 052's profiles, whose scenarios were curated
in P4.)

## Conformance implications
None.

## Suggested commit message
`feat(qa): 30-day soak rig — scraper, chaos windows, weekly report, runbook (GAP-12)`
(+ trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`)

## Suggested PR title & description
**Title:** Soak rig: resource trends + weekly chaos (GAP-12)
**Description:** Desktop-resident sampler over SSH + /metrics; weekly
netem windows; slope/gap/restart assertions; 48 h dry-run evidence;
runbook. Risk: low (read-only + scheduled chaos). Rollback:
`soak-stop.sh`.

## Code review checklist
- Sampler failure modes (dead node, PID churn, SSH timeout) all handled
  as data, not crashes.
- No writes on Pi storage; desktop-only artifacts.
- Chaos scheduling cannot overlap campaign cron (if any) — documented.

## Definition of done
Acceptance criteria + regression checklist + docs updated + status headers
(this file + 00_MASTER_INDEX) updated.

## Possible follow-up tasks
TASK-081 (30-day completion sign-off), backlog: SMART/wear-level
sampling (RSK-14), alerting hookup when 045's alert path lands.
