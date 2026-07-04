# TASK-009 — journald rate/size caps + flash wear budget

*Status: DONE, code only (2026-07-04, lexa-hub@1d47e10 on
`task/008-009-watchdogs-journald`) · Phase: P0 · Effort: S (≈2–3 h) · Difficulty: low ·
Risk: low — all six unit files carry `LogRateLimitIntervalSec=30` +
`LogRateLimitBurst=<per-service>`, `systemd/journald-lexa.conf` (200M cap) is created and
wired into `deploy-hub-pi.sh`, and `docs/FLASH_BUDGET.md` documents the rate/wear math.
The Burst values and rate table are PRE-DEPLOY ESTIMATES derived from the review's own
background numbers and each service's documented cadence — the on-bench measurement
(step 1), the live deploy + `journalctl --disk-usage` verification, the spam-burst
suppression demo, and the zero-suppression check across the targeted fault scenarios
(steps 4–5) are ALL deferred to the P0-exit gate, same as TASK-007/008's staged bench
work (no bench deploy, no service restart this wave). Acceptance-criteria items 2–3 and
the regression-checklist "Mayhem" and "all services is-active" rows are therefore NOT YET
satisfied — do not merge until the deploy/measurement wave closes them and
`FLASH_BUDGET.md`'s table is updated with real numbers.

## Objective
Every lexa unit carries explicit journald rate caps, the hub Pi's journal has a bounded
disk budget, and a written flash-wear budget (lines/day → MB/day → device lifetime)
exists so logging changes are reviewed against a number instead of a vibe.

## Background
Verified current state:
- The six unit files in `lexa-hub/systemd/lexa-*.service` set
  `StandardOutput=journal` / `StandardError=journal` and a `SyslogIdentifier`, but no
  `LogRateLimitIntervalSec`/`LogRateLimitBurst`, and nothing on the Pi bounds
  `SystemMaxUse` for the journal.
- Review §11 (flash wear): ~2 journald lines per hub tick ≈ 50k lines/day in FAST
  (3 s tick) on Pi SD / SOM eMMC, plus Mosquitto persistence autosave on the same
  partition. Under fault storms (e.g. `mqtt-broker-latency`, reconnect loops) per-tick
  logging multiplies.
- Deploy path: `scripts/deploy-hub-pi.sh` installs the unit files verbatim and is the
  vehicle for any `/etc/systemd/journald.conf.d/` drop-in.
- Budget math (write it into the doc, adjust with measured numbers):
  hub FAST = 28,800 ticks/day × ~2 lines ≈ 57.6k lines/day ≈ review's 50k; measured
  average journal line ≈ 100–150 B on disk (journald overhead) → ~6–9 MB/day for the hub,
  plus the other five services (northbound walk logs every 5 s in FAST) — order 20–30
  MB/day total in FAST, a few MB/day in STOCK. A 200 MB journal cap ≈ 1–4 weeks of
  retention; SD endurance (~10k P/E on decent cards, TBW ≫ this) makes wear a non-issue
  at these rates — the budget exists to keep it that way and to catch regressions
  (a debug-spam bug at 100 lines/s would write ~1 GB/day).

## Why this task exists
Review §11 "flash wear [Likely]" / §14 item 5-adjacent; RSK-14. Also a prerequisite
number for TASK-039's journal (P3) which shares the same flash.

## Architecture review sections
§11 (flash wear), RSK-14; 05 §9 (rate-conscious logging, "flash is a consumable");
03 P0.

## Prerequisites
None (independent). TASK-007/008 touch the same unit files — coordinate to avoid merge
noise; this task can land before or after.

## Files
- **Read first:** `lexa-hub/systemd/lexa-*.service` (all six),
  `lexa-hub/scripts/deploy-hub-pi.sh`, review §11.
- **Modify:** the six unit files; `scripts/deploy-hub-pi.sh` (install the journald
  drop-in).
- **Create:** `lexa-hub/systemd/journald-lexa.conf` (drop-in source),
  `lexa-hub/docs/FLASH_BUDGET.md`.

## Blast radius
Unit files + one journald drop-in on the Pi. Risk: over-tight rate limits silently drop
fault-storm logs — the QA culture root-causes from journal lines, so the caps must be
generous relative to normal rate and only clamp pathological spam.

## Implementation strategy
Measure the real line rate on the bench first, then set per-unit caps ≈ 20× normal
sustained rate, add a Pi-wide journal size cap via a `journald.conf.d` drop-in installed
by the deploy script, and write the budget doc with the measured numbers and the wear
math.

## Detailed steps
1. Measure on 69.0.0.1 (FAST mode):
   `journalctl -u lexa-hub --since -10min | wc -l` (and per unit for the other five);
   `journalctl --disk-usage`. Record lines/min per service, normal and during one
   Mayhem scenario (`--only mqtt-broker-latency` produces reconnect chatter).
2. Set per-unit caps in each `systemd/lexa-*.service` `[Service]`:
   `LogRateLimitIntervalSec=30` and `LogRateLimitBurst=<20× measured 30 s volume>`
   (e.g. hub FAST ≈ 20 lines/30 s → Burst=400; northbound similar; round up
   generously — the cap is for runaway bugs, not busy days). Comment each with the
   measured basis.
3. Create `systemd/journald-lexa.conf`:
   ```
   [Journal]
   SystemMaxUse=200M
   SystemKeepFree=500M
   MaxRetentionSec=1month
   ```
   and extend `deploy-hub-pi.sh` to `install -m 644` it to
   `/etc/systemd/journald.conf.d/lexa.conf` + `systemctl restart systemd-journald`.
4. Deploy to the Pi (full deploy; **re-run `hub-replay-tune.sh fast`** afterwards).
   Verify: `journalctl --disk-usage` bounded; force a spam burst
   (`logger -t lexa-hub --socket … ` or a tight loop via `systemd-cat -t lexa-hub`) and
   confirm suppression messages appear ("Suppressed N messages from …") rather than
   unbounded growth.
5. Run one targeted scenario set (`mqtt-broker-restart,mqtt-broker-latency,
   northbound-hang`) and verify NO suppression fired during them — QA forensics must
   survive fault storms. If suppression fired, raise Burst and re-measure.
6. Write `lexa-hub/docs/FLASH_BUDGET.md`: measured rates table (normal / fault-storm,
   FAST / STOCK if available), bytes/day, journal cap rationale, SD/eMMC wear math, the
   rule "new per-tick log lines are budgeted — a change adding >0.2 lines/tick sustained
   updates this doc" (cite 05 §9), and a pointer that TASK-039's event journal must set
   its own quota within this budget.
7. Note explicitly in the doc: Mosquitto `autosave_interval 60` write load is on the
   distro config on the Pi (the deploy drop-in doesn't set persistence knobs) — measured
   but not changed here; retained-store trust is TASK-042's problem.

## Testing changes
No Go tests. Bench evidence: disk-usage before/after, suppression demo, zero suppression
during the targeted scenarios.

## Documentation changes
- `lexa-hub/docs/FLASH_BUDGET.md` (new).
- 00_MASTER_INDEX status. Optional line in lexa-hub CLAUDE.md ops notes.

## Common mistakes to avoid
- Caps tight enough to suppress during Mayhem fault storms — you will destroy the
  journal-level root-causing culture the review calls the crown jewel. Verify step 5.
- Setting `MaxLevelStore` to drop debug globally — the services log at info; level
  filtering isn't the mechanism here, rate/size caps are (brief mentions MaxLevelStore
  as an option; rejected for this reason — say so in the PR).
- Editing `/etc/systemd/journald.conf` in place on the Pi instead of a
  `journald.conf.d` drop-in shipped from the repo — config must be reproducible by
  `deploy-hub-pi.sh`.
- Forgetting that `deploy-hub-pi.sh` overwrites `/etc/lexa/*.json` → re-tune FAST.

## Things that must NOT change
- Log *content*: no log lines added/removed/reworded in any service (QA diagnosis greps
  journal text, e.g. "COMPLIANCE BREACH", "REJECT implausible").
- `SyslogIdentifier` values (the dashboard/Mayhem journal queries key on unit names).
- Mosquitto persistence settings (owned by TASK-013/042 discussions).

## Acceptance criteria
- [ ] All six units have LogRateLimit* with measurement-based comments.
- [ ] `journalctl --disk-usage` on the Pi ≤ 200M after restart; drop-in present.
- [ ] Spam burst suppressed (journal shows suppression notice); targeted scenarios show zero suppression.
- [ ] `FLASH_BUDGET.md` committed with measured numbers and wear math.

## Regression checklist
- [ ] `go test -race ./internal/...` (lexa-hub) green — trivially (no Go changes)
- [ ] Conformance logic tests: unaffected
- [ ] Mayhem: targeted `mqtt-broker-restart,mqtt-broker-latency,northbound-hang` with zero log suppression
- [ ] All services `is-active` post-deploy; hub back in FAST

## Mayhem scenarios affected
None by intent; the step-5 check exists to prove fault-storm logging is unaffected.

## Conformance implications
None.

## Suggested commit message
`ops(systemd): journald rate caps per unit + Pi journal size budget + FLASH_BUDGET.md (§11, RSK-14)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** journald caps + flash wear budget
**Description:** Measurement-based per-unit rate limits (20× headroom), 200M journal
cap via drop-in, budget doc with wear math. Verified no suppression under fault
scenarios. Rollback: remove drop-in + unit lines.

## Code review checklist
- Burst values trace to the measurement table.
- Suppression-during-scenarios check actually performed (evidence).
- Budget doc numbers arithmetically consistent.

## Definition of done
Acceptance criteria + regression checklist + docs + status headers updated.

## Possible follow-up tasks
TASK-039 (event journal quota inside this budget), TASK-045 (structured logging obeys
the same budget), TASK-050 (disk-full scenario validates behavior at the cap),
TASK-078 (soak captures wear telemetry).
