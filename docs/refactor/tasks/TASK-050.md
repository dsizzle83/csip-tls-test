# TASK-050 — Mayhem: disk-full scenario

*Status: CODE COMPLETE (2026-07-05, csip-tls-test `task/049-051-scenarios` 01e97bc,
unmerged — batched with TASK-049/051 per the Principal Engineer's deadline-push
instruction, 05 §12 amendment): `disk-full` scenario + size-guarded `fillDisk`/
`freeDisk` ballast helpers (floor/reserve guard unit-tested as a pure string
builder), teardown-always-removes-the-ballast with a documented manual-cleanup
fallback for a dashboard crash mid-run. Bench validation (10× solo, `--abort`
ballast-removal check, full campaign) explicitly NOT run — rides the next
batched wave gate; another session owns the live bench for this gate.
· Phase: P4 · Effort: M (≈4–6 h) · Difficulty: med · Risk: low*

## Objective
Add a Mayhem scenario `disk-full` that fills the partition holding
Mosquitto persistence + journald + the event journal on the hub Pi via a
ballast file, holds an active export cap while the disk is full, asserts
control enforcement continues and degradation is visible (not a wedge), then
removes the ballast and asserts clean recovery. Teardown MUST delete the
ballast on any exit; INCONCLUSIVE without SSH.

## Background
Repo `~/projects/csip-tls-test`. GAP-03 / review §9 persistence family:
"Disk full (journald + mosquitto persistence on the same partition): never
injected." On the hub Pi (69.0.0.1), `/var/lib/mosquitto/` (persistence,
mosquitto-lexa.conf), journald, and — after TASK-039/040 —
`/var/lib/lexa/journal/` typically share the root partition. When it fills:
mosquitto autosave writes fail, journald stalls/drops, the journal's
`Append` hits ENOSPC (TASK-039 handles this: edge-logged, counter, returns
error, never panics — AD-011).

Injection: `fallocate -l <size> /var/lib/<ballast>` via SSH sudo fills the
partition to near-full deterministically (much safer than `dd` — instant,
no write churn). Compute the size from `df` headroom so a margin remains
(never 100% — that can wedge the OS; target ~99% or "free minus 20 MiB").
Teardown: `rm -f` the ballast. **The ballast file is the single most
dangerous artifact in the suite** — teardown must remove it even on
`--abort`, and the size must be self-limiting.

Pattern to copy: SSH via `d.hubSSH` (mayhem_world.go:91–105), BatchMode
probe → INCONCLUSIVE (mayhem_world.go:451–455), passwordless sudo on the
hub Pi (docs/BENCH.md). Export-cap preamble `armExportCap`
(mayhem_world.go:203). Oracle: cap must hold (ground truth via sims;
diagnoseSurvival ladder, mayhem_world.go:115); recovery after space returns
(no wedge — the hub's plan heartbeat must keep advancing, observable via
`/status` last_plan timestamp or the TASK-045 heartbeat field).

## Why this task exists
GAP-03: flash fills in the field (log growth, journal, a runaway); what
breaks first is unknown and untested. RSK-14 (flash wear) is the chronic
version; this is the acute one.

## Architecture review sections
§9 persistence family, §11 flash wear, item 12. Roadmap: 07 GAP-03
(validation: "control enforcement unaffected; degradation visible in
metrics; no wedge after space returns"); 06 §2 (10× solo).

## Prerequisites
SSH key auth to dmitri@69.0.0.1, bench FAST. TASK-039/040 helpful (journal
ENOSPC path exists to exercise) but not required. TASK-044/045 make
"degradation visible" a metric/heartbeat assertion instead of a log grep —
without them, judge on enforcement + recovery only.

## Files
- **Read first:**
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (hubSSH, hubSSHTarget, armExportCap, diagnoseSurvival, hub-restart-mid-cap for the SSH-probe pattern)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` (sample struct — HubReachable/HubAdopted fields lines 80–85; scanSamples; diagnoseSurvival usage)
  - `~/projects/csip-tls-test/docs/BENCH.md`
  - `~/projects/lexa-hub/systemd/mosquitto-lexa.conf` (persistence location)
- **Modify:**
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (add scenario + ballast helpers) — it is the SSH-fault home
- **Create:** none.

## Blast radius
Harness + a live hub Pi's filesystem. No product code. The ballast is a
real full-disk on a real node — teardown correctness is safety-critical for
the bench.

## Implementation strategy
SSH helpers to size, create, and remove the ballast with a hard cap and a
guard that refuses to fill below a floor of free space. Scenario: probe →
arm cap → fill disk mid-cap → hold ~30 s full → remove ballast → hold ~20 s
→ judge (cap held throughout via survivability ladder; recovery = heartbeat
advancing + no sustained breach). Teardown always `rm -f`s the ballast and
re-verifies free space.

## Detailed steps
1. Ballast helpers in mayhem_world.go (all via `d.hubSSH`, sudo):
   ```go
   const ballastPath = "/var/lib/mayhem-ballast.bin"
   func (d *mayhemDriver) fillDisk() error   // df --output=avail /var/lib (1K blocks) → size = max(0, availKiB-20480)KiB; refuse (return error) if avail < 60 MiB; fallocate -l <size>K ballastPath
   func (d *mayhemDriver) freeDisk() error   // rm -f ballastPath
   ```
   `fillDisk` composes one SSH command that reads avail and fallocates only
   if headroom is sane (so a re-run or a small partition fails safe →
   INCONCLUSIVE, never a bricked node). Keep 20 MiB reserved so the OS +
   sshd stay alive to run teardown.
2. Scenario `disk-full` (Category: "Persistence (INV-EXPORT survivability)",
   HoldS ≈ 80):
   - Hypothesis: the hub Pi's storage partition fills (log/journal growth)
     while a zero-export cap is active — mosquitto can't persist, journald
     stalls, the event journal hits ENOSPC.
   - Expected: keep enforcing the cap (control is in RAM + retained on a
     broker that was already connected); surface the condition
     (metric/heartbeat/log), do not wedge; recover cleanly when space
     returns.
   - setup: SSH probe (`hubSSH("true")` → INCONCLUSIVE); `armExportCap(d,
     80, "mayhem: cap under a full disk")`.
   - perTick: inject env; `i==15`: `fillDisk()` (goroutine-wrapped);
     `i==45`: `freeDisk()`.
   - evaluate: `diagnoseSurvival("the full disk")` — cap held throughout,
     bounded transient acceptable, sustained unseat = FAIL. Extend the
     finding diagnosis: if TASK-045 present, check `/status.plan_heartbeat`
     stayed `ok` (no wedge) across the full-disk window (sample
     `HubReachable`/adoption and, if exposed, the heartbeat field); if
     absent, assert `HubReachable` stayed true and adoption held.
   - teardown: `freeDisk()` (idempotent), then a verify SSH
     (`df` avail > 40 MiB) — log a loud error if the ballast couldn't be
     removed (should never happen; `rm -f` on a root-sudo node).
3. Rebuild `bin/dashboard`, restart csip-dashboard.
4. Validate: run once, then SSH to the Pi and confirm free space restored
   and no `mayhem-ballast.bin` remains. Run 10× solo. Test `--abort` at
   `i==30` (disk full) — confirm the ballast is gone afterward (teardown
   runs on abort in the engine's run loop — verify in mayhem.go's run()
   that teardown is deferred/always-called; if not, the `duration_s`-style
   self-limit doesn't apply to a file, so the ONLY safety is teardown — so
   also add a belt-and-suspenders: `fillDisk` could `at`-schedule a
   removal? Overkill; instead confirm the engine always runs teardown, and
   document that a dashboard CRASH mid-full-disk requires manual
   `ssh dmitri@69.0.0.1 sudo rm -f /var/lib/mayhem-ballast.bin` — put that
   in the scenario Fix/diagnosis text).
5. Full campaign.

## Testing changes
- `cmd/dashboard`: unit test the fillDisk command-composition logic if
  extracted as a pure string builder (size math + floor guard).
- HIL: single run + SSH verification, 10× solo, abort test, full campaign.
- `make test-fast` unaffected.

## Documentation changes
- `docs/QA_FINDINGS.md`: scenario + verdict; the manual-cleanup note for a
  dashboard crash.
- csip-tls-test CLAUDE.md Mayhem count.
- BENCH.md gotcha: "the disk-full scenario leaves /var/lib/mayhem-ballast.bin
  only if the dashboard itself crashes mid-run — remove it manually."

## Common mistakes to avoid
- **Never fill to 100%:** reserve ≥20 MiB or sshd/journald/teardown can't
  run — you'd need physical access to the Pi. The floor guard in `fillDisk`
  is mandatory.
- `fallocate` (not `dd`): instant, reservation-only, no write amplification
  on the SD card (RSK-14 — don't wear the card to test wear).
- Verify the engine ALWAYS runs `teardown` (including on abort and on a
  scenario error mid-hold) before trusting it as the cleanup path — read
  `run()` in mayhem.go. If teardown is skipped on some error path, that is a
  harness bug to fix FIRST (it would also strand other scenarios' faults).
- Rebuild `bin/dashboard` before validating (D8).
- Don't assert via hub journald timestamps (they may be stalled BY the
  full disk — that's the point); use sims + `/status` (served from RAM by
  lexa-api, which also may struggle to log but still serves).
- The partition holding `/var/lib` must be the same as journald/mosquitto —
  verify on the actual Pi (`df /var/lib/mosquitto /var/log/journal`); if
  they differ, target the mosquitto one (the control-plane persistence is
  the point) and note it.
- Scenario ID must be unique (grep existing 46).

## Things that must NOT change
- Existing scenario verdicts/baselines (V6).
- `restoreBench()` — do not add ballast removal there; scenario teardown
  owns it (restoreBench runs for all scenarios and must stay filesystem-
  neutral).
- Oracle margins.
- INV definitions.

## Acceptance criteria
- [ ] `--list` shows `disk-full`; missing SSH ⇒ INCONCLUSIVE.
- [ ] `fillDisk` refuses on a partition with <60 MiB free (unit or manual)
      and always leaves ≥20 MiB.
- [ ] 10× solo stable; cap holds (diagnoseSurvival PASS/bounded-DEGRADED);
      recovery clean (heartbeat/adoption held or restored).
- [ ] After every run AND an abort test, `ssh dmitri@69.0.0.1 ls
      /var/lib/mayhem-ballast.bin` reports absent.
- [ ] Full campaign ≤ baseline.

## Regression checklist
- [ ] `make test-fast` + `go test ./cmd/dashboard/` green
- [ ] Conformance logic tests: none (harness)
- [ ] Mayhem: 10× solo + full campaign
- [ ] `bin/dashboard` rebuilt + csip-dashboard restarted before validation

## Mayhem scenarios affected
Adds `disk-full`. Neighbors: `mqtt-broker-restart` (broker health),
`hub-restart-mid-cap`, `power-cut-retained-rollback` (TASK-043 — broker
persistence). Ensure disk-full runs don't leave the broker store
half-written for a following persistence scenario (freeing space + a settle
tick before teardown returns).

## Conformance implications
None (harness).

## Suggested commit message
`feat(mayhem): disk-full scenario with fallocate ballast + safe floor guard (GAP-03, TASK-050)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Mayhem: disk-full on the hub Pi (GAP-03, TASK-050)
**Description:** Fills the persistence/journal partition via a size-guarded
fallocate ballast mid-export-cap; asserts enforcement continues + no wedge +
clean recovery; teardown always removes the ballast (manual-cleanup note for
a dashboard crash). INCONCLUSIVE without SSH. Evidence: 10× solo + abort
test + campaign. Rollback: revert; additive.

## Code review checklist
- Floor guard mandatory and correct (≥20 MiB reserved; refuse <60 MiB).
- fallocate not dd; ballast path fixed and greppable.
- Teardown-always verified in the engine; manual-cleanup fallback
  documented.
- Assertions from ground truth, not hub journald.

## Definition of done
Acceptance + regression checklists green; QA/BENCH docs updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-078 (soak watches disk-free trend + wear), TASK-009 (journald caps
reduce the fill rate), backlog: separate quota/partition for the event
journal (RSK-14 mitigation).
