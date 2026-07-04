# TASK-052 — Bench `tc netem` packet-chaos harness + scenarios

*Status: TODO · Phase: P4 · Effort: L (≈6–8 h) · Difficulty: med · Risk: low*

## Objective
Add `scripts/netem.sh` to apply `tc netem` loss/reorder/delay/jitter
profiles to the bench Pis' Ethernet interfaces over SSH, integrate it into
Mayhem as a scenario modifier, and curate 2–3 scenarios (e.g. an export cap
under 5% packet loss) that prove control survives packet-level chaos.
Teardown resets the qdisc unconditionally; INCONCLUSIVE without SSH.

## Background
Repo `~/projects/csip-tls-test`. GAP-11 / review §9: "all faults are
app-layer via simapi; real LANs corrupt, reorder, and delay at the packet
level — `tc netem` on the bench LAN would be cheap and brutal." Today every
Mayhem fault is app-layer (simapi `/inject`, `/fault`; gridsim
`/admin/outage`; mqttproxy). Nothing hits the wire.

Bench topology (docs/BENCH.md): flat LAN 69.0.0.x; hub 69.0.0.1
(passwordless sudo), sims on .10/.11/.12/.14 (user units + linger), desktop
.20 (gridsim + dashboard). SSH `dmitri@` everywhere, key auth works. The
relevant links for control:
- hub ↔ gridsim (northbound mTLS to .20:11111) — netem on the hub's iface
  affects the utility link.
- hub ↔ sims (Modbus polls to .10/.11/.12, OCPP to .14) — netem on a sim's
  iface delays/loses device telemetry + control writes.
`tc qdisc add dev <iface> root netem loss 5% delay 50ms 10ms reorder 25%`
is the primitive; `tc qdisc del dev <iface> root` resets. The iface name
per Pi must be discovered (`ip -o route get <bench peer IP>` → `dev`;
never the default route — see step 1) — do NOT hardcode `eth0` (Pis vary;
desktop is `enp1s0` per BENCH.md but we apply netem on the
Pis, not the desktop, to avoid cutting our own dashboard/SSH path).

**Critical safety:** applying netem to the interface you SSH over can lock
you out or make teardown unreachable. Mitigations: (a) only ever apply on
the PIS' single LAN iface (they have one path; heavy loss still usually
lets a retried teardown through — SSH is TCP, retries), (b) always pair an
`at`/`sleep`-scheduled auto-reset on the Pi itself so even a lost teardown
self-heals:
`ssh … "sudo sh -c 'tc qdisc add … ; (sleep <maxHold+30>; tc qdisc del dev <iface> root) >/dev/null 2>&1 &'"`.
The scheduled reset is the safety net; the scenario teardown is the fast
path. Never apply netem to the desktop's iface.

Integration: Mayhem scenarios are `mayScenario` with `setup/perTick/
teardown` (mayhem.go:189). A "modifier" wraps an existing scenario's
lifecycle to arm netem in setup and reset in teardown — mirror how
`suppressDefault()` (mayhem_world.go:64) returns a restore closure, and how
the SSH scenarios probe (`hub-restart-mid-cap`).

## Why this task exists
GAP-11 / §9 load family: packet-level chaos is cheap and brutal and
entirely untested; app-layer injection cannot reproduce loss/reorder that a
real LAN does daily.

## Architecture review sections
§9 load/duration family, item 20 (`tc netem` chaos). Roadmap: 07 GAP-11
(validation: profiles applied via SSH, folded into 2–3 scenarios + soak
background); 06 §2; 08 (soak TASK-078 consumes the harness).

## Prerequisites
SSH key auth to all target Pis (`dmitri@69.0.0.1/.10/.11/.12`), passwordless
sudo — the hub has it (BENCH.md); the SIM Pis run user units and may NOT
have passwordless sudo. **Verify sudo on each target Pi before relying on
it**; where sudo needs a password, netem on that Pi is INCONCLUSIVE (probe
`ssh dmitri@<pi> sudo -n true`). Bench FAST.

## Files
- **Read first:**
  - `~/projects/csip-tls-test/docs/BENCH.md` (topology, SSH, ifaces)
  - `~/projects/csip-tls-test/scripts/mqtt-chaos.sh` (SSH-deploy script pattern to mirror)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (hubSSH, hubSSHTarget, suppressDefault-as-modifier pattern, armExportCap, diagnoseConstraint/Survival)
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem.go` (scenario struct, backends map for per-node SSH targets — `d.backends`, mayhem.go:160)
- **Modify:**
  - `~/projects/csip-tls-test/cmd/dashboard/mayhem_world.go` (netem helpers + scenarios)
- **Create:**
  - `~/projects/csip-tls-test/scripts/netem.sh` (standalone CLI: `netem.sh <pi> apply <profile>` / `<pi> reset`, with the self-healing scheduled reset baked in)

## Blast radius
Harness + live bench network qdiscs. No product code. A botched apply can
disrupt SSH to a Pi — the self-healing scheduled reset is the guardrail.

## Implementation strategy
`scripts/netem.sh` as the reusable primitive (also usable by TASK-078 soak);
Go helpers in mayhem_world.go call it via `hubSSH`-style exec to arbitrary
targets (generalize `hubSSHTarget` to any bench node using `d.backends` /
IPs). A netem "modifier" closure arms a profile in setup and returns a
reset func for teardown. 2–3 curated scenarios reuse existing export-cap
oracles under netem.

## Detailed steps
1. `scripts/netem.sh`:
   - Usage: `netem.sh <host> apply "<netem args>" <auto_reset_s>` and
     `netem.sh <host> reset`. `apply` discovers the iface: on each target
     run `ip -o route get <bench peer IP>` (69.0.0.20 from a sim Pi;
     69.0.0.10 from the hub Pi) and use its `dev`; NEVER the default route
     (dual-homed Pis default via WiFi — netem would land on the WAN iface
     and every netem scenario would silently no-op-pass). Then it
     runs `sudo -n tc qdisc replace dev <iface> root netem <args>`, and
     schedules the self-healing reset in a detached subshell. `reset` runs
     `sudo -n tc qdisc del dev <iface> root 2>/dev/null || true`.
   - Refuse to run against the desktop IP (69.0.0.20) — guard clause.
   - `sudo -n` so a password-required node fails fast (→ INCONCLUSIVE
     upstream) instead of hanging.
2. Go helpers in mayhem_world.go:
   ```go
   func (d *mayhemDriver) nodeSSH(node, command string) error // node ∈ {"hub","solar","battery","meter"}; resolves IP from d.backends or a fixed map
   func (d *mayhemDriver) netemApply(node, profile string, autoResetS int) error
   func (d *mayhemDriver) netemReset(node string) error
   func (d *mayhemDriver) netemModifier(node, profile string, holdS int) (func(), error) // probe sudo -n; apply with autoReset=holdS+30; return reset closure
   ```
   `netemModifier` probes `sudo -n true` on the node and returns an error
   (→ INCONCLUSIVE) when unavailable.
3. **Netem self-check (in `netemModifier`, before the scenario runs).**
   After applying a profile, verify it actually took effect on the bench
   LAN: measure ping RTT across the bench LAN to the target before and
   after apply and require the expected delta (a delay profile must move
   RTT; for loss-only profiles include a small delay component or check
   `tc -s qdisc show` packet counters). No delta ⇒ netem landed on the
   wrong interface ⇒ return an error (→ INCONCLUSIVE); never run the
   scenario.
4. Curated scenarios (append in `worldScenarios()`), each reusing
   `armExportCap` + a netem modifier:
   - `netem-loss-export-cap`: 5% loss + 50±10 ms delay on the **hub↔sims**
     path (apply on the battery/solar sim's iface, or the hub's — choose
     the hub iface so ALL device links degrade together; but that also
     degrades the hub↔gridsim link — acceptable, it models a bad hub uplink).
     Judge: cap holds (`diagnoseConstraint`), INV-HUNT clean under loss.
   - `netem-reorder-northbound`: 25% reorder + 100 ms delay on the hub iface
     (utility link chaos) while a gen-limit is active; judge survivability
     (`diagnoseSurvival("packet reorder")`) — the walker/fetcher must ride
     it out (SO_RCVTIMEO + fail-closed).
   - `netem-jitter-evse` (optional third): delay jitter on the ev-pi
     (.14) during an EV charging cap; judge INV-EVMAX clean.
   Each: setup probes SSH+sudo (INCONCLUSIVE otherwise) → armExportCap →
   `netemModifier`; perTick keeps env injected; teardown calls the reset
   closure + `deleteControls(0)`.
5. `bin/dashboard` rebuild + csip-dashboard restart.
6. Validate: run each once, confirm via SSH that no `netem` qdisc lingers
   (`tc qdisc show dev <iface>` = default). Test the self-heal: apply with a
   short autoReset, `--abort` the run, confirm the qdisc clears itself.
   10× solo each. Full campaign.

## Testing changes
- `scripts/netem.sh` is shell — add a `--dry-run` mode printing the tc
  commands, and a tiny bats-style or `go test` wrapper if the repo has
  script tests (else document a manual dry-run check).
- `cmd/dashboard`: pure test for node→IP resolution if extracted.
- HIL: 10× solo per scenario + full campaign.

## Documentation changes
- `docs/QA_FINDINGS.md`: scenarios + verdicts + which links tolerate what
  loss.
- csip-tls-test CLAUDE.md Mayhem count; BENCH.md: netem harness note + the
  "never on .20" rule + the sudo-on-sim-Pis caveat.

## Common mistakes to avoid
- **Never apply netem to 69.0.0.20** (desktop) — you'd cut the dashboard and
  your own SSH; the script guards it, keep the guard.
- **Self-healing scheduled reset is mandatory** — a lost teardown under
  heavy loss must self-clear; test it by aborting mid-run.
- `sudo -n` everywhere so a password-required sim Pi → INCONCLUSIVE, never a
  hang or a prompt inside the dashboard.
- Discover the iface via `ip -o route get <bench peer IP>`; never hardcode
  `eth0` and never use the default route — dual-homed Pis (WiFi uplink)
  default via the WAN iface, so netem lands on the wrong interface and the
  scenario silently no-op-passes. The post-apply ping-delta self-check
  (step 3) is the safety net for exactly this failure.
- `tc qdisc replace` (not `add`) so re-arming doesn't error on an existing
  qdisc; `del … || true` on reset so a missing qdisc isn't an error.
- Heavy loss on the hub iface also slows metric scrapes and `/status` polls
  — sample tolerantly (the harness client has a 3 s timeout, mayhem.go:175;
  a lost sample is a `SampleError`, already counted — don't treat it as a
  breach).
- Rebuild `bin/dashboard` (D8); no mqttproxy change here.
- Unique scenario IDs.

## Things that must NOT change
- Existing scenario verdicts/baselines (V6).
- `restoreBench()` network neutrality — netem reset lives in scenario
  teardown + the self-heal, not in the global restore.
- Oracle margins and INV definitions.
- The SO_RCVTIMEO / fail-closed behaviors these scenarios probe
  (`northbound-hang`, `wan-outage-hold` ledger) — the scenarios TEST them,
  must not require product changes to pass (if they fail, it's a real
  finding — pin it).

## Acceptance criteria
- [ ] `scripts/netem.sh <pi> apply "loss 5%" 10 --dry-run` prints correct
      tc commands incl. the self-heal; live apply+reset verified on one Pi.
- [ ] `--list` shows the 2–3 netem scenarios; missing SSH/sudo ⇒
      INCONCLUSIVE.
- [ ] Self-heal proven: abort mid-run, qdisc clears within autoReset window.
- [ ] 10× solo stable per scenario; export/gen caps hold under loss/reorder
      (or a real finding is pinned).
- [ ] No lingering qdisc on any Pi after a full campaign
      (`tc qdisc show` = default on each target).
- [ ] Full campaign ≤ baseline.

## Regression checklist
- [ ] `make test-fast` + `go test ./cmd/dashboard/` green
- [ ] Conformance logic tests: none (harness)
- [ ] Mayhem: 10× solo per new scenario + full campaign
- [ ] `bin/dashboard` rebuilt + csip-dashboard restarted; qdiscs clean
      post-run on all targets

## Mayhem scenarios affected
Adds `netem-loss-export-cap`, `netem-reorder-northbound`,
`netem-jitter-evse` (optional). Neighbors: `northbound-hang`,
`wan-outage-*`, `modbus-latency` (app-layer twin). No verdict changes
elsewhere; ensure qdisc always cleared between scenarios.

## Conformance implications
None (harness). Exercises the mTLS client + Modbus stack under realistic
transport degradation — closer to field conditions than app-layer faults.

## Suggested commit message
`feat(mayhem): tc netem packet-chaos harness + loss/reorder/jitter scenarios (GAP-11, TASK-052)`

Trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Bench tc netem packet chaos + scenarios (GAP-11, TASK-052)
**Description:** `scripts/netem.sh` applies loss/reorder/delay/jitter to Pi
ifaces over SSH with a mandatory self-healing auto-reset (never on the
desktop); 2–3 curated scenarios run export/gen caps under packet chaos.
INCONCLUSIVE without SSH+sudo. Abort-safe (self-heal proven). Evidence:
dry-run + 10× solo + campaign; qdiscs clean post-run. Rollback: revert;
additive.

## Code review checklist
- Desktop-IP guard present; iface discovered via peer-route (never default
  route or hardcoded); post-apply ping-delta self-check present.
- Self-healing scheduled reset in every apply; abort-tested.
- `sudo -n` → INCONCLUSIVE path; no hangs/prompts.
- Sample-loss under heavy netem treated as SampleError, not breach.
- Reset in teardown AND self-heal; qdisc-clean assertion.

## Definition of done
Acceptance + regression checklists green; QA/BENCH docs updated; status
headers updated (this file + 00_MASTER_INDEX).

## Possible follow-up tasks
TASK-078 (soak with background netem windows — reuses netem.sh), TASK-073
(reconnect churn under loss), backlog: netem as a matrix modifier over more
scenarios (07 deferred matrix cells).
