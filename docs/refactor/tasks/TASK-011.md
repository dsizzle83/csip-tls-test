# TASK-011 — Delete `gui/sim_gui.py`, root `sim_*.txt`; doc cleanup

*Status: DONE (2026-07-04, fb5b767) · Phase: P0 · Effort: S (≈2 h) · Difficulty: low · Risk: low*

## Objective
The deprecated Tkinter GUI and the seven legacy per-node setup guides are deleted;
README and CLAUDE.md stop referencing them and point to the living docs
(`docs/BENCH.md`, the run-demo skill, lexa-hub deploy scripts).

## Background
Verified inventory (csip-tls-test root):
- `gui/` — `sim_gui.py` (Tkinter, deprecated per CLAUDE.md line 14: "the web dashboard
  replaced it") + `requirements.txt`.
- Seven root-level guides: `sim_battery.txt`, `sim_dashboard.txt`, `sim_ev.txt`,
  `sim_gridsim.txt`, `sim_hub.txt`, `sim_meter.txt`, `sim_solar.txt` — CLAUDE.md line 41
  calls them "Per-node setup guides (root level, legacy)". Their live replacements:
  `docs/BENCH.md` (topology/deploy), `scripts/update-sim-pis.sh` + `bench-up.sh`
  (bring-up), `lexa-hub/scripts/deploy-hub-pi.sh` (hub), the run-demo skill.
- Verified references to update:
  - `README.md` line ~59 ("Install wolfSSL first — see sim_hub.txt STEP 2"), line ~101
    ("See `sim_hub.txt` for the full systemd unit file"), lines ~135–139 (the guide
    list).
  - `CLAUDE.md` line 14 (gui deprecation note — delete once gui/ is gone) and line 41
    (directory-map row).
  - `docs/HARNESS_REVIEW.md` mentions both (historical audit — leave untouched).
  - No `scripts/*.sh` or Go code references either (verified by grep; re-run including
    `.claude/skills/` — the run-demo skill may mention the old GUI).

This pairs with TASK-010 (monolith deletion): README's hub sections are rewritten there;
this task finishes the doc surface so onboarding hits only living material.

## Why this task exists
Review D2 ("onboarding noise") and HARNESS_REVIEW DOC-2 (CLAUDE.md documented the dead
GUI as *the* GUI). Dead docs actively misdirect: `sim_hub.txt` describes deploying the
deleted monolith.

## Architecture review sections
D2, §13 (onboarding cost). Roadmap: 03 P0 ("deprecated GUI deleted"); 04 row 011.

## Prerequisites
None hard. Best sequenced with/after TASK-010 (README is being rewritten there —
coordinate to avoid conflicts; if 010 isn't merged yet, base this branch on it).

## Files
- **Read first:** each `sim_*.txt` (skim for any fact NOT already in `docs/BENCH.md` —
  salvage before deleting), `README.md`, `CLAUDE.md`, `.claude/skills/run-demo/SKILL.md`,
  `docs/BENCH.md`.
- **Modify:** `README.md`, `CLAUDE.md`; possibly `docs/BENCH.md` (salvaged facts).
- **Create:** nothing.

## Blast radius
Docs only. Zero code. The only real risk is deleting a setup fact that exists nowhere
else — hence the salvage pass.

## Implementation strategy
Salvage-then-delete: skim the seven guides against BENCH.md; move any still-true,
still-unique operational fact into BENCH.md; delete the files and the GUI; update the two
entry-point docs.

## Detailed steps
1. Salvage pass: for each `sim_*.txt`, list facts not present in `docs/BENCH.md`,
   `README.md`, or the run-demo skill. Expect: mostly stale (WSL-era IPs, monolith
   deploy steps). Anything current and unique (e.g. a Pi-specific systemd quirk) gets a
   line in `docs/BENCH.md` with the same wording style. If in doubt whether a fact is
   current, check against the live bench (`ssh dmitri@<pi> systemctl --user cat <sim>`),
   or note it as unverified in the PR description rather than silently dropping it.
2. `git rm -r gui/` and `git rm sim_*.txt` (exactly the seven listed files — glob check
   `ls sim_*.txt` first so nothing extra matches).
3. `README.md`: replace the wolfSSL line-59 pointer with the Makefile/BENCH.md
   references; replace line-101's unit-file pointer with
   `lexa-hub/systemd/` + `deploy-hub-pi.sh`; delete the lines-135–139 guide list and
   point to `docs/BENCH.md` + the run-demo skill instead.
4. `CLAUDE.md`: delete line 14 (gui note); delete the `sim_*.txt` directory-map row
   (line 41). Do NOT touch anything else in the directory map.
5. Grep sweep: `grep -rn "sim_gui\|sim_hub.txt\|sim_solar.txt\|sim_battery.txt\|
   sim_meter.txt\|sim_ev.txt\|sim_gridsim.txt\|sim_dashboard.txt\|gui/" --include="*.md"
   --include="*.sh" --include="*.py" . | grep -v docs/HARNESS_REVIEW.md | grep -v
   ARCHITECTURE_REVIEW.MD | grep -v docs/refactor` → must be empty. Check
   `.claude/skills/` too.
6. `make test-fast` (nothing should move, but prove it) and commit.

## Testing changes
None (docs-only). `make test-fast` as a tripwire.

## Documentation changes
This task IS documentation change: README, CLAUDE.md, possibly BENCH.md salvage lines.
00_MASTER_INDEX status.

## Common mistakes to avoid
- Deleting without the salvage pass — `sim_ev.txt`/`sim_meter.txt` may hold the only
  written copy of a Pi-side quirk (linger setup, unit ExecStart forms) that predates
  BENCH.md. Salvage first.
- Touching `docs/HARNESS_REVIEW.md` or the QA reports — historical records reference the
  dead files by design.
- Removing the CLAUDE.md `gui/` mention but leaving `gui/` on disk (or vice versa) —
  docs and tree must move together in one commit.
- Editing `requirements.txt` matches elsewhere — only `gui/requirements.txt` goes.

## Things that must NOT change
- `docs/BENCH.md`'s existing content (additive salvage only).
- The run-demo skill's behavior (if it references the GUI, update the reference — do not
  restructure the skill).
- Everything under `docs/` history.

## Salvage pass results (run before deletion)
Skimmed all seven guides against `docs/BENCH.md`, `README.md`, the run-demo skill, the
Makefile, and (where a guide's claim was about current runtime behavior) the sim source.
Nothing needed to move into `BENCH.md` — every guide is stale in a way that would
misdirect rather than inform:

| Guide | What it claimed | Why it's stale / already covered |
|---|---|---|
| `sim_hub.txt` | ConnectCore-93 dev-kit hub at `69.0.0.2`, manual SCP deploy of 4 binaries, `mosquitto` cross-compile notes | Hub moved to `69.0.0.1` (`BENCH.md`); deploy is now `lexa-hub/scripts/deploy-hub-pi.sh`; mosquitto build notes explicitly deferred to the lexa-hub repo already |
| `sim_solar.txt`, `sim_battery.txt` | Per-Pi GitHub deploy-key bootstrap, manual `nmcli` static-IP setup (gateway `69.0.0.2`), hand-written systemd unit (`User=pi`, root unit) | Bench Pis are already provisioned and live (`BENCH.md`); current service model is **user** systemd units + linger under `dmitri@`, not root units under `pi` — the templates describe a service model the bench no longer uses; deploy is automated via `scripts/update-sim-pis.sh` |
| `sim_meter.txt` | `-solar-api`/`-battery-api` linked-mode flags and formula `meter_W = load_W - solar_W - battery_W` | Incomplete vs. current binary: `sim/metersim/main.go` now also has `-ev-api`/`-hub-api` and documents the current formula (`meter_W = load_W + ev_W - solar_W - battery_W`) directly in the source comment — the code is the more current, more complete, self-maintaining reference |
| `sim_ev.txt` | Session lifecycle simulated as bare `StatusNotification(Occupied)`→`StatusNotification(Available)` | Contradicts the live OCPP-1 invariant (CLAUDE.md): sessions must be `TransactionEvent` Started/Updated/Ended lifecycles. Salvaging this description would reintroduce a documented-wrong fact |
| `sim_gridsim.txt` | wolfSSL from-source build recipe (v5.7.6-stable, autoreconf + configure flags), manual cert-chain generation via raw `openssl` commands | Build recipe already lives as the `wolfssl-arm64` Makefile target in `lexa-hub` (confirmed in TASK-002's background, same version/flags); cert generation is already automated via `scripts/gen-server-cert.sh` / `gen-client-cert.sh` + `make gen-client-cert` |
| `sim_dashboard.txt` | Dashboard proxy routing table, GUI deprecation note | Routing table is implicit in the dashboard's own `-hub/-gridsim/-solar/...` flags and already summarized in CLAUDE.md's port map; GUI note is moot once `gui/` is gone |

No unverified/unique facts were found; none were dropped silently. Two stray references not
listed in the task's "Verified references to update" were caught by the step-5 grep sweep
and fixed: `scripts/run-conformance.sh` lines 22 and 36 (wolfSSL build pointer), now
pointing at `docs/BENCH.md` / the lexa-hub `wolfssl-arm64` Makefile target.

## Acceptance criteria
- [x] `gui/` and all seven `sim_*.txt` gone; `ls sim_*.txt` errors.
- [x] Step-5 grep empty (excluding historical docs) — after also fixing two hits in `scripts/run-conformance.sh` not in the task's original reference list.
- [x] README + CLAUDE.md point only to living docs; no facts needed salvaging into BENCH.md (see table above).
- [x] `make test-fast` green.

## Regression checklist
- [x] `make test-fast` green
- [x] Conformance logic tests: unaffected (docs-only change; `run-conformance.sh` edit is a comment/error-string pointer, not logic)
- [x] Mayhem: none (not run — task specifies none)
- [x] TASK-004 lockstep gate unaffected (no `internal/southbound/sunspec` changes)

## Mayhem scenarios affected
None.

## Conformance implications
None.

## Suggested commit message
`docs: delete deprecated Tkinter GUI + legacy sim_*.txt guides; repoint README/CLAUDE.md (D2)`
`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

## Suggested PR title & description
**Title:** Remove deprecated GUI and legacy per-node guides
**Description:** D2 cleanup. Salvage table included (facts moved to BENCH.md / confirmed
already covered / confirmed stale). Rollback: single revert.

## Code review checklist
- Salvage table convincing (reviewer spot-checks one guide against BENCH.md).
- Grep sweep output pasted in PR.
- No unrelated doc edits.

## Definition of done
Acceptance criteria + regression checklist + status headers updated.

## Possible follow-up tasks
Backlog: prune deprecated Makefile `sync-pi` docs the same way; TASK-010 (if not yet
done, its README rewrite overlaps).
