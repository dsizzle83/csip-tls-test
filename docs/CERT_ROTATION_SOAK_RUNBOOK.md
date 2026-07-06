# Cert rotation reconnect-churn soak (TASK-073, RSK-07) — DEFERRED

*Status: code-complete, soak NOT YET RUN. This document is the precise,
ready-to-execute procedure for the 24h bench soak TASK-073's acceptance
criteria require; per this program's soak-gating convention (see
`docs/refactor/00_MASTER_INDEX.md`'s P5 residual-soak entries), executing
it is deferred to a dedicated bench session — it needs the bench for a full
day, outside any Mayhem campaign window, and cannot be completed inside a
single implementation session.*

## What this proves

`lexa-northbound`'s `WolfSSLFetcher.Reload` (lexa-hub
`internal/tlsclient/fetcher.go`) tears down an old wolfSSL session
(`Close` → `FreeSSL` → `FreeCtx`) and builds a new one on every certificate
rotation. TASK-073's Background section states the risk plainly: *"One
misordered Free under a reconnect storm is a segfault in the service that
talks to the utility … there's no soak test for reconnect churn (certificate
rotation will churn it)."* Unit tests (lexa-hub
`internal/tlsclient/reload_test.go`) and a real-wolfSSL integration test
(`reload_integration_test.go`, 5 back-to-back rounds) already prove the
ordering is correct in the small. This soak proves it holds up over **many
hours and hundreds of cycles** against the real bench topology — the class
of bug that only shows up as a slow fd leak or a rare race condition never
triggers in a 5-round test.

Pass criteria (TASK-073 acceptance criteria):

- **Zero segfaults** — `lexa-northbound`'s systemd restart count stays flat
  across the whole soak (`systemctl show lexa-northbound -p NRestarts`).
- **Zero watchdog fires** — no `sd_notify` watchdog timeout in the journal
  for `lexa-northbound` (a wedge distinct from a segfault: the process is
  alive but stuck).
- **Flat fd count** — `ls /proc/$PID/fd | wc -l` does not trend upward
  across the soak (a leak from a skipped `FreeSSL`/`FreeCtx` would show up
  here well before OOM).
- **Flat RSS** — `ps -o rss= -p $PID` likewise does not trend upward.
- **No wolfSSL error lines** in the journal outside the deliberately-induced
  probe-rejection rotations (see below).

## Why alternating cert "A" and cert "B" is trickier than it sounds

TASK-073's step 6 describes the soak as "alternating cert A/B." Read
literally against this codebase's actual LFDI definition
(`lexa-hub/internal/northbound/identity.FromCertificate`: leftmost 160 bits
of SHA-256 **over the full DER-encoded certificate**), this needs a
deliberate design choice, spelled out here so nobody "fixes" the soak script
by quietly weakening the LFDI safety gate:

- Two **genuinely distinct** certs (different serial numbers, different key
  material, as `csip-tls-test/scripts/gen-client-cert.sh` produces on every
  invocation) have **different LFDIs by construction**. Rotating from A to
  B would trip `RotationController`'s LFDI-mismatch refusal on every single
  cycle — which is CORRECT behavior (see lexa-hub
  `docs/CERT_ROTATION_RUNBOOK.md`'s "Re-enrollment vs rotation" section),
  not a soak-script bug. A soak that "fixed" this by disabling or
  special-casing the LFDI check would no longer be testing the shipping
  code path.
- This soak therefore alternates between the ORIGINAL cert/key
  (`certs/client-staging/client-{cert,key}.pem`, generated once via
  `make gen-client-cert CN=<bench-device-CN>` before the soak starts) and a
  **byte-identical copy** of the same files saved under a second name
  (`client-cert-b.pem`/`client-key-b.pem`). Same DER bytes ⇒ same LFDI ⇒
  the LFDI check passes legitimately on every cycle, while the ROTATION
  MECHANISM still does real work each time: a brand-new wolfSSL context is
  built, dialed, and probed from the (differently-pathed) file, and the old
  one is fully freed — exactly the churn RSK-07 is worried about. Only the
  file PATH alternates, which is enough to prove `Reload` doesn't depend on
  any file-identity caching and genuinely tears down/rebuilds every cycle.
- A future "genuinely different identity, every cycle" variant would
  necessarily also be testing the RE-ENROLLMENT path (gridsim re-registering
  a new LFDI each cycle) — a different, heavier scenario than the reconnect
  churn this soak is chartered to test. Backlog item, not this soak.

## Prerequisites

- `docs/CERT_ROTATION_RUNBOOK.md` (lexa-hub) rotation mechanism deployed to
  the hub Pi (69.0.0.1) — `lexa-northbound` built from a commit that
  includes `cmd/northbound/rotate.go` (`RotationController`).
- `bash scripts/bench-up.sh --fast` (bench in FAST mode) is *not* required
  for this soak specifically — the soak targets `lexa-northbound`'s own
  cadence, not Mayhem scenario timing — but do NOT run this soak
  concurrently with a Mayhem campaign or a Bench Replay run (bench
  contention; also confounds the fd/RSS baseline with unrelated load).
  `scripts/hub-replay-tune.sh stock` beforehand is fine either way.
- The original cert/key pair used to enroll the bench device with gridsim
  (so LFDI matches gridsim's registration for the whole soak — this is
  rotation, not re-enrollment).
- Passwordless sudo / key-based SSH to the hub Pi (`dmitri@69.0.0.1`).

## Procedure

```bash
bash scripts/cert-churn-soak.sh 69.0.0.1 \
  --rotations-per-hour 12 \
  --duration-hours 24
```

See `scripts/cert-churn-soak.sh`'s own header for the exact invocation and
what it prepares (cert A + the byte-identical cert B copy) before starting.
At a high level, every cycle it:

1. Alternates calling lexa-hub's `scripts/rotate-cert.sh` with cert A then
   cert B (same LFDI, different path — see above).
2. Every 5 minutes (independent of the rotation cadence), samples and
   appends one CSV row: timestamp, `lexa-northbound` PID, RSS (KB), open fd
   count, `NRestarts` (systemd), and a grep count of wolfSSL/segfault-shaped
   journal lines since the last sample.
3. **Resolves the PID by systemd unit, not once at the start** — this
   matters more than it sounds: if `lexa-northbound` restarts (a crash),
   naively continuing to poll the OLD, now-dead PID would read
   `/proc/<pid>/fd` on a process that no longer exists as "0 fds, all
   healthy," silently passing a soak that just failed. The code-review
   checklist item "must FAIL the soak on restart, not silently re-resolve"
   means: the script explicitly compares the CURRENT PID and NRestarts
   count against the PREVIOUS sample every cycle, and if either changed,
   the soak **stops immediately and reports FAIL** — it does not keep
   sampling the new process as if nothing happened.
4. On completion (24h with no restart detected), writes a summary alongside
   the CSV: total rotations attempted, rotations committed/failed/rejected
   (parsed from the sentinel outcome suffixes accumulated on the Pi), fd/RSS
   trend (first vs last sample, and a naive linear-fit slope), and a PASS/
   FAIL verdict per the criteria above.

## Evidence to archive

Following this repo's QA report convention (`docs/QA_REPORT_*.md`), once
the soak runs, archive under `docs/`:

- `docs/CERT_ROTATION_SOAK_<YYYYMMDD>.csv` — the raw samples.
- `docs/CERT_ROTATION_SOAK_<YYYYMMDD>.md` — the summary + verdict, plus any
  anomalies investigated (a single transient fd blip that self-corrected is
  not the same finding as a monotonic leak — say which one, with numbers).
- Update `docs/refactor/08_RISK_REGISTER.md`'s RSK-07 row to fully
  "Mitigated" with a link to the summary, and TASK-073's status header /
  `00_MASTER_INDEX.md`'s P6 row.

## If it fails

A restart/segfault during the soak is itself the finding — do not re-run
and hope for a clean pass without root-causing it first:

1. Pull the core dump / journal around the exact restart timestamp
   (`coredumpctl list`, `journalctl -u lexa-northbound --since <ts> -n 200`).
2. Check which rotation cycle number it landed on and whether it correlates
   with a specific fetcher (discovery/response/flow-reservation) or a
   specific outcome (a probe-rejected cycle stresses the "tear down the NEW
   session" path harder than a committed one).
3. File the finding the same way Mayhem findings are filed
   (`docs/QA_FINDINGS.md` pattern) before attempting a fix — this is
   exactly the RSK-07 risk materializing, and deserves the same rigor as
   any other hostile-QA finding.
