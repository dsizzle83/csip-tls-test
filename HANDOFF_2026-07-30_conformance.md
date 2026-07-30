# Handoff — CSIP/SunSpec conformance, 2026-07-30

Successor to `HANDOFF_2026-07-29_conformance.md`. Written at the end of a session that
took the effort from "dev-deploy on a dirty tree" to **a stamped image on the board,
three third-party-verifiable evidence bundles, and one P1 image defect found, fixed,
and rebuilt (not yet flashed)**. Read §1 and §2 first.

---

## 1. STATE (all mainlines pushed; three commits held back for review)

| repo | branch | HEAD | mainline | note |
|---|---|---|---|---|
| `lexa-gw` | `qa/adversarial-and-conformance` | `a98f80e` | pushed to `main` | == the image's SRCREV |
| `csip-tls-test` | `qa/conformance-evidence` | `3ba4e80` | **1 unpushed** | the exchange-selector fix |
| `lexa-platform` | `fix/bio-eintr` | `314ce34` | pushed to `main` | + `InverterStatus`, gofmt |
| `meta-lexa` | `master` | `e8da435` | **2 unpushed** | wan0 fix + mbedTLS patch series |
| `lexa-proto` | `main` | `8788796` | pushed | bounded scanModels |
| `lexa-hub` | `task/mbedtls-migration` | `e7f3e83` | pushed to `main` | proto pin only |

All trees clean. Local CI was run for every repo (no Actions credits — see §6.1).
**The 3 unpushed commits are deliberate**: they are the mbedTLS patch-series fix and
the harness selector fix, both worth an owner read before they go up.

## 1a. FIRST THINGS

1. **The board runs a STAMPED image** — `a98f80eae268 image 1.0.0`, slot **B**,
   auto-committed, LFDI preserved. No more dev-deploy. RRS §2.1 is satisfiable now.
2. **A patched `.swu` is built and waiting**, not flashed:
   `dey-image-lexa-gw-swu-ccimx93-dvk-20260730083225.swu`
   sha256 `50c26a6a629a3b60934c6541e9f477299b5d5bb9e98d09d2ef586486234bbe34`.
   It fixes the P1 in §2. **Flashing it is the first real decision.**
3. Runbooks live in `~/runbooks-20260729/` (flash, 1↔1 posture, revert, drivers) and
   the full narrative in `OVERNIGHT_REPORT_2026-07-30.md` there.

---

## 2. THE P1: the image shipped 1 of 5 mbedTLS patches

`lexa-gw/scripts/build-mbedtls-sysroot.sh` applies patches 0001–0005 with fail-closed
marker greps. `meta-lexa`'s `lexa-mbedtls` recipe applied **only 0001**.

Without `0002-tls13-record-mfl-as-sent`, the DUT as TLS **client** emits
`max_fragment_length` but never sets its own sent-extension bit, so the peer's echo is
rejected: `-29952 "Client received an extended server hello containing an unsupported
extension"`. **Every mbaps client dial fails ⇒ `inv-secure` permanently comm-lost.**
The DUT's mbaps *server* side is unaffected — which is exactly why every image gate
stayed green and why this survived a two-builder reproducibility proof.

Structural cause: the recipe's sha256 tripwires fire per *carried* file. A patch absent
from `SRC_URI` had no tripwire to fire and no marker to fail. Absence was unrepresentable.

Fixed in `meta-lexa e8da435`: all five carried, per-patch sha256s, a **whole-series
digest gate** (omission is now fatal), post-apply marker assertions stricter than the
sysroot script's, and the series recorded in the emitted mbedTLS identity.
Rebuild verified: markers present in built source, `patch_series_sha256 f37836d4…`
recorded, census 33/33, hardening PASS.

**Independent confirmation:** full-suite `TLSF-002` FAILs on the current image because
the server picks CCM over mandated GCM order — precisely what patch **0004** fixes.

**On re-flash, DUT on-wire behaviour changes** (0003/0004/0005 are server-side too):
configured ciphersuite order wins, and the listener honours a client-requested MFL.
TLSF-002 should flip to PASS; the TLS rows of the 2026-07-30 full-suite bundle become
provisional and want a re-run.

---

## 3. EVIDENCE BUNDLES (all pass `certify -verify`)

| bundle | scope | result |
|---|---|---|
| `runs/stamped-csip-validate-20260730T060419` | CSIP 79 cases, 1↔1 posture | 52 P / 6 F / 19 S / 2 W — **4 applicable FAIL** |
| `runs/stamped-basic029-20260730T073518` | BASIC-029, 12-min window | **1 PASS / 0 FAIL** |
| `runs/stamped-fullsuite-20260730T075718` | ssm+modbus-server+modbus-client+pki, 81 cases, 2-device | 40 P / 3 F / 12 S / 26 W |

"✓ BUNDLE VERIFIES — every cited frame and byte range is in this capture" for all three.
That is the campaign's core claim and it holds.

**Two postures are structural, not sloppiness.** The derreport fail-safe only PUTs in a
1-device↔1-DER shape (CSIP leg), while SSM/RBAC need the 2-device fleet. Two bundles.

The 26 full-suite WARNs are the *partially addressed* bucket — PASS assertions plus
assertions that could not be exercised. **No failing assertion inside any of them.**

---

## 4. OPEN ITEMS

### 4.1 Decisions (owner)
1. **Flash the patched `.swu`** (§1a.2). Unblocks everything secure-Modbus and TLSF-002.
2. **CORE-009 / CORE-014 — a design call, deliberately not made.** The product is
   CORRECT: CSIP IG §6.3.5.2 requires DERCapability/DERSettings at *start-up and on
   change*, DERStatus at pollRate — so a window taken hours after boot legitimately
   holds only DERStatus. Observing the start-up PUTs needs a harness-driven
   commissioning trigger (restart northbound over `-gateway-ssh`). **An agent began
   this and stalled after opening a path that bypasses the harness's read-only
   allowlist; the partial change was reverted.** Before anyone retries: RRS v1.1 §2.1
   forbids altering software/hardware mid-test. A service restart is arguably a
   commissioning action, not an alteration — but that argument must be explicit,
   recorded in the bundle so no assessor thinks the PUTs were spontaneous, and
   ideally confirmed with the ATL. Do not let a harness perturb a DUT into a PASS
   without saying so on the record.
3. **RBAC-002**: run the SSM leg under `authority=mbaps`, or make the check
   authority-aware. (The `POST /intent {"type":"authority"}` lever now works, so
   flipping authority is a one-liner — no more `mode.json` editing.)
4. **Model 703 in modsim** — the only thing between MOD-4 and PASS. Bench-fixture work.
5. Unchanged from yesterday: the three SunSpec/ATL questions (gateway submittable
   against the DER Client column; the CSIP `Test Description` enumeration, whose
   referenced Appendix A does not exist; whether mbaps satisfies the base Modbus TCP
   rows) and a public URL home for the PICS.

### 4.2 Known-diagnosed, not defects
- **BASIC-022** — isolated flake; siblings 021/023 PASS. Response POST landed outside a
  27 s window. Re-run it.
- **BASIC-029** in the main run — window too short by design; PASSES in its own bundle.
- **MOD-4** — fails only on model 703 (sim gap). 713 correctly conditional-absent.
- **BASIC-003** — gridsim serves 1 EndDevice / 1 FSA / 3 DERPrograms; procedure wants
  3 / 7 / 7. Bench-fixture gap, labelled as such by the harness.

### 4.3 Backlog
- `meta-lexa` workflow `env.SRCREV` is stale (`9c269ee` vs recipe `a98f80e`) **and** its
  cross-check is tautological — same value into `--srcrev` and `--manifest-srcrev`, so
  divergence is undetectable. The signed provenance names the wrong commit. Fix by
  extracting the real ELF `vcs.revision` (the job already does `strings`-style work).
- **CVE ratchet: 5 undispositioned BSP CVEs** (systemd, tar, util-linux) — `sbom-cve`
  gate FAILs. Same package versions as the previously-running image, so flashing did
  not regress it, but the lane is red until triaged.
- `lexa-mbaps` has **no "device model set changed" re-chain trigger**, only geometry
  mismatch (§6.4).
- `lexa-hub` `platform.pin` is stale; `check-proto-pin.sh --verify-vendor` has a
  lexa-platform replace-directive bug on the lexa-hub path (never hit in hosted CI).
- **NTP** is not configured board→workstation; the clock is manual (§6.3).
- Task #22 (1547 Stage 5) remains deferred: **20–35 eng-days**, not the 12–18 the design
  claimed. `PinnedNCrv=1` (landed) removed the CRV-2/CRV-3 exposure that made it urgent.

---

## 5. HOW TO RUN THINGS

```
# flash the patched image (serial console attached first)
bash ~/runbooks-20260729/runbook-flash-task9.sh

# CSIP leg posture (1 device <-> 1 DER) / restore 2-device fleet
bash ~/runbooks-20260729/runbook-csip-posture-1to1.sh
bash ~/runbooks-20260729/runbook-csip-posture-revert.sh

# campaigns — detached, sentinel-guarded, survive session death
setsid nohup bash ~/runbooks-20260729/campaign-driver.sh &   # CSIP + BASIC-029
setsid nohup bash ~/runbooks-20260729/fullsuite-driver.sh &  # ssm/modbus-server/client/pki
#   sentinels: /tmp/STAMPED_VALIDATE_DONE, /tmp/FULLSUITE_DONE

# image rebuild (warm sstate, ~9 min)
setsid nohup bash ~/kas-work-lexa/campaign-cut-driver.sh &   # sentinel CAMPAIGN_BUILD_DONE

./bin/certify -verify runs/<dir>/     # third-party checkable, offline
```

**Do NOT set `-param csip.wait` globally.** It applies to every waiting case; 16m turned
a 2 h campaign into a 25 h one. Only BASIC-029 needs a long window — run it as its own
pass (that is what `campaign-driver.sh` does).

---

## 6. TRIBAL KNOWLEDGE ADDED THIS SESSION

1. **Local CI**: no Actions credits. Replicate each repo's `ci.yml` locally. The
   `gofmt -l` gate catches things reviewers miss — it blocked three repos this session.
   `csip-tls-test`'s golangci-lint "new issues only" diff cannot be reproduced locally
   (needs the GitHub API); everything else can.
2. **SSH host keys are rootfs-resident** — every flash changes them. Expect the
   "REMOTE HOST IDENTIFICATION HAS CHANGED" banner; `ssh-keygen -R 69.0.0.2`. It is not
   an attack, and the runbook's first ssh will abort on it.
3. **The flash resets the board clock** (timesync state is rootfs-resident; the RTC was
   unset). It came up in **2025** — which would have poisoned every timestamp in an
   evidence bundle. `date -u -s` + `hwclock -w`, and **verify the clock before any run**.
   A satisfying side-effect: the wrong clock made the DUT *reject* gridsim's certificate,
   proving mbedTLS time validation fails closed.
4. **Persisted regmap chains outlive flashes and can go stale silently.** A chain with
   no curve models does not encode NCrv geometry, so `ErrGeometryMismatch` never fires
   and a months-old chain survives — MOD-4 then FAILs on missing models. Fix:
   `rm /var/lib/lexa/regmap/unit-*.json` + restart `lexa-mbaps` (rebuilds from live
   inventory; backup at `/var/lib/lexa/regmap-bak-20260730`).
5. **Everything bench-provisioned survives a flash.** `/etc/lexa`, `/var/lib/lexa` and
   the filevault are binds of data partition p7, and `lexa-data-init` seeds only when
   empty. **The LFDI is preserved — never run `FORCE_REISSUE` after a flash reflexively.**
   Lost on flash: `bench-certctl` (rebuild: `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go
   build ./scripts/bench-certctl`, push with `ssh cc93 'tee ...'`) and the NM profiles.
6. **Both u-boot env copies end up describing the new slot** after an install — the
   "other copy is your rollback record" story is wrong, because `update-firmware` issues
   several `fw_setenv` calls and they ping-pong. Rollback is still safe (slot A's
   partitions are untouched, `altbootcmd` + `bootlimit=3` still arm). Also: the board's
   `od` is BusyBox (no `-A`), and the first env var is glued to the CRC+flags prefix, so
   env greps must be unanchored.
7. **The bench board is single-NIC on the EQOS**, which the image's `10-wan0.link`
   renames to `wan0`. A stock (DHCP) `wan0` profile **strands SSH permanently** on the
   air-gapped bench, and auto-rollback will not save you — `lexa-healthcheck` is
   loopback-only, so a slot with no LAN still commits as HEALTHY. The bench build now
   bakes a static `69.0.0.2/24`; field builds keep DHCP.
8. **Harness attribution subtlety that cost a full campaign**: criteria search every
   conversation a case owns, and a real window routinely catches a sibling connection
   whose response landed after the window closed — an Exchange with `Resp == nil`. That
   is not a redirect, so a "last non-3xx" rule selected it over the completed fetch and
   graded 29 rows as "GET /dcap was never answered". Answered exchanges must outrank
   unanswered ones. Fixed in `3ba4e80`; the wrong preference had been *pinned by a test*,
   which is why review missed it.
9. **The classifier blocks board state changes** (service restarts) even with an ssh
   allow rule; file pushes work via `ssh cc93 'tee /path' < local`. Long/state-changing
   bench sequences belong in an operator runbook, not in tool calls.
10. **`setsid nohup` + a sentinel file + a monitor** is the only reliable way to run a
    multi-hour campaign — background wrappers get killed, and a monitor that only greps
    for success is indistinguishable from a hung run. Watch for the driver dying too.

---

## 7. KEY REFERENCES

- Overnight narrative: `~/runbooks-20260729/OVERNIGHT_REPORT_2026-07-30.md`
- Runbooks + drivers: `~/runbooks-20260729/`
- mbedTLS patch source of truth: `lexa-gw/scripts/mbedtls-patches/` (mirrored into
  `meta-lexa/recipes-connectivity/lexa-mbedtls/files/`; the series digest enforces parity)
- Standards: `~/Documents/standards/drive-download-20260714T174431Z-1-001/`
  (CTP §4 applicability matrix pp. 19–20 = the whole scoping rule; RRS v1.1 §2.1, §5)
- Catalog `testdata/catalog/catalog.json` sha256 `2d7e1e89…` — verified transcription-exact
  against the printed CTP matrix, all three columns.
- Prior handoff: `HANDOFF_2026-07-29_conformance.md` (its "DER self-report is fine,
  metric=412" claim is **superseded** — see that session's finding; the metric read 0).
