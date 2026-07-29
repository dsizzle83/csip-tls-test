# Handoff — CSIP/SunSpec conformance, 2026-07-29

Successor to `HANDOFF_2026-07-28_csip.md`. Written at the end of a long autonomous
session that took the conformance effort from "the last opus session may have made
a mess" to: **one real product security bug found, fixed, and confirmed on
hardware; everything else resolved, validated, or precisely scoped.** Read §1 and
§2 first.

---

## 1. REPO STATE (everything pushed and clean as of session end)

All branches are pushed to origin; working trees clean. Tips:
| repo | branch | HEAD | note |
|---|---|---|---|
| `lexa-gw` | `qa/adversarial-and-conformance` | `dc35085` | deploy config-preservation, walk regression tests, platform-pin bump/vendor sync |
| `csip-tls-test` | `qa/conformance-evidence` | `3dc66a3` (+ this handoff commit) | 5 evaluator-bug fixes, mRID isolation, obs-window fixes |
| `lexa-platform` | `fix/bio-eintr` | `3eba5bd` | the COMM-004 cert-validation fix (3 commits) |
| `meta-lexa` | `chore/wolfssl-stale-refs` | `189f2e0` | image build-id + census |
| `lexa-proto` | `main` | `67cadfe` | pushed; all repos pin it |

Each tip is a verified state: lexa-platform tested after the recover-guard,
lexa-gw `make build-arm64` + provmanifest PASS, csip-tls-test full-suite-green
on both builds. None of these branches is merged to `main` yet — that's a PR
decision for you (note: `csip-tls-test` and `lexa-hub` are PUBLIC repos, §6.13).

## 1a. FIRST THINGS (do these before anything else)

1. **The board is on a dev-deploy, not a stamped image.** Board build =
   `dc35085` (lexa-gw), installed via `scripts/deploy-gw.sh` (build-id marked
   `dev-deploy`). Fine for bench; a formal ATL submission wants a stamped image
   (task #9). See §5.

3. **Bench is healthy and idle.** Board `cc93` running the fixed firmware,
   `authority=csip`, both sims connected, gridsim up. §3 has the health-check.

---

## 2. WHAT WAS ACCOMPLISHED (so you don't redo it)

### The one real product security finding — CLOSED end-to-end
**mbedTLS CSIP client accepted malformed intermediate CAs** (COMM-004D/E/F).
Root cause: mbedTLS 4.1.1 doesn't implement `nameConstraints`, `policyMappings`,
or EKU chain-nesting — no config fixes it. Fix (lexa-platform `d1897a8`,
`2486144`, `3eba5bd`): a custom `mbedtls_ssl_conf_verify` callback
(`mbedtls/caverify.go`) with three targeted RFC-5280 checks, **CSIP-leg only**
(`tlsclient/client.go:288`; mbaps/securemodbus untouched), fails closed on a
panic. Adversarially reviewed SHIP. **Deployed and CONFIRMED ON HARDWARE**
(`runs/certfix-validate-20260729T192416`): COMM-004D/E/F all reject the bad
intermediates, 004B still accepts a valid chain (no false-reject), bundle
verifies. THIS IS DONE.

### Everything the overnight 4-run batch surfaced that turned out NOT to be a product bug
- **status=2 "flakiness"** (BASIC-017..026 failing runs 2/3/4 of the overnight
  batch) = **test-isolation artifact**. The harness reused *static* control
  mRIDs; the gateway correctly refuses to re-Ack an mRID it already ran to
  terminal (IEEE 2030.5 mRIDs are globally unique+stable). Fixed with per-run
  mRIDs (`csip-tls-test` `a598d10`). **Validated**: 2 consecutive runs both 0
  FAIL on the block (overnight had 10 FAIL each). The status=2 path is CORRECT.
- **707-710 / MOD-4** = **stale bench admission**, not a walk bug. The SunSpec
  walk is correct (regression-tested, lexa-gw `65b25ec`). Devices were admitted
  2026-07-21, before the trip-serving sim existed; re-admission picks them up.
  Validated live: 707-710 appear after `systemctl restart lexa-modbus` with the
  bench device list present. Only 703 remains genuinely absent (sim doesn't
  serve it).
- **DER self-report FAILs** (BASIC-028, CORE-009, CORE-014) = product IS correct
  (metric `lexa_nb_derreport_puts_total`=412); harness observation-window issue.
  Partly fixed (`3dc66a3` run-scoped observation) but still FAILs under
  `-require-citation` because the observation is server-record not wire-cited —
  see task #34.
- **RBAC-002** = correct-by-design: under `authority=csip` the CSIP overlay
  denies privileged 704-712 writes (a pinned, tested expectation). Passed in the
  earlier shakedown only because that ran `authority=mbaps`. Test needs to be
  authority-aware.
- **PKI-4** = harness citation-window bug (fixed `a9f6843`); the hwType cert
  itself WORKS (PKI-5 confirms empty Subject + hwType `1.3.6.1.4.1.50316.1.1` +
  hwSerialNum on the leaf).

### Harness quality (all in csip-tls-test, all reviewed)
- 5 evaluator bugs fixed + reviewed SHIP (the big one: a FALSE PASS on the
  negative COMM-004 security rows from direction-blind fatal-alert attribution).
- Applicable/informative FAIL split in the run summary (claim-relevant vs
  implemented-but-not-claimed).
- gridsim: chain-swap lever (COMM-004 D-G), Figure-15 fleet + Subscription, the
  aggregator evaluators, `-no-tickets`.

### Product / platform (lexa-gw, lexa-platform, meta-lexa)
- hwType device cert (empty Subject + RFC4108 HardwareModuleName SAN),
  CSIP-domain-only. Reissue: `FORCE_REISSUE=nb-csip-identity bash
  scripts/bench-pki-bootstrap.sh` (LFDI changes → re-registration).
- Event-driven confirm latch + fast-fail CannotComply under non-CSIP authority +
  Started(2) dateTime from the report timestamp (all in
  `internal/northbound/responses/tracker.go`).
- TLS 1.3 MFL reaches the record layer (mbedtls patch 0005).
- 1547 models 703 + 705-712 read-only northbound (Stages 0-4; write path is
  Stage 5 = task #22).
- `deploy-gw.sh` now preserves bench-provisioned config through a redeploy
  (`PROVISIONED_KEYS`: certmgr.vault.provider, northbound.server,
  modbus.devices) — proven live during the cert-fix deploy.
- TRR generation (`certify -trr`) + the `results-report` suite validates the
  submission report.

### The commercial decisions (recorded, don't relitigate)
- **CSIP profile = DER Client, GFEMS scenario** (NOT aggregator). Aligns with
  utility decision pack D3.1 (Scenario 1/Direct). The 22 aggregator-column rows
  are implemented and run **informatively**, not claimed. PICS:
  `lexa-gw/docs/conformance/PICS_CSIP.md`.
- status=2: **keep the actuation-confirm gate** (confirm-then-report matches the
  CTP ordering + EVENT.042); don't post Started at adopt.
- TLS 1.3 server MFL: **completed patch 0003** into the record layer.
- Catalog is at DER-Client scoping, sha256 `2d7e1e89...`.

---

## 3. BENCH STATE + HEALTH CHECK

**Board `cc93`** = `ccimx93-dvk`, User=root (ssh alias set), UTC-4 (EDT). Runs
**mbedTLS**, NOT wolfSSL (the migration shipped; ignore any stale "9e1e350
wolfSSL" note). Build `dc35085`, dev-deploy.

Posture that must hold for a CSIP campaign (all currently set):
- `authority=csip` — `/etc/lexa/mode.json` `"authority":"csip"`
- `actuation_confirm_window_s=180` — `/etc/lexa/northbound.json` (NOT preserved
  by deploy; re-set after any redeploy: it reverts to the 60s default)
- `northbound.json` `"server":"69.0.0.20:11113"` (preserved by deploy now)
- `modbus.json` `devices` = inv-plain `tcp://69.0.0.20:5020` + inv-secure
  `mbaps://69.0.0.20:8021` (preserved by deploy now)
- certmgr `vault.provider=filevault` (bench; ele isn't linked — preserved now)

**Sims** (on the workstation, `69.0.0.20`): `scripts/bench-sims-up.sh`. For the
2-sim setup: modsim `:5020` (start with `DER_MODELS=full` for 707-710 trip
models), mbapsdev `:8021`. gridsim is the **keylog build** with the chain-swap
lever, run as one process on both ports:
```
setsid nohup ./bin/server-keylog -listen 0.0.0.0:11113 -admin 0.0.0.0:11114 \
  -ca certs/mbaps/ca-cert.pem -cert-chain certs/mbaps/dev-server-cert.pem \
  -key certs/mbaps/dev-server-key.pem -poll-rate-s 60 -idle-timeout-s 10 \
  -no-tickets -keylog /tmp/bench-shared.keylog > /tmp/gridsim-campaign.log 2>&1 &
```

**60-second health check before trusting any run:**
```
ss -ltnp | grep -E '11113|11114'          # ONE pid on BOTH ports (§8 landmine)
grep 'GET /dcap' /tmp/gridsim-campaign.log | tail -1   # DUT walking (recent)
ssh cc93 'systemctl is-active lexa-northbound lexa-modbus lexa-mbaps'
# inventory shows 707-710 on inv-plain:
ssh cc93 'TOKEN=$(tr -d "\n\r" </etc/lexa/api.token); wget -qO- --no-check-certificate \
  --header="Authorization: Bearer $TOKEN" https://127.0.0.1:9100/southbound/inventory'
```

---

## 4. THE OPEN GAPS — how to close each

### Task #34 — wire-cite DER-report PUTs (harness) — SMALL, do first
BASIC-028/CORE-009/CORE-014/UTIL-002 FAIL under `-require-citation` even though
the product emits the PUTs, because the harness observes them via gridsim's admin
log (server record), not the wire. **Fix:** the DER-report checks must find the
actual HTTP PUT frames in the decrypted capture (keylog is already collected) and
cite them, so the assertion carries a digest. Look at how COMM-003 wire-cites a
decrypted HTTP body and mirror it. Files: `internal/certify/suitecsip/`
(`critDERPut` in `criteria_2030.go`, `critDERStatusElements` in `basic.go`) +
`observe.go` `RunDERPuts`. Verify with a csip run: those 4 rows go PASS.

### Task #24 — wire authority intents into lexa-mode (product) — SMALL/MEDIUM
`POST /intent {"type":"authority",...}` validates and publishes
`lexa/intent/authority` but **lexa-mode never subscribes to it** (only
`lexa/intent/local/+`, `cmd/mode/main.go:203`). So the dev-API lever is dead; the
bench workaround is editing `/etc/lexa/mode.json` + `systemctl restart lexa-mode`.
**Fix:** subscribe authority/vendor_access intents in lexa-mode, apply, publish
`lexa/intent/result`. ACL grants already exist. OR (smaller) make the API return
501 for unwired intent types instead of a misleading `pending`.

### Task #22 — 1547 Stage 5, northbound curve write path (product) — LARGE (~12-18 eng-days)
Read-only MOD-4 already passes; this closes profile G3 (second curve writable).
Full design is in `lexa-gw/docs/design/DESIGN_2026-07-28_1547-northbound-models.md`
§5: staging store beside `image.shadow`, a third "staged" disposition in the
serve ladder (`internal/listener/serve.go`), `AdptCrvReq` as the commit point
assembling a new `topics.MbapsCurveWrite`, `mbapsin` curve executor →
`bus.DesiredAdvanced`. Also needs `enumAllowed` entries for 705-712 and the G1
trip-`Ena` equality gate. Not campaign-gating.

### Task #32 — harden lexa-proto scanModels (adversarial) — SMALL, cross-repo
`vendor/lexa-proto/sunspec/scanModels` relies on a read failure to terminate a
no-End chain. Real hardware is safe (IllegalDataAddress). An adversarial device
answering every read non-0xFFFF could spin on uint16 wrap. **Fix:** add a
max-model / max-register bound in the lexa-proto sunspec codec. Cross-repo pin
ripple (proto.pin in 3 repos). Low priority.

### Task #9 — flash the gate-proven migrated image (release/bench) — MEDIUM
The board runs dev-deployed binaries over an old rootfs (no on-device build-id
file beyond `/etc/lexa/build-id`; rootfs epoch is a placeholder). The gate-proven
migrated image (`meta-lexa` `lexa-mbedtls_4.1.1`, two-builder PASS) has never been
flashed. For a formal ATL submission the evidence bundle should name a **stamped
image**, not a dirty-tree dev-deploy. Path: bump the image SRCREV to the final
lexa-gw commit, build via the self-hosted lane (hours), `.swu` into the inactive
A/B slot, health-confirm. The bench posture (§3) must be re-applied after (the
image ships factory defaults). This is the last thing before a real submission.

### Also outstanding (not yet ticketed as tasks, from the analysis)
- **RBAC-002 authority-awareness**: run the SSM RBAC suite under
  `authority=mbaps`, or make the check read the live `GatewayMode.Authority`.
- **BASIC-029 (MirrorUsagePoint)**: telemetry isn't commissioned on the bench
  (`/etc/lexa/telemetry.json` `server:""`, `devices:[]`). Commission it if MUP
  coverage is wanted; else it's correctly informative-absent.
- **COMM-004 coverage on any re-run**: the chain-swap fixtures are a coverage
  lottery. The `certfix-validate` run happened to catch all of D/E/F; if a future
  run SKIPs some, lower gridsim `-idle-timeout-s` below the DUT poll cadence and
  raise `-param csip.wait`.
- **WARN decay from session attribution**: overlapping TLS sessions on the shared
  `:11113` make the discovery-session ambiguous, decaying some PASS→WARN across a
  serialized batch. Per-run gridsim session isolation (fresh gridsim, or
  idle-timeout tuning) would fix it. Not a product signal.

---

## 5. HOW TO RUN THINGS

**Full campaign** (all 6 suites, ~2.5-3h on a clean CSIP leg):
```
cd ~/projects/csip-tls-test
./bin/certify-keylog -suite ssm,modbus-server,csip,modbus-client,pki \
  -target 69.0.0.2:802 -iface enp1s0 -pki certs/mbaps -gateway-ssh cc93 \
  -gridsim 69.0.0.20:11113 -gridsim-admin http://69.0.0.20:11114 \
  -keylog /tmp/bench-shared.keylog -require-citation \
  -dut-build <build-id> -dut-identity <LFDI> -out runs/<name>/
```
`-gridsim` MUST be `69.0.0.20:11113`, never `127.0.0.1` (loopback never appears on
`enp1s0` → 0 attributed frames). Get `<LFDI>` from `journalctl -u lexa-northbound
| grep 'CSIP sessions up'`; `<build-id>` from `ssh cc93 cat /etc/lexa/build-id`.

**Verify a bundle** (third-party checkable, offline): `./bin/certify -verify
runs/<dir>/`. **Generate the TRR**: `./bin/certify -trr runs/<dir>/ ...` then run
the `results-report` suite against it.

**Rebuild after harness changes**: `make certify-keylog build-certify`. gridsim:
`make server-keylog` (needs the keylog sysroot `~/.local/wolfssl-amd64-keylog`).

**Only the reconciled CONFORMANCE RUN SUMMARY is real** — the live `[p/f/s/w]`
counters are provisional and the citation phase can only lower a verdict. A run
shown live as all-SKIP finalizes to real verdicts.

**Deploy the product to the board**: `bash scripts/deploy-gw.sh cc93 root
[--skip-build]` (from lexa-gw; build arm64 first or let it, needs
`$MBEDTLS_SYSROOT_ARM64` = `/tmp/mbedtls-arm64-sysroot`, rebuild with
`make build-mbedtls-sysroots` — it's in /tmp, wiped on reboot). Re-set
`actuation_confirm_window_s=180` after.

---

## 6. TRIBAL KNOWLEDGE / LANDMINES (each cost real time)

1. **`deploy-gw.sh` clobbers bench-provisioned config.** Now fixed for
   `certmgr.vault.provider`, `northbound.server`, `modbus.devices` (the
   `PROVISIONED_KEYS` allowlist). NOT preserved: `actuation_confirm_window_s`
   (re-set to 180 after every deploy). A stale in-RAM admission cache masks a
   clobbered `modbus.json` until the next `lexa-modbus` restart.
2. **certmgr crash-loops on `elevault` on a pure bench build** ("provider not
   linked"). Bench uses `filevault`. The deploy forces it now.
3. **PKI reissue ordering**: restart northbound ONLY after `FORCE_REISSUE`
   completes AND certmgr has promoted the new leaf — otherwise the client serves
   the OLD cert with the NEW key → CertificateVerify mismatch → all handshakes
   fail. If in doubt, restart certmgr then northbound. The reissue **changes the
   LFDI** (northbound re-registers with gridsim).
4. **northbound reads its CSIP server URL from `northbound.json` `"server"`**,
   not from a discovery. Empty → "uncommissioned idle", it silently stops
   dialing. The old process keeps its in-memory config until restarted, which
   masks a clobbered file.
5. **The board has no `curl`/`nc`.** Dev-API is HTTPS on `:9100` — use `wget
   --no-check-certificate`, Bearer token from `/etc/lexa/api.token` (strip the
   newline: `tr -d '\n\r'`). `bench-certctl` must run `sudo -u lexa-api` (socket
   authz by peer uid).
6. **lexa-mode ignores `POST /intent authority`** (task #24). Switch authority
   via `/etc/lexa/mode.json` + `systemctl restart lexa-mode`.
7. **Static mRIDs + a long-lived gateway = the whole "status=2 flakiness."** Any
   NEW event-lifecycle test needs per-run-unique mRIDs (the harness now mints a
   run nonce; `register.go`). The gateway is CORRECT to dedup.
8. **A device is re-identified only on (re)admission, not per poll.** Stale
   inventory (e.g. missing 707-710) → `systemctl restart lexa-modbus` (with the
   right `modbus.json` devices present) to re-admit.
9. **gridsim: ONE process on BOTH ports.** An orphaned old gridsim on `:11114`
   while a new one holds `:11113` makes the harness read observations from a
   different server than the DUT talks to. `ss -ltnp | grep -E '11113|11114'`
   must show one pid. Preflight enforces host-match now.
10. **`-no-tickets` on gridsim** forces a full mTLS handshake per dial, so every
    CSIP session is decryptable/citable. Without it the gateway holds one
    persistent session (correctly) and re-handshakes rarely.
11. **`setsid nohup ... &` — `$!` is the wrapper, not the process.** Re-read the
    real pid with `pgrep -f 'bin/...'`. A monitor's `pgrep` pattern must match
    the ACTUAL script name (a repurposed monitor false-alarmed this session
    because it still grepped the old batch name).
12. **wolfSSL never ships in the product; mbedTLS never gets keylog.** The bench
    keylog is a separate wolfSSL sysroot (`~/.local/wolfssl-amd64-keylog`, gridsim
    side) — the DUT's mbedTLS is unmodified. Never add key export to the product.
13. **`csip-tls-test` and `lexa-hub` are PUBLIC** — no self-hosted CI runners
    there; a PR could execute code on the workstation holding bench SSH keys.
14. **Never `make gen-mbaps-certs`** (RemoveAll + new root, locks the bench out).
    Use `-reuse-ca`. `runs/` is gitignored (keys.log = real secrets).
15. **Board clock is UTC-4; gridsim logs local, certify/bundles log UTC.** Don't
    mis-compute elapsed times across them.

---

## 7. KEY REFERENCES

- Catalog: `testdata/catalog/catalog.json` sha256 `2d7e1e89...`, hand-curated
  (no generator), applicability = DER-Client/GFEMS column.
- PICS: `lexa-gw/docs/conformance/PICS.md` + `PICS_CSIP.md` +
  `PICS_SUNSPEC_MODBUS.md`.
- 1547 design: `lexa-gw/docs/design/DESIGN_2026-07-28_1547-northbound-models.md`;
  scope `docs/design/MOD4_1547_PROFILE_SCOPE.md`.
- Cert-fix: lexa-platform `mbedtls/caverify.go` + `mbedtls_shim.c`
  `lexa_ca_ext_verify_cb`; enabled `tlsclient/client.go:288`.
- Confirm-latch / responses: `lexa-gw/internal/northbound/responses/tracker.go`.
- Deploy: `lexa-gw/scripts/deploy-gw.sh` (`PROVISIONED_KEYS`).
- PKI bootstrap: `lexa-gw/scripts/bench-pki-bootstrap.sh` (`FORCE_REISSUE`).
- Standards PDFs: `~/Documents/standards/drive-download-20260714T174431Z-1-001/`.
- Evidence bundles this session: `runs/overnight-20260729T045336/` (4-run
  baseline), `runs/validation-20260729T153348/` (harness-fix validation),
  `runs/certfix-validate-20260729T192416/` (cert-fix hardware confirmation).

---

## 8. SUGGESTED ORDER FOR THE NEXT SESSION

1. Push the three branches (§1).
2. Close #34 (wire-cite DER-report PUTs) — small, and it turns 4 applicable rows
   green, tightening the CSIP scorecard.
3. Close #24 (lexa-mode authority intents) — small, removes a bench workaround.
4. Decide on #9 (flash the stamped image) if a formal ATL submission is near —
   that's the gate to real evidence.
5. #22 (1547 write path) and #32 (codec hardening) are larger / lower priority.
6. Then a clean full 6-suite campaign on the stamped image, `certify -verify` +
   `certify -trr` + `results-report`, per §5, as the submission evidence.
