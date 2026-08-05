# PRE-FLIGHT — flashed-image conformance campaign, 2026-08-05

Written from the harness at `qa/conformance-evidence` after the round-8 hermeticity
fix and the post-`0d01403` stale-expectation sweep. Read it before the first
`certify` invocation of the night; everything here is either a posture the bench
must be put into or a verdict that will look different from the 2026-08-01 run
and should not be mistaken for a regression.

The authority for what a leg will actually run is
`./bin/certify -dry-run -suite <list>`. Every count below was taken from it.

---

## 1. The two legs, and why there are two

`HANDOFF_2026-07-30_conformance.md` §"Two postures are structural, not
sloppiness": the derreport fail-safe only PUTs in an unambiguous 1 device ↔ 1
server-DER shape, while the SSM/RBAC rows need the 2-device fleet. One bench
cannot be both at once, so the campaign is two bundles, not one.

### Leg A — CSIP (`-suite csip`)

| | |
|---|---|
| catalog rows selected | **79** — 51 applicable, 79 implemented, 0 unimplemented |
| southbound posture | **1 device**: `inv-plain` only (`tcp://69.0.0.20:5020`) |
| northbound | gridsim data plane `69.0.0.20:11113`, admin `http://69.0.0.20:11114` |
| DUT authority | `authority=csip` (`/etc/lexa/mode.json` + `systemctl restart lexa-mode` — the intent API does NOT switch authority, landmine #6) |
| posture script | `~/runbooks-20260729/runbook-csip-posture-1to1.sh`, revert with `runbook-csip-posture-revert.sh` |
| long-window rows | BASIC-029, CORE-022, CORE-023 run as **separate `-uid` invocations** with per-run `-param csip.wait`; never set `csip.wait` globally (it applies to every waiting case and turned a 2 h campaign into a 25 h one) |

Ordering inside the posture script is load-bearing and is not a style choice:
`lexa-modbus` first (republishes inventory, retires `inv-secure`), then
`lexa-telemetry` (the derproducer diffs and tombstones the retired device),
then `lexa-northbound` **last** — its seed buffer must be built from the
corrected set. Verify one non-empty `lexa/der/+/report` line before continuing,
and never hand-clear `lexa/southbound/inventory` (whole-table doc).

### Leg B — full suite (`-suite ssm,modbus-server,modbus-client,pki`)

| | |
|---|---|
| catalog rows selected | **81** — 76 applicable, 81 implemented, 0 unimplemented |
| per document | SS-1547-TEST 2 · SS-MODBUS-CONF 16 · SS-MODBUS-CLIENT-CONF 16 · SS-TEST-PKI 10 · SSM-CONF 37 |
| southbound posture | **2 devices**: `inv-plain` `tcp://69.0.0.20:5020` + `inv-secure` `mbaps://69.0.0.20:8021` |
| DUT authority | flipped to **`authority=mbaps`** for the run (RBAC-002's PASS shape) and reverted after — `~/runbooks-20260729/fullsuite-driver-comb.sh` does the flip, the run and the revert, and the revert must happen even on abort |
| gridsim | still configured (`-gridsim`/`-gridsim-admin`), because preflight cross-checks the pair and several rows read its server-side log |

### Not in either leg

`-suite results-report` (**97** rows: SS-CSIP-RESULTS-v1.1 45, SS-MODBUS-RESULTS-v1.2 52)
is a reporting layer driven from finished bundles via `-report` / `-trr`, not a
third live leg. 79 + 81 + 97 + the 25 catalog rows no suite registers = the
catalog's 282.

---

## 2. Bench bring-up and the ops rules that bite

```bash
scripts/bench-sims-up.sh            # SIM_FLEET=2 (default) — the campaign fleet
```

Starts `modsim` :5020/:6020 (`-advanced -wmax 8000`), `mbapsdev` :8021/:6031
(`-model inverter -wmax 6000`), gridsim on **:11113 data / :11114 admin**, and
the aggregator loop against `69.0.0.2:802`. `SIM_FLEET=4` is the CTP Figure-15
fixture for the DER-Aggregator-Client rows and is **not** this campaign's shape.

1. **One gridsim pid must hold BOTH ports.** `ss -ltnp | grep -E '11113|11114'`
   must show a single pid. An orphan on :11114 beside a new process on :11113
   makes every server-side observation a fact about the wrong server. Preflight
   now refuses the host-mismatch form; it cannot see the orphan form, so check.
2. **A gridsim restart requires a northbound restart.** `lexa-northbound` reads
   its CSIP server URL from `northbound.json` and keeps its in-memory config and
   its long-lived session until restarted; a gridsim that came back underneath it
   leaves the DUT talking to a socket that no longer exists while the harness
   asks the new process what the DUT did, and gets an honest "nothing".
3. **`-no-tickets` on gridsim** or the gateway holds one persistent session and
   almost never re-handshakes, and every CSIP wire citation becomes unavailable.
   **The SAME applies to the mbaps leg: `-no-tickets` on mbapsdev**
   (`MBAPS_NO_TICKETS=1 scripts/bench-sims-up.sh`, or add `-no-tickets` to the
   `mbapsdev-keylog` launch). Without it every steady-state southbound session
   RESUMES, and a resumed TLS 1.3 handshake carries **no Certificate message**
   (RFC 8446 §2.2) — so RBAC-011 has no client certificate to cite and the
   role-extension row cannot be proved from the capture. With it, every gateway
   dial is a full mTLS handshake and RBAC-011 is citable **by construction**, on
   every poll cycle rather than only after a manual bounce. (The citation now
   also scans EVERY conversation to the sim endpoint for the full handshake
   rather than binding to the first ClientHello, so a single full handshake
   anywhere in the window is enough; `-no-tickets` guarantees one.)
4. **After any deploy, re-set `actuation_confirm_window_s=180`** in
   `/etc/lexa/northbound.json`. It is not in the deploy's preserved-keys
   allowlist and reverts to 60 s.
5. **`rm -f bin/modsim` before bring-up** if the binary predates 2026-08-04.
   `build_if_missing` will not rebuild an existing one, and the rate-rating
   change in §4.1 only exists in a fresh build. This is the single most
   important line in this document, because a stale binary makes §4.1's whole
   analysis wrong in the other direction.
6. **Never `make gen-mbaps-certs`** (RemoveAll + new root; locks the bench out).
   `-reuse-ca` only.

---

## 3. Do the battery packs join a leg? **No.**

They are built (`batsim -pack setpoint-zero|cease`, harness `0d01403`) and they
are runbooked (`scripts/bench/battery-pack-sim.md`), but:

- `scripts/bench-sims-up.sh` does not start them, deliberately — that script
  brings up the fleet every existing run is measured against.
- Nothing in `internal/certify`, `internal/campaign`, `internal/invariant`,
  `internal/diff` or `qa/scenarios` knows they exist. `cmd/gw-campaign`'s live
  DER inventory is a hard-coded `{inv-plain, inv-secure}` pair with no
  `-inv-battery` flag.
- Neither leg's `modbus.json` lists one.

**So tonight's campaign is inverter-only, and the RMD-025 / RMD-028 battery rows
stay bench-unproven.** If someone decides to admit a pack anyway, four things
change and none of them are automatic:

| | consequence of admitting a pack |
|---|---|
| MOD-4.702 | The pack serves model 713, which switches OFF the storage-conditional excuse in §4.1 — correctly. Its `WChaRteMaxRtg`/`WDisChaRteMaxRtg` are real and below nameplate, so those pass. Its **APPARENT-power** rate ratings are still the not-implemented sentinel, so **`VAChaRteMaxRtg` will FAIL MOD-4.702**. That is a true statement about the bench fixture, not about the DUT. Fix the fixture (declare a real symmetric VA rate rating in `populate702Pack`) before running MOD-4 against a pack. |
| I2 (failsafe) | `internal/invariant/i2.go` is expressible only as a `WMaxLimPct` percentage. A `-pack cease` device's failsafe is M123 `Conn`=0 and a `-pack setpoint-zero` device's is 704 `WSet`=0, so I2 would report its benign "no DER published a readable WMaxLimPct" and **pass by vacuum**. |
| I1 (nameplate) | `DecodeNameplate` carries no rate-rating field at all, so the pack's 90 %-of-nameplate clamp is invisible to it. |
| `internal/diff` | `DeviceSpec` has no rate-rating field and every diff fixture publishes the sentinel, so the referee cannot see the bound either. |

All four are recorded gaps with no owner tonight. They are the work that makes a
battery leg meaningful; running one without them measures less than it appears to.

---

## 4. Verdicts that will look DIFFERENT from 2026-08-01, and why

### 4.1 MOD-4.702 — rate ratings — **amended, verdict preserved**

The 2026-08-01 bundle (`runs/tail-fullsuite-20260801T173831`) records
`MOD-4.702 … all 19 profile-required points of model 702 are implemented — PASS`.
That PASS was manufactured. `populate702` left `WChaRteMaxRtg`/`WDisChaRteMaxRtg`
at the Go **zero** value, and a `Tuint16` zero is *implemented data* — a device
positively declaring a rated charge maximum of 0 W, which under lexa-proto
derbase's `maxRatingBound` denies every nonzero active-power setpoint outright.

Harness `07178d1` replaced the zeros with the SunSpec not-implemented sentinel,
which is the honest encoding for a PV inverter with no battery behind it. The
gateway mirrors it faithfully — lexa-gw's admission `readRatings` **omits** a
not-implemented point rather than zero-filling it, so the northbound 702 serves
`0xFFFF` too, and lexa-gw's own `ratings_test.go` says in as many words that a
0xFFFF there "fails MOD-4".

**Without an amendment this campaign would have turned an honest device
declaration into a DUT conformance FAILURE.** So `profile1547.go` now carries a
`storageConditional` qualifier for `WChaRteMaxRtg` and `VAChaRteMaxRtg`, keyed on
whether the DUT serves **model 713** — the profile's own marker for storage
support, and the same conditionality the profile already prints for 713 itself.

It is labelled in the source and in every excused assertion as an
**INTERPRETATION, not a transcription**: Table 18 prints no qualifier beside
those two points. A reviewer will see the excuse text name itself as such. This
is the same move `phaseConditional` already makes for 701's voltage points.

**Expect:** MOD-4.702 PASS, with the observation line now reading
`… ; not required of this device: WChaRteMaxRtg (INTERPRETATION …), VAChaRteMaxRtg (…)`.
If it reads "all 19 … implemented" instead, the sims are running a pre-`07178d1`
`bin/modsim` — see §2 rule 5.

### 4.2 WR-1 / WR-2 — the write lever — **amended, verdict may improve**

Both rows SKIPped for want of an observed write in every campaign so far, and
the reason was in the harness. Their whole provocation is "diverge the server's
ceiling register, then restore it", and both halves were no-ops:
`POST /inject {"WMaxLimPct_pct": N}` encodes `RawFromScaleSigned(N*100, SF)` at
SF −2, i.e. N × 10000, so the old **50** and **100** both saturated to the same
word 0x7FFF. The restore restored nothing, and WR-2 — running after WR-1 had
parked the register at the saturation — diverged by zero.

The constants are now `0.5` (raw 5000 = 50.00 %) and `1.0` (raw 10000 = 100.00 %,
which is also the sim's own power-on ceiling), with the arithmetic written beside
them and pinned by `writelever_test.go` in both directions — including a test
that *demonstrates* the old pair collapsing, so the workaround is checkable
rather than asserted.

The encoding defect itself is **deliberately not fixed** (see §5).

A second, honest caveat now travels with these rows' SKIP notes: on an advanced
sim the M123 ceiling this lever writes is a **derived mirror** that the sim's own
bridge re-computes from 704 on its next animation tick, and the DUT reads and
writes 704. The simapi exposes no 704-ceiling inject, so an absent write here may
mean the divergence never reached the DUT rather than that the DUT declined to
re-assert. `-param modbus-client.dercontrol=on` is the lever that moves the
register the DUT actually owns; it posts a bounded, self-expiring 4000 W /120 s
DERControl and is off by default because it makes the DUT do something.

### 4.3 RBAC-011 — client-certificate role — **verdict improves (WARN → PASS), with `-no-tickets`**

On 2026-08-05 RBAC-011 read **WARN** because it could not cite the gateway's
client-certificate role from the capture. Two things were wrong and both are
fixed in the harness (csip-tls-test):

- The citation bound to the FIRST conversation with a ClientHello, which in
  steady state is a **resumed** session — and a resumed TLS 1.3 handshake carries
  no Certificate message (RFC 8446 §2.2). It now scans **every** conversation to
  the sim endpoint and cites the **full handshake** that actually put the leaf on
  the wire. On the 2026-08-05 capture this recovers the role
  `SuperAdministratorSunSpec` from the forced-reconnect handshake — the decryption
  was never the miss, the conversation choice was.
- If the window happens to hold **only** resumed sessions, the row no longer reads
  as a product WARN: it is declared **off-wire** with the reason
  `citation-requires-full-handshake` (a TLS-resumption property, not a product
  fault), so an operator sees an honest limitation, not a phantom failure.

**To get a real citation (PASS) by construction, run mbapsdev with `-no-tickets`**
(see §2 rule 3): every dial is then a full handshake and the role is on the wire
every poll cycle. Do NOT read a WARN here as a product defect — the product is
correct (mbapsdev logs `role="SuperAdministratorSunSpec"` device-side); the only
question is whether the capture caught a full handshake.

### 4.4 Everything else — unchanged

No case is added to or removed from either leg. Counts are the same 79 / 81 as
the 2026-08-01 run. The catalog is unchanged (sha256 `aeebe841e894…`, 282 cases).

---

## 5. Recorded, NOT fixed — read before filing a bug

- **`WMaxLimPct_pct` saturates.** Both sims encode the key as N × 10000 at
  SF −2. Left alone because the mistake is load-bearing at two other call sites:
  `cmd/dashboard/mayhem.go` uses `{"WMaxLimPct_pct":100}` to *uncurtail* a solar
  sim and gets the effect it wants from the saturation, and
  `qa/scenarios/solar-reboot-forget.json` releases the ceiling at tick 25 the
  same way. Both are now annotated in place. Correcting the encoding is a
  separate change with its own evidence, and it touches the dashboard oracles,
  the UI and `/state`'s reported value (which divides by 100 a second time).
  A pack offers `{"CommandedW_W": <signed watts>}` instead — no harness uses it
  yet.
- **`sentinel_field{fields:["W","VAr"]}` names model 103.** On an advanced sim
  the 701 points are registered under the suffixed names `W_701`/`VAr_701`, and
  a 7xx-capable gateway reads 701 — so that entry blanks a block the DUT never
  looks at. `internal/campaign/layers.go` now offers **both spellings** as two
  catalog entries; a device without one records an honest ARM-ERR for that
  action and the run continues. Verified on the hermetic loopback: both arm,
  no ARM-ERR.
- **`freeze_block{}` is armed bare by the campaign.** The multi-window `models`
  and `except` forms added in `807f549`/`d0934d6` (and `af1db3a`'s correction
  that `except:["Hz"]` is *not* the detection row, Hz being volatile-class) are
  exercised only in `sim/southbound/lying_test.go`. Coverage gap, not a stale
  expectation; no change made.
- **`revert_after` acts on a different axis per device** — 704 `WMaxLimPct` on
  an advanced solar sim, 704 `WSetEna` on a pack. The campaign's `delay_s: 12`
  was tuned for the ceiling axis; the pack runbook uses 40 s.

---

## 6. Known-inapplicable — what a SKIP means tonight

The catalog marks **58 of 282** rows inapplicable, each with a written reason
that travels into the bundle and becomes `NOT SUPPORTED` in the TRR.

- **CSIP leg:** 28 of the 79 selected are inapplicable. Twenty-two are the DER
  Aggregator Client rows the 2026-07-28 GFEMS profile-scope decision drops
  (`docs/PROFILE_SCOPE_2026-07-28_der-client-gfems.md`); their checks stay
  registered and keep running as **informative**, which is this tool's standing
  treatment of an implemented-but-inapplicable row. Six are bound to the
  `notApplicable` stub: CORE-001, CORE-002, CORE-004, UTIL-001, MAINT-002,
  COMM-001. `suitecsip/register.go` says explicitly that this list is *not* the
  list of inapplicable rows and must not be grown to match it.
- **Full-suite leg:** 5 of the 81 selected are inapplicable-but-run (1 in
  SS-MODBUS-CONF, 4 in SS-TEST-PKI). A further 21 catalog rows in those four
  documents carry no registration at all, by design.
- **SSM:** `PKI-005` (the DUT holds exactly one mbaps server identity) and
  `RBAC-003` (the optional IEC 62351-8 roles, the DUT's single deferred
  requirement row) — both exported as `suitessm.InapplicableUIDs` and asserted
  both ways by that package's tests.
- **Report layer:** RPT-005, RPT-006, RPT-APX-1, RPT-APX-2.
- **Modbus client:** CLI-5 (serial baud rates), informative.

An applicable case that ends up unaddressed is a **run failure**, not a skip —
the runner exits 1 and says which.

---

## 7. Bundle discipline

Every run self-verifies from disk before it exits; a bundle that does not verify
makes the run unclean. Re-check any bundle offline and without trusting us:

```bash
./bin/certify -verify runs/<dir>/
```

Use the **keylog build** (`make certify-keylog`, separate
`~/.local/wolfssl-amd64-keylog` sysroot) or the encrypted payload claims report
as unmeasured rather than asserting on ciphertext. The DUT's mbedTLS is
unmodified — the key log is gridsim's and the sims', never the product's.
