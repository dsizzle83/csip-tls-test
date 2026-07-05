# TASK-020 — SunSpec / derbase / modbus fork reconciliation & disposition

*Author: TASK-020 implementer · 2026-07-05 · Risk: high (RSK-02 wrong-side merge)*

This is the **review artifact** the task requires: for every divergence between
the product fork (`~/projects/lexa-hub/internal/southbound/{sunspec,modbus,derbase}`)
and the bench fork (`~/projects/csip-tls-test/internal/southbound/{...}`), which
side won and why, with git-log provenance. Per AD-003 the **product side is merge
authority**; the review's job is to catch any bench-side register-semantic *fix*
the product lacks and port it BEFORE the move. **Result: none found** — the one
substantive bench fix is already in the product. Zero `investigate` rows remain.

Consumed by: TASK-021 (bench flip), TASK-023 (csipmodel + derbase move),
TASK-024 (lockstep pin gate), TASK-075 (golden fixtures).

---

## 1. Raw diff evidence (`diff -rq`)

### `modbus` — IDENTICAL
```
$ diff -rq lexa-hub/internal/southbound/modbus csip-tls-test/internal/southbound/modbus
(no output — byte-identical)
```
Single file `transport.go`. Imports only `github.com/simonvetter/modbus`. Moved
byte-for-byte to `lexa-proto/modbus`.

### `sunspec`
```
$ diff -rq lexa-hub/.../sunspec csip-tls-test/.../sunspec
Files .../der1547.go differ
Files .../models.go  differ
Files .../reader.go  differ
Files .../reader_test.go differ
Files .../scanner.go differ
Only in lexa-hub: der1547_roundtrip_test.go, derlayout.go, derlayout_test.go, layout.go
```
Classification of each file:

| File | Class | Notes |
|---|---|---|
| `scale.go`, `scale_test.go` | **identical** | not listed by diff = byte-identical. `ApplyScale{Signed,Uint}`, `RawFromScale*`, `0x8000`→NaN sentinel. Moved verbatim. |
| `reader.go`, `scanner.go`, `reader_test.go` | **import-only** | differ *only* by the `internal/southbound/modbus` (and, in the test, `sunspec`) import path — verified: `diff <(sed 's#lexa-proto/#lexa-hub/internal/southbound/#g' NEW) OLD` is empty. |
| `der1547.go`, `models.go` | **semantic (two generations)** | product = declarative layout engine; bench = hand-rolled structs. See §2. |
| `layout.go`, `derlayout.go`, `*_roundtrip_test.go`, `derlayout_test.go` | **product-only** | the layout engine + its tests. No bench counterpart. Moved verbatim. |

### `derbase`
```
Files .../derbase.go differ
Only in lexa-hub: derbase_csip_test.go
```
Two generations of the CSIP→SunSpec mapping. **derbase was NOT moved this task**
(see §4). Its `sunspec` import was repointed to `lexa-proto/sunspec`; it stays in
`lexa-hub`.

---

## 2. Semantic inventory & dispositions (models 103/121/122/123/802/201-203, 701-714)

Disposition values: `product` (default authority) / `port-from-bench` (bench holds
a fix product lacks) / `investigate`. **All rows → `product`. 0 `port-from-bench`,
0 `investigate`.**

### 2a. Legacy models — the only register maps the bench sims + conformance exercise

The bench sims (`sim/southbound/*`) expose **only** legacy models: inverter M103
(+121/123), battery M103+M802, meter M201. Grep for `ModelDER`/701-714 in the sim
sources returns nothing — **no DER model 701-714 is served on the bench today**.
Conformance (`modsim-conformance`) therefore exercises only these legacy maps.

| Model | Product offsets | Bench offsets | Disposition |
|---|---|---|---|
| 103 (inverter AC) | lines 61-104 of `models.go` | **byte-identical** | product ≡ bench — no divergence |
| 120 (nameplate) | 106-136 | **byte-identical** | ≡ |
| 121 (basic settings) | 152-156 | **byte-identical** | ≡ |
| 122 (ext status) | 138-150 | **byte-identical** | ≡ |
| 123 (immediate ctrl) | 287-313 | **byte-identical** | ≡ |
| 802 (Li-Ion) | 158-189 (SoC=14,SoH=17,DoD=15,ChaSt=21,W_SF=6) | **byte-identical** | ≡ |
| 201/202/203 (meter) | 191-285 (105-reg common-meter, MTR-4 fix) | **byte-identical** | ≡ |

**Verification:** `diff <(sed -n '61,313p' PRODUCT/models.go) <(sed -n '61,313p'
BENCH/models.go)` → empty. Every legacy register offset, scale-factor index, and
sign is identical across the forks. **RSK-02 has no live exposure**: the maps that
touch real hardware / the sims today are not in disagreement.

> Doc nit (out of scope, not fixed here): `csip-tls-test/internal/southbound/CLAUDE.md`
> lists a stale M802 offset table (SoC 10 / SoH 11 / DoD 12 / ChaSt 16) that does
> **not** match the actual bench `models.go` (SoC 14 / SoH 17 / DoD 15 / ChaSt 21).
> The *code* agrees across forks; only that prose table is wrong. Flag for TASK-024
> (it edits the lockstep CLAUDE.md prose).

### 2b. DER models 701-714 — structural (generation) divergence

Product transcribes 701-714 point-for-point in spec order via the layout engine
(`layout.go`/`derlayout.go`, "SunSpec DER Information Model Spec v1.2, exact spec
order"). Bench uses an older hand-rolled compressed layout (`models.go` M701_*…
M713_* constants + `der1547.go` structs). The register **orders differ wholesale**
— e.g. real SunSpec M701 begins `ACType,St,InvSt,ConnSt,Alrm,DERMode,W…` (product,
`W`@offset 8) whereas the bench compresses to `W,Var,VA,PF,A,…` (`W`@offset 0).

**This is the exact §9 self-confirmation / RSK-16 hazard**: the bench sims *and* the
bench hub fork share the compressed 701 layout, so they agree with each other while
disagreeing with real 1547 hardware. That is a reason to **prefer the product
(spec-faithful) generation, not the bench** — the opposite of a bench-side fix.
Not hardware-exercised today (2a). Disposition of the whole 701-714 structural
divergence: **product** (authority + demonstrably more spec-correct).

### 2c. Genuinely semantic behaviours within 701-714 (adjudicated individually)

| # | Behaviour | Product | Bench | Disposition + reason |
|---|---|---|---|---|
| S1 | M701 `PF` decode | SF only (`raw×10^SF`) | additionally `/100` | **product** — SunSpec M701 `PF` carries its own `PF_SF`; the extra `/100` is the legacy-M103 (`PF×100`) convention carried over. Non-exercised. |
| S2 | M701 voltage select / NaN | `LNV` then `VL1`, NaN via layout `0x8000` sentinel | `VL1` then `LNV`, explicit `==0x8000` | **product** — both sentinel-safe; different preference only. Layout-wide sentinel handling is the general form. |
| S3 | Curve adopt workflow (705/706/707-710/712) | full §3.1.2: write staging idx1 → `AdptCrvReq=2` → poll `AdptCrvRslt` → `Ena=1` | write curve → `AdptCrvReq=1` (no poll, no enable) | **product** — more spec-complete handshake. Bench is a simplification, not a fix. |
| S4 | M703 field widths | `ESHzHi/Lo` + timers = **uint32** ("corrected widths") | uint16 | **product** — spec-correct widths. Non-exercised. |
| S5 | M713 layout | spec Table 16 (`WHRtg,WHAvail,SoC,SoH,Sta`; "corrected from prior non-spec layout") | older `WHRtg,AHRtg,MaxChaSoC,…,NCyc` | **product** — the explicit spec-Table-16 correction. Battery uses M802, not M713 — non-exercised. |
| S6 | M712 point-count | `EncodeWattVarCurve` allows `≤NPt` | `WriteWattVar` rejects `len≠6` | **product** — intentional generality; a validation strictness choice, not a register semantic. |
| S7 | 702 optional block / `IntIslandCat` | present in layout | absent | **product** — superset; `ReadWMaxFrom702` reads `WMaxRtg`@0 either way; 702 not served by sims. |
| S8 | 714 (DC measurement) | full model + `ModelDERMeasureDC=714` | **absent entirely** | **product** — product-only capability; nothing to reconcile. |

### 2d. derbase CSIP→SunSpec mapping semantics

| # | Behaviour | Product | Bench | Disposition + reason |
|---|---|---|---|---|
| D1 | `OpModImpLimW`/`OpModLoadLimW` on a 704 device | negative `WSet` (Set Active Power) → correct charge command | `SetWMaxLimPct704` (positive ceiling — cannot command charge) | **product** — more correct. |
| D2 | Legacy M123 signed import limit (charge = negative `WMaxLimPct`) | `setLegacyWMaxLimPct`: `charge → RawFromScaleSigned(-pct,sf)` | `SetImportLimit`: `pct=-(W/Wmax)*100`, `RawFromScaleSigned` | **product already carries the bench fix** — see provenance §3. Behaviour-equivalent. |
| D3 | Control coverage | handles `OpModFixedW` (WSet), `GenLimW`, `LoadLimW`, reversion timers, atomic PF sync-group write | narrower subset | **product** — superset. |

---

## 3. Provenance (`git log`) — is any bench divergence a deliberate fix?

Product fork last touched: `31948ac` "Debugging the hub after simulation results
over 3 month time frame" (the layout-engine QA-arc generation).
Bench fork: `8b3bed7` "…extend Modbus stack to IEEE 1547-2018" (older hand-rolled)
then `b31e5e6` (bench's copy of the same QA-arc commit).

Bench `derbase` history shows exactly one substantive post-fork fix:

```
e1d7ba2 Battery bidirectional control: signed WMaxLimPct + import limit dispatch
```

That commit added `SetImportLimit` (negative signed `WMaxLimPct` = charge) and
routed `OpModImpLimW` → `SetImportLimit`. **Checked against the product**:
`derbase.go` already implements the identical semantics in `setLegacyWMaxLimPct`
(`charge → RawFromScaleSigned(-pct, sf)`) and dispatches `OpModImpLimW`/`LoadLimW`
to a negative setpoint. → **already present. No port needed.** (`git show e1d7ba2`
`derbase` hunk vs product `setLegacyWMaxLimPct` — same math, same ramp=5, same
enable sequence.)

No other bench commit touches register offsets, scale, sign, or sentinel handling
in a way the product lacks. **0 `port-from-bench` commits were needed.**

---

## 4. What moved, and why derbase did NOT

**Moved to `lexa-proto` (byte-identical modulo import path):**
- `modbus/transport.go` → `lexa-proto/modbus` (+ `simonvetter/modbus` require).
- `sunspec/*` (11 files) → `lexa-proto/sunspec`; only `reader.go`/`scanner.go`/
  `reader_test.go` changed, only their import paths.
- `lexa-hub` deletes its `internal/southbound/{sunspec,modbus}` and imports
  `lexa-proto/...` via `go.work`.

**Deferred: `derbase` (deviation from task step 8 / acceptance-criterion "derbase
deleted").** Reason: product `derbase` imports **two** cross-internal packages —
`internal/northbound/model` (anticipated by step 8) *and* `internal/southbound/device`
(NOT anticipated). `device` itself imports `model`, and `derbase` returns
`device.Measurements`. A Go module cannot import another module's `internal/`, so a
clean move needs BOTH a `csipmodel` forward-slice (`DERControlBase`, `ActivePower`,
`FixedVar`) AND a decision on where `device.Measurements` lives — the latter belongs
to TASK-023 (csipmodel) / TASK-025 (Device Reconciler owns the `device` abstraction),
not to a mechanical codec move on the highest-risk task. Forcing it here would mean
improvising a design call about a protected abstraction. Per the implementer brief
(“STOP and report … do not improvise around protected behavior”), `derbase` stays in
`lexa-hub` with its `sunspec` import repointed; `derbase_csip_test.go` passes
unchanged, proving the mapping is behaviour-identical.

**No csipmodel aliases were created** (step 8's alias path was not entered, since
derbase did not move). TASK-023 should move `derbase` together with the
`csipmodel` slice and resolve the `device.Measurements` placement.

---

## 5. Test evidence

- `lexa-proto`: `CGO_ENABLED=0 GOWORK=off go test ./...` → `ok lexa-proto/sunspec`
  (moved `reader_test`/`scale_test`/`derlayout_test`/`der1547_roundtrip_test` pass);
  `scripts/check-cgo-free.sh` OK.
- `lexa-hub`: `make test` (`go test -race ./internal/...`) green incl. `derbase`;
  `make test-nocgo` green incl. `cmd/modbus`; `make build-arm64` green (pure-Go +
  CGO wolfSSL targets).
- `csip-tls-test` (bench untouched): `make test-fast` green, `go test ./tests/` green.
- **Not run this task (batched to TASK-021 per PE lane note — no bench deploy):**
  hub redeploy, `modsim-conformance ×3`, full Mayhem FAST campaign.
