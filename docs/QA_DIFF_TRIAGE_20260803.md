# Differential run — full findings triage, 2026-08-03

**Closes:** independent-audit **FINDING 11** — *"The same control differential run still
reports 16 other findings and a FAIL verdict."*

**Runs:** `runs/diff-20260803-220016/` (before) → `runs/diff-20260803-221134/` (after)
**Command:** `make diff` (= `go run ./cmd/gw-diff -seed 1`), families `reg,sf,chain,ctl`
**Proto pin:** `lexa-proto e05dacc` (`proto.pin`) · **Branch:** `qa/conformance-evidence`

| | before | after |
|---|---|---|
| cases | 120 | 120 |
| comparisons evaluated | 596 | 649 |
| **findings** | **40** | **15** |
| case verdicts | FAIL 36 · WARN 8 · PASS 76 | FAIL 11 · WARN 16 · PASS 93 |
| run verdict | FAIL | **FAIL** |

**The verdict is still FAIL, and that is the correct answer.** Every one of the 15
remaining findings is a real, still-unfixed product defect in `lexa-proto/derbase`,
reproduced from the register bank. None is stale, none is a harness artifact, and none is
a by-design divergence. §2 is the routing list. The 25 findings that went away were the
`sf` family's `silent-saturation` class, which stopped being a statement about the product
when lexa-proto 1bda02c landed and was only still reproducing because this harness kept
calling the deprecated entry point (§3).

---

## 1. Every finding, classified

Classification key: **(a)** real product defect still present · **(b)** fixed by recent
work, harness expectation stale · **(c)** harness artifact — oracle or fixture wrong ·
**(d)** expected/by-design divergence.

### 1.1 The `ctl` family — 15 findings, all (a)

All five defect classes that `TestCtlCatalog_ConfirmedDefectClassesStillReproduce` locks
were re-confirmed **by reading e05dacc's source**, not just by observing the finding: the
lock passing is not on its own evidence that the defect is real, because a lock can pass
against a fixture that stopped exercising the path (which is exactly what a47436b had to
repair). Source citations are in §2.

| finding | class | sev | why (a) |
|---|---|---|---|
| DIFF-CTL-001/magnitude | magnitude | P2 | `RefType` still read nowhere outside tests |
| DIFF-CTL-002/magnitude | magnitude | P2 | same, on the reactive-poor fixture |
| DIFF-CTL-004b/magnitude | magnitude | P1 | same, `%statVarAvail` vs `VarMaxInj` |
| DIFF-CTL-005/uninterpretable-applied | uninterpretable-applied | P1 | `refType=0` still passes preflight |
| DIFF-CTL-010/dropped-limit | dropped-limit | P1 | `firstNonNilAxis` over the three ceilings |
| DIFF-CTL-010/magnitude | magnitude | P1 | consequence of the same `firstNonNilAxis` |
| DIFF-CTL-012/dropped-limit | dropped-limit | P1 | as CTL-010, with three ceilings |
| DIFF-CTL-012/magnitude | magnitude | P1 | as CTL-010 |
| DIFF-CTL-020/kind | kind | P1 | `opModImpLimW` → `SetActivePowerWatts` |
| DIFF-CTL-021/kind | kind | P1 | `opModLoadLimW` → `SetActivePowerWatts` |
| DIFF-CTL-022/kind ×2 | kind | P1 | both import axes → WSet; `firstNonNilAxis` picks one |
| DIFF-CTL-030/kind | kind | P1 | import ceiling → WSet |
| DIFF-CTL-030/magnitude | magnitude | P2 | `opModFixedW`'s WSet overwritten by the import axis |
| DIFF-CTL-040/silent-clamp | silent-clamp | P2 | `SetActivePowerWatts` clamps to ±WMax, returns nil |

Two notes on how these read in the artifact:

* **DIFF-CTL-010/012 raise two findings each.** `dropped-limit` names the axis that WAS
  applied and should not have been; `magnitude` names the axis that SHOULD have bound and
  did not. They are one root cause and two distinct statements about the device's state,
  and collapsing them would lose the second.
* **DIFF-CTL-022's second finding was reworded** (§3.2). The kind check fires before the
  superseded check, so a document whose several import axes collide in one register raises
  `kind` for each — including for the axis that was never written at all. The finding used
  to be titled *"opModLoadLimW (ceiling) applied through WSet"*, which asserts an
  application that did not happen; it now says *"…is expressed nowhere: the device's only W
  control is WSet, a setpoint register holding −8000 W"*, and the impact line adds that the
  −3000 W bound is not in force at all. **The check order was deliberately not changed:**
  the `dropped-limit` branch requires the held value to match the superseded intent, which
  it does not here (−8000 W held vs −3000 W asked), so reordering would silently drop the
  finding instead of relabelling it.

### 1.2 The `sf` family — 25 findings, all (b), now closed

`DIFF-SF-021`, `-023`, `-025` and 22 of the 64 generated probes each raised
`/silent-saturation` P2: *"an unrepresentable value is clamped and the caller is not
told"*, with the product side rendered *"raw N, no signal (the encoder returns uint16
only)"*.

That sentence is no longer true of the product. lexa-proto **1bda02c (LXR-004)** — landed
in response to this very finding — split the codec:

```
EncodeScaleSigned/Uint  (uint16, EncodeOutcome)  ← the COMMAND-WRITER entry point
RawFromScaleSigned/Uint  uint16                  ← round-trip wrapper, discards the outcome
```

`EncodeOutcome` separates `EncodeExact` from `EncodeSaturatedHigh` / `EncodeSaturatedLow`
/ `EncodeNotImplemented` / `EncodeBadSF`, and `derbase` acts on it (`derbase.go:1822`, the
M123 limit plan's compensation path). `RawFromScale*`'s own doc comment says command
writers must not use it.

`internal/diff/scale.go`'s `compareEncode` was still calling the wrapper. So the finding
reproduced because the referee kept dialling the deprecated number — it measured the
harness's choice of entry point, not the product. csip-tls-test **8f17f1c** inverted the
*other* half of LXR-004 (illegal scale factors) and left this half standing with a comment
saying the class "MAY still appear here"; that comment was the stale expectation this task
removes.

**Measured before changing anything** (throwaway probe over the same 67 encode probes the
default run drives):

```
raw-word mismatches product-vs-referee : 0
UNDER-report (referee saturated, product silent) : 0     ← the defect, gone
OVER-report  (product signals, referee finds it fits) : 8 ← §1.3
```

Zero under-reports is the whole claim: there is no input in the catalogue on which the
command-writer entry point clamps without telling the caller.

### 1.3 The 8 remaining `sf` divergences — (d), by design, encoded as WARN

Eight generated probes now emit a `sf.representable` **WARN** and no finding. All eight
are the same shape: a **negative** value into an **unsigned** register at a large scale
factor, e.g. `DIFF-SF-GEN-0003`, `−16595.05` into a uint16 at `sf=10` (one count = 10 GW).

* The referee (`refEncode`) rounds first and then range-checks, so `−16595.05` rounds to
  raw 0, which is inside `[0, 65534]` — representable, to within half a count.
* The product (`EncodeScaleUint`, `sunspec/scale.go:125`) answers the **domain** question
  before rounding: `if val < 0 → EncodeSaturatedLow`, because an unsigned register cannot
  carry a sign at any resolution.

Both sides produce the **same raw word**. They differ only on whether that counts as
saturation, and the product's reading is the stricter one — it over-reports the loss of a
sign and never under-reports it. That is not a defect in either direction, so it is a WARN
carrying the full explanation rather than a finding.

**The referee was deliberately not changed to agree.** `csipref.go`'s standing rule — a
referee reconciled with the product stops being able to find anything — applies to
`scale.go` too. The divergence is reported, not normalised away, and
`TestSFCatalog_SaturationIsReportedToTheCaller` asserts these rows can never become FAILs,
so a future edit cannot quietly turn conservatism into a manufactured defect.

### 1.4 Everything else in the run

* `reg` (the control family): 8 cases, all PASS, ~430 comparisons. Unchanged, and it is
  what earns the other families the right to be believed.
* `chain`: 10 cases, all PASS. Pinned in inverted form by
  `TestChainCatalog_BoundedWalkTerminatesWithSentinel` since lexa-proto 8788796.
* `ctl` atomicity: PASS everywhere it is exercised. Pinned in inverted form by
  `TestCtlCatalog_WholeRequestPreflightIsAtomic` since lexa-proto b760d5a (24389d7).
* The 8 `ctl` WARN cases are the standing `enum-independence` advisory — both sides read
  the SunSpec 704 mode enum from the same shared constants, so their agreement about it is
  not evidence. It is a disclosed blind spot, not a finding, and by construction it does
  not count towards the assertion floor.
* `DIFF-CTL-042` / `-050` (no-702 device) produce no finding: e05dacc's deny-by-default
  `CapAbsent` gate now refuses those axes outright instead of applying an uninterpretable
  percentage. That is category (b) and was already recorded in a47436b's message; the
  `uninterpretable-applied` lock needed no inversion because DIFF-CTL-005 (refType=0 on a
  device *with* a 702) still reproduces it.

---

## 2. Category (a) defect list — for routing

**None of these is covered by `lexa-gw/docs/known_issues.json`.** All 15 issue entries
there were read; the nearest neighbour is `LXR-012-connect`, which is about connect
read-back and does not touch any of the paths below. These five need registry entries of
their own, or a decision that they do not.

Suggested owner for all five: **`controls`** (the owner label `lexa-gw`'s registry already
uses for `derbase` actuation defects). All five are in `lexa-proto/derbase`, none in the
harness. **No product code was changed by this task.**

### D-A1 — `opModFixedVar.refType` is parsed and then ignored (class `magnitude`)

`csipmodel/resources.go:316` declares `RefType uint8`; a repo-wide search finds no
non-test read of it. `derbase.preflightControl` (`derbase.go:720-733`) takes only
`.Value.Value`, range-checks it against ±100 %, and hands it to `SetConstantVar`
(`derbase.go:1059`), which writes 704 `VarSetEna=1`, **`VarSetMod=M704_VarSetMod_VarMaxPct`
(hardcoded)**, `VarSetPri=Reactive`, `VarSetPct=pct`. Every `DERUnitRefType` therefore
resolves against the same SunSpec base, `VarMaxInj`. Register-level repro (DIFF-CTL-001,
`balanced-60kW`, WMax 60 kW / VarMaxInj 26.4 kvar): `opModFixedVar{refType=1,value=8000}`
→ device holds `VarSetPct=80 %` of `VarMaxInj` = **21 120 var** where `%setMaxW` asks for
80 % of WMax = **48 000 var**. On `reactive-poor-60kW-2kvar` (DIFF-CTL-002) the same
document yields **1 600 var** against **48 000 var** asked — a 30× error on a device you
can buy. On `loaded-60kW-at-62kVA` (DIFF-CTL-004b) `refType=3 (%statVarAvail)` at 100 %
gives **26 400 var** against the **11 180 var** of headroom the machine actually has, an
overcommand of the operating point rather than of the nameplate (which is why I1 correctly
does not fail it — nothing exceeded the nameplate). **Conformance impact: P1 for CSIP.**
Whatever the three codes mean, they cannot all mean the same thing, so a client that
writes one base for all three is wrong for at least two of them; any CSIP case exercising
`opModFixedVar` with `refType` 1 or 3 is answered with the wrong physical quantity. IEEE
1547 reactive-power-capability tests inherit it.

### D-A2 — simultaneous active-power ceilings: first non-nil wins (class `dropped-limit`)

`derbase.preflightControl:752-755` reduces the three ceiling axes with
`firstNonNilAxis(opModExpLimW, opModMaxLimW, opModGenLimW)` — a fixed preference order,
not a minimum. Limits are conjunctive: each one must hold, so the binding ceiling is the
narrowest. Register-level repro (DIFF-CTL-010, `balanced-60kW`, WMax 60 kW):
`{opModMaxLimW=5 kW, opModExpLimW=30 kW}` → `SetWMaxLimPctW(30000)` writes 704
`WMaxLimPctEna=1`, `WMaxLimPct=50 %`, and the device is bounded at **30 kW** with the
utility's **5 kW** ceiling nowhere on the device. DIFF-CTL-012 shows it survives three
simultaneous ceilings: `{Max=20 kW, Exp=40 kW, Gen=2 kW}` → 40 kW held, 2 kW asked. The
same `firstNonNilAxis` shape governs the import pair (`:795-797`), so
`{opModImpLimW=8 kW, opModLoadLimW=3 kW}` (DIFF-CTL-022) applies the 8 kW one and drops
the 3 kW one. **Conformance impact: P1, and it is the safety-relevant one** — a utility
curtailment instruction is silently not in force while the head end is told the control
was applied. Fixing it is a two-line change in shape (reduce to the minimum magnitude
instead of picking) but it changes which axis name any error is attributed to, so the
`ElementOutcome` naming in `ApplyControlPlan` needs to move with it.

### D-A3 — import/load CEILINGS are applied through WSet, a SETPOINT register (class `kind`)

`derbase.preflightControl:795-813` routes `opModImpLimW` / `opModLoadLimW` to
`SetActivePowerWatts(-w)`, which writes 704 `WSetEna=1`, `WSetMod=M704_WSetMod_Watts`,
`WSet=-w`, `WSetRvrtTms`. `WSet` means *produce this*; the document said *do not import
more than this*. Register-level repro (DIFF-CTL-020, `balanced-60kW`, idle):
`opModImpLimW{5 kW}` → device holds `WSet=-5000 W`. A machine that was under no obligation
to move any active power is now **commanded to import 5 kW**. The correct SunSpec
expression of a charge ceiling is a bound (`WMaxLimPct` on the charge side, or the 704
charge-rate points), not a setpoint. Second consequence: because both `opModFixedW` and
the import axes land in `WSet` and both rank `rankLimit`, a document carrying both
(DIFF-CTL-030) has the import axis **silently overwrite** the discharge setpoint —
`{opModFixedW=20 kW, opModImpLimW=5 kW}` leaves `WSet=−5000 W`, so the 20 kW the head end
commanded is nowhere, with no error and no outcome element saying so. **Conformance
impact: P1**, and it is the only finding in this run that makes an idle DER move real
power it was never told to move.

### D-A4 — `opModFixedVar` with `refType=0` (N/A) is applied anyway (class `uninterpretable-applied`)

`derbase.preflightControl:727-731` validates only that the percentage is finite and inside
±100; `refType` is not consulted (D-A1), so `refType=0` — "no rating nominated" — is
indistinguishable from any other. Register-level repro (DIFF-CTL-005, `balanced-60kW`):
`opModFixedVar{refType=0,value=8000}` → device holds `VarSetEna=1`, `VarSetMod=VarMaxPct`,
`VarSetPct=80 %`. A live reactive setpoint is in force and **no party — head end, gateway
or referee — can state what physical quantity it commands**, because the document declined
to name one. The two defensible answers are to refuse it (`CannotComply`) or to leave the
device alone. **Conformance impact: P1**, adjudicated by invariant I10 ("never accepts a
control it cannot safely carry out, and says so"). Closing D-A1 makes this a one-line
consequence, so route them together.

### D-A5 — a setpoint beyond the nameplate is clamped and the head end is not told (class `silent-clamp`)

`SetActivePowerWatts` (`derbase.go:1070-1078`) clamps `w` to ±`WMax` when WMax is known and
then returns `nil`. Register-level repro (DIFF-CTL-040, `balanced-60kW`, WMax 60 kW):
`opModFixedW{200 kW}` → preflight passes (the fixture leaves `WDisChaRteMaxRtg` at the
not-implemented sentinel, so `validateSetpointW` imposes no bound, which is the honest
modelling of a device that publishes no such rating) → device holds `WSet=60000 W` and
`ApplyControl` reports success. **The clamp itself is right** — 200 kW on a 60 kW machine
must not be written — but IEEE 2030.5's answer to "I cannot do that" is `CannotComply`,
not a different number applied without comment. **Conformance impact: P2 physically** (the
substituted value is safe) **but P1-adjacent for CSIP Response/status behaviour**: the head
end's model of the fleet is wrong and nothing on either side holds the true state. Note the
adjacent path is already correct — `EncodeScale*` returns an outcome for exactly this
reason (§1.2) — so the fix is to give `SetActivePowerWatts` the same shape and let
`ApplyControlPlan` carry it as a degraded `ElementOutcome`.

---

## 3. What changed in the harness

Product code: **untouched**. Fixtures: **untouched**.

### 3.1 `internal/diff/scale.go` — `compareEncode` asks the command-writer entry point

Drives `sunspec.EncodeScaleSigned/Uint` and adjudicates the returned `EncodeOutcome`
against the referee's own `saturated` flag, in both directions:

| referee | product | row | verdict |
|---|---|---|---|
| saturated | signals | `sf.saturation-visible` | PASS |
| saturated | silent | `sf.saturation-visible` | **FAIL** + `/silent-saturation` finding |
| fits | signals | `sf.representable` | WARN (§1.3) |
| fits | exact | `sf.representable` | PASS |

`RawFromScale*` is still exercised, as a new `sf.encode.wrapper` row compared **against the
referee** — not against the reporting encoder, because a product-versus-product check would
agree by construction the day one is implemented in terms of the other, which is what it is
today. Net effect on coverage: the wrapper keeps its differential test and the entry point
that ships in control writes gains one it never had.

### 3.2 `internal/diff/ctl.go` — the `kind` finding stops asserting an application that did not happen

When the register the product used does not carry this mode's number (within the family's
standing tolerance, anchored to the **referee's** value — the helper `withinCtlTolerance`
restates that anchoring in a comment so the BR-02 tautology cannot creep back in through a
wording decision), the title and impact say so. See §1.1.

### 3.3 `internal/diff/diff_test.go` — the lock, inverted

* **Added `TestSFCatalog_SaturationIsReportedToTheCaller`**, mirroring 24389d7's
  `TestCtlCatalog_WholeRequestPreflightIsAtomic` and 8f17f1c's chain inversion: it asserts
  the class no longer reproduces, *and* sweeps every `sf.saturation-visible` row so the
  count cannot go to zero because the catalogue stopped asking (`exercised == 0` is a
  `t.Fatal` with instructions), *and* asserts no `sf.representable` row ever becomes a FAIL.
  It runs `RunSFCatalog(ctx, r, 64)` at seed 1 — cmd/gw-diff's defaults — so the test sees
  the same probes an operator's `make diff` does.
* **Removed** the stale "this class MAY still appear here" paragraph in
  `TestSFCatalog_IllegalScaleFactorsAreRefused`, replaced by a pointer to the new lock.
  Nothing was deleted without replacement.
* `TestCtlCatalog_ConfirmedDefectClassesStillReproduce` is **unchanged**: all five classes
  it pins are still real (§2), and inverting a lock whose defect is still shipping would be
  the exact dishonesty the file's header warns about.

---

## 4. Verification

| gate | result |
|---|---|
| `make test-diff` (`go test -race ./internal/diff/...`) | PASS — 16 tests incl. the new lock |
| `make test-campaign` (`-race`, campaign + invariant) | PASS |
| `make qa` (`scripts/qa-regression.sh`, `-race`) | PASS |
| `make test-fast` | PASS |
| `gofmt -l internal/diff`, `go vet ./internal/diff/...` | clean |
| `make qa-campaign-teeth` (hermetic loopback) | teeth CONFIRMED, target exits 1 — pre-existing, see below |
| `make diff` | **FAIL, 15 findings** — the intended state, see §2 |

Pre-existing and untouched: `suites/suitemodbusserver` fails to LINK in the non-race build
(wolfSSL libm ordering). Nothing in this change goes near it.

### 4.1 `make qa-campaign-teeth` exits 1 even when the teeth bite — pre-existing

The teeth run did exactly what it exists to do. Against the deliberately non-conformant
loopback it caught the injected defect —

```
finding : credential "ReadOnlySunSpec" (role ReadOnlySunSpec) has no write authorization
          but write#2 was ACCEPTED on unit 1 point WMaxLimPct
status  : 1-MINIMAL over 5 attempts — 8 actions -> 1
minimal : authz-probe/write-readonlysunspec@dut#1
```

— which is the whole proof the Makefile comment asks for, including the shrink converging
on the single read-only write probe rather than on a "minimal" set of eight. It then exits
1, so `make` fails the target.

The cause is a clause ordering in `campaign.decide` (`internal/campaign/runner.go:395-412`):

```go
case cfg.MustViolate && !violated:   // found nothing → fail (correct)
case !sum.OK:                        // ← fires here
case cfg.MustViolate:                // "teeth confirmed: …" → unreachable
```

`invariant.Summary.OK` is set false by `monitor.go:513-517` whenever any violation carries
verdict Fail, and `violated` is derived from those same violations — so for a P1 defect,
`!sum.OK` is true exactly when the teeth bit, and the `MustViolate` success branch cannot
be reached. The target therefore exits non-zero on both outcomes, and the one existing test
(`TestMustViolateFailsARunThatFoundNothing`) only covers the found-nothing direction.

**This is not a regression from this change.** The ordering dates to fc2d17c (2026-07-27),
`internal/campaign` has zero build dependency on `internal/diff` (`go list -deps`), and this
change touches nothing outside `internal/diff` and this file — so the `bin/gw-campaign` the
target built is identical to the one HEAD builds. It is left alone deliberately: it is a
gate's verdict semantics in a different subsystem, and it deserves its own commit and its
own reasoning rather than riding along inside a differential-triage change. **Routing it
alongside §2 is recommended** — a gate that cannot go green is a gate people stop running.

## 5. Read next

* `internal/diff/doc.go` — what each family compares and what it cannot catch.
* `internal/diff/diff_test.go` header — the three test groups and the inversion discipline.
* `lexa-gw/docs/known_issues.json` — where §2 belongs if the orchestrator accepts it.
