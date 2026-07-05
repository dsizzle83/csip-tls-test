# TASK-023 — csipmodel + derbase move: disposition & field table

*Author: TASK-023 implementer · 2026-07-05 · Risk: high (silent-failure XML hazard)*

Review artifact required by the task: for every field/tag divergence between the
product model (`~/projects/lexa-hub/internal/northbound/model`) and the bench model
fork (`~/projects/csip-tls-test/internal/csip/model`), which side won and why. Per
AD-003 the **product side is merge authority**. **Result: zero unresolved `conflict`
rows.** The bench fork turned out to be a strict subset of the product model with
byte-identical tags on every field it shares — the opposite of TASK-020's `sunspec`
situation (structural generation divergence), this is the easy case: no field the
bench defines is missing, renamed, or differently-tagged in the product.

Also covers the scope addendum (from TASK-020's deferral): moving product `derbase`
into `lexa-proto/derbase` and resolving its `internal/southbound/device` coupling.

Consumed by: TASK-024 (lockstep pin gate), TASK-082 (bench derbase/model-fork
disposal, csip discovery/scheduler fork AD), TASK-025 (Device Reconciler — owns
`internal/southbound/device` going forward).

---

## 1. Per-file disposition (product vs. bench `internal/csip/model`)

| File | Product | Bench | Disposition |
|---|---|---|---|
| `resources.go` | 561 lines, superset | 527 lines | **product** — every bench field/const present in product with identical `xml` tag and type (verified: `comm -23` on exported type names, and per-field diff of the shared 0-438 line range is comment/whitespace only). Product adds `TariffProfileListLink`/`FlowReservationRequestListLink`/`FlowReservationResponseListLink` link fields, extra `ReadingType` TOU fields, `ResponseEventCancelled`/`ResponseEventSuperseded`/`ResponseCannotComply` (LEXA extension, 0xF0 range — deliberately outside IEEE Table 27's 1-7), and `Uom`/`Kind`/`DataQualifier` MUP constants. All additive. |
| `pricing.go` | 161 lines | 123 lines | **product** — `UnitValue`/`TariffProfile`/`RateComponent`/`TimeTariffInterval`/`ConsumptionTariffInterval` fields and tags identical across both; product adds `PriceResponseCfg`/`PriceResponseCfgList` (server-side threshold config, no bench consumer). |
| `billing.go` | 231 lines | 54 lines (stub subset) | **product** — bench's `CustomerAccount`/`CustomerAgreement` (+ Lists) fields are a strict subset of product's with identical tags; product adds `ServiceSupplier`, `BillingPeriod`, `Charge`/`BillingReading(Set)`, `HistoricalReading`, `ProjectionReading`, `TargetReading` (+ Lists) — none referenced by bench's `sim/gridsim/extended.go` (grepped; it only constructs `CustomerAccountList`/`CustomerAgreementList`, both present verbatim in product). |
| `der.go` (product) / `curves.go` (bench) | 434 lines | 49 lines | **product** — bench's 3 curve types (`DERCurveData`, `DERCurve`, `DERCurveList`) exist in product `der.go` with identical XML tags; product's `DERCurve` additionally carries `AutonomousVRefEnable`/`AutonomousVRefTimeConstant`/`RampPT1Tms` (comment-documented additions, additive only). Bench `curves.go` **dropped** — product's `der.go` is the union. Product also carries `ExtendedDERControlBase`/`DERCapabilityFull`/`DERStatusFull`/`DERAvailability`/`DERSettingsFull` etc. which the bench never had; grepped bench sources for all of these type names — zero references outside the deleted model package itself (bench's `DERAvailabilityLink *Link` field is just an href reference, tag-identical to product's). |
| `flowreservation.go` | 111 lines | absent | **product** — bench never had a Flow Reservation function set; nothing to reconcile. |
| `resources_test.go` | 667 lines, 20 test funcs | 348 lines, 17 test funcs | **product** — `comm` diff of `^func Test` names shows the bench's 17 are a strict subset of the product's 20 (`TestBillingPeriodParse`, `TestConsumptionTariffIntervalParse`, `TestCustomerAccountParse`, `TestFlowReservationRequestRoundTrip`, `TestFlowReservationResponseParse`, `TestReadingTypeWithTouFields`, `TestTariffProfileParse`, `TestTimeTariffIntervalParse` are product-only additions covering the product-only types above). The merged suite is simply the product test file — no bench-only test case exists to port. |

**Const-level check:** `grep`-derived const tables for both packages cross-checked
value-for-value (`ResponseEventReceived=1` … `ResponseOptOut=5` identical in both;
product's extra `ResponseEventCancelled=6`/`ResponseEventSuperseded=7`/
`ResponseCannotComply=0xF0` are additive). Zero numeric mismatches.

**Type-level check:** `comm -23` on `^type ` declarations across both packages
returns an empty bench-only set — every type the bench defines, the product also
defines (by name), and per-field checks above show identical layout for every
shared type actually diffed field-by-field.

## 2. gridsim / conformance consumer verification

Grepped every bench consumer (`sim/gridsim/*`, `sim/conformance/main.go`,
`sim/modsim-client/main.go`, `internal/csip/discovery`, `internal/csip/scheduler`,
`tests/*`) for any symbol not present in the merged model — none found. In
particular `sim/gridsim/malform.go` (constructs deliberately-broken XML for the QA
malform-* scenarios) references only `model.DERProgramList`, `model.DERControlList`,
`model.ConsumptionTariffInterval`, `model.TariffProfile`, `model.DERCurveList` and
friends — all present, tag-identical, in the merged model. `malform_test.go` passes
unchanged post-move (`go test ./sim/gridsim/...` — see §5).

## 3. The merge itself

`lexa-proto/csipmodel/{resources,der,pricing,billing,flowreservation}.go` +
`resources_test.go` are the product files verbatim (package clause rewritten
`model` → `csipmodel`; no other line changed — diff against
`lexa-hub/internal/northbound/model/*.go` pre-move is package-clause-only).
`doc.go` (TASK-019 skeleton) is deleted; its content folds into `resources.go`'s
package doc comment, which now states the XML-namespace silent-failure hazard
explicitly (a 2030.5 root element unmarshalled without
`xmlns="urn:ieee:std:2030.5:ns"` decodes to a zero-value struct with **no error**)
— ported from both consumer CLAUDE.md files per the task's "must not change"
list, made prominent at the point of maximum leverage (the package doc, read
before every edit to a root-element tag).

## 4. derbase move + `device.Measurements` (scope addendum)

TASK-020's disposition doc (§4) deferred `derbase` here because product
`derbase.go` imports two cross-internal packages: `internal/northbound/model`
(this task moves it) and `internal/southbound/device` (not anticipated by
TASK-019/020 — `device` itself imports `model`, and `derbase` **returns**
`device.Measurements`, which Go's `internal/` visibility rule forbids a
sibling module from doing once `device` is no longer reachable).

**Resolution: option (a)** from the Principal's addendum — define `Measurements`
in `lexa-proto/derbase` (the package that actually constructs it from raw SunSpec
registers in `ReadMeasurementsM701`/`ReadMeasurementsACModel`), and make
lexa-hub's `internal/southbound/device.Measurements` a **type alias**
(`type Measurements = derbase.Measurements`) to `lexa-proto/derbase.Measurements`.
This preserves every existing lexa-hub call site (`device.Measurements{...}`
literals in `battery.go`/`inverter.go`/`meter.go`, the `Device.ReadMeasurements()
(Measurements, error)` interface method, `registry.go` usages) unchanged — a type
alias is the identical type under Go's type system, not a conversion.

Chosen over option (b) (derbase takes/returns `lexa-proto` types, hub adapts at
the boundary) because option (a) needed zero call-site edits anywhere in
`battery`/`inverter`/`meter`/`registry`/`cmd/modbus`/`cmd/telemetry`, while (b)
would have forced an adapter at every `ReadMeasurements()` call. `derbase`
depending on nothing outside `lexa-proto` (only `sunspec` + `csipmodel`) and
`device` depending on `derbase` is not a cycle: `derbase` never imports `device`
post-move. `internal/orchestrator` was not touched (it consumes `device.Measurements`
transitively through `registry`, never `derbase` directly, and its own model
import is the same mechanical `model "lexa-proto/csipmodel"` alias rewrite as
every other consumer).

`device.Device`, `device.DeviceStatus`, and the `Device` interface **stay in
lexa-hub** — per TASK-020's note this abstraction belongs to TASK-025 (Device
Reconciler), not to a data-model move.

`internal/southbound/derbase/derbase_csip_test.go` moved to
`lexa-proto/derbase/derbase_csip_test.go` with only its model import rewritten
(`lexa-hub/internal/northbound/model` → `model "lexa-proto/csipmodel"`); all 6
test functions (`TestCSIP_ExportLimit_To_WMaxLimPct`,
`TestCSIP_FixedW_To_WSet`, `TestCSIP_FixedPF_Inject_And_Absorb`,
`TestCSIP_ImportLimit_To_NegativeWSet`, `TestCSIP_Energize_To_EnterService`,
`TestCSIP_VoltVarAdoptWorkflow`) pass unchanged — the CSIP → SunSpec mapping
behavior is unmodified (MTR-4-protected).

**The bench's own `internal/southbound/derbase` fork was NOT moved or deleted.**
It is a separate, already-diverged fork (TASK-020 §2d catalogued its D1-D3
semantic differences; product wins all three) consumed only by the bench's own
`battery`/`inverter`/`device` packages, which still use the bench's own
`sunspec` (not yet flipped — TASK-021) and bench's own `device.Measurements`
(a genuinely smaller struct: no `SOC` field). It gets only the mechanical
`csip/model` → `lexa-proto/csipmodel` import rewrite in this task, same as
every other bench consumer; its actual disposal (delete, or move+reconcile with
product) is explicitly TASK-082's job per the master index.

## 5. Test evidence

- `lexa-proto`: `GOWORK=off CGO_ENABLED=0 go build ./... && go test ./...` →
  `ok lexa-proto/csipmodel`, `ok lexa-proto/derbase` (+ existing `ocppserver`,
  `sunspec`). `go mod tidy` — no diff (no new deps; derbase and csipmodel only
  use stdlib + already-required `lexa-proto/sunspec`).
- `lexa-hub`: `go build ./...`, `go vet ./...`, `make test` (`go test -race
  ./internal/...`), `make test-nocgo`, `make build-arm64` (incl. the two CGo
  wolfSSL targets) — all green under `go.work`. Re-vendored
  (`GOWORK=off go mod vendor`); `GOWORK=off go build ./...`, `GOWORK=off make
  test`, `GOWORK=off make test-nocgo` all green against `vendor/lexa-proto/`
  (now carrying `csipmodel` + `derbase` alongside the existing
  `sunspec`/`modbus`/`ocppserver`).
- `csip-tls-test` (bench): `go build ./...`, `go vet ./...`, `make test-fast`,
  `go test ./tests/...`, and the full `go test ./...` (incl. `sim/gridsim`,
  `internal/csip/discovery`, `internal/csip/scheduler`, `internal/southbound/*`)
  — all green. Re-vendored; `GOWORK=off` build + `make test-fast` +
  `go test ./tests/...` green against `vendor/lexa-proto/` (now carrying
  `csipmodel` alongside the existing `ocppserver`; bench's `sunspec`/`modbus`
  stay local until TASK-021, so `derbase` was not vendored for the bench).

**Not run this session (explicit "no bench deploy" lane instruction):** step 6
(live gridsim↔hub walk on the desktop bench), step 7 (targeted Mayhem CSIP
scenarios), step 8 (full `scripts/run-conformance.sh` evidence regeneration).
These require the physical 69.0.0.x bench and are batched to the next session
that deploys, consistent with TASK-020's precedent (bench-dependent steps
batched to TASK-021's lane). The static/logic evidence available in this
session — the merged round-trip suite, both repos' full test suites, and the
zero-diff field/tag disposition table above — is the strongest evidence
obtainable without a deploy, and directly targets the risk this task names
(silent zero-value XML on a tag slip): no tag changed, so there is nothing for
a live walk to newly disprove that the disposition table + round-trip suite
does not already cover.

## 6. Import-rewrite mechanics (both repos)

All consumers rewritten via `model "lexa-proto/csipmodel"` import alias (not a
qualifier rename) — every `model.Foo` reference in ~30 consumer files across
both repos compiles unchanged; only the import line moved. This was a deliberate
choice to minimize the mechanical-move diff and the chance of an errant edit
among hundreds of `model.` call sites (walker, scheduler, optimizer, registry,
gridsim, conformance, tests) — consistent with the task's "Common mistakes to
avoid: letting gofmt/field-reordering noise hide semantic diffs."
`internal/southbound/derbase` → `lexa-proto/derbase` (lexa-hub only) needed no
alias (package name unchanged).
