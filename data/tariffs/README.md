# Tariffs (`data/tariffs/*.json`)

One file = one retail electricity plan a real customer could have been on.

## Schema

The tariff JSON schema is **defined and owned by
[`docs/dashboard-v2/CONTRACTS.md` §1](../../docs/dashboard-v2/CONTRACTS.md)** —
that document is authoritative. The Go implementation (types, validation, rate
lookup, and the billing accumulator) lives in
[`internal/tariff`](../../internal/tariff); its package doc records the two
resolved contract ambiguities (net-metering export credits the bare period
energy rate; `BillCalc` scopes itself to its `(year, month)`).

Every file is validated at load time (`tariff.Load`): seasons partition the
months they declare, each season's `day_types` cover the week exactly once,
each `day_type`'s periods tile 24 h with no gap or overlap (midnight-wrapping
periods included), all per-kWh rates are in `[0, 5)`, the IANA `timezone`
resolves, and the `effective` range parses. A file that fails any rule is a
hard load error, not a warning.

Worked, penny-exact examples live under
[`internal/tariff/testdata/`](../../internal/tariff/testdata) with their
hand-computed bills in `internal/tariff/bill_test.go`.

## Provenance discipline (non-negotiable)

Every number a customer sees traces back to the file's `provenance` block, and
the block must be **honest**:

- `confidence: "filed"` — taken from a tariff/rate schedule filed with the
  regulator (PUC/CPUC/etc.).
- `confidence: "published"` — from the utility's published EFL / rate sheet /
  price-to-compare, not the raw filing.
- `confidence: "estimated"` — reconstructed, interpolated, or otherwise not
  lifted verbatim from a primary source. Delivery charges folded from a
  separate TDU sheet, or any hand-tuned value, is **estimated** — say so.

Estimated ≠ filed. The UI renders the confidence level and never hides it, so
do not label a reconstruction as `filed`/`published` to make it look
authoritative. Record the `source_url`, the `retrieved` date, and enough
`notes` for a reviewer to reproduce the numbers. Synthetic test fixtures (the
`test-*` files under `internal/tariff/testdata/`) are always `estimated` and
say so in their notes.

Nothing in `data/` may embed API keys or secrets.
