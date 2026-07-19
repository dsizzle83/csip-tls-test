# gw-mayhem gateway hostile-QA scenarios (`camp_v: 1`)

Data specs for the **gateway** hostile-QA suite (`sim/gw-mayhem`, runner
`cmd/gw-mayhem`) — the adversarial counterpart of the dashboard's Mayhem family,
targeting the lexa-gw gateway's northbound Secure-SunSpec-Modbus (`:802`) surface.

A spec here is an **aggregator control campaign** (`internal/aggregator`, the same
`camp_v: 1` schema as `qa/aggregator/*.json`): the gw-mayhem engine loads it, runs
it through the aggregator engine, and folds its verdict into the suite gate. This
is maximal reuse — the gateway QA is a hostile *driver* on top of the aggregator
emulator, never a fork of it.

## The go/spec split (Mayhem's rule)

- **Go-literal scenarios** (`sim/gw-mayhem/*.go`) hold the families whose logic the
  data schema cannot express: the role×op **matrix** sweep, the raw hostile-cert
  **cert-authz** negatives, the raw-frame **malformed-write** probes, and the
  concurrent **session flood**.
- **Spec scenarios** (this dir) express the single-role denial/grant proofs the
  vocabulary already covers.
- A spec whose `id` collides with a Go scenario's (or another spec's) is a
  **load-time error** — logged, skipped, never a silent shadow, never a blocker for
  another file (`AllScenarios`, mirroring the Mayhem loader).

## Schema

Identical to `qa/aggregator/README.md` (`camp_v: 1`): `id`, `name`, `role` (one of
the five bench roles), `target` (`gateway`/`device`), `steps[]` from the fixed
action vocabulary, `oracle{name}`, `expected_verdicts[]`. Oracles are code
(`internal/aggregator`): `denyExpected` (a role's write must answer exception 01),
`convergeWithinSLA` (a granted write must be accepted + echoed), etc.

## Files

- `authz-networkadmin-write-denied.json` — the non-obvious matrix cell as reviewable
  data: NetworkAdmin's `net-admin` write grant is empty in v1, so a control write is
  denied 01 (`denyExpected`).
- `authz-gridservice-write-granted.json` — the grant half: GridService's commanded
  write is accepted + echoed (`convergeWithinSLA`).

## Running

```bash
gw-mayhem -loopback -pki certs/mbaps          # hermetic (no bench)
gw-mayhem -target 69.0.0.2:802 -pki certs/mbaps   # live
gw-mayhem -list                               # list the whole suite (go + spec)
gw-mayhem -loopback -only authz-role-denial-matrix -json
```

The runner exits non-zero when any scenario's verdict falls outside its
`expected_verdicts` (a security-critical non-PASS trips the gate unless it is a
documented, pinned gap), or on any spec load error.
