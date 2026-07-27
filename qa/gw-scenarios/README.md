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

## What each run mode reaches, and why

The hermetic invocation at the top of that list runs **9 of the suite's 38
scenarios** and *declines* the other 29 (28 in a default run — one is `[ext]` and
excluded unless asked for). That ratio used to be invisible: a decline landed as a
bare `INCONCLUSIVE`, so a roll-up reading `asserted 9/37 | GATE PASS` looked like a
37-check suite of which 28 checks had come back unreadable. It now reads
`applicable 9, declined 28 (23 need the live bench, 5 need a board mutation) |
asserted 9/9 applicable`, every declined line is tagged `[declined:…]`, and the
hermetic set itself is pinned in `sim/gw-mayhem/hermeticset_test.go` so it cannot
shrink without a diff.

**The reason 29 scenarios decline is structural, not an unfinished wiring job.**
`gwloopback` is a faithful *peer*: an mbaps server with a SunSpec register map, a
role authz model, a write decoder enforcing the same bounds the gateway does, and a
session cap. It is not a *gateway*. It has no CSIP client, no head-end schedule, no
southbound poll loop, no reconciler, no reversion timer, no exclusive-authority
arbitration and no board — and every declined scenario judges an effect produced by
exactly one of those.

| Family | n | What it judges | Why the loopback cannot stand in | Hermetic coverage it does have |
|---|--:|---|---|---|
| `nb-malform-*` | 9 | a hostile head-end serves a malformed or absurd CSIP control; the gateway must fail closed and never project it onto a DER | the effect is *northbound ingest → reconcile → southbound write*. The loopback has no CSIP client and no DERs to project onto, so there is nothing for a malformed control to be wrong *about* | `bench_stub_test.go` runs the real arm functions against httptest gridsim/DER stubs playing a conformant gateway and five specific broken ones — the oracle's teeth |
| `nb-headend-*` | 3 | head-end outage / hang / clock jump: the gateway holds, and its schedule stays sane | same — a property of the gateway's northbound client and scheduler, neither of which exists on this side of `:802` | same stub |
| `sb-*` | 6 | a broken DER (comm loss, sentinel registers, stalled handshake, frozen values); the gateway must isolate it, digest it safely and recover | the adversary is a *southbound* device the gateway polls. The loopback has no poll loop, and giving it one would mean emulating the product | same stub |
| `control-*` | 4 | write→apply→readback through the real control loop: rapid re-curtailment, a `RvrtTms` reversion, mbaps-vs-CSIP exclusive authority, boundary dither | the loopback echoes a written register immediately, and every one of these claims is about a *delay* or an *arbitration* that an immediate echo satisfies vacuously. A PASS here would be a PASS about the loopback | pure-oracle unit tests over constructed evidence |
| `perfect-storm-compound-fault`, `comm-loss-sentinel-mask` | 2 | three simultaneous faults; and the northbound sentinel mask with its 704 control-echo exemption | compositions of the above, plus a projection rule that lives in the gateway's northbound view | pure-oracle unit tests |
| `[board]` family D | 5 | authority mode switch, vendor-access toggle, cert rotation mid-session, trust-store tamper, service restart under an active cap | the adversary is a change to the *board's* files and services. This suite never mutates the board: the orchestrator arms it and re-runs with `-board-armed <id>` | `-list` and the decline line carry each arm/teardown hook verbatim |

Two conclusions worth stating plainly, since "wire them up" is the obvious first
answer:

1. **Making these run hermetically would mean building a second gateway**, and a
   bench that reimplements the product cannot referee it (PN-1/C9). The right
   hermetic artefact for these families is the one that already exists — a stub the
   *oracle* is run against, proving the oracle FAILs a broken gateway. That is a
   proof about the check, which is not the same claim as a proof about the device;
   the two are now counted separately instead of summed.
2. **The honest fix was the denominator, not the wiring.** A scenario that can
   never run in a given mode must not inflate that mode's apparent size, and a run
   must say which mode it was. Both are now true, and
   `TestHermeticApplicableSetIsPinned` stops this table and the code drifting apart.
