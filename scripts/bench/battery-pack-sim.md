# Bench: the battery-shaped simulator (both shapes)

Written for lexa-gw's bench runbook. It is the counterpart of that repo's
`scripts/bench/legacy-sim.md`, one device class over — and it exists because
lexa-gw `docs/known_issues.json` BENCH-000 has recorded the same blocking gap
since IW3, three times over:

> THE BENCH HAS NO BATTERY-SHAPED SIMULATOR. The 704-less shape exists on the
> bench only as an INVERTER (`modsim -der-models legacy`, registered as
> `inv-legacy`, `der_gen "12x"`), and the two 7xx bench devices are inverters
> too; nothing there answers as role `"battery"` at all, so neither posture can
> be exercised.

Six rows are queued behind it — (e) cease posture on a 704-less pack, (f)
reconnect on release, (g) the admission refusal against firmware that leaves
`Conn` unimplemented, (h) the setpoint-shape regression, (j) a pre-disconnected
pack at boot, (k) ownership across a real rail drop — plus the older
"setpoint convergence (battery sim mode w/ 704 WSet bridge)". This file is what
makes all of them runnable.

Nothing here restarts automatically. If the sim host reboots, re-run the launch
line before re-registering anything, or every assertion fails at the transport
layer rather than where it was aimed.

## 0. The two shapes, and why they are named after postures

`batsim` (in this repo, `sim/batsim`) grew a `-pack` flag. Its values are
lexa-gw `internal/topics`' `FailsafePostureSetpointZero` /
`FailsafePostureCease` verbatim — the value that rides on
`InventoryRecord.FailsafePosture` — because on a battery the SHAPE *is* the
posture, and an operator reading a bench log should not have to translate.

| `-pack` | SunSpec model chain | Containment it can execute | `der_gen` to register with |
|---|---|---|---|
| `setpoint-zero` | 1, 120, 121, 103, 123, 802, **701, 702, 703, 704, 713** | 704 `WSet` = 0 (idle, never leaves service) | `7xx` |
| `cease` | 1, 120, 121, 103, 123, 802 | M123 `Conn` = 0 (physical cease) | `12x` |
| *(omitted)* | unchanged historical demo battery | — | — |

`-pack` also accepts the aliases `704`/`setpoint` and `704-less`/`legacy`.
An unrecognised value is a hard error, not a fall-back: the difference between
the two spellings is the difference between a pack that can be idled and one
that has to be disconnected.

## 1. Launching

On the bench sim host (69.0.0.20), from the `csip-tls-test` checkout. Build
once with `make build-batsim` (or `go build -o bin/batsim ./sim/batsim`) — and
note that `scripts/bench-sims-up.sh`-style `build_if_missing` helpers will NOT
rebuild an existing `bin/batsim`, so `rm -f bin/batsim` after pulling this
change or `-pack` will be rejected by a stale binary.

```bash
# The 704-CAPABLE pack — rows (h) and setpoint convergence.
./bin/batsim -pack setpoint-zero -port 5023 -api-port 6023 -kwh 20 -wmax 5000

# The 704-LESS pack — rows (e), (f), (g), (k).
./bin/batsim -pack cease -port 5024 -api-port 6024 -kwh 20 -wmax 5000

# Row (j): the pack a technician locked out at the cabinet, OPEN before the
# gateway can dial. Doing it with the flag rather than a post-start
# POST /inject removes the race in which the gateway reads a connected pack
# and adopts it before the injection lands.
./bin/batsim -pack cease -port 5024 -api-port 6024 -kwh 20 -wmax 5000 -start-disconnected
```

Ports 5023/5024 and 6023/6024 are deliberately clear of the Pi sim map
(`modsim` 5020/6020, `batsim` 5021/6021, `metersim` 5022/6022 — see this
repo's CLAUDE.md) and of `bench-sims-up.sh`'s desktop fleet ports
(5030/5031, 6040/6041), so a stray connection to a Pi cannot look like a
healthy pack.

Confirm the shape before trusting a row:

```bash
curl -s localhost:6023/state | jq '.pack | {shape, failsafe_posture, connected, commanded_W, measured_W, ramp_W_per_tick}'
curl -s localhost:6024/state | jq '.pack.shape'          # -> "cease"
curl -s localhost:6023/registers | jq 'to_entries|length' # non-truncated dump incl. the 7xx block
```

## 2. Registering with lexa-modbus

The gateway does NOT sweep — `configs/modbus.json` ships
`admission.sweep_enabled=false` for plain TCP — so a sim nobody listed is a sim
the gateway never dials. This is a BOARD-SIDE edit
(`/etc/lexa/modbus.json` on 69.0.0.2) that no script in this repo can or should
make. Back up first, then add:

```json
{
    "name": "bat-704",
    "endpoint": "tcp://69.0.0.20:5023",
    "unit_id": 1,
    "role": "battery",
    "max_w": 5000,
    "der_gen": "7xx"
},
{
    "name": "bat-legacy",
    "endpoint": "tcp://69.0.0.20:5024",
    "unit_id": 1,
    "role": "battery",
    "max_w": 5000,
    "der_gen": "12x"
}
```

then `systemctl restart lexa-modbus`.

`der_gen` is a DECLARATION and is deliberately NOT where the posture is
decided — RMD-025 moved that to the measured model walk, and `config.go` says
so. Registering `bat-704` as `12x` will therefore NOT produce the cease shape;
it will produce a device whose declaration disagrees with its measurement,
which is a different (and also interesting) row. Use the table in §0.

Verify the gateway measured what you launched, before running any row:

```bash
# On the board: the admission verdict, per device. ONE retained census document
# on ONE topic — there is no lexa/inventory/* family, and a subscriber to a
# topic this product does not publish gets silence that is indistinguishable
# from a missing ACL grant (Wave-H finding (n)). -C 1 because the document is
# retained: the first delivery is the current census.
mosquitto_sub -C 1 -t 'lexa/southbound/inventory' |
  jq '.records[] | {device, role, failsafe_posture, models, inactive}'
# der_gen is NOT in the census: it is a CONFIG declaration, and this document
# reports what the model walk MEASURED. Asking for it here prints null, which
# reads like a gateway that lost the field rather than a field that is not there.
```

`bat-704` must report `failsafe_posture: "setpoint-zero"` and `bat-legacy`
`"cease"`. Anything else and the rows below are measuring the wrong device.

## 3. The rows

All `POST /fault` and `POST /inject` bodies go to the sim's own API port
(6023/6024), never to the gateway.

### (e) Cease posture on a 704-less pack

```bash
# Get the pack running first — the state RMD-025's pre-fix capture was taken in.
# CommandedW_W is the shape-agnostic lever: signed watts through whichever
# active-power axis the shape has. "WMaxLimPct_pct" is unsigned/clamped
# [0,100] and cannot express a charge direction — see §4.
curl -sX POST localhost:6024/inject -d '{"CommandedW_W":4000}'
sleep 20 && curl -s localhost:6024/state | jq '.pack.measured_W'   # ~ +4000
```

Then engage the gateway's fail-safe. Expect: M123 `Conn` → 0, the DER's own
state follows (`802 State` = DISCONNECTED, `802 ChaSt` = OFF, `103 St` = OFF),
measured power lands inside the cessation band **in the same poll** (a
contactor is not a ramp), and `lexa_mb_connect_converged_total` climbs.

```bash
watch -n2 "curl -s localhost:6024/state | jq -c '.pack|{connected,measured_W}'"
```

### (f) Reconnect on release

Clear the fail-safe. Expect the same axis to put the pack back in service and
measured power to return to the standing dispatch **via the ramp** — reclosing
a contactor onto an inverter does not instantly restore its output, so allow
~3 animation ticks (15 s). Per RMD-028 the reconnect must be shown to ride on
the durable ownership record, not on the document alone; run the
restart-across-the-release-edge variant too.

### (g) The admission refusal on firmware that leaves Conn unimplemented

No third register image needed:

```bash
curl -sX POST localhost:6024/fault -d '{"kind":"sentinel_field","fields":["Conn"],"value":65535}'
systemctl restart lexa-modbus     # force a fresh identify
```

Expect a typed `*NoFailsafeChainError` at admission, journaled and counted,
BEFORE a northbound unit is allocated. The register bank stays honest
throughout (`curl -s localhost:6024/registers`), so the referee can still see
what the pack really is. Clear with `{"kind":"sentinel_field","clear":true}`.

### (h) The setpoint-shape regression

The 704 pack's posture must be unchanged by RMD-025/028. Drive a setpoint in
both directions and confirm convergence, then engage/release the fail-safe and
confirm the pack IDLES rather than disconnecting:

```bash
curl -sX POST localhost:6023/inject -d '{"WSet_W":3000}'   # discharge
sleep 20 && curl -s localhost:6023/state | jq -c '.pack|{commanded_W,measured_W}'
curl -sX POST localhost:6023/inject -d '{"WSet_W":-2500}'  # charge
sleep 25 && curl -s localhost:6023/state | jq -c '.pack|{commanded_W,measured_W}' \
          && curl -s localhost:6023/state | jq '.battery.SoC_pct'
```

Under the fail-safe: `connected` stays `true`, `measured_W` → 0. A pack that
disconnects here has been given the wrong posture.

### (j) Pre-disconnected pack at boot

Launch with `-start-disconnected` (§1), boot the gateway over the retained
ordinary CSIP document, and confirm **zero** M123 `Conn` writes and
`lexa_mb_failsafe_reconnect_withheld_total` climbing. The pack reports itself
open on every surface a gateway reads — the connect register, its own
operating state, and its measured power — so "we did not observe it
disconnected" is not available as an excuse.

### (k) Ownership across a real power cut

Cease a running pack, pull the board's rail mid-cease, confirm the record
replays from p7 and the release still reconnects. The sim side needs nothing
special; leave `bat-legacy` running throughout so the pack the gateway comes
back to is the same one it left.

### Setpoint convergence, and the two false-Applied rows

```bash
# An ACKed setpoint that never latched (704 pack).
curl -sX POST localhost:6023/fault -d '{"kind":"ack_no_apply","fields":["WSet","WSetEna"]}'
# An ACKed cease that never opened the contactor (either pack).
curl -sX POST localhost:6024/fault -d '{"kind":"ack_no_apply","fields":["Conn"]}'
# Clear:
curl -sX POST localhost:6023/fault -d '{"kind":"ack_no_apply","clear":true}'
```

In both cases the write succeeds at the protocol level and the pack keeps doing
exactly what it was doing. The gateway must NOT report Applied. The sim's own
`/state` stays honest (`.pack.lies.fired` counts what actually fired), so the
divergence between what the device SAYS and what it DOES is directly readable.

Also available on a pack, same bodies as the inverter rows:
`{"kind":"freeze_block","models":["701","103"]}` (or `["802"]`, `["123"]`,
`["704"]`, `["713"]`), `{"kind":"revert_after","delay_s":40}` (acts on 704
`WSetEna`), `{"kind":"reboot_forget"}` (the pack comes back with the contactor
CLOSED and no standing dispatch — RMD-025's DER-reboot-to-defaults row), and
the effect-time battery faults `soc_refuse` / `charge_disabled` /
`discharge_disabled`, which reach a power commanded through 704 as well.

**Idle-at-zero needs no fault**: drive SoC to an extreme and command into it.

```bash
curl -sX POST localhost:6023/inject -d '{"SoC_pct":100}'
curl -sX POST localhost:6023/inject -d '{"WSet_W":-4000}'   # charge a full pack
sleep 20 && curl -s localhost:6023/state | jq '.battery.ChaSt_text'   # -> "full"
```

`ChaSt` FULL/EMPTY rather than HOLDING is how a hub tells "this pack is
refusing" from "this pack is uncommanded".

## 4. `WMaxLimPct_pct` is unsigned/clamped — use `CommandedW_W` for a signed dispatch

Found by the live smoke of this work, on 2026-08-04, **fixed as RMD-046**
(2026-08-05).

`POST /inject {"WMaxLimPct_pct": N}` — the historical spelling on BOTH this
battery sim and the solar one — used to encode `RawFromScaleSigned(N*100, SF)`
against a scale factor of −2, which is `N x 10000`. The register therefore
**saturated at 32767 for any N above ~3.27**. Injecting 80 did not command
80 %; it commanded the saturated word, which `hubBatteryW` read back as
**327.67 % of nameplate** and `GET /state` reported (dividing by 100 again,
matching the same mistaken convention) as `"WMaxLimPct_pct": 3.28`.

Observed live: `{"WMaxLimPct_pct":80,"Ena":1}` on a 5 kW `-pack cease` sim
produced `M123[0] = 32767` and a measured power pinned at the pack's declared
rate rating — correct behaviour by the pack, in response to a command nobody
meant.

That double scale is now fixed everywhere at once: `battery.go` and
`solar.go`'s `Inject` encode `val` directly (no `*100`), and CLAMP it to
`[0,100]` — the domain WMaxLimPct is defined over — rather than let an
out-of-range value encode into a representable-but-meaningless raw word.
`{"WMaxLimPct_pct":80,"Ena":1}` now produces `M123[0] = 8000` (80.00 %), and
`GET /state` reports `"WMaxLimPct_pct": 80` to match.

`WMaxLimPct_pct` remains the WRONG lever for a pack, though — not because it
is broken, but because it is unsigned: it cannot express a charge direction.
**On a pack, use `{"CommandedW_W": <signed watts>}`**, which writes 704
`WSet` on the setpoint shape and the correctly-encoded, signed M123 dispatch
on the cease shape. `{"WMaxLimPct_pct":0}` (the QA harness's inter-scenario
reset) behaves the same as before the fix — zero encodes to zero regardless
of the multiplier.

## 5. Before every hand deploy

The ACL/`/etc/lexa/*.json` drift check in lexa-gw's
`scripts/bench/legacy-sim.md` §5a applies unchanged here, and DEF-1 plus the
`telemetry.json` finding are why: a config that ships with the binaries but is
not re-synced is a silently-breaking deploy. Adding two battery devices touches
`/etc/lexa/modbus.json`, which is squarely inside the "thirteenth deployable
artifact" that finding named.

## 6. What this file does NOT cover

- `scripts/bench-sims-up.sh`. The packs are deliberately NOT wired into it:
  that script brings up the smoke-test fleet every existing run is measured
  against, and adding two devices to it would change what every one of those
  runs sees without anyone editing a command line. Launch the packs by hand
  from §1, alongside it.
- The bench's northbound half. A battery under CSIP control needs `gridsim`
  serving a DERProgram that names it; that is `bench-sims-up.sh`'s territory.
- Mixed-state / `ExportContained` (BENCH-000's C4 gap). No fault in this
  simulator can put a device into a genuine mixed state — see
  `sim/southbound/lying.go`'s "Known gap: C4" section. It is recorded, not
  closed.
- The `mbaps` (secure transport) battery. `sim/mbapsdev -model battery` serves
  the OLDER advanced battery image (701/704/713, 704 NOT bridged) and is
  deliberately unchanged, because its chain is what every T06.3 scenario walks.
  A secure-transport pack is a separate decision.
