# Lab simulators — the desktop-side half of the lexa-gw lab loop

`scripts/lab/lab-sims-up.sh [up|down|status|reset]`

The lexa-gw **lab loop** (`lexa-gw/docs/LAB_LOOP.md`) runs the production
service binaries on the developer's own host, as the product's own uids, so a
single conformance case takes tens of seconds instead of a rebuild/flash cycle.
This script is the simulator half of that: gridsim, modsim and mbapsdev on
loopback, in the **evidence-grade posture**, on a port block that does not
collide with the bench.

```sh
scripts/lab/lab-sims-up.sh up
#   gridsim   https://127.0.0.20:21113   admin http://127.0.0.20:21114
#   modsim    tcp://127.0.0.20:15020     api   http://127.0.0.20:16020
#   mbapsdev  mbaps://127.0.0.20:18021   api   http://127.0.0.20:16031
```

## Why it is not `bench-sims-up.sh` with different env

It was written to be, and could not be. `bench-sims-up.sh` hardcodes the two
**simapi ports** — modsim `6020`, mbapsdev `6031`. They are not env-overridable,
and `sim/simapi` binds the wildcard address (`http.ListenAndServe(":<port>")`),
so a second set cannot be separated by address either.

A developer host that is *also* serving the bench board already holds
`5020/6020/8021/6031/11113/11114`. A lab that reused them would either fail to
start or — far worse — silently attach the local loop to the simulators a live
bench campaign is grading. So the lab runs its own set on its own port block and
launches it directly.

> **Suggested follow-up in this repo:** make `bench-sims-up.sh` accept
> `MODSIM_API` and `MBAPSDEV_API` (it already accepts `MODSIM2_API`/
> `MODSIM3_API` for the fleet sims), and the two launchers can converge on one
> file. That edit was out of scope for the change that added this script.

## The posture is the bench's, knob for knob

Every default below is `bench-sims-up.sh`'s, and every one is load-bearing.
Dropping any of them does not fail loudly — it silently degrades some fraction
of verdicts to SKIP or FAIL.

| Knob | Default | Why |
|---|---|---|
| `GRIDSIM_BIN` / `MBAPS_BIN` | the `*-keylog` builds | without them there is no `-keylog` flag, the capture cannot be decrypted, and every citation-dependent case loses its transcript |
| `SIMS_KEYLOG` | `$LAB/run/lab-sims.keylog` | both sims append to one file, so a single capture decrypts against it |
| `GRIDSIM_NO_TICKETS` / `MBAPS_NO_TICKETS` | `1` | forces a full mTLS handshake on every gateway dial. A resumed TLS 1.3 handshake carries no Certificate message (RFC 8446 §2.2), so without this RBAC-011 and every client-certificate citation is unavailable |
| `GRIDSIM_IDLE_S` | `30` | closes idle CSIP sessions, so each poll is its own observable session instead of one spanning the whole run |
| `GRIDSIM_POLL_S` | `60` | advertises a uniform pollRate. Without it the built-ins apply (300 `/dcap`, 900 `/tm`, 60 control lists) and a `poll_rate_mode=honor` DUT paces its **whole** walk at 900 s, so every wait-for-fetch case times out. Omitting it once collapsed 64 of 79 CSIP verdicts |
| `DER_MODELS` | `full` | 707–710 trip models on top of the 7xx set; the reduced fixture was being measured as a product gap it never was |
| `MBAPS_WMAX` | `2000` | LXR-013 reserves an uncontrollable device's full nameplate out of the site ceiling; a 6000 W second device alone exceeds the 5000 W default and zeroes every controllable device's budget |
| `SIM_FLEET` | `2` | one configured DER — RC0's frozen single-DER scope and the audit's one-to-one topology |
| aggregator | **off** | the bench loop targets `${GW_HOST}:802` with the port hardcoded, and the lab's listener is on 8802 |

## Addresses

Sims **127.0.0.20**, DUT **127.0.0.2**, harness **127.0.0.1**. Distinct
addresses are not cosmetic: certify decides a captured frame's direction by
comparing its source against the DUT's, and on 127.0.0.1-for-everything every
frame looks like it came from the DUT. (Linux still sources *outbound* loopback
connections from 127.0.0.1 regardless of destination, so the DUT-as-client legs
remain undecidable in the lab — see `lexa-gw/docs/LAB_LOOP.md` §5.)

## `reset`

A full down/up, deliberately. The audit's Layer 2 forbids sharing authority, TLS
tickets, event history or register state between profiles, and the only way to be
certain of that is a fresh process, not an admin poke.

## Stopping

By **pid file only**, never `pkill` by name: this host runs the same simulator
binaries for the bench and for other agents' worktrees, and a name-matched kill
in a shared environment eventually kills the wrong one.
