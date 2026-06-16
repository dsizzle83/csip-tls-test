# Bench Replay Runbook — fire-up + what we learned (2026-06-16)

Quick reference for running the hardware-in-the-loop cost/compliance replay after
a desktop reboot, plus the state of the hub optimizer fixes.

## Fire everything back up after a reboot (desktop = 69.0.0.20)

```bash
cd ~/projects/csip-tls-test
bash scripts/bench-up.sh          # restores LAN IP, starts gridsim+dashboard, verifies, sets hub fast
```

Then launch a long test (runs server-side in the dashboard; survives the terminal):

```bash
python3 scripts/replay-launch.py 99 --tick-ms 8000 --launch        # full 92 days (~19.6 h)
# progress:  curl -s http://localhost:8080/api/replay/status | python3 -m json.tool
# when done: bash scripts/bench-up.sh --stock
```

### What a reboot breaks (and `bench-up.sh` fixes)
1. **Desktop bench-LAN IP is lost.** `enp1s0`'s `69.0.0.20/24` is a NetworkManager
   manual address that does **not** re-apply on boot. Without it, nothing on
   `69.0.0.x` is reachable. Restore: `sudo nmcli connection up "Wired connection 1"`
   (needs your password — the desktop has no passwordless sudo; only the hub Pi does).
2. **gridsim + dashboard die.** They run as **transient** `--user` units
   (`csip-gridsim`, `csip-dashboard`) with **no linger**, so a reboot wipes them
   entirely. `bench-up.sh` recreates them via `systemd-run --user`.
3. **The Pis do NOT reboot with the desktop.** Hub (`.1`) + sims (`.10`–`.14`)
   run with linger and stay up; once the LAN is back they should already be live.
   (Optional hardening: `sudo loginctl enable-linger dmitri` so the desktop units
   auto-start at boot too — not done, to avoid surprising system changes.)

## Deployed code state (as of 2026-06-16)
- **Both repos committed + pushed** (local == GitHub): `lexa-hub` @ `main` (`03f03d5`),
  `csip-tls-test` @ `lexa-hub` branch (`f0215e2`).
- **Hub binary on `69.0.0.1:/usr/local/sbin/lexa-hub`** is the 3-fix build. (The
  installed binary's sha differs from a fresh `go build` only by the embedded
  `-buildvcs` stamp — same source. Redeploy any time with:
  `cd ~/projects/lexa-hub && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/h ./cmd/hub`
  then scp to the Pi + `sudo systemctl restart lexa-hub`.)
- **modsim** on `69.0.0.10` already runs the paused-curtailment solar fix (proven by
  the sanity replays curtailing correctly). No sim redeploy needed for these changes.

## What we learned / fixed (the 92-day replay → 87.2% cap compliance)
Three optimizer bugs in `lexa-hub/internal/orchestrator/optimizer.go`, all fixed +
regression-tested:

1. **Export curtailment released to free-running nameplate.** The solar backstop set
   `solarCeilingW = NaN` whenever the computed ceiling reached nameplate; the battery
   credit kept it released, so the inverter ran wide open over-exporting 1–2 kW for
   whole midday episodes (every export violation had solar pinned at 5.0 kW). Fix:
   **sticky-clamp to nameplate** (never release mid-episode), like `applyGenLimitRule`.

2. **Battery drained through the 20% reserve to 0%** (the dominant issue; also the real
   cause of the evening importCap misses). Every discharge rule correctly *stops* at
   the reserve, but `applyRestoreRule` only sent the idle (0 W) command when
   `SOC > reserve` — so at/below the reserve nothing was commanded and the device kept
   its **latched discharge setpoint**, draining to empty. Fix: **always idle an
   uncommanded battery** (idling can't breach the reserve — it enforces it).

3. **Tight-cap hunting** (found during sanity testing). The sticky-clamp alone let the
   controller hunt under the bench meter's ~1-tick lag (slammed the ceiling to 0 W,
   then flung it back up into a re-violation). Fix: **slew-limit the ceiling**
   (≤1.5 kW/tick down, ≤0.5 kW/tick up).

### Policy decision (battery)
Keep cost-optimal TOU arbitrage, but enforce a **hard 20% SOC reserve** (= ~4 h of the
observed ~0.5 kW overnight load on the 10 kWh pack; also battery health). No separate
self-sufficiency objective — the energy is there (92-day solar 3722 kWh vs demand
2464 kWh, +1258 surplus) but the 10 kWh battery can't bridge a full night, so ~70% grid-
import reduction is the realistic ceiling, not 100%.

### Sanity result (seed 99 day-0, the tightest 1.5 kW cap)
77.3% → **86.4%** after the slew fix. importCap 100%; export hunting gone (remaining
misses = 1 onset + 1 settling + 1 relax-blip, all transient). Battery floors & holds
(no drain to 0%).

### Known residuals / possible next tweaks
- **Reserve floors at ~12% in the replay, not 20%** — a replay artifact (it advances
  15 sim-min per 8 s tick, so SOC drops in ~10% jumps and the hub reacts one jump late;
  production with smooth SOC + a 3–15 s engine tick would hold ~19–20%). A **discharge
  taper near the reserve** (mirror of the charge taper at `socTaperStart=80`) would make
  even the replay land at ~20%. Offered, not yet implemented.
- **Export onset transient** (~1 tick at cap activation) is inherent — can't curtail
  before observing the over-export. A rare relax-blip could be trimmed with a slower
  ceiling rise / a relax safe-count.
