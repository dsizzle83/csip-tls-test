---
name: bench-deploy
description: Cross-compile and deploy simulators/hub to the 69.0.0.x bench Pis, restart services, and verify. Use for any "deploy", "push to the Pis", "update the bench", or "restart the sims" request.
---

# Bench deploy

**Read `docs/BENCH.md` first** — it is the source of truth for IPs, SSH users, and service
models, and it changes as the bench evolves. Summary: SSH as `dmitri@` on the desktop and sim
Pis (sims run as *user* systemd units, binaries in `~/bin`); the hub is the ConnectCore 93 dev
kit at 69.0.0.2, reached as `root@` with root systemd units (hub-pi 69.0.0.1 is STANDBY). Defer
to `docs/BENCH.md` for the current hub host.

## Build

```bash
# Sims are pure Go — cross-compile from this desktop:
GOOS=linux GOARCH=arm64 go build -o bin/arm64/<sim> ./sim/<sim>     # modsim batsim metersim evsim

# Hub binaries are built in the lexa-hub repo:
cd ~/projects/lexa-hub && make wolfssl-arm64 && make build-arm64
# (arm64 wolfSSL sysroot lives in /tmp and is wiped on reboot — rebuild it first)
```

## Secure Modbus (mbaps) pieces run on the DESKTOP, not the Pis (PN-2)

`sim/mbapsdev` (secure device sim), `sim/aggregator` (the mbaps aggregator emulator),
and `sim/ssm-conformance` (the 62-requirement conformance walker) are **cgo (wolfSSL)** —
unlike the plain pure-Go sims, they do NOT cross-compile freely. Default topology keeps
all three on the desktop (69.0.0.20), built with the amd64 sysroot:

```bash
make build-mbapsdev build-aggregator build-ssm-conformance   # desktop, amd64 wolfSSL sysroot
bin/mbapsdev -listen :8021 -model inverter -api-port 6031     # southbound target, desktop-only
make ssm-conformance                                         # 62-req suite vs a loopback (no bench)
make ssm-conformance TARGET="-target 69.0.0.2:802 -pki certs/mbaps"   # vs the live gateway on the CC93
```

The aggregator emulator drives the gateway northbound over the LAN from where it is built
(the desktop) — **no cross-compile needed**. Deploying `mbapsdev` onto a sim Pi is optional
and requires an **arm64 wolfSSL sysroot** cross-build (the plain sims never needed one):
`GOOS=linux GOARCH=arm64` alone will not build it — set the arm64 wolfSSL `CGO_CFLAGS`/
`CGO_LDFLAGS` first, as the lexa-hub `wolfssl-arm64` recipe does. Live mbaps runs (aggregator
campaigns, `ssm-conformance -target …`) need `make gen-mbaps-certs` first for the role/device
keys (gitignored); the loopback self-tests mint their own throwaway PKI and need none.

## Deploy

1. **Hub**: `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.2 root`
2. **Sims**: `bash scripts/update-sim-pis.sh <hub-ip> dmitri` — auto-detects each Pi's
   layout (user unit in `~/.config/systemd/user` vs legacy root unit), installs over the
   unit's existing ExecStart path, rewrites metersim to linked mode and evsim's CSMS URL,
   then restarts and reports `is-active` per sim.
3. **MTR-4 lockstep**: never deploy only one side of a SunSpec register-map change —
   hub (`lexa-modbus`) and metersim must go out together or one reads garbage.
4. **Deploy resets hub timing to STOCK** — `deploy-hub-pi.sh` copies `configs/*.json`
   over `/etc/lexa/`, wiping FAST-mode tuning. If a Mayhem/replay session is active,
   re-run `scripts/hub-replay-tune.sh fast 69.0.0.2 root` after every hub deploy, or
   QA verdicts silently degrade (2026-07-02: stock 15 s engine ticks turned scheduler
   fixes into phantom FAILs).

## Verify (always, after any deploy)

```bash
curl -s http://69.0.0.10:6020/state | head -c 200    # solar
curl -s http://69.0.0.11:6021/state | head -c 200    # battery
curl -s http://69.0.0.12:6022/state | head -c 200    # meter (linked mode: check W ≈ load+ev−solar−battery)
curl -s http://69.0.0.14:6024/state | head -c 200    # ev
curl -sk https://69.0.0.2:9100/status                # hub (HTTPS, self-signed leaf — WS-B)
ssh root@69.0.0.2 'sudo systemctl is-active lexa-hub lexa-modbus lexa-northbound lexa-telemetry lexa-ocpp lexa-api mosquitto'
```
Report which checks passed/failed, with the failing unit's last journal lines.

## Never
- `pkill -f` over SSH (can match the wrapping `bash -c` and kill the session). Use systemctl.
- Copy a `*-key.pem` anywhere except via the established deploy scripts.
- Restart hub services mid-demo without saying so first.
