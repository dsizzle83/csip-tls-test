---
name: bench-deploy
description: Cross-compile and deploy simulators/hub to the 69.0.0.x bench Pis, restart services, and verify. Use for any "deploy", "push to the Pis", "update the bench", or "restart the sims" request.
---

# Bench deploy

**Read `docs/BENCH.md` first** — it is the source of truth for IPs, SSH users, and service
models, and it changes as the bench evolves. Summary: SSH as `dmitri@`; sims run as *user*
systemd units (binaries in `~/bin`); only hub-pi (69.0.0.1) has passwordless sudo and root units.

## Build

```bash
# Sims are pure Go — cross-compile from this desktop:
GOOS=linux GOARCH=arm64 go build -o bin/arm64/<sim> ./sim/<sim>     # modsim batsim metersim evsim

# Hub binaries are built in the lexa-hub repo:
cd ~/projects/lexa-hub && make wolfssl-arm64 && make build-arm64
# (arm64 wolfSSL sysroot lives in /tmp and is wiped on reboot — rebuild it first)
```

## Deploy

1. **Hub**: `bash ~/projects/lexa-hub/scripts/deploy-hub-pi.sh 69.0.0.1 dmitri`
2. **Sims**: `bash scripts/update-sim-pis.sh <hub-ip> dmitri` — auto-detects each Pi's
   layout (user unit in `~/.config/systemd/user` vs legacy root unit), installs over the
   unit's existing ExecStart path, rewrites metersim to linked mode and evsim's CSMS URL,
   then restarts and reports `is-active` per sim.
3. **MTR-4 lockstep**: never deploy only one side of a SunSpec register-map change —
   hub (`lexa-modbus`) and metersim must go out together or one reads garbage.
4. **Deploy resets hub timing to STOCK** — `deploy-hub-pi.sh` copies `configs/*.json`
   over `/etc/lexa/`, wiping FAST-mode tuning. If a Mayhem/replay session is active,
   re-run `scripts/hub-replay-tune.sh fast 69.0.0.1 dmitri` after every hub deploy, or
   QA verdicts silently degrade (2026-07-02: stock 15 s engine ticks turned scheduler
   fixes into phantom FAILs).

## Verify (always, after any deploy)

```bash
curl -s http://69.0.0.10:6020/state | head -c 200    # solar
curl -s http://69.0.0.11:6021/state | head -c 200    # battery
curl -s http://69.0.0.12:6022/state | head -c 200    # meter (linked mode: check W ≈ load+ev−solar−battery)
curl -s http://69.0.0.14:6024/state | head -c 200    # ev
curl -s http://69.0.0.1:9100/status                  # hub
ssh dmitri@69.0.0.1 'sudo systemctl is-active lexa-hub lexa-modbus lexa-northbound lexa-telemetry lexa-ocpp lexa-api mosquitto'
```
Report which checks passed/failed, with the failing unit's last journal lines.

## Never
- `pkill -f` over SSH (can match the wrapping `bash -c` and kill the session). Use systemctl.
- Copy a `*-key.pem` anywhere except via the established deploy scripts.
- Restart hub services mid-demo without saying so first.
