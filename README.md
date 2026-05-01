# CSIP DER Hub

A DERMS hub that implements IEEE 2030.5 / CSIP for residential DER management. It connects northbound to a utility grid management server over wolfSSL mTLS and controls DER assets southbound over Modbus/SunSpec and OCPP 2.0.1.

Target hardware: Raspberry Pi 4/5 (development), NXP i.MX 93 (production).

## Architecture

```
Utility Grid Server (IEEE 2030.5)
        │  wolfSSL mTLS (ECDHE-ECDSA-AES128-CCM-8 / TLS 1.2)
        ▼
   [ Hub Pi — cmd/hub ]
        │
        ├── Modbus TCP ──► Solar inverter   (SunSpec M103/121/123)
        ├── Modbus TCP ──► Battery storage  (SunSpec M103/802)
        ├── Modbus TCP ──► Smart meter      (SunSpec M201, bi-directional)
        └── OCPP 2.0.1 ◄── EV charger       (station connects inbound)
```

Home load is inferred from the energy balance — no separate load meter needed:
```
load_W = solar_W + battery_W - meter_W
```

## Hub Configuration

The hub reads a JSON config file (see `hub-example.json`):

```json
{
  "server":      "<grid-server-ip>:11111",
  "ca_cert":     "certs/ca-cert.pem",
  "client_cert": "certs/client-cert.pem",
  "client_key":  "certs/client-key.pem",
  "ocpp_port":   8887,
  "devices": [
    { "name": "solar-1",   "url": "tcp://69.0.0.10:5020", "unit_id": 1, "role": "inverter" },
    { "name": "battery-1", "url": "tcp://69.0.0.11:5021", "unit_id": 1, "role": "battery"  },
    { "name": "meter",     "url": "tcp://69.0.0.12:5022", "unit_id": 1, "role": "meter"    }
  ]
}
```

Device roles:

| Role       | Protocol           | SunSpec models   |
|------------|--------------------|------------------|
| `inverter` | Modbus TCP         | M103, M121, M123 |
| `battery`  | Modbus TCP         | M103, M802       |
| `meter`    | Modbus TCP         | M201             |
| EV charger | OCPP 2.0.1 inbound | —                |

## Building the Hub

The hub uses wolfSSL via cgo and **must be built natively on the Pi** (arm64 headers required).

```bash
# Install wolfSSL first — see sim_hub.txt STEP 2 for the full build recipe.

CGO_ENABLED=1 go build -o bin/hub ./cmd/hub
```

To push a code update from your development machine and rebuild on the Pi:

```bash
# On your dev machine
git push

# On the hub Pi
cd ~/csip-tls-test && git pull
CGO_ENABLED=1 go build -o bin/hub ./cmd/hub
```

## Running the Hub

```bash
./bin/hub -config hub.json
```

Expected startup log:

```
[wolfssl] init OK
[hub] loading config: hub.json
[modbus] connected: solar-1   tcp://69.0.0.10:5020
[modbus] connected: battery-1 tcp://69.0.0.11:5021
[modbus] connected: meter     tcp://69.0.0.12:5022
[ocpp] CSMS listening on :8887/ocpp/{id}
[csip] walker started → <grid-server-ip>:11111
```

## Running as a System Service

```bash
sudo systemctl enable hub
sudo systemctl start hub
journalctl -u hub -f
```

See `sim_hub.txt` for the full systemd unit file.

## Certificates

The hub requires three files for mTLS:

| File                    | Purpose                                   |
|-------------------------|-------------------------------------------|
| `certs/ca-cert.pem`     | CA that signed the server cert            |
| `certs/client-cert.pem` | This hub's identity (tracked in git)      |
| `certs/client-key.pem`  | Private key (gitignored — copy manually)  |

Issue a new client certificate:

```bash
make gen-client-cert CN=csip-pi-002
```

## Demo Network Layout

All Pis connect via Ethernet to a dedicated switch on `69.0.0.x/24`. WiFi is a separate subnet used for internet access only.

| Hostname   | IP        | Binary   | Port        |
|------------|-----------|----------|-------------|
| hub-pi     | 69.0.0.1  | hub      | 8887 (OCPP) |
| solar-pi   | 69.0.0.10 | modsim   | 5020        |
| battery-pi | 69.0.0.11 | batsim   | 5021        |
| meter-pi   | 69.0.0.12 | metersim | 5022        |
| ev-pi      | 69.0.0.14 | evsim    | → hub:8887  |

## Simulator Setup Guides

Each simulator Pi has its own step-by-step deployment guide:

- `sim_hub.txt` — Hub Pi (wolfSSL, certs, hub.json, systemd)
- `sim_solar.txt` — Solar PV inverter (modsim)
- `sim_battery.txt` — Battery storage (batsim)
- `sim_meter.txt` — Bi-directional smart meter (metersim)
- `sim_ev.txt` — EV charger (evsim, OCPP 2.0.1)

## Development

```bash
make test-fast                      # unit tests, no network
make test-integration               # wolfSSL mTLS handshake tests
go test ./tests/                    # 2030.5 discovery + MUP integration
go test ./internal/southbound/...   # Modbus/SunSpec unit tests
make build                          # server + client binaries → bin/
```
