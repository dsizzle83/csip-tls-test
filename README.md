# csip-tls-test

CSIP / IEEE 2030.5 mTLS client and server, built on wolfSSL.

The **client** is the product — it runs on DER devices (Raspberry Pi
during development, NXP i.MX 93 in production) and talks to utility
grid management servers using the cipher and protocol mandated by CSIP
§5.2.1.1. The **server** in this repo is a test fixture that simulates
a utility server, used to validate the client during development.

## Quick start

```bash
# First-time setup (auto-generates test certs)
make test

# Iterate on the client (fast feedback loop, sub-second)
make test-fast

# Full integration with real TLS handshakes
make test-integration

# Build deployable binaries
make build

# Validate against real hardware (Pi)
make smoke-pi
```

## Layout

```
csip-tls-test/
├── Makefile
├── go.mod
├── client/main.go              ← Thin client binary (deployed to Pi)
├── server/main.go              ← Thin server binary (runs on dev machine)
├── internal/
│   ├── wolfssl/                ← Shared cgo bridge — the only package
│   │                             that touches C. Both tlsclient and
│   │                             tlsserver import this.
│   ├── tlsclient/              ← Client logic (the product)
│   │   ├── client.go               Dial / Get / Close / Free
│   │   ├── request.go              Pure-Go HTTP request building
│   │   ├── response.go             Pure-Go HTTP response parsing
│   │   ├── dcap.go                 DCAP fetch + XML unmarshal
│   │   ├── parsing_test.go         Unit tests (no network)
│   │   ├── helpers_test.go         TestMain + in-process server fixture
│   │   ├── client_test.go          Integration tests (build tag)
│   │   └── testdata/certs/         Test cert fixtures
│   └── tlsserver/              ← Test fixture server
│       ├── server.go
│       ├── handlers.go             Pure-Go HTTP routing
│       ├── handlers_test.go        Unit tests + golden file
│       ├── helpers_test.go         TestMain + startTestServer
│       ├── testclient_test.go      Per-test wolfSSL client (for negative tests)
│       ├── server_test.go          Integration tests (build tag)
│       └── testdata/certs/         Test cert fixtures
└── scripts/
    ├── gen-test-certs.sh       Generates test cert fixtures
    └── smoke-pi.sh             Manual hardware validation
```

## Key design decisions

**The cgo bridge is shared.** Both client and server import
`internal/wolfssl`, which is the only package that touches C.
This eliminates the maintenance trap of having two slightly-divergent
copies of the same wolfSSL wrapper.

**Tests are layered.** Unit tests cover request building, response
parsing, and DCAP XML unmarshaling — pure Go, no network, runs in
milliseconds. Integration tests cover the full handshake stack —
cgo, real TLS, runs against an in-process server, completes in a
fraction of a second per test. Hardware validation is a separate
manual smoke test, NOT part of `go test`.

**Why no automated end-to-end Pi tests.** Baking the Pi into the test
framework would require Pi availability for every `go test` run, SSH
credential handling in test code, and identical hardware setup for
every developer. The in-process integration tests catch ~95% of bugs
at <1% of the friction. The `make smoke-pi` script catches the
remaining 5% (cross-compilation, real-network behavior) when run
deliberately.

**Negative tests are first-class.** Both packages have table-driven
rejection tests proving the server rejects unauthenticated clients,
clients with wrong CAs, and clients offering non-CSIP ciphers — and
proving the client rejects servers with wrong certs and refuses to
negotiate non-CSIP ciphers. Each rejection scenario is one row in a
struct table. Adding a new conformance requirement = adding one row.

**`TestMain` is mandatory.** `wolfSSL_Init` is process-global C state
and double-init is undefined behavior. Both `tlsclient` and `tlsserver`
have `TestMain` functions that call `wolfssl.Init()` exactly once per
test binary.

## SunSpec Modbus simulator (Docker)

The simulator exposes a SunSpec-compliant Modbus TCP server with the same
register layout as the inverter package's in-process unit tests. Use it to
develop and validate southbound Modbus code without physical hardware.

**Models exposed** (starting at Modbus address 40001):

| Model | Description |
|-------|-------------|
| 1     | Common — manufacturer, model, serial |
| 121   | Basic Settings — WMax nameplate rating |
| 103   | Three-Phase Inverter — live measurements |
| 123   | Immediate Controls — Conn, WMaxLimPct |

**Initial measurement values:** W = 3000 W, V = 240.0 V, Hz = 60.00 Hz,
PF = 0.968, TmpCab = 35.0 °C, DCV = 380.0 V, DCW = 3200 W, St = 4 (MPPT).
Control writes to Model 123 are accepted and held immediately.

### Prerequisites

- Docker Desktop (Windows) or Docker Engine (Linux) installed and running.
- Port 5020 free on the host.

### Build and run

```bash
# Build the Docker image (first time or after code changes).
make modsim-image

# Start the simulator in the background.
make modsim-run

# Verify it is responding — read the SunS header at register 40001.
# mbpoll is included in the image; this runs it inside the container.
docker exec modsim mbpoll -t 3:hex -r 40001 -c 2 -1 localhost 5020
# Expected output: [40001]: 0x5375  [40002]: 0x6E53  (ASCII "SunS")

# Stop when done.
make modsim-stop
```

Override defaults at build/run time:

```bash
# 7600 W nameplate, port 5021.
make modsim-run MODSIM_PORT=5021 MODSIM_WMAX=7600

# Or run directly without Docker (for quick local iteration):
make build-modsim
./bin/modsim -port 5020 -wmax 5000
```

### Inspecting live register values

mbpoll uses 1-based register addresses (Modbus convention), so add 1 to any
0-based address from the Go code.

```bash
# Read 4 registers at 40001 (1-based) — SunS header + first model ID+len.
# Expected: 0x5375 0x6E53 0x0001 0x0042  ("SunS", Model-1, len=66)
docker exec modsim mbpoll -t 3:hex -r 40001 -c 4 -1 localhost 5020

# Model 103 AC power register W is at 0-based offset 12 within its data block.
# Data block starts at 0-based 40104 (= 40103 1-based + 1 = 40104 1-based).
# W is at 0-based 40104+12 = 40116, i.e. 1-based 40117.
# In practice: start of model block varies — use the layout table in sim.go.
docker exec modsim mbpoll -t 3 -r 40117 -c 2 -1 localhost 5020
```

### Connecting a Go client to the simulator

```go
import (
    "time"
    "csip-tls-test/internal/southbound/inverter"
)

inv, err := inverter.New("tcp://localhost:5020", 2*time.Second, 1)
if err != nil { log.Fatal(err) }
defer inv.Close()

m, _ := inv.ReadMeasurements()
fmt.Printf("W=%.0f V=%.1f Hz=%.2f\n", m.W, m.V, m.Hz)
```

---

## Deploying to the Raspberry Pi

The client binary is what gets deployed. The Pi needs:

1. **The compiled binary** — either cross-compiled from WSL with
   `aarch64-linux-gnu-gcc` or natively built on the Pi.
2. **wolfSSL installed** — the same version as on WSL, with the same
   configure flags. The Pi already has this from earlier setup.
3. **The production cert vault** — `ca-cert.pem`, `client-cert.pem`,
   and `client-key.pem` in `/home/dmitri/csip-tls-test/certs/`. These
   were generated from the offline CA on WSL and SCP'd to the Pi.

Then:

```bash
# On the Pi
~/csip-tls-test/bin/client \
    -server 192.168.0.188:11111 \
    -ca   ~/csip-tls-test/certs/ca-cert.pem \
    -cert ~/csip-tls-test/certs/client-cert.pem \
    -key  ~/csip-tls-test/certs/client-key.pem
```

Or use `make smoke-pi` from WSL to do the whole thing in one shot.

---

## Pi → desktop Modbus simulator

Use this to run the southbound Go stack on the Pi while the SunSpec simulator
runs in Docker on your desktop. This validates the Modbus client over a real
TCP network before connecting to inverter hardware.

### Network topology

```
Raspberry Pi (192.168.0.81)
  └── TCP :5020 ──► Windows desktop (192.168.0.x)
                      └── Docker container running modsim
```

Docker Desktop for Windows publishes the container port to the Windows host
IP. WSL2 also routes to that IP. The Pi just needs the desktop's LAN address.

### Step 1 — start the simulator on the desktop

```bash
# In WSL2 on the desktop:
make modsim-run

# Find your Windows host LAN IP (not the WSL IP):
# Run in PowerShell on Windows:  ipconfig | findstr "IPv4"
# Typically 192.168.0.x on a home network.
```

If Docker Desktop is not in use and you are running Docker inside WSL2
directly, the container port is reachable at the WSL2 IP instead:

```bash
# WSL2 IP (run in WSL2):
hostname -I | awk '{print $1}'
```

### Step 2 — cross-compile and deploy the client to the Pi

The southbound packages are pure Go (no cgo), so they cross-compile from WSL
without any Pi-side toolchain.

```bash
# In WSL2 on the desktop — cross-compile and SCP to Pi in one shot:
make deploy-modsim-client-pi

# Or, if DESKTOP_IP auto-detection gets the WSL IP instead of the Windows IP:
make deploy-modsim-client-pi DESKTOP_IP=192.168.0.X
```

This cross-compiles `cmd/modsim-client` for `linux/arm64`, SCPs the binary to
`~/csip-tls-test/bin/modsim-client` on the Pi, and prints the run command.

### Step 3 — run the connection check on the Pi

```bash
# SSH into the Pi:
ssh dmitri@192.168.0.81

# One-shot read (replace IP with your Windows LAN IP):
~/csip-tls-test/bin/modsim-client -url tcp://192.168.0.50:5020
```

Expected output:

```
W=  3000  VA=  3100  VAr=   780  PF=0.968  V=240.0  Hz=60.00  DCV=380.0  DCW= 3200  TmpCab=35.0°C  Connected=true   Energized=true
```

Poll continuously (Ctrl-C to stop):

```bash
~/csip-tls-test/bin/modsim-client -url tcp://192.168.0.50:5020 -poll 5s
```

Apply controls from the Pi:

```bash
# Disconnect the inverter:
~/csip-tls-test/bin/modsim-client -url tcp://192.168.0.50:5020 -connect=false

# Reconnect:
~/csip-tls-test/bin/modsim-client -url tcp://192.168.0.50:5020 -connect=true

# Limit export to 2500 W, then poll to watch the register hold:
~/csip-tls-test/bin/modsim-client -url tcp://192.168.0.50:5020 -exp-lim-w 2500 -poll 3s
```

### Step 3 (shortcut) — one-command smoke test from WSL

```bash
# Prerequisites: simulator already running (make modsim-run).
make smoke-modbus-pi

# Override desktop IP if needed:
make smoke-modbus-pi DESKTOP_IP=192.168.0.50
```

`smoke-modbus-pi` cross-compiles, deploys, and runs one read — all from WSL.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `connection refused` on Pi | Desktop firewall blocking 5020 | Allow TCP 5020 inbound in Windows Defender Firewall |
| `connection refused` on Pi | Docker not forwarding | Check `docker ps` shows `0.0.0.0:5020->5020/tcp` |
| `no SunS header` error | Connected to wrong host/port | Verify IP and that modsim is running (`docker ps`) |
| Reads return all zeros | Wrong unit ID | Pass unitID=1 (default for this simulator) |
| Pi can ping desktop but TCP fails | WSL2 port not forwarded to Windows | Use Windows host IP, not WSL IP; or add a `netsh` portproxy rule |

**WSL2 → Windows port forward** (if needed — Docker Desktop usually handles this automatically):

```powershell
# Run in PowerShell as Administrator on Windows:
netsh interface portproxy add v4tov4 `
    listenport=5020 listenaddress=0.0.0.0 `
    connectport=5020 connectaddress=127.0.0.1
```
