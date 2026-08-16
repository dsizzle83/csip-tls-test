// mbapsdev runs a secure Modbus (mbaps) DEVICE simulator: an mbTLS server
// (internal/mbtls, T06.2) that serves SunSpec register maps over
// lexa-proto/mbap-framed ADUs, so it is a southbound TARGET the lexa-gw
// gateway (or, in development, the T06.4 aggregator emulator) can poll over
// Secure SunSpec Modbus. It reuses the plain sims' animated register world
// (sim/southbound's SolarServer/BatteryServer — see newModel) so its
// register semantics, fault-injection vocabulary, and SunSpec layouts never
// fork from modsim/batsim's.
//
// Usage:
//
//	mbapsdev -listen :8021 -model battery|inverter -wmax 5000 -kwh 10 \
//	         -ca certs/mbaps/dev-ca.pem -cert certs/mbaps/dev-server-cert.pem \
//	         -key certs/mbaps/dev-server-key.pem -api-port 6031 -serial SN-...
//
// Models exposed: Common Model 1, plus 120/121/(122)/103/123 (legacy) and
// 701/702/703/704 (inverter) or 701/704/713/802 (battery) — see sim/southbound's
// solar_adv.go / battery_adv.go.
//
// API (default :6031, see sim/simapi):
//
//	GET  /state    — JSON snapshot: the underlying model's Snapshot() plus
//	                 connected mbaps sessions and armed mbaps-fault state
//	POST /inject   — override fields, same vocabulary as modsim/batsim
//	POST /control  — {"cmd":"pause"|"resume"}, {"speed":N}
//	POST /fault    — arm/clear a fault: the full modsim/batsim register-level
//	                 vocabulary (reject_write, nan_sentinel, latency,
//	                 exception_code, unit_id_confusion, register_tearing, …)
//	                 PLUS three mbaps-transport kinds (drop_session,
//	                 refuse_resume, stall_handshake) — see faults.go
//	GET  /registers — raw Modbus register dump
//	GET  /ws        — WebSocket; pushes /state every 2 s
//	GET  /logs      — SSE log stream
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
	"csip-tls-test/sim/simapi"
	sim "csip-tls-test/sim/southbound"
)

// Device wires together the register-image model, the mbaps-transport fault
// hooks, and the session registry — the three things dispatch.go's
// dispatchSession needs per accepted mbtls.Session.
type Device struct {
	regs       *sim.RegisterMap
	modelFault func([]byte) error // underlying SolarServer/BatteryServer.ApplyFault
	faults     mbapsFaults        // mbaps-transport fault state (faults.go)
	sessions   *sessionRegistry
}

// ApplyFault is the simapi POST /fault handler: mbaps-transport kinds
// (faults.go) are handled here; every other kind (the full modsim/batsim
// register-level vocabulary) delegates to the underlying model.
func (d *Device) ApplyFault(body []byte) error {
	spec, err := parseFaultSpec(body)
	if err != nil {
		return err
	}
	if handled, err := d.faults.apply(spec); handled {
		return err
	}
	return d.modelFault(body)
}

// stateSnapshot is the GET /state payload: the underlying SunSpec model's own
// snapshot (ground-truth registers, same shape modsim/batsim expose) plus
// mbapsdev's own transport-layer state, so a QA driver can see both without a
// packet capture.
type stateSnapshot struct {
	Model    any                 `json:"model"`
	Sessions []sessionInfo       `json:"sessions"`
	Faults   mbapsFaultsSnapshot `json:"mbaps_faults"`
}

func (d *Device) stateSnapshot(modelSnapshot any) stateSnapshot {
	return stateSnapshot{
		Model:    modelSnapshot,
		Sessions: d.sessions.snapshot(),
		Faults:   d.faults.snapshot(),
	}
}

// acceptLoop accepts mbaps sessions until lis is closed. When stall_handshake
// is armed it sleeps the configured delay before each Accept, so the ensuing
// TLS handshake (which Accept performs synchronously — see internal/mbtls)
// starts late from the client's point of view: the client's TCP connect
// succeeds immediately (the kernel completes the three-way handshake
// regardless of userspace accept()), but no ServerHello arrives until the
// delay elapses, exercising the client's connect/handshake timeout.
//
// The flag is only re-checked between Accept calls: arming it while a call
// is already blocked inside Accept (waiting for the next connection) does
// not retroactively delay that in-flight one — only the next. This mirrors
// sim.FaultTCPDrop's "acts on what's next, not retroactively" contract and
// is the documented behavior, not a bug (see integration_test.go).
func (d *Device) acceptLoop(lis *mbtls.Listener) {
	for {
		if armed, delay := d.faults.stallInfo(); armed {
			log.Printf("[mbapsdev] stall_handshake armed: delaying next accept by %s", delay)
			time.Sleep(delay)
		}
		sess, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[mbapsdev] accept: %v", err)
			continue
		}
		go d.dispatchSession(sess)
	}
}

// modelBundle adapts either *sim.SolarServer or *sim.BatteryServer to the
// function-value surface main() needs (CODING_PRINCIPLES §1: inject
// dependencies as functions, not concrete imports at every call site).
type modelBundle struct {
	regs      *sim.RegisterMap
	snapshot  func() any
	inject    func([]byte) error
	registers func() any
	fault     func([]byte) error
	control   func(simapi.ControlCmd) error
	stop      func()
	// base is the embedded *sim.Server of whichever model was built, so
	// post-construction identity overrides (SetFirmwareVersion) reach the
	// register image without newModel growing a parameter per field.
	base *sim.Server
}

// newModel builds the animated SunSpec register world for -model, bound to a
// loopback, OS-assigned port that mbapsdev never advertises or dials: the
// plain-Modbus TCP listener sim.NewSolarServerAdvanced/NewBatteryServerAdvanced
// always bind is reused ONLY for its animation goroutine, fault-injection
// hooks, and Snapshot/Inject/Registers machinery — every mbaps client request
// is served by dispatch.go calling RegisterMap.HandleHoldingRegisters
// directly (see dispatch.go's doc comment), so that internal listener is
// never dialed and exposes no plaintext Modbus surface. This is the "reuse
// SolarServer/BatteryServer register images" T06.3 asks for: Regs is already
// an exported field (no new accessor needed) and ApplyFault/Snapshot/Inject/
// Registers are already public methods.
// defaultMbapsInverterSerial is this sim's own SunSpec Model 1 serial.
//
// It is NOT modsim's "SN-SOLAR-001", and the difference is the point. Both sims
// took that default, so the pairing their own -serial help text names as the
// collision hazard — "modsim plus this mbapsdev" — collided BY DEFAULT, and the
// help put the burden on an operator to notice and pass a flag.
//
// That mattered more than a duplicated string usually does. A gateway keying
// device identity on manufacturer|model|serial dedupes two identical sims into
// one device, and csip-tls-test's own referee now keys two mechanisms on that
// same identity (internal/invariant/i3.go): with a collision it declines to
// pair, which is SAFE but degraded — the ghost de-duplication and the
// lying-peer exemption both switch off. A bench whose default configuration
// silently disables a referee's mechanisms is a bench that reports less than it
// could and says nothing about it.
//
// A distinct default costs nothing: -serial still overrides, the battery model
// is untouched, and any caller that was already passing -serial is unaffected.
const defaultMbapsInverterSerial = "SN-MBAPS-001"

func newModel(kind string, wmax, kwh float64, serial string) (*modelBundle, error) {
	const loopbackAny = "tcp://127.0.0.1:0"
	switch kind {
	case "inverter":
		if serial == "" {
			serial = defaultMbapsInverterSerial
		}
		srv, err := sim.NewSolarServerAdvanced(loopbackAny, wmax, serial)
		if err != nil {
			return nil, fmt.Errorf("mbapsdev: new inverter model: %w", err)
		}
		return &modelBundle{
			regs:      srv.Regs,
			snapshot:  func() any { return srv.Snapshot() },
			inject:    srv.Inject,
			registers: func() any { return srv.Registers() },
			fault:     srv.ApplyFault,
			control:   controlFunc("inverter", srv.Server),
			stop:      srv.Stop,
			base:      srv.Server,
		}, nil
	case "battery":
		srv, err := sim.NewBatteryServerAdvanced(loopbackAny, kwh, wmax)
		if err != nil {
			return nil, fmt.Errorf("mbapsdev: new battery model: %w", err)
		}
		return &modelBundle{
			regs:      srv.Regs,
			snapshot:  func() any { return srv.Snapshot() },
			inject:    srv.Inject,
			registers: func() any { return srv.Registers() },
			fault:     srv.ApplyFault,
			control:   controlFunc("battery", srv.Server),
			stop:      srv.Stop,
			base:      srv.Server,
		}, nil
	default:
		return nil, fmt.Errorf("mbapsdev: unknown -model %q (want inverter|battery)", kind)
	}
}

// controlFunc builds the simapi POST /control handler shared by both models
// (pause/resume/speed act on the embedded *sim.Server identically —
// mirrors modsim/batsim's inline closures).
func controlFunc(label string, base *sim.Server) func(simapi.ControlCmd) error {
	return func(cmd simapi.ControlCmd) error {
		switch cmd.Cmd {
		case "pause":
			base.Pause()
			log.Printf("[mbapsdev] %s: animation paused", label)
		case "resume", "reset":
			base.Resume()
			log.Printf("[mbapsdev] %s: animation resumed", label)
		}
		if cmd.Speed > 0 {
			base.SetSpeed(cmd.Speed)
			log.Printf("[mbapsdev] %s: animation speed set to %.1f×", label, cmd.Speed)
		}
		return nil
	}
}

func main() {
	listen := flag.String("listen", ":8021", "mbaps (secure Modbus/TLS) listen address")
	model := flag.String("model", "inverter", "device model: inverter|battery")
	wmax := flag.Float64("wmax", 5000, "nameplate WMax in watts")
	kwh := flag.Float64("kwh", 10, "battery energy capacity in kWh (battery model only)")
	caFile := flag.String("ca", "certs/mbaps/dev-ca.pem", "CA file trusting the gateway's southbound client cert")
	certFile := flag.String("cert", "certs/mbaps/dev-server-cert.pem", "device server certificate chain (leaf first, full chain — TCP-51)")
	keyFile := flag.String("key", "certs/mbaps/dev-server-key.pem", "device server private key")
	apiPort := flag.Int("api-port", 6031, "HTTP API port (0 to disable)")
	serial := flag.String("serial", "", "SunSpec Model 1 serial number (SN) override for the inverter "+
		"model; empty keeps this sim's own default \""+defaultMbapsInverterSerial+"\", which is distinct "+
		"from modsim's \"SN-SOLAR-001\" so the documented two-sim bench is NOT identity-degraded before "+
		"anyone passes a flag. Ignored for -model battery, which keeps its own default (\"SN-BAT-001\").")
	fwVersion := flag.String("fw-version", "", "SunSpec Model 1 firmware version (Vr) override for either "+
		"model; empty keeps the sim's built-in default. Vr is REQUIRED by the IEEE 1547-2018 profile "+
		"\u00a73.2 Table 16, and a gateway mirroring this device northbound passes it through VERBATIM \u2014 it "+
		"is a fact about the DER's firmware, not about the gateway \u2014 so set it when two co-located sims "+
		"must be distinguishable by firmware as well as by serial.")

	// Bench-only, and only in a -tags keylog build. Point this at the SAME
	// file certify (and, when both are in play, sim/server) writes:
	// wolfssl.OpenKeylog appends, the NSS format is line-oriented, and the
	// analyzer does not care which process wrote which line — so one file
	// ends up holding every captured session's secrets, this device sim's
	// southbound mbaps leg included.
	//
	// The export itself needs no wiring here beyond opening the file:
	// internal/mbtls.Listener.Accept (server.go) already arms
	// wolfssl.EnableTLS13Keylog before every handshake and calls
	// WriteTLS12Keylog after one completes — the same two calls
	// sim/tlsserver.Server's northbound listener makes. Without OpenKeylog
	// ever being called those are no-ops (KeylogPath() == ""), which is why
	// the gateway's southbound TLS 1.3 Certificate message — the one RBAC-011
	// reads the SunSpec role extension from — stayed undecryptable even
	// though the export PATH was already there: nothing had ever opened the
	// file. A TLS 1.3 endpoint derives BOTH directions' traffic secrets as
	// part of its own key schedule, so exporting THIS process's (the device
	// sim's) side is sufficient to decrypt the GATEWAY's Certificate message
	// too — nothing is extracted from the DUT.
	keylogPath := flag.String("keylog", "", "append this device sim's TLS session secrets to an NSS key "+
		"log (requires a -tags keylog build; bench evidence only — see internal/wolfssl/keylog.go)")
	// Bench evidence only. The mbaps profile defaults resumption ON (SunSpecTCP-46
	// SHOULD), so once a gateway has completed its one full handshake for the run,
	// every later southbound session RESUMES — and a resumed TLS 1.3 handshake
	// carries NO Certificate message (RFC 8446 §2.2), so the gateway's client
	// certificate and its SunSpec role extension never reappear on the wire.
	// RBAC-011 reads that extension from the capture and cannot cite it against a
	// resumed session. This flag makes every dial a FULL mTLS handshake — the
	// mbaps equivalent of gridsim's -no-tickets — so the role is on the wire on
	// every poll cycle, not only after a manual bounce. Leave it OFF for
	// resumption-behaviour testing (TCP-46); turn it ON for the conformance
	// campaign so RBAC-011 is citable by construction.
	noTickets := flag.Bool("no-tickets", false, "issue no TLS session tickets and keep no session cache, so "+
		"every gateway dial is a FULL mTLS handshake with the client certificate (and its SunSpec role "+
		"extension) on the wire — conformance evidence runs; default allows resumption (TCP-46)")
	flag.Parse()

	// wolfSSL_Init: process-global C state, exactly once per process
	// (CLAUDE.md invariant; mirrors sim/server/main.go).
	wolfssl.Init()
	defer wolfssl.Cleanup()

	// Fail loudly rather than serving a run whose southbound capture nobody
	// can decrypt. A silent no-op here is discovered at analysis time — a
	// WARN on RBAC-011 with no obvious cause — when the run is already stale
	// and the bench has moved on. Mirrors sim/server/main.go's -keylog gate.
	if *keylogPath != "" {
		if err := wolfssl.OpenKeylog(*keylogPath); err != nil {
			log.Fatalf("-keylog %s: %v (a keylog build is required: make mbapsdev-keylog)", *keylogPath, err)
		}
		defer wolfssl.CloseKeylog()
		log.Printf("mbapsdev: TLS session secrets APPEND to %s — bench evidence build", *keylogPath)
	}

	if *serial != "" && *model != "inverter" {
		log.Printf("mbapsdev: -serial is ignored for -model %s (only -model inverter supports the "+
			"override); keeping the default battery serial", *model)
	}
	mb, err := newModel(*model, *wmax, *kwh, *serial)
	if err != nil {
		log.Fatalf("mbapsdev: %v", err)
	}
	if err := mb.base.SetFirmwareVersion(*fwVersion); err != nil {
		log.Fatalf("mbapsdev: %v", err)
	}
	if *fwVersion != "" {
		log.Printf("mbapsdev: SunSpec Model 1 firmware version (Vr) override %q", *fwVersion)
	}

	// Server certs need no role extension (TCP-28) — mbtls.DefaultServerProfile
	// presents whatever leaf/chain -cert points at as-is. mbapsdev does not
	// inspect the gateway's client-cert role (AuthZ is the gateway's job,
	// dispatch.go's doc comment); mbtls.Listen still unconditionally demands
	// SOME client certificate (RequireClientCert — TCP-11/13/48).
	profile := mbtls.DefaultServerProfile(*caFile, *certFile, *keyFile)
	if *noTickets {
		// See mbtls.Listen: SessionCache=false pulls every resumption lever, so
		// every dial is a full mTLS handshake.
		profile.SessionCache = false
	}
	lis, err := mbtls.Listen(*listen, profile)
	if err != nil {
		log.Fatalf("mbapsdev: mbtls.Listen(%s): %v", *listen, err)
	}
	if *noTickets {
		log.Printf("mbapsdev: -no-tickets — resumption disabled; every gateway dial is a FULL mTLS handshake " +
			"(client certificate on the wire for RBAC-011)")
	}
	log.Printf("mbapsdev: %s device serving mbaps on %s (wmax=%.0fW)", *model, *listen, *wmax)

	d := &Device{
		regs:       mb.regs,
		modelFault: mb.fault,
		sessions:   newSessionRegistry(),
	}

	if *apiPort != 0 {
		apiAddr := fmt.Sprintf(":%d", *apiPort)
		api := simapi.New(
			apiAddr,
			func() any { return d.stateSnapshot(mb.snapshot()) },
			mb.inject,
			mb.registers,
			mb.control,
		)
		api.SetFaultFn(d.ApplyFault)
		// Tee logs into the API ring so the dashboard's Logs tab can stream
		// them, exactly like the plain sims.
		log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))
	}

	go d.acceptLoop(lis)

	log.Printf("mbapsdev: listening — press Ctrl-C to stop")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("mbapsdev: shutting down")
	_ = lis.Close()
	mb.stop()
}
