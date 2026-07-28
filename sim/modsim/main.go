// modsim runs an animated SunSpec PV inverter simulator with a built-in HTTP
// API for GUI inspection and test injection.
//
// Usage:
//
//	modsim [-port 5020] [-wmax 5000] [-api-port 6020] [-cloud-pct 0] [-serial SN-...]
//
// Models exposed: 1 (Common), 120 (Nameplate), 121 (Basic Settings),
// 122 (Extended Status), 103 (Three-Phase Inverter), 123 (Immediate Controls).
//
// API (default :6020):
//
//	GET  /state      — JSON snapshot of all decoded measurements + controls
//	POST /inject     — override fields: {"W_W":4500.0,"Conn":0,"Cloud_pct":70,...}
//	POST /control    — {"cmd":"pause"}, {"cmd":"resume"}, {"speed":10.0}
//	GET  /registers  — raw Modbus register dump
//	GET  /ws         — WebSocket; pushes /state every 2 s
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"csip-tls-test/sim/simapi"
	"csip-tls-test/sim/southbound"
)

func main() {
	port := flag.Int("port", 5020, "Modbus TCP port")
	wmax := flag.Float64("wmax", 5000, "Nameplate WMax in watts")
	apiPort := flag.Int("api-port", 6020, "HTTP API port (0 to disable)")
	advanced := flag.Bool("advanced", false, "serve the IEEE 1547-2018 7xx DER models "+
		"(701/702/704/705/706/711/712) for advanced-DER QA scenarios")
	cloudPct := flag.Float64("cloud-pct", 0, "initial cloud cover percent (0=clear sky .. 100=full overcast); "+
		"deterministically attenuates the running irradiance and is injectable live via POST /inject {\"Cloud_pct\":N}")
	serial := flag.String("serial", "", "SunSpec Model 1 serial number (SN) override; empty keeps the "+
		"default \"SN-SOLAR-001\" — set this so two co-located sims (e.g. this modsim plus a mbapsdev "+
		"-model inverter) present distinct device identity to a downstream gateway that keys identity "+
		"on manufacturer|model|serial")
	fwVersion := flag.String("fw-version", "", "SunSpec Model 1 firmware version (Vr) override; empty keeps "+
		"the sim's built-in default. Vr is REQUIRED by the IEEE 1547-2018 profile \u00a73.2 Table 16, and a "+
		"gateway mirroring this device northbound passes it through VERBATIM \u2014 it is a fact about the DER's "+
		"firmware, not about the gateway \u2014 so set it when two co-located sims must be distinguishable by "+
		"firmware as well as by serial")
	mangle := flag.Bool("mangle", false, "interpose the MBAP wire mangler (sim/southbound/wire.go): the Modbus "+
		"server binds loopback and a framing-level relay binds -port instead, enabling the wire-lie fault kinds "+
		"(truncate_response, mbap_length_lie, wrong_unit_id, txn_id_swap, stack_responses) that cannot be "+
		"expressed above the framing layer. OFF by default — a shared live bench is never silently reframed")
	flag.Parse()

	// With -mangle the device binds a loopback port and the mangler takes the
	// public one, so a client dials exactly the address it always did and the
	// interposition is invisible until a wire fault is armed. Without it,
	// nothing about the sim's listening behaviour changes.
	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)
	upstreamAddr := ""
	if *mangle {
		upstreamAddr = fmt.Sprintf("127.0.0.1:%d", *port+10000)
		listenURL = "tcp://" + upstreamAddr
	}

	var srv *sim.SolarServer
	var err error
	if *advanced {
		log.Printf("modsim: starting ADVANCED (7xx) PV inverter on %s (WMax=%.0f W)", listenURL, *wmax)
		srv, err = sim.NewSolarServerAdvanced(listenURL, *wmax, *serial)
	} else {
		log.Printf("modsim: starting animated PV inverter on %s (WMax=%.0f W)", listenURL, *wmax)
		srv, err = sim.NewSolarServer(listenURL, *wmax, *serial)
	}
	if *serial != "" {
		log.Printf("modsim: SunSpec Model 1 serial override %q", *serial)
	}
	if err != nil {
		log.Fatalf("modsim: %v", err)
	}
	if err := srv.SetFirmwareVersion(*fwVersion); err != nil {
		log.Fatalf("modsim: %v", err)
	}
	if *fwVersion != "" {
		log.Printf("modsim: SunSpec Model 1 firmware version (Vr) override %q", *fwVersion)
	}

	var mangler *sim.Mangler
	if *mangle {
		mangler, err = sim.NewMangler(fmt.Sprintf("0.0.0.0:%d", *port), upstreamAddr)
		if err != nil {
			log.Fatalf("modsim: %v", err)
		}
		defer mangler.Close()
		log.Printf("modsim: MBAP wire mangler interposed on :%d → %s (framing-level fault kinds enabled)",
			*port, upstreamAddr)
	}

	// Seed the initial cloud cover (0 = clear = today's byte-identical behavior);
	// srv.Inject already handles the live "Cloud_pct" key, so no wrapper is needed.
	srv.SetCloud(*cloudPct / 100)
	if *cloudPct != 0 {
		log.Printf("modsim: initial cloud cover %.0f%%", *cloudPct)
	}

	if *apiPort != 0 {
		apiAddr := fmt.Sprintf(":%d", *apiPort)
		api := simapi.New(
			apiAddr,
			func() any { return srv.Snapshot() },
			srv.Inject,
			func() any { return srv.Registers() },
			func(cmd simapi.ControlCmd) error {
				switch cmd.Cmd {
				case "pause":
					srv.Pause()
					log.Printf("modsim: animation paused")
				case "resume":
					srv.Resume()
					log.Printf("modsim: animation resumed")
				case "reset":
					srv.Resume()
				}
				if cmd.Speed > 0 {
					srv.SetSpeed(cmd.Speed)
					log.Printf("modsim: animation speed set to %.1f×", cmd.Speed)
				}
				return nil
			},
		)
		// Fault injection: POST /fault {"kind":"ack_before_effect","delay_s":30}.
		// One endpoint, three layers. A wire-level kind is offered to the mangler
		// first when one is interposed; when one is NOT, it is refused by NAME
		// rather than falling through to the device controller, which would call
		// it an unknown kind and hide the real reason (the sim was started
		// without -mangle). A scenario can then report SKIP-with-reason instead
		// of mistaking "we never asked" for "the gateway passed".
		api.SetFaultFn(func(body []byte) error {
			if mangler != nil {
				if handled, err := mangler.ApplyFault(body); handled {
					return err
				}
			} else if sim.WireFaultRequested(body) {
				return sim.ErrNoMangler
			}
			return srv.ApplyFault(body)
		})
		// Tee logs into the API ring so the dashboard's Logs tab can stream them.
		log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))
	}

	log.Printf("modsim: listening — press Ctrl-C to stop")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("modsim: shutting down")
	srv.Stop()
}
