// modsim runs an animated SunSpec PV inverter simulator with a built-in HTTP
// API for GUI inspection and test injection.
//
// Usage:
//
//	modsim [-port 5020] [-bind ""] [-wmax 5000] [-api-port 6020] [-cloud-pct 0] [-serial SN-...]
//	       [-advanced | -der-models legacy|advanced|full] [-base 40000] [-mangle] [-protofault]
//
// Models exposed by the default (legacy) image: 1 (Common), 120 (Nameplate),
// 121 (Basic Settings), 122 (Extended Status), 103 (Three-Phase Inverter),
// 123 (Immediate Controls).
//
// -advanced (= -der-models advanced) adds the IEEE 1547-2018 DER models
// 701/702/703/704 and the curve models 705/706/711/712.
//
// -der-models full adds, on top of those, the trip models 707/708/709/710
// (DERTripLV/HV/LF/HF) carrying Category III default trip curves — see
// sim/southbound/trip1547.go. It is opt-in because it lengthens the SunSpec
// model chain every existing scenario walks.
//
// API (default :6020):
//
//	GET  /state      — JSON snapshot of all decoded measurements + controls
//	POST /inject     — override fields: {"W_W":4500.0,"Conn":0,"Cloud_pct":70,...}
//	                   also: {"insert_model":{"id":65000,"len":4}} / {"clear_insert_model":true}
//	                   (sim/southbound/modelsplice.go); {"unimplemented":[{"addr":40190,
//	                   "type":"int16"}]} / {"clear_unimplemented":true} (sim/southbound/sentinel.go)
//	POST /control    — {"cmd":"pause"}, {"cmd":"resume"}, {"speed":10.0}
//	POST /fault      — arm/clear a fault; also: {"kind":"relocate","base":N} / {"clear":true}
//	                   (sim/southbound/relocate.go, always available); {"kind":"exception_code",
//	                   "code":1,"on_fc":3,"on_addr":[a,b]} (targeted scoping of the existing
//	                   exception_code fault, sim/southbound/exception_target.go, always available);
//	                   {"kind":"segment_response","split_after":N} / {"kind":"short_response",
//	                   "truncate_bytes":N} (sim/southbound/protorelay.go, needs -protofault)
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
	"lexa-proto/sunspec"
)

func main() {
	port := flag.Int("port", 5020, "Modbus TCP port")
	bind := flag.String("bind", "", "listener bind address (empty = 0.0.0.0, all interfaces); set to pin "+
		"the Modbus/TCP listener to one network segment, e.g. -bind 192.168.0.188 on a split WAN/LAN bench "+
		"— mirrors mbapsdev's -listen, but as a bare host since -port is already separate here")
	wmax := flag.Float64("wmax", 5000, "Nameplate WMax in watts")
	apiPort := flag.Int("api-port", 6020, "HTTP API port (0 to disable)")
	advanced := flag.Bool("advanced", false, "serve the IEEE 1547-2018 7xx DER models "+
		"(701/702/703/704/705/706/711/712) for advanced-DER QA scenarios")
	derModels := flag.String("der-models", "", "which DER model set to serve, overriding -advanced: "+
		"\"legacy\" = 1/103/120/121/122/123 only; \"advanced\" = plus 701/702/703/704/705/706/711/712 "+
		"(identical to -advanced); \"full\" = plus the IEEE 1547-2018 trip models 707/708/709/710 "+
		"(DERTripLV/HV/LF/HF) with Category III default trip curves. Empty follows -advanced, which "+
		"keeps every existing bench invocation serving the register image it has always served — the "+
		"trip models are OPT-IN because adding them lengthens the SunSpec chain every scenario walks")
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
	protofault := flag.Bool("protofault", false, "interpose a second, independent framing-level relay "+
		"(sim/southbound/protorelay.go), enabling segment_response and short_response — kept separate from "+
		"-mangle's relay for change isolation. OFF by default, mirroring -mangle: a shared live bench is never "+
		"silently reframed. Cannot be combined with -mangle in this build")
	baseFlag := flag.Int("base", int(sunspec.SunSpecBase), "SunSpec map starting register address; the three "+
		"standard bases are 0, 40000 (default) and 50000 — any other value (e.g. 40001) deliberately serves a "+
		"noncompliant map for ERR-1 testing. Equivalent to POST /fault {\"kind\":\"relocate\",\"base\":N} issued "+
		"at startup before any client can dial in; see sim/southbound/relocate.go")
	flag.Parse()

	if *mangle && *protofault {
		log.Fatalf("modsim: -mangle and -protofault cannot both be set (each interposes its own relay; " +
			"combining them is not yet supported)")
	}

	// With -mangle OR -protofault the device binds a loopback port and the
	// relay takes the public one, so a client dials exactly the address it
	// always did and the interposition is invisible until a fault is armed.
	// With NEITHER, nothing about the sim's listening behaviour changes.
	listenURL := "tcp://" + listenAddr(*bind, *port)
	upstreamAddr := ""
	if *mangle || *protofault {
		upstreamAddr = fmt.Sprintf("127.0.0.1:%d", *port+10000)
		listenURL = "tcp://" + upstreamAddr
	}

	models, err := resolveDERModels(*derModels, *advanced)
	if err != nil {
		log.Fatalf("modsim: %v", err)
	}

	var srv *sim.SolarServer
	switch models {
	case modelsFull:
		log.Printf("modsim: starting FULL (7xx + 707-710 trip) PV inverter on %s (WMax=%.0f W)", listenURL, *wmax)
		srv, err = sim.NewSolarServerTrip(listenURL, *wmax, *serial)
	case modelsAdvanced:
		log.Printf("modsim: starting ADVANCED (7xx) PV inverter on %s (WMax=%.0f W)", listenURL, *wmax)
		srv, err = sim.NewSolarServerAdvanced(listenURL, *wmax, *serial)
	default:
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

	// ── Protocol-fault verbs (sim/southbound: relocate.go, exception_target.go,
	// sentinel.go, modelsplice.go) — layered on top of srv.Regs' existing hooks
	// from OUT HERE rather than inside solar.go/solar_adv.go, so none of them
	// touch that construction path. Each is a pure pass-through when unused —
	// see sim/southbound/faultlayers_noop_test.go for the byte-identity pin.
	reloc := sim.NewRelocator(srv.Regs)
	if *baseFlag != int(sunspec.SunSpecBase) {
		if *baseFlag < 0 || *baseFlag > 0xFFFF {
			log.Fatalf("modsim: -base %d is not a valid Modbus register address", *baseFlag)
		}
		reloc.Relocate(uint16(*baseFlag))
		log.Printf("modsim: SunSpec map relocated to base %d at startup", *baseFlag)
	}

	targetedExc := sim.NewTargetedException()
	srv.Regs.OnRead = targetedExc.WrapOnRead(srv.Regs.OnRead)
	srv.Regs.OnWriteError = targetedExc.OnWriteError // unset by every solar variant; safe to assign directly

	sentinels := sim.NewSentinelInjector(srv.Regs)
	splicer := sim.NewModelSplicer(srv.Regs)

	var mangler *sim.Mangler
	if *mangle {
		mangler, err = sim.NewMangler(listenAddr(*bind, *port), upstreamAddr)
		if err != nil {
			log.Fatalf("modsim: %v", err)
		}
		defer mangler.Close()
		log.Printf("modsim: MBAP wire mangler interposed on :%d → %s (framing-level fault kinds enabled)",
			*port, upstreamAddr)
	}

	var protoRelay *sim.ProtoRelay
	if *protofault {
		protoRelay, err = sim.NewProtoRelay(listenAddr(*bind, *port), upstreamAddr)
		if err != nil {
			log.Fatalf("modsim: %v", err)
		}
		defer protoRelay.Close()
		log.Printf("modsim: proto-fault relay interposed on :%d → %s (segment_response, short_response enabled)",
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
		// POST /inject: insert_model (modelsplice.go) and unimplemented
		// (sentinel.go) are claimed here, ahead of the classic field-override
		// path; a body carrying neither key falls through to srv.Inject
		// completely unchanged.
		injectFn := func(body []byte) error {
			if handled, err := sentinels.ApplyInject(body); handled {
				return err
			}
			if handled, err := splicer.ApplyInject(body); handled {
				return err
			}
			return srv.Inject(body)
		}
		api := simapi.New(
			apiAddr,
			func() any { return srv.Snapshot() },
			injectFn,
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
		// One endpoint, several layers, checked in order:
		//
		//  1. relocate (always available — moves register CONTENT, no relay)
		//  2. targeted exception_code scoping (always available — layered on
		//     srv.Regs' OnRead/OnWriteError hooks; a plain, untargeted
		//     exception_code body is deliberately left unhandled here so it
		//     falls all the way through to faultController unchanged)
		//  3. the proto-fault relay (segment_response, short_response) — offered
		//     when -protofault interposed it; refused BY NAME (not silently
		//     passed through as "unknown kind") when it was not, so a scenario
		//     can report SKIP-with-reason instead of mistaking "we never asked"
		//     for "the gateway passed"
		//  4. the MBAP wire mangler (wire.go) — same offered/refused-by-name
		//     pattern as -protofault, for its own five kinds
		//  5. the device-level faultController (faults.go), the original
		//     fallback this chain has always ended at
		api.SetFaultFn(func(body []byte) error {
			if handled, err := reloc.ApplyFault(body); handled {
				return err
			}
			if handled, err := targetedExc.ApplyFault(body); handled {
				return err
			}
			if protoRelay != nil {
				if handled, err := protoRelay.ApplyFault(body); handled {
					return err
				}
			} else if sim.ProtoFaultRequested(body) {
				return sim.ErrNoProtoRelay
			}
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

// derModelSet names the register images modsim can serve.
type derModelSet int

const (
	modelsLegacy derModelSet = iota
	modelsAdvanced
	modelsFull
)

// listenAddr forms the "host:port" pair modsim's Modbus/TCP listener (and,
// when -mangle/-protofault is set, the public-facing relay) binds to.
// bind=="" is -bind's default and preserves the historical wildcard
// behavior — the sim serves 0.0.0.0, all interfaces. A non-empty bind pins
// the listener to one address, e.g. for the WAN/LAN split bench where a
// southbound sim must be reachable on exactly one network segment.
func listenAddr(bind string, port int) string {
	if bind == "" {
		bind = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", bind, port)
}

// resolveDERModels resolves -der-models against the older -advanced boolean.
//
// The two knobs coexist rather than one replacing the other because -advanced
// is written into bench-sims-up.sh, several Makefile targets and every runbook
// in docs/. Silently redefining what it serves would have changed the register
// image on a shared bench without anyone editing a command line, which is
// exactly the kind of change that gets discovered as a mysterious test failure
// three days later. An unrecognised -der-models is an error rather than a
// fall-back to the default, for the same reason: a typo must not quietly serve
// a different device than the operator asked for.
func resolveDERModels(flagValue string, advanced bool) (derModelSet, error) {
	switch flagValue {
	case "":
		if advanced {
			return modelsAdvanced, nil
		}
		return modelsLegacy, nil
	case "legacy":
		return modelsLegacy, nil
	case "advanced":
		return modelsAdvanced, nil
	case "full":
		return modelsFull, nil
	default:
		return modelsLegacy, fmt.Errorf("-der-models %q is not one of legacy, advanced, full", flagValue)
	}
}
