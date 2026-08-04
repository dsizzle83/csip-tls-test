// batsim runs an animated SunSpec Li-Ion battery storage simulator with a
// built-in HTTP API for GUI inspection and test injection.
//
// Usage:
//
//	batsim [-port 5021] [-kwh 10] [-wmax 5000] [-api-port 6021]
//	       [-pack setpoint-zero|cease] [-start-disconnected]
//
// # Modes
//
// DEFAULT (no -pack): the historical demo battery, byte-identical to what this
// command has always served. Models 1 (Common), 120 (Nameplate), 121 (Basic
// Settings), 103 (Three-Phase Inverter/Converter AC), 123 (Immediate
// Controls), 802 (Li-Ion Battery Base).
//
// -pack selects a BENCH BATTERY PACK (sim/southbound/battery_pack.go) instead,
// named for the fail-safe posture a gateway will measure the shape to have —
// lexa-gw internal/topics' FailsafePostureSetpointZero / FailsafePostureCease,
// the value that rides on InventoryRecord.FailsafePosture:
//
//	-pack setpoint-zero   the 704-CAPABLE pack: the models above PLUS
//	                      701/702/703/704/713, M702 declaring FIXED_W, and
//	                      M704 WSet BRIDGED TO PHYSICAL EFFECT — a setpoint
//	                      write commands the pack, the animation ramps measured
//	                      power toward it in both directions, and SoC
//	                      integrates against it.
//	-pack cease           the 704-LESS pack: the legacy models only, with M123
//	                      Conn implemented and DRIVEN — a Conn write opens the
//	                      contactor, measured power collapses in the same tick,
//	                      and a reconnect puts the pack back in service.
//
// Both pack shapes carry the LYING-DEVICE fault layer (sim/southbound/lying.go)
// with the control registers named, so `ack_no_apply` can be armed against
// WSet/WSetEna (setpoint shape) and Conn (both) — the false-Applied shapes the
// gateway's two-sided proofs exist to catch. The historical default carries
// the faults.go vocabulary alone, exactly as it always has.
//
// -start-disconnected opens the contactor BEFORE the listener accepts a
// client, which is the precondition of the pre-disconnected-pack-at-boot row:
// a gateway must not reconnect a pack it has no record of disconnecting.
//
// API (default :6021):
//
//	GET  /state      — JSON snapshot: measurements + battery SoC/SoH/ChaSt + controls
//	                   (+ a "pack" object with commanded/measured power, the 704
//	                   setpoint, the 701 mirror and the lie counters, on a -pack sim)
//	POST /inject     — override fields: {"SoC_pct":85.0,"W_W":-3000.0,"Conn":0,...}
//	                   -pack setpoint-zero also accepts {"WSet_W":-3000} / {"WSetEna":0}
//	POST /control    — {"cmd":"pause"}, {"cmd":"resume"}, {"speed":10.0}
//	POST /fault      — arm/clear a fault (faults.go kinds always; the lying.go
//	                   kinds additionally on a -pack sim)
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
	port := flag.Int("port", 5021, "Modbus TCP port")
	kwh := flag.Float64("kwh", 10, "Energy capacity in kWh")
	wmax := flag.Float64("wmax", 5000, "Max charge/discharge rate in watts")
	apiPort := flag.Int("api-port", 6021, "HTTP API port (0 to disable)")
	pack := flag.String("pack", "", "serve a BENCH BATTERY PACK instead of the historical demo battery, "+
		"named for the fail-safe posture a gateway will measure the shape to have: \"setpoint-zero\" = the "+
		"704-capable pack (adds 701/702/703/704/713, declares FIXED_W, and bridges M704 WSet to physical "+
		"effect); \"cease\" = the 704-less pack (legacy models only, M123 Conn implemented and driven). "+
		"Empty (default) keeps the image and behaviour this command has always served, so no running bench "+
		"changes underneath anyone")
	startDisconnected := flag.Bool("start-disconnected", false, "open the pack's contactor (M123 Conn=0) before "+
		"the listener accepts a client — the pre-disconnected-pack-at-boot fixture, in which a gateway must "+
		"NOT reconnect a pack it holds no record of having disconnected. Requires -pack")
	flag.Parse()

	shape, isPack, err := resolvePackShape(*pack)
	if err != nil {
		log.Fatalf("batsim: %v", err)
	}
	if *startDisconnected && !isPack {
		log.Fatalf("batsim: -start-disconnected needs -pack (the historical demo battery has no cease posture " +
			"to start in; use POST /inject {\"Conn\":0} if you really want the old image opened after start)")
	}

	listenURL := fmt.Sprintf("tcp://0.0.0.0:%d", *port)

	var srv *sim.BatteryServer
	switch {
	case shape == sim.PackShapeSetpoint:
		log.Printf("batsim: starting 704-CAPABLE battery pack on %s (%.0f kWh, WMax=%.0f W) — "+
			"models 1/120/121/103/123/802 + 701/702/703/704/713, WSet bridged to physical effect",
			listenURL, *kwh, *wmax)
		srv, err = sim.NewBatteryPack(listenURL, *kwh, *wmax)
	case shape == sim.PackShapeCease:
		log.Printf("batsim: starting 704-LESS battery pack on %s (%.0f kWh, WMax=%.0f W) — "+
			"models 1/120/121/103/123/802, containment is a physical cease through M123 Conn",
			listenURL, *kwh, *wmax)
		srv, err = sim.NewBatteryPackLegacy(listenURL, *kwh, *wmax)
	default:
		log.Printf("batsim: starting animated battery on %s (%.0f kWh, WMax=%.0f W)", listenURL, *kwh, *wmax)
		srv, err = sim.NewBatteryServer(listenURL, *kwh, *wmax)
	}
	if err != nil {
		log.Fatalf("batsim: %v", err)
	}
	if *startDisconnected {
		srv.StartDisconnected()
		log.Printf("batsim: pack starts DISCONNECTED (M123 Conn=0) — no gateway authored this")
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
					log.Printf("batsim: animation paused")
				case "resume":
					srv.Resume()
					log.Printf("batsim: animation resumed")
				case "reset":
					srv.Resume()
				}
				if cmd.Speed > 0 {
					srv.SetSpeed(cmd.Speed)
					log.Printf("batsim: animation speed set to %.1f×", cmd.Speed)
				}
				return nil
			},
		)
		// Fault injection: POST /fault {"kind":"reject_write"} | {"kind":"wrong_sign"};
		// on a -pack sim additionally the lying.go kinds, e.g.
		// {"kind":"ack_no_apply","fields":["Conn"]}.
		api.SetFaultFn(srv.ApplyFault)
		// Tee logs into the API ring so the dashboard's Logs tab can stream them.
		log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))
	}

	log.Printf("batsim: listening — press Ctrl-C to stop")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("batsim: shutting down")
	srv.Stop()
}

// resolvePackShape resolves the -pack flag. An unrecognised value is an ERROR
// rather than a fall-back to the historical image, for the same reason modsim
// refuses an unrecognised -der-models: a typo must not quietly serve a
// different device than the operator asked for, and on this flag specifically
// the difference between the two spellings is the difference between a pack
// that can be idled and one that has to be disconnected.
func resolvePackShape(v string) (sim.BatteryPackShape, bool, error) {
	switch v {
	case "":
		return "", false, nil
	case string(sim.PackShapeSetpoint), "704", "setpoint":
		return sim.PackShapeSetpoint, true, nil
	case string(sim.PackShapeCease), "legacy", "704-less":
		return sim.PackShapeCease, true, nil
	default:
		return "", false, fmt.Errorf("-pack %q is not one of setpoint-zero (aliases 704, setpoint) "+
			"or cease (aliases legacy, 704-less)", v)
	}
}
