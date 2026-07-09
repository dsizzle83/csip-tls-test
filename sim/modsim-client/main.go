// modsim-client connects to a SunSpec Modbus TCP server, reads measurements
// and device status, and optionally applies DER controls. Designed as the
// Pi-side tool for validating southbound Modbus connectivity against the
// desktop simulator (cmd/modsim) before connecting to real inverter hardware.
//
// Usage:
//
//	modsim-client -url tcp://HOST:5020 [flags]
//
// Examples:
//
//	# Single measurement read:
//	modsim-client -url tcp://192.168.0.50:5020
//
//	# Poll every 5 seconds until Ctrl-C:
//	modsim-client -url tcp://192.168.0.50:5020 -poll 5s
//
//	# Disconnect the inverter, then reconnect:
//	modsim-client -url tcp://192.168.0.50:5020 -connect=false
//	modsim-client -url tcp://192.168.0.50:5020 -connect=true
//
//	# Limit export power to 2500 W:
//	modsim-client -url tcp://192.168.0.50:5020 -exp-lim-w 2500
//
//	# Limit then poll to watch the register hold:
//	modsim-client -url tcp://192.168.0.50:5020 -exp-lim-w 3000 -poll 3s
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"csip-tls-test/internal/southbound/inverter"
	model "lexa-proto/csipmodel"
)

func main() {
	url := flag.String("url", "", "Modbus server URL, e.g. tcp://192.168.0.50:5020 (required)")
	unit := flag.Uint("unit", 1, "Modbus unit/slave ID (1 for most standalone inverters)")
	timeout := flag.Duration("timeout", 3*time.Second, "Per-request Modbus timeout")
	poll := flag.Duration("poll", 0, "If >0, read measurements repeatedly at this interval until Ctrl-C")

	// Control flags — applied once before the first measurement read.
	connectFlag := flag.String("connect", "", "Set OpModConnect: true or false")
	expLimW := flag.Float64("exp-lim-w", 0, "Set export power limit in watts (0 = no change)")

	flag.Parse()

	if *url == "" {
		fmt.Fprintln(os.Stderr, "error: -url is required")
		flag.Usage()
		os.Exit(1)
	}

	inv, err := inverter.New(*url, *timeout, uint8(*unit))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer inv.Close()

	log.Printf("connected to %s (unit %d)", *url, *unit)

	// ── Apply controls (if requested) ────────────────────────────────────────
	ctrl := model.DERControlBase{}
	dirty := false

	if *connectFlag != "" {
		switch *connectFlag {
		case "true", "1", "yes":
			b := true
			ctrl.OpModConnect = &b
		case "false", "0", "no":
			b := false
			ctrl.OpModConnect = &b
		default:
			log.Fatalf("-connect must be true or false, got %q", *connectFlag)
		}
		dirty = true
	}

	if *expLimW > 0 {
		// Round to nearest watt; Multiplier=0 → raw watts.
		ap := model.ActivePower{Value: int16(math.Round(*expLimW)), Multiplier: 0}
		ctrl.OpModExpLimW = &ap
		dirty = true
	}

	if dirty {
		if err := inv.ApplyControl(ctrl); err != nil {
			log.Fatalf("apply control: %v", err)
		}
		log.Printf("control applied")
	}

	// ── Read measurements ─────────────────────────────────────────────────────
	printOnce := func() {
		m, err := inv.ReadMeasurements()
		if err != nil {
			log.Printf("read measurements: %v", err)
			return
		}
		st, err := inv.Status()
		if err != nil {
			log.Printf("read status: %v", err)
			return
		}
		fmt.Printf("W=%6.0f  VA=%6.0f  VAr=%6.0f  PF=%5.3f  V=%5.1f  Hz=%5.2f  "+
			"DCV=%5.1f  DCW=%5.0f  TmpCab=%4.1f°C  Connected=%-5v  Energized=%v\n",
			m.W, m.VA, m.Var, m.PF, m.V, m.Hz,
			m.DCV, m.DCW, m.TmpCab, st.Connected, st.Energized)
	}

	printOnce()

	if *poll == 0 {
		return
	}

	ticker := time.NewTicker(*poll)
	defer ticker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			printOnce()
		case <-quit:
			return
		}
	}
}
