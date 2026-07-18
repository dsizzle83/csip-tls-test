package sim

// battery_adv.go — the advanced-DER (IEEE 1547-2018 / SunSpec 7xx) surface of
// the battery simulator, added by NewBatteryServerAdvanced. It is OPT-IN: the
// legacy NewBatteryServer serves only models 1/120/121/103/123/802 and
// behaves exactly as before. An advanced battery sim additionally advertises:
//
//	701 (DER AC Measurement)   — measurement + St/ConnSt, mirrored from the
//	                             same physical state the 103/802 animation
//	                             already computes (see solar_adv.go's
//	                             populate701 — reused verbatim here).
//	704 (DER AC Controls)      — WMaxLimPct, reused verbatim from
//	                             solar_adv.go's populate704. Unlike the
//	                             inverter's 704 (bridged into the legacy 123
//	                             curtailment ceiling by advBridgeCeiling), a
//	                             704 write here is NOT wired to physical
//	                             effect: this bench's battery dispatch
//	                             convention (a SIGNED legacy 123 WMaxLimPct —
//	                             see interceptWrite/hubBatteryW) predates 704
//	                             and is not re-derived from it. A 704 write
//	                             still round-trips correctly (SunSpec write-
//	                             then-read is itself part of the conformance
//	                             contract — mbapsdev's T06.3 acceptance is
//	                             "write a 704 control and read back the
//	                             echo"), it just does not additionally command
//	                             the pack. See T06.4/T06.10 reviewer note in
//	                             the task report.
//	713 (DER Storage Capacity) — WHRtg/WHAvail/SoC/SoH mirrored every tick
//	                             from the same 802 state the legacy animation
//	                             maintains, so /state (802) and 713 never
//	                             diverge.
//
// This exists for sim/mbapsdev (T06.3): the secure mbaps device sim needs a
// battery register world that includes 701/713 alongside the legacy 802
// surface (the inverter side already gets 701/704 for free from
// NewSolarServerAdvanced). No curve/adopt-handshake models (705/706/711/712)
// are served — the battery mode of mbapsdev does not need them and adding
// them would duplicate solar's adopt-handshake machinery for no consumer.

import (
	"sync/atomic"
	"time"

	"lexa-proto/sunspec"
)

// batteryAdvBases holds the data-block base addresses of the battery's
// advanced (7xx) models.
type batteryAdvBases struct {
	M701    uint16
	M701Len int
	M704    uint16
	M713    uint16
}

// NewBatteryServerAdvanced creates an animated Li-Ion battery simulator that
// ALSO serves the IEEE 1547-2018 DER measurement (701), control (704), and
// storage-capacity (713) models alongside the legacy 802 surface. Use it for
// mbapsdev's battery mode; NewBatteryServer stays the legacy-only default
// used by batsim.
func NewBatteryServerAdvanced(listenURL string, wmaxKwh, wmaxW float64) (*BatteryServer, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	bases, cursor := populateBatteryCore(regs, wmaxKwh, wmaxW)
	adv, cursor := populateBattery7xx(regs, cursor, wmaxKwh, wmaxW)
	regs.Set(cursor, sunspec.EndMarker)
	regs.Set(cursor+1, 0)

	bs := &BatteryServer{bases: bases, wmaxW: wmaxW, wmaxKwh: wmaxKwh, advanced: true, adv: adv}
	bs.faults.label = "battery"

	// Same wiring as NewBatteryServer (hub-write hook installed before the
	// Modbus server starts, per finding MOD-3).
	regs.OnWrite = func(startAddr uint16) {
		if startAddr >= bases.M123Base && startAddr < bases.M123Base+23 {
			applyHubBatteryWrite(regs, bases, wmaxW, &bs.faults)
		}
	}
	regs.OnWriteAttempt = bs.interceptWrite
	regs.OnRead = bs.faults.transportRead

	srv, err := newAnimatedServer(listenURL, regs, func(s *Server, r *RegisterMap, stop <-chan struct{}) {
		animateBatteryAdvanced(s, r, wmaxW, wmaxKwh, bases, adv, &bs.pendingSoC, &bs.faults, stop)
	})
	if err != nil {
		return nil, err
	}
	bs.Server = srv
	return bs, nil
}

// populateBattery7xx appends the advanced models after the legacy layout
// (before the end marker) and returns their bases plus the next cursor.
// populate701/populate704 are reused verbatim from solar_adv.go (same
// package, model-agnostic — they only seed scale factors and generic
// enum/float defaults, no solar-specific bases).
func populateBattery7xx(r *RegisterMap, cursor uint16, wmaxKwh, wmaxW float64) (batteryAdvBases, uint16) {
	var adv batteryAdvBases
	adv.M701, adv.M701Len, cursor = populate701(r, cursor)
	adv.M704, cursor = populate704(r, cursor)
	adv.M713, cursor = populate713(r, cursor, wmaxKwh)

	// SF write-protection (protect.go), derived from the layouts themselves —
	// see solar_adv.go's populateSolar7xx for the rationale.
	protectLayoutSFs(r, adv.M701, sunspec.L701)
	protectLayoutSFs(r, adv.M704, sunspec.L704)
	protectLayoutSFs(r, adv.M713, sunspec.L713)
	return adv, cursor
}

// populate713 writes model 713 (DER Storage Capacity — spec Table 16): the
// small operational-SoC model. Seeded to match the legacy 802 block's initial
// SoC (55%) and refreshed every tick by mirrorBattery701713 so it never
// diverges from the 802 ground truth.
func populate713(r *RegisterMap, cursor uint16, wmaxKwh float64) (base, next uint16) {
	dataLen := sunspec.L713.Len()
	base, next = writeModelHeader(r, cursor, sunspec.ModelDERStorageCap, dataLen)
	regs := make([]uint16, dataLen)
	setSF(regs, sunspec.L713, "WH_SF", 0)
	setSF(regs, sunspec.L713, "Pct_SF", -2)
	v := sunspec.L713.View(regs)
	v.SetFloat("WHRtg", wmaxKwh*1000)
	v.SetFloat("WHAvail", wmaxKwh*1000*0.55)
	v.SetFloat("SoC", 55)
	v.SetFloat("SoH", 100)
	v.SetEnum("Sta", 0) // 0 = OK
	writeSlice(r, base, regs)
	return base, next
}

// animateBatteryAdvanced runs the legacy battery animation (unmodified,
// exactly as NewBatteryServer does) plus a second ticker that mirrors the
// resulting 103/802 physical state into the 701/713 advanced models. Two
// independent 5 s tickers (rather than in-lining the mirror into
// animateBattery's tick, as solar_adv.go does with advMirror701) — splitting
// animateBattery's monolithic loop to expose a per-tick step function is a
// larger refactor than mbapsdev's T06.3 acceptance bar needs (read Model 1 +
// a measurement model, write a 704 control and read back the echo — the 704
// echo is the register store itself, independent of any mirroring); the
// mirror ticker exists purely so /state-style consumers of the 701/713
// blocks see values consistent with 802 within one tick period.
func animateBatteryAdvanced(s *Server, r *RegisterMap, wmaxW, wmaxKwh float64, bases BatteryBases,
	adv batteryAdvBases, pendingSoC *atomic.Pointer[float64], fc *faultController, stop <-chan struct{}) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		animateBattery(s, r, wmaxW, wmaxKwh, bases, pendingSoC, fc, stop)
	}()
	mirrorBattery701713(r, bases, adv, wmaxKwh, stop)
	<-done
}

// mirrorBattery701713 refreshes the 701 measurement and 713 storage-capacity
// blocks from the 103/802 state every 5 s, so a client reading the advanced
// models sees the same ground truth GET /state (802-based) exposes.
func mirrorBattery701713(r *RegisterMap, bases BatteryBases, adv batteryAdvBases, wmaxKwh float64, stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	mirrorBattery701713Once(r, bases, adv, wmaxKwh) // seed so an immediately-read sim is coherent
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			mirrorBattery701713Once(r, bases, adv, wmaxKwh)
		}
	}
}

// mirrorBattery701713Once performs one mirror pass (see mirrorBattery701713).
// Split out so unit tests can drive it synchronously without waiting on a
// ticker (mirrors solar_adv.go's advMirror701 being a standalone function).
func mirrorBattery701713Once(r *RegisterMap, bases BatteryBases, adv batteryAdvBases, wmaxKwh float64) {
	m103, m802 := bases.M103Base, bases.M802Base
	w := sunspec.ApplyScaleSigned(r.Get(m103+sunspec.M103_W), int16(r.Get(m103+sunspec.M103_W_SF)))
	soc := sunspec.ApplyScaleUint(r.Get(m802+uint16(sunspec.M802_SoC)), int16(r.Get(m802+uint16(sunspec.M802_SoC_SF))))
	soh := sunspec.ApplyScaleUint(r.Get(m802+uint16(sunspec.M802_SoH)), int16(r.Get(m802+uint16(sunspec.M802_SoH_SF))))
	conn := r.Get(bases.M123Base + sunspec.M123_Conn)

	regs701 := readSlice(r, adv.M701, adv.M701Len)
	v := sunspec.L701.View(regs701)
	v.SetEnum("ACType", 2)
	if conn == 0 {
		v.SetEnum("St", 0)
		v.SetEnum("ConnSt", 0)
	} else {
		v.SetEnum("St", 1)
		v.SetEnum("ConnSt", 1)
	}
	v.SetFloat("W", w)
	writeSlice(r, adv.M701, regs701)

	regs713 := readSlice(r, adv.M713, sunspec.L713.Len())
	v713 := sunspec.L713.View(regs713)
	v713.SetFloat("SoC", soc)
	v713.SetFloat("SoH", soh)
	v713.SetFloat("WHAvail", wmaxKwh*1000*soc/100.0)
	writeSlice(r, adv.M713, regs713)
}
