// Package sim provides in-process SunSpec Modbus TCP servers for development
// and integration testing without real hardware.
//
// There are three constructors:
//
//   - NewServer — static inverter layout (Models 1/121/103/123); used by tests.
//   - NewSolarServer — animated PV inverter (Models 1/120/121/122/103/123).
//   - NewBatteryServer — animated Li-Ion storage (Models 1/120/121/103/123/802).
//
// Both animated servers update their registers every 5 seconds to simulate
// realistic power flow. Stop() shuts down the animation and the Modbus server.
package sim

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	modbuslib "github.com/simonvetter/modbus"
	"csip-tls-test/internal/southbound/sunspec"
)

// RegisterMap is a thread-safe Modbus holding-register store. It doubles as
// the simonvetter RequestHandler so it can be passed directly to NewServer.
type RegisterMap struct {
	mu   sync.RWMutex
	regs map[uint16]uint16
}

// Get returns the value of a holding register (0-based Modbus address).
func (r *RegisterMap) Get(addr uint16) uint16 {
	r.mu.RLock()
	v := r.regs[addr]
	r.mu.RUnlock()
	return v
}

// Set writes a value to a holding register.
func (r *RegisterMap) Set(addr, val uint16) {
	r.mu.Lock()
	r.regs[addr] = val
	r.mu.Unlock()
}

// HandleCoils satisfies modbuslib.RequestHandler (not used in SunSpec).
func (r *RegisterMap) HandleCoils(_ *modbuslib.CoilsRequest) ([]bool, error) {
	return nil, modbuslib.ErrIllegalFunction
}

// HandleDiscreteInputs satisfies modbuslib.RequestHandler.
func (r *RegisterMap) HandleDiscreteInputs(_ *modbuslib.DiscreteInputsRequest) ([]bool, error) {
	return nil, modbuslib.ErrIllegalFunction
}

// HandleHoldingRegisters serves Modbus FC03 (read) and FC06/FC16 (write).
func (r *RegisterMap) HandleHoldingRegisters(req *modbuslib.HoldingRegistersRequest) ([]uint16, error) {
	if req.IsWrite {
		r.mu.Lock()
		for i, v := range req.Args {
			r.regs[req.Addr+uint16(i)] = v
		}
		r.mu.Unlock()
		return nil, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]uint16, req.Quantity)
	for i := uint16(0); i < req.Quantity; i++ {
		result[i] = r.regs[req.Addr+i]
	}
	return result, nil
}

// HandleInputRegisters satisfies modbuslib.RequestHandler.
func (r *RegisterMap) HandleInputRegisters(_ *modbuslib.InputRegistersRequest) ([]uint16, error) {
	return nil, modbuslib.ErrIllegalFunction
}

// Server is a running SunSpec Modbus TCP server.
type Server struct {
	// Regs is the live register bank. Inspect or mutate during a test to
	// simulate changing inverter state or verify that a write landed.
	Regs *RegisterMap

	srv  *modbuslib.ModbusServer
	stop chan struct{} // closed by Stop to signal the animation goroutine
	done chan struct{} // closed by animation goroutine when it exits

	// Animation control. Safe for concurrent use via atomic / mutex.
	paused atomic.Bool // when true the animation loop skips register updates

	sfMu  sync.Mutex
	speed float64 // animation speed multiplier (0 / negative → treated as 1.0)
}

// Pause suspends the animation without stopping the Modbus server.
// Register values are frozen at their current state.
func (s *Server) Pause() { s.paused.Store(true) }

// Resume resumes a paused animation.
func (s *Server) Resume() { s.paused.Store(false) }

// IsPaused returns true when the animation is currently paused.
func (s *Server) IsPaused() bool { return s.paused.Load() }

// SetSpeed sets the animation speed multiplier.  A value of 1.0 (default) is
// real-time; 10.0 runs the simulation 10× faster (600 s cycle in 60 s).
// Values ≤ 0 reset to 1.0.
func (s *Server) SetSpeed(f float64) {
	if f <= 0 {
		f = 1.0
	}
	s.sfMu.Lock()
	s.speed = f
	s.sfMu.Unlock()
}

// Speed returns the current animation speed multiplier.
func (s *Server) Speed() float64 {
	s.sfMu.Lock()
	f := s.speed
	s.sfMu.Unlock()
	if f <= 0 {
		return 1.0
	}
	return f
}

// simTime returns the effective simulation time: Unix seconds × speed factor.
// All animation formulas should use this instead of time.Now().Unix() directly.
func (s *Server) simTime() float64 {
	return float64(time.Now().Unix()) * s.Speed()
}

// NewServer creates and starts a static SunSpec inverter simulator on
// listenURL (e.g. "tcp://0.0.0.0:5020"). Register values do not change
// after startup. This variant is used by package inverter tests.
//
// For an animated solar or battery simulator use NewSolarServer /
// NewBatteryServer instead.
func NewServer(listenURL string, wmaxW float64) (*Server, error) {
	regs := &RegisterMap{regs: make(map[uint16]uint16)}
	Populate(regs, wmaxW)
	return startServer(listenURL, regs)
}

// startServerRaw starts the Modbus TCP listener and returns a Server with
// stop/done channels ready but no goroutine started.  Callers must either
// start a goroutine that closes done (for static servers) or use
// newAnimatedServer (which starts an animation goroutine).
func startServerRaw(listenURL string, regs *RegisterMap) (*Server, error) {
	srv, err := modbuslib.NewServer(&modbuslib.ServerConfiguration{
		URL:        listenURL,
		MaxClients: 8,
		Timeout:    30 * time.Second,
	}, regs)
	if err != nil {
		return nil, fmt.Errorf("sim: new server at %s: %w", listenURL, err)
	}
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("sim: start server at %s: %w", listenURL, err)
	}
	time.Sleep(20 * time.Millisecond)

	return &Server{
		Regs: regs,
		srv:  srv,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}, nil
}

// startServer is the shared server-launch helper for static (non-animated)
// servers.  It starts a single goroutine that closes done when stop fires.
func startServer(listenURL string, regs *RegisterMap) (*Server, error) {
	s, err := startServerRaw(listenURL, regs)
	if err != nil {
		return nil, err
	}
	// Static server: no animation — just wait for stop.
	go func() {
		defer close(s.done)
		<-s.stop
	}()
	return s, nil
}

// Stop shuts the animation goroutine and the Modbus server down cleanly.
func (s *Server) Stop() {
	close(s.stop)
	<-s.done
	s.srv.Stop()
}

// Populate writes a complete SunSpec inverter profile into regs.
// Models written: 1 (Common), 121 (Basic Settings), 103 (Three-Phase
// Inverter), 123 (Immediate Controls), plus the SunS header and end marker.
// Initial values represent a 5000 W inverter producing 3000 W at 240 V / 60 Hz.
// wmaxW overrides the nameplate WMax in Model 121.
func Populate(r *RegisterMap, wmaxW float64) {
	sfN := func(v int16) uint16 { return uint16(v) }
	base := sunspec.SunSpecBase

	// ── SunS header ──────────────────────────────────────────────────────────
	r.Set(base+0, sunspec.SunSMagic0)
	r.Set(base+1, sunspec.SunSMagic1)
	cursor := base + 2

	// ── Model 1 (Common) — 66 data registers ─────────────────────────────────
	const m1Len = 66
	r.Set(cursor+0, sunspec.ModelCommon)
	r.Set(cursor+1, m1Len)
	m1Base := cursor + 2
	setStr16(r, m1Base+0, "SunSpec Sim") // Mn (manufacturer, 32 chars = 16 regs)
	setStr8(r, m1Base+16, "CSIP-Dev-5000") // Md (model, 16 chars = 8 regs)
	setStr8(r, m1Base+32, "SN-0001")      // SN (serial, 32 chars = 16 regs)
	cursor += 2 + m1Len

	// ── Model 121 (Basic Settings) — 30 data registers ───────────────────────
	const m121Len = 30
	r.Set(cursor+0, sunspec.ModelBasicSettings)
	r.Set(cursor+1, m121Len)
	m121Base := cursor + 2
	wmaxRaw := uint16(wmaxW) // sf=0 → raw == watts
	r.Set(m121Base+sunspec.M121_WMax, wmaxRaw)
	r.Set(m121Base+sunspec.M121_WMax_SF, 0)
	cursor += 2 + m121Len

	// ── Model 103 (Three-Phase Inverter) — 50 data registers ─────────────────
	const m103Len = 50
	r.Set(cursor+0, sunspec.ModelInverterThreePh)
	r.Set(cursor+1, m103Len)
	m103Base := cursor + 2
	// AC power: 3000 W (sf=0).
	r.Set(m103Base+sunspec.M103_W, uint16(int16(3000)))
	r.Set(m103Base+sunspec.M103_W_SF, 0)
	// Voltage: 2400 × 10^-1 = 240.0 V.
	r.Set(m103Base+sunspec.M103_PhVphA, 2400)
	r.Set(m103Base+sunspec.M103_V_SF, sfN(-1))
	// Frequency: 6000 × 10^-2 = 60.00 Hz.
	r.Set(m103Base+sunspec.M103_Hz, 6000)
	r.Set(m103Base+sunspec.M103_Hz_SF, sfN(-2))
	// Apparent power: 3100 VA (sf=0).
	r.Set(m103Base+sunspec.M103_VA, uint16(int16(3100)))
	r.Set(m103Base+sunspec.M103_VA_SF, 0)
	// Reactive power: 780 var (sf=0).
	r.Set(m103Base+sunspec.M103_VAr, uint16(int16(780)))
	r.Set(m103Base+sunspec.M103_VAr_SF, 0)
	// Power factor: 9677 × 10^-2 = 96.77, divided by 100 = 0.9677.
	r.Set(m103Base+sunspec.M103_PF, uint16(int16(9677)))
	r.Set(m103Base+sunspec.M103_PF_SF, sfN(-2))
	// DC: 380.0 V (3800 × 10^-1), 3200 W (sf=0).
	r.Set(m103Base+sunspec.M103_DCV, 3800)
	r.Set(m103Base+sunspec.M103_DCV_SF, sfN(-1))
	r.Set(m103Base+sunspec.M103_DCW, uint16(int16(3200)))
	r.Set(m103Base+sunspec.M103_DCW_SF, 0)
	// Cabinet temp: 35.0 °C (350 × 10^-1).
	r.Set(m103Base+sunspec.M103_TmpCab, uint16(int16(350)))
	r.Set(m103Base+sunspec.M103_Tmp_SF, sfN(-1))
	// St = 4 (MPPT — grid-connected, producing).
	r.Set(m103Base+sunspec.M103_St, 4)
	cursor += 2 + m103Len

	// ── Model 123 (Immediate Controls) — 23 data registers ───────────────────
	const m123Len = 23
	r.Set(cursor+0, sunspec.ModelImmediateCtrl)
	r.Set(cursor+1, m123Len)
	m123Base := cursor + 2
	// 100.00% power limit (10000 × 10^-2 = 100.00).
	r.Set(m123Base+sunspec.M123_WMaxLimPct, 10000)
	r.Set(m123Base+sunspec.M123_WMaxLimPct_Ena, 1)
	r.Set(m123Base+sunspec.M123_WMaxLimPct_SF, sfN(-2))
	// Connected.
	r.Set(m123Base+sunspec.M123_Conn, 1)
	cursor += 2 + m123Len

	// ── End marker ───────────────────────────────────────────────────────────
	r.Set(cursor+0, sunspec.EndMarker)
	r.Set(cursor+1, 0)
}

// setStr16 writes a string as up to 16 Modbus registers (32 ASCII bytes,
// null-padded). Excess characters are silently truncated.
func setStr16(r *RegisterMap, base uint16, s string) {
	writeStr(r, base, s, 16)
}

// setStr8 writes a string as up to 8 Modbus registers (16 ASCII bytes).
func setStr8(r *RegisterMap, base uint16, s string) {
	writeStr(r, base, s, 8)
}

func writeStr(r *RegisterMap, base uint16, s string, maxRegs uint16) {
	b := []byte(s)
	for i := uint16(0); i < maxRegs; i++ {
		var hi, lo byte
		idx := int(i) * 2
		if idx < len(b) {
			hi = b[idx]
		}
		if idx+1 < len(b) {
			lo = b[idx+1]
		}
		r.Set(base+i, uint16(hi)<<8|uint16(lo))
	}
}
