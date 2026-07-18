package aggregator

import (
	"context"
	"fmt"
	"math"
	"time"

	"lexa-proto/sunspec"
)

// measurementModel is the DER AC Measurement model the poller reads. 701 is the
// IEEE 1547-2018 measurement model the gateway projects; it is the only model
// Poll parses today (reviewer note, T06.5/T06.7: add 702/713 parsing here when
// battery capacity/SoC telemetry is wanted — Sample/Poll structure is model-
// agnostic, only pollUnit's Parse701 call is 701-specific).
const measurementModel = uint16(701)

// Snapshot is one telemetry sample of one unit — the JSON-serializable unit the
// scenario engine and report writer consume. Points carries only FINITE
// engineering values: an unimplemented/sentinel point is omitted, never emitted
// as NaN (CODING_PRINCIPLES §2 — NaN never crosses the wire). Stale and CommLoss
// are the emulator observing the same single-truth freshness the gateway
// projects (design doc 02 §4.3).
type Snapshot struct {
	Unit   uint8              `json:"unit"`
	Model  uint16             `json:"model"`
	At     time.Time          `json:"at"`
	Points map[string]float64 `json:"points,omitempty"`
	St     uint16             `json:"st"`      // operating state (0=off,1=on)
	InvSt  uint16             `json:"inv_st"`  // inverter state
	ConnSt uint16             `json:"conn_st"` // 0=disconnected, 1=connected
	Alrm   uint32             `json:"alrm"`    // raw 701 alarm bitfield (oracles interpret bits)
	// Stale is set when the measurement block read looks corrupt/not-implemented
	// (scale-factor sentinels — the failed/stale-read shape a nan_sentinel fault
	// produces), i.e. the device answered but the data is not fresh.
	Stale bool `json:"stale"`
	// CommLoss is set when this poll cycle could not get a fresh reading at all —
	// a transport failure, a device-down exception (0x0B), or a configured Alrm
	// comms-loss bit. Distinct from Stale: Stale = stale data returned; CommLoss =
	// no data returned.
	CommLoss bool `json:"comm_loss"`
	// Err carries the transport error message for a failed cycle (diagnostics).
	Err string `json:"err,omitempty"`
}

// SnapshotSink receives each telemetry sample as it is produced. Implementations
// must not block the poll loop (buffer or drop internally); the loop calls
// Publish inline.
type SnapshotSink interface {
	Publish(Snapshot)
}

// SnapshotFunc adapts a plain function to a SnapshotSink.
type SnapshotFunc func(Snapshot)

// Publish satisfies SnapshotSink.
func (f SnapshotFunc) Publish(s Snapshot) { f(s) }

// Sample reads one telemetry snapshot of unit right now (no loop). It is the
// primitive Poll runs on a cadence and the one a scenario step's readback uses
// to observe a control's effect.
func (c *Conn) Sample(unit uint8) Snapshot {
	return c.pollUnit(unit)
}

// Poll reads a telemetry snapshot of every unit every period, publishing each to
// sink and caching it as the unit's latest (queryable via Latest/Snapshots). It
// samples once immediately, then on each tick — a caller need not wait a full
// period for the first reading. It runs until ctx is cancelled, then returns nil
// (a cancelled context is the intended stop, not a failure). A per-cycle read
// failure becomes a CommLoss/Stale snapshot rather than ending the loop: a
// momentary outage must not stop telemetry, and the following cycle recovers
// (the raw ops redial transparently).
func (c *Conn) Poll(ctx context.Context, units []uint8, period time.Duration, sink SnapshotSink) error {
	if period <= 0 {
		return fmt.Errorf("aggregator: poll period must be > 0, got %s", period)
	}
	if len(units) == 0 {
		return fmt.Errorf("aggregator: poll needs at least one unit")
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		for _, u := range units {
			if ctx.Err() != nil {
				return nil
			}
			snap := c.pollUnit(u)
			c.storeLatest(snap)
			if sink != nil {
				sink.Publish(snap)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// pollUnit reads and classifies one telemetry sample. It never returns an error:
// every failure mode is encoded in the Snapshot (CommLoss/Stale/Err) so a poll
// loop keeps producing samples the oracle can reason over.
func (c *Conn) pollUnit(unit uint8) Snapshot {
	snap := Snapshot{Unit: unit, At: time.Now(), Model: measurementModel}

	r, err := c.readerFor(unit)
	if err != nil {
		// Could not even scan the unit (unmapped, down, or session broken) — no
		// fresh reading is available this cycle.
		snap.CommLoss = true
		snap.Err = err.Error()
		return snap
	}
	if !r.HasModel(measurementModel) {
		snap.Stale = true
		snap.Err = fmt.Sprintf("device on unit %d has no measurement model %d", unit, measurementModel)
		return snap
	}
	regs, err := r.ReadModel(measurementModel)
	if err != nil {
		// A device-down exception (0x0B) or a transport break: no fresh data.
		snap.CommLoss = true
		snap.Err = err.Error()
		return snap
	}

	m := sunspec.Parse701(regs)
	snap.St, snap.InvSt, snap.ConnSt, snap.Alrm = m.St, m.InvSt, m.ConnSt, m.Alrm
	snap.Points = measPoints(m)
	// The codec's own corruption gate: sentinel scale factors (or a sentinel-
	// saturated block) mean the read is not a real, fresh sample (audit E2). This
	// is exactly what a nan_sentinel fault produces on the device.
	snap.Stale = sunspec.L701.View(regs).ReadLooksCorrupt()
	return snap
}

// measPoints extracts the finite engineering values from a 701 measurement,
// dropping any NaN (unimplemented/sentinel) point so the map is JSON-safe.
func measPoints(m sunspec.ACMeasurement) map[string]float64 {
	out := make(map[string]float64, 9)
	add := func(name string, v float64) {
		if !math.IsNaN(v) {
			out[name] = v
		}
	}
	add("W", m.W)
	add("VA", m.VA)
	add("Var", m.Var)
	add("PF", m.PF)
	add("A", m.A)
	add("Hz", m.Hz)
	add("LNV", m.LNV)
	add("LLV", m.LLV)
	add("TmpCab", m.TmpCab)
	return out
}

// storeLatest records snap as the unit's latest sample.
func (c *Conn) storeLatest(snap Snapshot) {
	c.latestMu.Lock()
	c.latest[snap.Unit] = snap
	c.latestMu.Unlock()
}

// Latest returns the most recent snapshot for unit, or ok=false if none has been
// sampled yet.
func (c *Conn) Latest(unit uint8) (Snapshot, bool) {
	c.latestMu.Lock()
	defer c.latestMu.Unlock()
	s, ok := c.latest[unit]
	return s, ok
}

// Snapshots returns a copy of the latest snapshot per unit.
func (c *Conn) Snapshots() map[uint8]Snapshot {
	c.latestMu.Lock()
	defer c.latestMu.Unlock()
	out := make(map[uint8]Snapshot, len(c.latest))
	for u, s := range c.latest {
		out[u] = s
	}
	return out
}
