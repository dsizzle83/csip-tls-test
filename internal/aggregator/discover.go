package aggregator

import (
	"context"
	"errors"
	"fmt"

	"lexa-proto/sunspec"
)

// Device is one discovered per-device unit on the gateway: its unit id, its
// SunSpec Common (model 1) identity, and the model IDs it advertises. It is
// JSON-serializable for the run report.
//
// PN-6: lexa-gw serves per-device units only (1..246) — CSIP owns aggregation,
// there is NO virtual aggregate unit. So discovery is a walk of the per-device
// unit map (one Model 1 per responding unit); a unit the gateway does not map
// answers exception 0x0A and is skipped, never treated as a device.
type Device struct {
	Unit     uint8          `json:"unit"`
	Identity sunspec.Common `json:"identity"`
	Models   []uint16       `json:"models"`
}

// maxUnit is the top of the per-device unit range lexa-gw serves (ARCHITECTURE
// §10: units 1..246; CSIP owns aggregation). Discover with no explicit units
// walks 1..maxUnit.
const maxUnit = 246

// Discover walks the gateway's per-device unit map and inventories each
// responding device by reading the SunSpec Common (model 1) identity and the
// model chain. With no units given it probes 1..246; otherwise it probes exactly
// the units listed (a smaller, faster range for tests and targeted campaigns).
//
// A unit that answers with no SunS header — an unmapped unit (exception 0x0A) or
// a silent gap — is skipped, not an error: discovery of an empty slot is a
// normal result, and one dead unit must not abort the whole inventory. A
// transport-level break (the session desynced) DOES abort, because every
// subsequent probe would ride a broken stream. ctx cancellation is honored
// between units.
//
// Discovery reuses sunspec.NewReader/ReadCommon over the T06.4 transport (no
// bespoke decode) and warms the Conn's block-layout cache for every device it
// finds, so a following Poll or WritePoint on that unit needs no re-scan.
func (c *Conn) Discover(ctx context.Context, units ...uint8) ([]Device, error) {
	if len(units) == 0 {
		units = make([]uint8, 0, maxUnit)
		for u := 1; u <= maxUnit; u++ {
			units = append(units, uint8(u))
		}
	}
	var devices []Device
	for _, u := range units {
		if err := ctx.Err(); err != nil {
			return devices, err
		}
		dev, found, err := c.identify(u)
		if err != nil {
			// A transport break poisons the stream; nothing after this probe is
			// trustworthy. A mere "no device here" is not an error (found=false).
			return devices, fmt.Errorf("aggregator: discover unit %d: %w", u, err)
		}
		if found {
			devices = append(devices, dev)
		}
	}
	return devices, nil
}

// identify probes one unit. found=false with err=nil means "no device mapped
// here" (no SunS header / exception 0x0A) — skip it. err!=nil means the session
// desynced (a transport break, not a protocol exception) and discovery must
// stop.
func (c *Conn) identify(unit uint8) (Device, bool, error) {
	r, err := c.readerFor(unit)
	if err != nil {
		// A SunSpec scan failure at a probe base is "not here" — the scanner
		// tried every permitted base (40000/0/50000) and none presented a SunS
		// header, which for the gateway means the unit is unmapped (0x0A). Only a
		// transport break (broken session) is a real error; distinguish them.
		if c.transportBroken() {
			return Device{}, false, err
		}
		return Device{}, false, nil
	}
	common, err := sunspec.ReadCommon(r)
	if err != nil {
		// The unit answered a SunS header but its Common model read failed. A
		// missing/short Common is a malformed device, not a transport break: keep
		// its unit + model list but leave the identity zero-valued rather than
		// aborting the whole walk. A transport break still aborts.
		if c.transportBroken() {
			return Device{}, false, fmt.Errorf("read common model: %w", err)
		}
		if !errors.Is(err, sunspec.ErrNoCommonModel) && !errors.Is(err, sunspec.ErrShortCommonModel) {
			// Unexpected non-transport error — surface it against this unit.
			return Device{}, false, fmt.Errorf("read common model: %w", err)
		}
	}
	return Device{Unit: unit, Identity: common, Models: modelIDs(r.Blocks())}, true, nil
}

// transportBroken reports whether the last op desynced the session.
func (c *Conn) transportBroken() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.broken
}

// modelIDs pulls the model IDs out of a scanned block list, in device order.
func modelIDs(blocks []sunspec.Block) []uint16 {
	ids := make([]uint16, 0, len(blocks))
	for _, b := range blocks {
		ids = append(ids, b.ModelID)
	}
	return ids
}

// readerFor returns a SunSpec Reader for unit, scanning the device once and
// caching its block layout (the codec's own design: scan once, then reads are
// single transactions). The cache is redial-safe — the layout describes the
// device, not the connection, and the reader's transport always resolves the
// Conn's CURRENT session — so it survives a reconnect. Only a successful scan is
// cached; an unmapped unit is re-probed each call (caching a negative would just
// hide a unit that later comes online).
func (c *Conn) readerFor(unit uint8) (*sunspec.Reader, error) {
	c.readersMu.Lock()
	if r, ok := c.readers[unit]; ok {
		c.readersMu.Unlock()
		return r, nil
	}
	c.readersMu.Unlock()

	// Scan outside the readers lock — NewReader drives transport I/O, which takes
	// c.mu; holding readersMu across it is unnecessary and a concurrent scan of
	// the same unit is harmless (idempotent layout, last writer wins).
	r, err := sunspec.NewReader(c.transportForUnit(unit))
	if err != nil {
		return nil, err
	}
	c.readersMu.Lock()
	c.readers[unit] = r
	c.readersMu.Unlock()
	return r, nil
}
