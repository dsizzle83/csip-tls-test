package certify

// preflight_fixture.go holds the candidate's declared `models` list against the
// SunSpec model chain the DER SIMULATOR actually serves on this bench.
//
// # Why the fixture needs checking, separately from the DUT
//
// preflight_manifest.go asks the DUT's own southbound inventory whether the
// device it ADMITTED matches the manifest. This asks a different witness the
// same kind of question: does the FIXTURE — the modsim the southbound oracle
// reads every register verdict from — serve the model chain the candidate says
// its DER implements? The two are independent, and both matter. A campaign whose
// oracle sim serves models the candidate never declared (an advanced fixture
// left serving the trip models 707-710, say) grades the product against a device
// it was never claimed to be, and every register verdict it produces is
// measured on the wrong instrument. A candidate that declares a model the
// fixture does not serve is the mirror gap: rows that rest on that model read an
// absence and blame the DUT for it.
//
// # Both directions are fatal; silence is fatal only on a gating campaign
//
// A model the sim serves that the manifest omits, OR a model the manifest
// declares that the sim does not serve, ends the run before the capture: the
// oracle would spend the whole campaign reading a device the declaration does
// not describe, and the bundle would record this tool's mis-fixtured bench as
// the product's own model surface. A sim that cannot be read at all (no
// -modsim-api, a transport hiccup, a register image that is not a SunSpec
// chain) is UNPROVEN, and what that costs depends on the run: an EXPLORATORY
// poke reports it and continues, so a quick look is not blocked by a bench the
// tool cannot reach; a GATING campaign STOPS, because the fixture every
// southbound register verdict is read from was never confirmed to serve the
// declared chain, and a cert bundle may not be graded on an unchecked
// instrument. That split is unprovable's (preflight.go), the same posture
// preflight_manifest.go now uses when the DUT cannot be asked at all.
//
// It lives in package certify (not suitecsip) because it is a whole-campaign
// precondition the Runner enforces before case 1, alongside the authority and
// manifest preflights. That placement is why it reads the sim's register image
// through a local SunSpec scan rather than through internal/invariant's
// SimAPIDER: invariant imports certify, so certify cannot import invariant, and
// the model-chain scan is a dozen lines the vendored SunSpec reader already owns.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"lexa-proto/modbus"
	"lexa-proto/sunspec"
)

// preflightFixture checks the candidate manifest's `models` against the DER
// simulator's served model chain. It is a no-op when no manifest was given.
func (r *Runner) preflightFixture(ctx context.Context, reporter *Reporter) error {
	m := r.manifest
	if m == nil {
		return nil
	}

	sim := NewSimClient("modsim", r.opts.Targets.ModSimAPI, r.opts.HTTP)
	if !sim.Available() {
		// UNPROVEN. On a gating campaign the oracle reads EVERY southbound
		// register verdict from this fixture, so a run that never confirmed the
		// fixture serves the declared chain is a cert bundle graded on an
		// unchecked instrument — fatal (unprovable); an exploratory poke says so
		// and continues.
		return r.unprovable(reporter,
			"the fixture's served SunSpec model chain (no DER simulator API is configured, -modsim-api)",
			"The southbound oracle reads every register verdict from this fixture, so nothing here would "+
				"establish that it serves the model chain the manifest declares; pass -modsim-api")
	}

	served, err := readSimModelChain(ctx, sim)
	if err != nil {
		// UNPROVEN, not contradicted. A sim that could not be read says nothing
		// about the manifest, and manufacturing a CONTRADICTION from it would be
		// a lie — but on a gating campaign a fixture whose served chain could not
		// be read is a precondition that was not established, which is fatal for
		// the reason unprovable states; on an exploratory run it stays a warn
		// (preflight_manifest.go's posture, one witness over).
		return r.unprovable(reporter,
			fmt.Sprintf("the fixture's served SunSpec model chain (the DER simulator could not be read: %v)", err),
			"The southbound oracle reads every register verdict from this fixture, so nothing here would "+
				"establish that it serves the model chain the manifest declares")
	}

	declared := dedupSortedInts(m.Models)
	simExtra := modelsAOnly(served, intSet(declared)) // sim serves, manifest omits
	manifestExtra := modelsAOnly(declared, intSet(served))

	if len(simExtra) == 0 && len(manifestExtra) == 0 {
		reporter.Line("candidate: the DER fixture's served SunSpec model chain matches the manifest's "+
			"`models` — %v", served)
		return nil
	}

	var problems []string
	if len(simExtra) > 0 {
		problems = append(problems, fmt.Sprintf(
			"the DER simulator SERVES model(s) %v that the manifest's `models` does NOT declare",
			simExtra))
	}
	if len(manifestExtra) > 0 {
		problems = append(problems, fmt.Sprintf(
			"the manifest DECLARES model(s) %v that the DER simulator does NOT serve",
			manifestExtra))
	}

	// BOTH directions are treated the SAME, and that symmetry is deliberate. The
	// DER simulator serves a COMPLETE, KNOWN model chain (not an admitted subset
	// the way preflightManifest's DUT inventory is — the dev API publishes only
	// what has finished admitting, so an under-declaration there is a soft
	// WARN). A fixture that serves a model the candidate does not declare, OR a
	// candidate that declares a model the fixture does not serve, is a real
	// fixture/candidate DRIFT either way: the oracle reads this fixture for every
	// southbound register verdict, and a gating campaign that generated cert
	// evidence against a fixture its own manifest does not describe would record
	// this tool's mis-fixtured bench as the product's model surface.
	//
	// So it is FATAL on the GATING path and a WARN on an exploratory one — the
	// same posture split preflightManifest now uses for its own under-declaration,
	// so the two checks agree on how a served-but-undeclared model is treated. A
	// gating run against a mismatched fixture must stop before case 1; an
	// exploratory poke reports the drift and continues.
	msg := fmt.Sprintf("the candidate manifest %s and the DER fixture on this bench disagree about the "+
		"served SunSpec model chain:\n  - %s\nThe manifest declares %v; the fixture serves %v",
		m.Path(), joinProblems(problems), declared, served)
	if !r.gatingCampaign() {
		reporter.Line("candidate: %s. This is an EXPLORATORY run (no -campaign), so it is a WARNING, not a "+
			"refusal; a gating campaign would stop here. Reconcile the manifest's `models` with the fixture "+
			"(modsim -der-models)", msg)
		return nil
	}
	return fmt.Errorf("certify: preflight: %s. Every southbound register verdict in this run is read from "+
		"that fixture and every scope decision is made from that manifest, so a gating run against a fixture "+
		"the manifest does not describe would record this tool's mis-fixtured bench as the product's own "+
		"model surface. Reconcile the manifest's `models` with the fixture (modsim -der-models), or point "+
		"the run at the fixture the manifest describes", msg)
}

// gatingCampaign reports whether this run declared a campaign — the signal that
// a fixture/candidate mismatch should STOP the run rather than merely warn. An
// exploratory selection (no -campaign) is marked NOT GATING and its preflights
// warn instead of refusing, so a quick poke is not blocked by drift a real
// campaign must reject before generating evidence.
func (r *Runner) gatingCampaign() bool { return r.campaign.Name != "" }

// readSimModelChain reads the DER simulator's /registers image and returns the
// SunSpec model ids it serves, in chain order, deduped and ascending.
//
// It decodes the register image and scans it with the same vendored SunSpec
// reader internal/invariant uses, so the chain this preflight sees is the chain
// every oracle in the run will see — the fixture is one device, read one way.
func readSimModelChain(ctx context.Context, sim *SimClient) ([]int, error) {
	var raw map[string]any
	if err := sim.Registers(ctx, &raw); err != nil {
		return nil, fmt.Errorf("read the DER simulator's /registers: %w", err)
	}
	regs, err := simRegisterImage(raw)
	if err != nil {
		return nil, err
	}
	rdr, err := sunspec.NewReader(&simMemTransport{regs: regs, unit: 1})
	if err != nil {
		return nil, fmt.Errorf("scan the DER simulator's register image for a SunSpec chain: %w", err)
	}
	seen := map[int]bool{}
	var out []int
	for _, b := range rdr.Blocks() {
		id := int(b.ModelID)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the DER simulator served a SunSpec header but no model blocks")
	}
	sort.Ints(out)
	return out, nil
}

// simRegisterImage decodes a simapi /registers body (addr-string -> value) into
// a register map. It is the small, unshared half of internal/invariant's
// registerImage — restated here rather than imported because invariant imports
// certify and the cycle is not worth a helper this size.
func simRegisterImage(raw map[string]any) (map[uint16]uint16, error) {
	out := make(map[uint16]uint16, len(raw))
	for k, v := range raw {
		addr, err := strconv.ParseUint(k, 10, 16)
		if err != nil {
			continue // a non-address key (a nested object) is not a register
		}
		switch n := v.(type) {
		case float64:
			out[uint16(addr)] = uint16(int64(n) & 0xFFFF)
		case json.Number:
			i, err := n.Int64()
			if err != nil {
				continue
			}
			out[uint16(addr)] = uint16(i & 0xFFFF)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the /registers response contained no numeric register entries")
	}
	return out, nil
}

// simMemTransport serves an in-memory register image to the SunSpec reader,
// read-only. It mirrors internal/invariant's memTransport (see simRegisterImage
// for why it is restated) — an unset register reads zero, as an unpopulated
// holding register does on the wire.
type simMemTransport struct {
	regs map[uint16]uint16
	unit uint8
}

func (m *simMemTransport) Open() error              { return nil }
func (m *simMemTransport) Close() error             { return nil }
func (m *simMemTransport) SetUnitID(id uint8) error { m.unit = id; return nil }

func (m *simMemTransport) ReadHolding(addr, quantity uint16) ([]uint16, error) {
	if quantity == 0 || quantity > 125 {
		return nil, fmt.Errorf("simMemTransport: illegal quantity %d", quantity)
	}
	out := make([]uint16, quantity)
	for i := uint16(0); i < quantity; i++ {
		out[i] = m.regs[addr+i]
	}
	return out, nil
}

func (m *simMemTransport) ReadInput(addr, quantity uint16) ([]uint16, error) {
	return m.ReadHolding(addr, quantity)
}

func (m *simMemTransport) WriteHolding(uint16, []uint16) error {
	return fmt.Errorf("simMemTransport is read-only: a preflight witness never writes")
}

// compile-time proof the local transport satisfies the vendored interface.
var _ modbus.Transport = (*simMemTransport)(nil)

// dedupSortedInts returns xs deduped and ascending.
func dedupSortedInts(xs []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, x := range xs {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Ints(out)
	return out
}

func intSet(xs []int) map[int]bool {
	s := make(map[int]bool, len(xs))
	for _, x := range xs {
		s[x] = true
	}
	return s
}

// modelsAOnly returns the members of a not present in b, ascending.
func modelsAOnly(a []int, b map[int]bool) []int {
	var out []int
	for _, x := range a {
		if !b[x] {
			out = append(out, x)
		}
	}
	sort.Ints(out)
	return out
}

func joinProblems(ps []string) string {
	out := ""
	for i, p := range ps {
		if i > 0 {
			out += "\n  - "
		}
		out += p
	}
	return out
}
