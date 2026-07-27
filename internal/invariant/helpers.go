package invariant

// helpers.go holds the handful of things more than one invariant needs: the
// enumeration of "every device register image this observation contains", the
// point-value lookups several checkers compare against, and the small
// vocabulary for talking about which witness a fact came from.
//
// The enumeration is worth a word. Two independent witnesses publish a model
// 704 for the same physical inverter: the DER itself (its own register image,
// read from the device) and the DUT (its northbound projection of that device,
// read over :802). Several invariants care about both, for different reasons —
// I1 because a projection that exceeds the device's own nameplate is a
// violation wherever it is observed, I7 because a projection that disagrees
// with the device is the DUT claiming something that did not happen. Rather
// than have each checker re-derive the pairing, [deviceViews] returns them all,
// labelled with which witness they came from.

import (
	"fmt"
	"sort"
	"time"
)

// witness names which independent observer produced a register image.
type witness string

const (
	// witnessDER — the device's own account of itself. Ground truth.
	witnessDER witness = "der"
	// witnessDUT — the DUT's northbound projection of a device. A claim.
	witnessDUT witness = "dut"
)

// devView is one device register image with its provenance.
type devView struct {
	// Witness says whether this is the device's own account or the DUT's.
	Witness witness
	// Label is a stable identifier for facts, e.g. "der.inv-plain" or
	// "dut.unit3".
	Label string
	// Device is the bench name of the physical device, when known — the key
	// that pairs a DER's own view with the DUT's projection of it.
	Device string
	// Source is the observation channel.
	Source string
	Unit   UnitView
}

// deviceViews enumerates every register image in an observation: each reachable
// DER's own image first, then the DUT's projection of each served unit.
func deviceViews(o *Observation) []devView {
	var out []devView
	for _, name := range o.DERNames() {
		d := o.DERs[name]
		if !d.Reachable {
			continue
		}
		out = append(out, devView{
			Witness: witnessDER,
			Label:   "der." + name,
			Device:  name,
			Source:  d.Source,
			Unit:    d.Unit,
		})
	}
	if o.DUT.Reachable {
		for _, u := range o.DUT.UnitIDs() {
			out = append(out, devView{
				Witness: witnessDUT,
				Label:   fmt.Sprintf("dut.unit%d", u),
				Device:  fmt.Sprintf("unit%d", u),
				Source:  o.DUT.Source,
				Unit:    o.DUT.Units[u],
			})
		}
	}
	return out
}

// derViews enumerates only the devices' own accounts of themselves.
func derViews(o *Observation) []devView {
	var out []devView
	for _, v := range deviceViews(o) {
		if v.Witness == witnessDER {
			out = append(out, v)
		}
	}
	return out
}

// commandOf returns the named 704 command from a decoded set.
func commandOf(cmds []Command, point string) (Command, bool) {
	for _, c := range cmds {
		if c.Point == point {
			return c, true
		}
	}
	return Command{}, false
}

// enabledCommands returns the commands the device's own mode enums say are
// presently governing.
func enabledCommands(cmds []Command) []Command {
	var out []Command
	for _, c := range cmds {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out
}

// unreachableReason renders a one-line summary of which witnesses were
// unreachable, for a SKIP that must name what it was missing.
func unreachableReason(o *Observation) string {
	var missing []string
	if !o.DUT.Reachable {
		missing = append(missing, "DUT northbound")
	}
	for _, n := range o.DERNames() {
		if !o.DERs[n].Reachable {
			missing = append(missing, "DER "+n)
		}
	}
	if !o.HeadEnd.Reachable {
		missing = append(missing, "head-end")
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return "every witness was reachable"
	}
	return "unreachable: " + joinComma(missing)
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// skipf builds a Skip result with a formatted reason.
func skipf(format string, args ...any) Result {
	return Result{Verdict: Skip, Reason: fmt.Sprintf(format, args...)}
}

// dur renders a duration for a fact value.
func dur(d time.Duration) string { return d.Round(time.Second).String() }
