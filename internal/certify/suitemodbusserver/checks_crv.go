package suitemodbusserver

// checks_crv.go implements CRV-1, Curve 1 Support, of SunSpec Modbus
// Conformance Test Procedures v1.4 §2.5.1.
//
// # Why CRV-1 is here and CRV-2 / CRV-3 are not
//
// The three curve procedures are not one family. CRV-1 asserts a REFUSAL —
// curve 1 exists, is declared read-only, and its points cannot be written —
// while CRV-2 and CRV-3 both require a WRITABLE second curve and the
// adopt-curve handshake that commits it. The DUT's read-only posture is what
// makes CRV-2 and CRV-3 unrunnable and is exactly what CRV-1 asks about, so the
// three separate on the product's own behaviour rather than on the fact that
// they share a section number.
//
// # The correction this file records
//
// Until 2026-07-28 all three were catalogued inapplicable with the same reason:
// that the gateway's chain builder REJECTS models 705-712 northbound. That
// stopped being true when the curve models joined the class chains, and the
// current shape is device-conditional: a unit carries 703 and 705-712 if and
// only if its own DER serves them southbound (lexa-gw
// internal/regmap/chain.go's deviceConditionalModels, applied by
// ClassModelsFor). So a curve model IS reachable northbound, and whether one is
// present on a given unit is a fact about that unit's DER — which is the same
// per-(build, DER model) scoping MOD-4 carries.
//
// # What this check can and cannot assert, stated once
//
// Step 1 — a curve-based model is present — is answered from the discovery
// walk, for real, with the chain's own frames behind it.
//
// Steps 2 and 3 are not answerable by this suite today and are reported as
// SKIPs naming why. The curve models size their repeating blocks from NPt /
// NCrv / NCrvSet / NCtl read out of the device, this suite carries no
// transcription of the resulting layout (the same gap sweepModels and checkMOD4
// already report for those models), and the read-only indicator and the
// registers a write test would target therefore cannot be located. Locating
// them by arithmetic on a guessed geometry would produce a confident verdict
// about whichever registers the guess landed on, which is worse than no verdict
// at all: it would read as evidence.
//
// A registered SKIP with a reason is an engineering judgement. An unregistered
// row is an oversight. That is why this check exists in this shape rather than
// not existing.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

const (
	crv1ClaimSubject = "a curve-based model of the 7xx range is present in the DUT's northbound " +
		"projection, which is CTP §2.5's precondition for performing the curve tests at all"
	crv1ClaimReadOnly = "curve 1 is present in the model's curve repeating block and is declared " +
		"read-only by the device"
	crv1ClaimRefused = "a write to a point belonging to curve 1 does not take effect: the DUT answers " +
		"with a Modbus exception (per EXC-2, code 2, 3 or 4) or the value reads back unchanged"
)

// crv1NoLayout is the reason steps 2 and 3 cannot be asserted. It names the
// suite's own gap rather than anything about the DUT, because a reader who
// mistook it for a DUT finding would be reading a harness limit as a defect.
const crv1NoLayout = "this suite carries no transcription of the curve models' layout. Models 705-712 " +
	"size their repeating blocks from the NPt / NCrv / NCrvSet / NCtl geometry points read out of the " +
	"device, so curve 1's sub-block, its read-only indicator point (which the source document does not " +
	"name) and the registers a write attempt would target cannot be located from this suite's model " +
	"transcriptions. Computing them from a guessed geometry would yield a verdict about whichever " +
	"registers the guess landed on. Closing this needs the flattened curve layouts transcribed into " +
	"models.go, the same gap MOD-4's per-point sweep reports for these models"

// checkCRV1 implements SS-MODBUS-CONF-v1.4 CRV-1, Curve 1 Support.
//
// The procedure is labelled per model — CRV-1.705, CRV-1.706 and so on — and
// the catalog carries one row, so the check sweeps every curve model the walk
// found and reports them together, exactly as MOD-1..MOD-3 do.
func checkCRV1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "CRV-1 curve 1 support")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	var curves, all []string
	for _, ref := range ch.Models {
		all = append(all, fmt.Sprintf("%d", ref.ID))
		if curveModels[ref.ID] {
			curves = append(curves, fmt.Sprintf("%d", ref.ID))
		}
	}

	subject := len(curves) > 0
	observed := fmt.Sprintf("chain: %s; curve-based (7xx) models present: %s",
		orNone(all), orNone(curves))

	notes := fmt.Sprintf("%s. Steps 2 and 3 were not asserted: %s.", observed, crv1NoLayout)
	if !subject {
		notes = fmt.Sprintf("%s. CTP §2.5's precondition scopes the curve tests to 'each curve-based "+
			"model implemented in the device', and this unit implements none, so the procedure has no "+
			"subject here. On this DUT that is a statement about the DER behind the unit rather than "+
			"about the gateway: the curve and trip models are chained device-conditionally, a unit "+
			"carrying one only if its own DER serves it southbound.", observed)
	}

	return certify.Result{
		// SKIP either way: with no curve model there is nothing to test, and
		// with one there are two steps this suite cannot reach. Neither is a
		// statement about the DUT's conformance and neither may be reported as
		// one.
		Verdict: certify.Skip,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason, crv1ClaimSubject, crv1ClaimReadOnly, crv1ClaimRefused), nil
			}
			var out []certify.Assertion
			t, err := c.transportAssertion()
			if err != nil {
				return nil, err
			}
			out = append(out, t)

			// Step 1's precondition, from the chain the walk actually read.
			if subject {
				a, err := c.frames(crv1ClaimSubject,
					"the SunSpec model chain walked from the standard base address",
					certify.Pass, observed, tidsFor(s.client.log, "DEV-1 model header"))
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			} else {
				out = append(out, ev.SkipAssertion(crv1ClaimSubject,
					"the SunSpec model chain walked from the standard base address",
					"the chain carries no 7xx curve model on this unit — "+observed+
						". The gateway chains 703 and 705-712 device-conditionally, so this is a "+
						"property of the DER behind the unit, and the procedure's own precondition "+
						"excludes it"))
			}

			out = append(out,
				ev.SkipAssertion(crv1ClaimReadOnly, "read of the curve repeating block", crv1NoLayout),
				ev.SkipAssertion(crv1ClaimRefused, "write attempt to a curve-1 point", crv1NoLayout))
			return out, nil
		},
	}, nil
}

func orNone(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, ", ")
}
