package suitemodbusserver

// checks_dev.go implements the two General Device Tests of SunSpec Modbus
// Conformance Test Procedures v1.4 §2.3: DEV-1 General Discovery and DEV-2
// Model 1 Support.
//
// These two are the foundation. If the identifier is not where the
// specification says, or the chain does not terminate, then every other
// procedure in both documents is reading registers whose meaning is
// unestablished — so DEV-1 asserts each of its three steps separately rather
// than rolling them into one verdict, and it cites the negative base probes as
// well as the positive one, because "the content is located at one of the
// standard start addresses" is a claim about all three addresses.

import (
	"context"
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
)

// checkDEV1 implements SS-MODBUS-CONF-v1.4 DEV-1, General Discovery.
//
// Steps, verbatim: (1) the models the PICS declares are found by the standard
// discovery procedure; (2) the content is at one of the standard start
// addresses 0 / 40000 / 50000 and begins with the two-register start marker;
// (3) the end model, ID 65535, is present with length 0.
//
// The document does not print the marker's value; it comes from the SunSpec
// Device Information Model Specification §6.1.1 and is transcribed in walk.go.
func checkDEV1(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "DEV-1 general discovery")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, walkErr := discover(s.client)

	baseFound := uint16(0)
	baseOK := false
	var probeText []string
	for _, p := range ch.Probes {
		probeText = append(probeText, p.String())
		if p.Found() && !baseOK {
			baseFound, baseOK = p.Base, true
		}
	}
	multiBase := 0
	for _, p := range ch.Probes {
		if p.Found() {
			multiBase++
		}
	}

	endOK := ch.EndSeen && ch.EndLen == 0
	walkOK := walkErr == nil

	verdict := certify.Pass
	notes := ch.Summary()
	switch {
	case !baseOK:
		verdict = certify.Fail
		notes = "no SunSpec identifier at any standard base address: " + strings.Join(probeText, "; ")
	case !walkOK:
		verdict = certify.Fail
		notes = fmt.Sprintf("the model chain walk from base %d did not complete: %v", baseFound, walkErr)
	case !endOK:
		verdict = certify.Fail
		notes = fmt.Sprintf("the chain does not terminate correctly: %s", ch.Summary())
	}

	picsModels := paramOr(rc, paramPICSModels, "")

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"the SunSpec content is at a standard base address behind the two-register start marker",
					"the model chain is walkable by the standard discovery procedure",
					"the model chain is terminated by the end model, ID 65535 with length 0"), nil
			}
			var out []certify.Assertion
			t, err := c.transportAssertion()
			if err != nil {
				return nil, err
			}
			out = append(out, t)

			// Step 2 — base address and marker. Cite ALL three probes, so the
			// negative answers at the other two bases are in the bundle too.
			baseTIDs := tidsFor(s.client.log, "DEV-1 base probe")
			observed := strings.Join(probeText, "; ")
			if multiBase > 1 {
				observed += fmt.Sprintf(" — WARNING: the identifier answered at %d different base addresses", multiBase)
			}
			a, err := c.frames(
				"the SunSpec content is located at one of the standard start addresses (0, 40000, 50000) "+
					"and the first two registers there are the SunSpec start marker 0x5375 0x6E53",
				"FC 3 read of 2 registers at each of the three standard base addresses",
				verdictIf(baseOK && multiBase == 1), observed, baseTIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// Step 1 — the discovery walk itself.
			walkTIDs := tidsFor(s.client.log, "DEV-1 model header")
			walkObserved := ch.Summary()
			if walkErr != nil {
				walkObserved += " — " + walkErr.Error()
			}
			a, err = c.frames(
				"every model in the device is located by the standard SunSpec discovery procedure: "+
					"read the (ID, L) header, skip L registers, repeat",
				"successive FC 3 reads of 2-register model headers from base+2, following each declared length",
				verdictIf(walkOK), walkObserved, walkTIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// Step 3 — the end model.
			endObserved := "the walk did not reach an end model"
			if ch.EndSeen {
				endObserved = fmt.Sprintf("model ID 0x%04x with length %d at address %d", endModelID, ch.EndLen, ch.EndAddr)
			}
			a, err = c.frames(
				"the model chain is terminated by the SunSpec end model: ID 65535 with length 0",
				"FC 3 read of the two-register header at the address the walk arrived at",
				verdictIf(endOK), endObserved, walkTIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			// Step 1's PICS half. Without a PICS workbook there is nothing to
			// compare the discovered chain against, and saying so is the only
			// honest option: the chain cannot be its own specification.
			if picsModels == "" {
				out = append(out, ev.SkipAssertion(
					"every SunSpec model listed in the device PICS is located by the discovery walk",
					"comparison of the discovered chain against the PICS model list",
					"no PICS model list was supplied (-param "+paramPICSModels+"=1,701,702,...); "+
						"the discovered chain is recorded in the assertion above, but a chain cannot be "+
						"checked against itself"))
			} else {
				want, perr := parseModelList(picsModels)
				if perr != nil {
					return nil, perr
				}
				present := ch.PresentSet()
				var missing []uint16
				for _, id := range want {
					if !present[id] {
						missing = append(missing, id)
					}
				}
				obs := fmt.Sprintf("PICS declares %v; the walk found %v", want, ch.IDs())
				if len(missing) > 0 {
					obs += fmt.Sprintf("; missing %v", missing)
				}
				a, err = c.frames(
					"every SunSpec model listed in the device PICS is located by the discovery walk",
					"comparison of the discovered chain against the operator-supplied PICS model list",
					verdictIf(len(missing) == 0), obs, walkTIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}

// checkDEV2 implements SS-MODBUS-CONF-v1.4 DEV-2, Model 1 Support.
//
// One step: model 1 is present and its content matches the PICS. The PICS half
// needs an external input, so the check asserts what it can establish from the
// specification alone — presence, and that every point the Common Model marks
// mandatory carries a real value rather than the not-implemented sentinel — and
// compares the identity strings against -param pics.mn / pics.md / pics.sn when
// the operator supplies them.
func checkDEV2(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "DEV-2 model 1 support")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}
	m1, present := ch.Model(1)
	if !present {
		return certify.Result{
			Verdict: certify.Fail,
			Notes:   fmt.Sprintf("model 1 is absent from the chain; the DUT serves %v", ch.IDs()),
			Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
				c, reason := newCiter(ev, s, false)
				if c == nil {
					return skipAll(ev, reason, "SunSpec model 1 is present in the device model chain"), nil
				}
				return citeOne(c, "SunSpec model 1 is present in the device model chain",
					"SunSpec discovery walk of the whole chain",
					certify.Fail, fmt.Sprintf("the chain carries %v and no model 1", ch.IDs()),
					tidsFor(s.client.log, "DEV-1 model header", "DEV-2"))
			},
		}, nil
	}

	block, rerr := readModelBlock(s.client, m1, "DEV-2 model 1 read")
	if rerr != nil {
		return certify.Result{}, fmt.Errorf("read model 1 at %d: %w", m1.Addr, rerr)
	}

	def := Models[1]
	type pointObs struct {
		Point Point
		Regs  []uint16
		Text  string
		Bad   string
	}
	var obs []pointObs
	mandatoryOK := true
	for _, p := range def.Points {
		regs, ok := pointRegs(block, p)
		if !ok {
			obs = append(obs, pointObs{Point: p, Bad: "the model's declared length does not reach this point"})
			if p.Mandatory {
				mandatoryOK = false
			}
			continue
		}
		o := pointObs{Point: p, Regs: regs}
		switch p.Type {
		case TypeString:
			o.Text = decodeString(regs)
		case TypePad:
			o.Text = fmt.Sprintf("0x%04x", regs[0])
		default:
			o.Text = fmt.Sprintf("%d", regs[0])
		}
		if p.Mandatory && p.Type.NotImplemented(regs) {
			o.Bad = "mandatory, but reads the not-implemented value for its type"
			mandatoryOK = false
		}
		obs = append(obs, o)
	}

	identity := map[string]string{}
	for _, o := range obs {
		if o.Point.Type == TypeString {
			identity[o.Point.Name] = o.Text
		}
	}
	lengthOK := int(m1.L) == def.L

	// PICS comparison, when the operator supplied one.
	picsWant := map[string]string{
		"Mn": paramOr(rc, paramPICSMn, ""),
		"Md": paramOr(rc, paramPICSMd, ""),
		"SN": paramOr(rc, paramPICSSN, ""),
	}
	picsGiven := false
	picsMismatch := []string{}
	for k, want := range picsWant {
		if want == "" {
			continue
		}
		picsGiven = true
		if identity[k] != want {
			picsMismatch = append(picsMismatch, fmt.Sprintf("%s: device %q, PICS %q", k, identity[k], want))
		}
	}

	verdict := certify.Pass
	notes := fmt.Sprintf("model 1 at %d, L=%d, Mn=%q Md=%q SN=%q",
		m1.Addr, m1.L, identity["Mn"], identity["Md"], identity["SN"])
	if !mandatoryOK || !lengthOK || len(picsMismatch) > 0 {
		verdict = certify.Fail
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"SunSpec model 1 is present in the device model chain",
					"model 1's mandatory points all carry implemented values",
					"model 1's content matches the device PICS"), nil
			}
			var out []certify.Assertion
			t, err := c.transportAssertion()
			if err != nil {
				return nil, err
			}
			out = append(out, t)

			hdrTIDs := tidsFor(s.client.log, "DEV-1 model header")
			bodyTIDs := tidsFor(s.client.log, "DEV-2 model 1 read")

			a, err := c.frames(
				"SunSpec model 1 is present in the device model chain, with the length its definition fixes (66)",
				"FC 3 read of the two-register model header located by the discovery walk",
				verdictIf(lengthOK),
				fmt.Sprintf("header at %d reads ID=1 L=%d (definition: %d)", m1.Addr, m1.L, def.L),
				hdrTIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			var lines []string
			for _, o := range obs {
				line := fmt.Sprintf("%s=%s", o.Point.Name, o.Text)
				if o.Point.Mandatory {
					line += " [M]"
				}
				if o.Bad != "" {
					line += " ** " + o.Bad
				}
				lines = append(lines, line)
			}
			a, err = c.frames(
				"every point the Common Model definition marks mandatory (ID, L, Mn, Md, SN) carries an "+
					"implemented value in model 1",
				"FC 3 read of model 1's whole register block, decoded against this suite's own transcription "+
					"of the Common Model definition, and each mandatory point compared with its type's "+
					"not-implemented sentinel",
				verdictIf(mandatoryOK), strings.Join(lines, ", "), bodyTIDs)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			if !picsGiven {
				out = append(out, ev.SkipAssertion(
					"the content of model 1 matches what the device PICS declares",
					"comparison of the decoded model 1 identity against the PICS workbook",
					"no PICS identity was supplied (-param "+paramPICSMn+"/"+paramPICSMd+"/"+paramPICSSN+"); "+
						"the decoded identity is recorded in the assertion above, but a device cannot be its "+
						"own conformance statement"))
			} else {
				obsText := fmt.Sprintf("device Mn=%q Md=%q SN=%q", identity["Mn"], identity["Md"], identity["SN"])
				if len(picsMismatch) > 0 {
					obsText += "; mismatches: " + strings.Join(picsMismatch, ", ")
				}
				a, err = c.frames(
					"the content of model 1 matches what the device PICS declares",
					"comparison of the decoded model 1 identity strings against the operator-supplied PICS values",
					verdictIf(len(picsMismatch) == 0), obsText, bodyTIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}
			return out, nil
		},
	}, nil
}
