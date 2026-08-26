package suitemodbusserver

// checks_1547.go implements the two server-side procedures of SunSpec Modbus
// for IEEE 1547 Test Procedures: §2.3.1 MOD-4 Mandatory Points and §2.4 Scale
// Factor Test.
//
// Both are procedures whose pass criterion lives in another document. MOD-4
// says "compare the point to the list of mandatory points for IEEE 1547
// implementation" and prints no list; §2.4 says "verify the scale factor value
// lies in the acceptable range to meet the IEEE 1547 requirements" and prints
// no ranges. The lists this suite compares against are in profile1547.go, and
// every assertion below names that file so a reviewer can check the
// transcription instead of taking the verdict on trust.
//
// MOD-4 is the row this DUT is expected to fail, and the failure is the useful
// output. The IEEE 1547-2018 profile requires models 703 and 705 through 712;
// the gateway's northbound projection serves none of them — they are
// implemented southbound and are rejected by the northbound chain builder as a
// v1 product policy. That is a real gap between what the product exposes and
// what the profile demands, it is exactly what a certification reviewer would
// find, and softening it into a PASS scoped to whatever the device happens to
// serve would make this tool worthless. The check reports FAIL, names every
// missing model, and offers -param 1547.require-models only so that a PICS-
// scoped claim can be recorded deliberately, with the override printed in the
// bundle.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
)

// storageCapability decides whether the profile's storage requirements — model
// 713 (DERStorageCapacity) and model 702's charge-rate ratings — apply to this
// candidate, and returns the signal it used so the evidence bundle names it.
//
// Model 713 is "conditionally optional ... for an implementation that does not
// support storage" (profile §3, Table 30 note; ProfileModelConditional). Read
// the other way, that same sentence REQUIRES it of an implementation that DOES
// support storage. The signals, in order of authority:
//
//   - the DUT serving model 713 on the wire is the profile's own marker for
//     storage support, so a DUT that serves it is storage-capable (and, being
//     present, is not among the missing models this governs);
//   - otherwise the candidate manifest's declaration: topology.role == "battery"
//     is storage, and a manifest that lists model 713 among the models it serves
//     is claiming storage even where its role does not;
//   - otherwise — no manifest, and no 713 on the wire — the candidate is treated
//     as NON-storage. This is the pre-manifest behaviour, and the right default
//     for the RC0 candidate: a solar 7xx inverter must not be failed for
//     omitting a storage model it does not have (advertising one it lacks would
//     be the opposite defect — a false capability claim).
func storageCapability(rc *certify.RunCtx, present map[uint16]bool) (bool, string) {
	if present[storageModel] {
		return true, fmt.Sprintf(
			"the DUT serves model %d on the wire, the profile's own marker for storage support", storageModel)
	}
	if rc != nil {
		if m := rc.Manifest(); m != nil {
			if strings.EqualFold(m.Role, "battery") {
				return true, fmt.Sprintf("the candidate manifest declares topology.role=%q (%s)", m.Role, m.Path())
			}
			for _, id := range m.Models {
				if id == int(storageModel) {
					return true, fmt.Sprintf(
						"the candidate manifest lists model %d among its served models (%s)", storageModel, m.Path())
				}
			}
			return false, fmt.Sprintf(
				"the candidate manifest declares topology.role=%q and lists no model %d, so it does not "+
					"support storage (%s)", m.Role, storageModel, m.Path())
		}
	}
	return false, fmt.Sprintf(
		"no candidate manifest was supplied and the DUT serves no model %d, so storage is not assumed "+
			"(the pre-manifest behaviour)", storageModel)
}

// checkMOD4 implements SS-1547-TEST-v1.1 MOD-4, Mandatory Points.
//
// Steps: for each model, read the points; compare them against the list of
// mandatory points for IEEE 1547 implementation; verify all the required points
// are implemented in the model; verify every required model is implemented.
func checkMOD4(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "MOD-4 IEEE 1547 mandatory points")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	required := ProfileModels
	override := paramOr(rc, param1547Models, "")
	if override != "" {
		required, err = parseModelList(override)
		if err != nil {
			return certify.Result{}, err
		}
	}
	present := ch.PresentSet()
	// Whether the profile's storage requirements — model 713 and model 702's
	// charge-rate ratings — apply to this candidate. A storage-capable
	// candidate must serve model 713; a non-storage inverter must not be failed
	// for omitting a storage model it does not have.
	storageCapable, storageSignal := storageCapability(rc, present)
	hardMissing, condMissing := missingModels(present, required, storageCapable)

	// The DUT's own AC topology decides which of model 701's six voltage points
	// the profile actually requires of it.
	acType, acTypeKnown := uint16(0), false
	blocks := map[uint16][]uint16{}
	for _, ref := range ch.Models {
		if _, ok := Models[ref.ID]; !ok {
			continue
		}
		block, berr := readModelBlock(s.client, ref, fmt.Sprintf("MOD-4 model %d", ref.ID))
		if berr != nil {
			return certify.Result{}, fmt.Errorf("read model %d: %w", ref.ID, berr)
		}
		blocks[ref.ID] = block
		if ref.ID == 701 {
			if p, ok := Models[701].Point("ACType"); ok {
				if regs, ok := pointRegs(block, p); ok && len(regs) == 1 && !p.Type.NotImplemented(regs) {
					acType, acTypeKnown = regs[0], true
				}
			}
		}
	}

	type pointResult struct {
		Model   uint16
		OK      bool
		Text    string
		Skipped string
		TIDs    []uint16
	}
	var perModel []pointResult
	pointsOK := true

	for _, id := range required {
		if !present[id] {
			continue // covered by the missing-models assertion
		}
		def, transcribed := Models[id]
		reqNames, haveList := requiredPoints[id]
		switch {
		case !transcribed:
			perModel = append(perModel, pointResult{Model: id, Skipped: fmt.Sprintf(
				"this suite carries no transcription of model %d's layout (it is a runtime-geometry curve "+
					"model), so its required points cannot be located on the wire", id)})
			continue
		case !haveList:
			perModel = append(perModel, pointResult{Model: id, Skipped: fmt.Sprintf(
				"profile1547.go carries no required-point list for model %d", id)})
			continue
		}
		ref, _ := ch.Model(id)
		block := blocks[id]
		var bad, excused []string
		for _, name := range reqNames {
			need, excuse := pointRequired(id, name, acType, acTypeKnown, storageCapable)
			if !need {
				excused = append(excused, fmt.Sprintf("%s (%s)", name, excuse))
				continue
			}
			p, ok := def.Point(name)
			if !ok {
				bad = append(bad, fmt.Sprintf("%s: the model definition this suite transcribed has no such point", name))
				continue
			}
			regs, ok := pointRegs(block, p)
			if !ok {
				bad = append(bad, fmt.Sprintf("%s: the model's declared length does not reach its offset %d", name, p.Off))
				continue
			}
			if p.Type.NotImplemented(regs) {
				bad = append(bad, fmt.Sprintf("%s (%s @%d): reads its type's not-implemented value",
					name, p.Type, int(ref.Addr)+p.Off))
			}
		}
		pr := pointResult{Model: id, OK: len(bad) == 0, TIDs: tidsFor(s.client.log, fmt.Sprintf("MOD-4 model %d", id))}
		if pr.OK {
			pr.Text = fmt.Sprintf("all %d profile-required points of model %d are implemented", len(reqNames), id)
			if len(excused) > 0 {
				pr.Text += "; not required of this device: " + strings.Join(excused, ", ")
			}
		} else {
			pr.Text = strings.Join(bad, "; ")
			pointsOK = false
		}
		perModel = append(perModel, pr)
	}

	modelsOK := len(hardMissing) == 0
	verdict := verdictIf(modelsOK && pointsOK)

	notes := fmt.Sprintf("the DUT serves %v; the IEEE 1547-2018 profile requires %v", ch.IDs(), required)
	if len(hardMissing) > 0 {
		notes += fmt.Sprintf("; MISSING %v", hardMissing)
	}
	if len(condMissing) > 0 {
		notes += fmt.Sprintf("; conditionally optional and absent: %v", condMissing)
	}
	notes += "; storage support: " + storageSignal
	if override != "" {
		notes += "; the required-model list was overridden by -param " + param1547Models + "=" + override
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"every model the IEEE 1547-2018 profile requires is implemented in the device",
					"every point the IEEE 1547-2018 profile marks mandatory is implemented in its model"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}

			// Step 4 — every required model implemented. The chain walk's
			// terminator is what makes an ABSENCE provable: a model missing
			// from a chain that demonstrably ended is missing, not merely
			// unlooked-for.
			obs := fmt.Sprintf("the discovery walk found %v and terminated on the end model at %d; the profile "+
				"requires %v", ch.IDs(), ch.EndAddr, required)
			if len(hardMissing) > 0 {
				obs += fmt.Sprintf("; ABSENT: %v", hardMissing)
			}
			for _, id := range condMissing {
				obs += fmt.Sprintf("; model %d absent — %s", id, ProfileModelConditional[id])
			}
			// Model 713's classification above turns on whether the candidate
			// supports storage; the signal is recorded so a reviewer sees WHY a
			// missing 713 was a shrug or a failure on this run.
			obs += "; storage support: " + storageSignal
			a, err := c.frames(
				"every SunSpec model the IEEE 1547-2018 profile requires is implemented in the device",
				"the complete SunSpec discovery walk, terminated on the end model, compared against the "+
					"profile's required-model list transcribed in profile1547.go from the SunSpec Modbus "+
					"IEEE 1547-2018 Profile Specification §3",
				verdictIf(modelsOK), obs, tidsFor(s.client.log, "DEV-1 model header"))
			if err != nil {
				return nil, err
			}
			if !ch.EndSeen {
				a.Note = joinNote(a.Note, "the chain did not terminate on an end model, so an absence cannot "+
					"be distinguished from an incomplete walk")
			}
			if override != "" {
				a.Note = joinNote(a.Note, "the required-model list was OVERRIDDEN by -param "+
					param1547Models+"="+override+"; this assertion is scoped to that list, not to the "+
					"profile's own")
			}
			out = append(out, a)

			// Steps 1-3 — per model, every required point implemented.
			for _, pr := range perModel {
				claim := fmt.Sprintf("MOD-4.%d: every point the IEEE 1547-2018 profile marks mandatory for "+
					"model %d is implemented", pr.Model, pr.Model)
				method := "FC 3 read of the model's whole register block; each profile-required point compared " +
					"against its type's not-implemented sentinel, with model 701's voltage points judged " +
					"against the device's own ACType per the profile's applicability qualifier"
				if pr.Skipped != "" {
					out = append(out, ev.SkipAssertion(claim, method, pr.Skipped))
					continue
				}
				a, err := c.frames(claim, method, verdictIf(pr.OK), pr.Text, pr.TIDs)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			// The procedure's own precondition, recorded so the bundle does not
			// imply a PICS was consulted.
			out = append(out, ev.SkipAssertion(
				"the device PICS agrees with the profile's mandatory-point list",
				"comparison of the PICS workbook against the profile specification",
				"no PICS workbook was supplied; MOD-4 was executed against profile1547.go's transcription of "+
					"the SunSpec Modbus IEEE 1547-2018 Profile Specification, which is the document the test "+
					"procedure delegates its list to"))
			return out, nil
		},
	}, nil
}

// checkSF implements SS-1547-TEST-v1.1 §2.4, the Scale Factor Test.
//
// Steps: for each implemented point that has a scale factor, read the scale
// factor value and verify it lies in the acceptable range for the point's data
// type.
//
// The document gives no ranges. Three things can be asserted without inventing
// any:
//
//   - Every sunssf value must be in -10..10, or be the not-implemented
//     sentinel 0x8000. That is the type's definition in the SunSpec Device
//     Information Model Specification, and it is the outer bound any
//     "acceptable range" sits inside.
//   - Every scale factor the IEEE 1547 profile lists as required for a model
//     must be implemented — a scaled point whose scale factor reads
//     not-implemented has no engineering value at all.
//   - A scale factor MUST be static. The specification says so in as many
//     words, and it is cheap to demonstrate: read every scale factor twice,
//     separated by the rest of the sweep, and compare.
//
// Anything narrower than that would be this suite inventing the 1547 accuracy
// requirements, and it says so rather than doing it.
func checkSF(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	s, res, err := open(ctx, rc, "1547 §2.4 scale factor test")
	if s == nil {
		return res, err
	}
	defer s.Close()

	ch, err := discover(s.client)
	if err != nil {
		return certify.Result{}, fmt.Errorf("discovery walk: %w", err)
	}

	type sfObs struct {
		Model uint16
		Name  string
		Addr  uint16
		First []uint16
		Again []uint16
		Bad   string
	}
	var observed []sfObs
	var skippedModels []string
	scaledButUnimplemented := map[string][]string{}

	before := len(s.client.log)
	for _, ref := range ch.Models {
		def, ok := Models[ref.ID]
		if !ok {
			skippedModels = append(skippedModels, fmt.Sprintf("%d", ref.ID))
			continue
		}
		block, berr := readModelBlock(s.client, ref, fmt.Sprintf("2.4 model %d first read", ref.ID))
		if berr != nil {
			return certify.Result{}, fmt.Errorf("read model %d: %w", ref.ID, berr)
		}
		for _, p := range def.ScaleFactors() {
			regs, ok := pointRegs(block, p)
			if !ok {
				continue
			}
			o := sfObs{Model: ref.ID, Name: p.Name, Addr: ref.Addr + uint16(p.Off), First: regs}
			if !p.Type.InDatatypeRange(regs) {
				o.Bad = fmt.Sprintf("value %d is outside the sunssf range -10..10 and is not the "+
					"not-implemented sentinel 0x8000", int16(regs[0]))
			}
			observed = append(observed, o)
		}
		// A point that declares a scale factor whose sunssf reads
		// not-implemented has no engineering value; record it per model.
		for _, p := range def.Points {
			if p.SF == "" {
				continue
			}
			sfp, ok := def.Point(p.SF)
			if !ok {
				continue
			}
			sfRegs, ok := pointRegs(block, sfp)
			if !ok || !sfp.Type.NotImplemented(sfRegs) {
				continue
			}
			pr, ok := pointRegs(block, p)
			if !ok || p.Type.NotImplemented(pr) {
				continue // the point itself is unimplemented; nothing to scale
			}
			key := fmt.Sprintf("%d", ref.ID)
			scaledButUnimplemented[key] = append(scaledButUnimplemented[key],
				fmt.Sprintf("%s is implemented but its scale factor %s is not", p.Name, p.SF))
		}
	}

	// The static-value demonstration: re-read every scale factor after the
	// whole sweep and compare.
	for i := range observed {
		o := &observed[i]
		regs, rerr := s.client.readHolding(o.Addr, 1,
			fmt.Sprintf("2.4 re-read %d.%s for the static-value check", o.Model, o.Name))
		if rerr != nil {
			if o.Bad == "" {
				o.Bad = "the scale factor could not be re-read: " + errText(rerr)
			}
			continue
		}
		o.Again = regs
		if regs[0] != o.First[0] && o.Bad == "" {
			o.Bad = fmt.Sprintf("the scale factor changed from %d to %d between two reads; the specification "+
				"requires a scale factor's value to be static", int16(o.First[0]), int16(regs[0]))
		}
	}
	tids := tidsSince(s.client, before)

	// Profile-required scale factors.
	var missingSF []string
	for _, ref := range ch.Models {
		want, ok := requiredScaleFactors[ref.ID]
		if !ok {
			continue
		}
		def, transcribed := Models[ref.ID]
		if !transcribed {
			continue
		}
		for _, name := range want {
			p, ok := def.Point(name)
			if !ok {
				missingSF = append(missingSF, fmt.Sprintf("%d.%s: absent from the model definition", ref.ID, name))
				continue
			}
			found := false
			for _, o := range observed {
				if o.Model == ref.ID && o.Name == name {
					found = true
					if p.Type.NotImplemented(o.First) {
						missingSF = append(missingSF, fmt.Sprintf("%d.%s: reads the not-implemented value 0x8000",
							ref.ID, name))
					}
				}
			}
			if !found {
				missingSF = append(missingSF, fmt.Sprintf("%d.%s: not present in the device's register block",
					ref.ID, name))
			}
		}
	}

	rangeOK := true
	var lines []string
	for _, o := range observed {
		v := int16(o.First[0])
		txt := fmt.Sprintf("%d.%s@%d=%d", o.Model, o.Name, o.Addr, v)
		if uint16(v) == 0x8000 {
			txt = fmt.Sprintf("%d.%s@%d=not implemented", o.Model, o.Name, o.Addr)
		}
		if o.Bad != "" {
			txt += " ** " + o.Bad
			rangeOK = false
		}
		lines = append(lines, txt)
	}
	sort.Strings(lines)

	verdict := verdictIf(rangeOK && len(missingSF) == 0)
	if len(observed) == 0 {
		verdict = certify.Skip
	}
	notes := fmt.Sprintf("%d scale factor(s) read across %d model(s)", len(observed), len(ch.Models))
	if len(skippedModels) > 0 {
		notes += "; not transcribed by this suite: " + strings.Join(skippedModels, ", ")
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			c, reason := newCiter(ev, s, false)
			if c == nil {
				return skipAll(ev, reason,
					"every scale factor lies inside the sunssf range and is static",
					"every scale factor the IEEE 1547 profile requires is implemented",
					"each scale factor's acceptable range under IEEE 1547 is satisfied"), nil
			}
			out, err := transportPlus(c, verdict)
			if err != nil {
				return nil, err
			}
			if len(observed) == 0 {
				out = append(out, ev.SkipAssertion(
					"every implemented scale-factored point carries a scale factor in the acceptable range",
					"FC 3 read of every sunssf point in every transcribed model",
					"the DUT serves no model this suite has a transcription for, so no scale-factor point "+
						"could be located"))
				return out, nil
			}

			a, err := c.frames(
				"every scale factor the device implements lies inside the sunssf type's range of -10..10, or "+
					"reads the defined not-implemented value, and does not change between two reads",
				"FC 3 read of every sunssf point in every transcribed model, re-read after the sweep; the "+
					"range is the sunssf definition in the SunSpec Device Information Model Specification "+
					"§4.2.4, and the static-value requirement is §4.2.8",
				verdictIf(rangeOK), strings.Join(lines, ", "), tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			sfObsText := "every scale factor the profile requires is implemented"
			if len(missingSF) > 0 {
				sfObsText = strings.Join(missingSF, "; ")
			}
			a, err = c.frames(
				"every scale factor the IEEE 1547-2018 profile lists as required for a model the device "+
					"implements is itself implemented",
				"the profile's per-model required scale-factor list, transcribed in profile1547.go from the "+
					"profile specification §3, compared against the sunssf values read from the device",
				verdictIf(len(missingSF) == 0), sfObsText, tids)
			if err != nil {
				return nil, err
			}
			out = append(out, a)

			if len(scaledButUnimplemented) > 0 {
				var s2 []string
				for k, v := range scaledButUnimplemented {
					s2 = append(s2, fmt.Sprintf("model %s: %s", k, strings.Join(v, ", ")))
				}
				sort.Strings(s2)
				a, err = c.frames(
					"no point the device implements is left without an engineering value by an unimplemented "+
						"scale factor",
					"for every implemented point that declares a scale factor, the referenced sunssf point is "+
						"checked for the not-implemented sentinel",
					certify.Fail, strings.Join(s2, "; "), tids)
				if err != nil {
					return nil, err
				}
				out = append(out, a)
			}

			out = append(out, ev.SkipAssertion(
				"each scale factor lies in the acceptable range required to meet the IEEE 1547 requirements "+
					"for its point's data type",
				"comparison against the per-point IEEE 1547 accuracy and range requirements",
				"the test procedure does not enumerate those ranges — it delegates them to IEEE 1547-2018 and "+
					"the device PICS, neither of which was supplied. The assertions above establish the outer "+
					"bound (the sunssf type's own range, staticness, and the profile's required-scale-factor "+
					"list); the per-point accuracy envelope is not asserted, and this suite will not invent it"))
			return out, nil
		},
	}, nil
}
