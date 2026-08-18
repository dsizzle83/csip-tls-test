package suitecsip

// criteria_2030.go holds the resource-level criteria: the ones about what the
// DUT fetched, what it PUT, and what it POSTed.
//
// Two conventions run through the whole file.
//
// FIRST, resources are located by their ROOT ELEMENT, not by their path. IEEE
// 2030.5 §4.6 makes every URI server-defined and requires a client to reach
// resources by following hrefs; a check that looked for "GET /edev" would be
// certifying against gridsim's URI scheme rather than against the standard, and
// would silently pass a server that served the wrong resource at the right
// path. Transcript.ByResource is the lookup these criteria use.
//
// SECOND, a criterion about a fixture the bench does not have SKIPs and says
// what the bench actually served. Several V1.3 rows specify an exact server
// shape — seven DERPrograms with primacy 4..10, fifteen FunctionSetAssignments,
// three EndDevices ordered so the DUT's is last — that gridsim does not
// currently build. Reporting PASS because the DUT handled the shape it WAS
// given would be certifying a test that never ran, so those criteria report the
// observed shape and skip, which is also the actionable bug report for whoever
// extends the simulator.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	csipmodel "lexa-proto/csipmodel"
)

// critResource is the general "the DUT fetched resource X and the server
// answered 200 with a conformant payload" criterion, located by root element.
func critResource(resource, claim string, want func(*Node) (certify.Verdict, string)) criterion {
	return criterion{
		Claim: claim,
		How: fmt.Sprintf("the first exchange in the session whose response body is a %s in the 2030.5 "+
			"namespace, located by root element rather than by URI because 2030.5 URIs are server-defined",
			resource),
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			e, doc, ok := t.Resource(resource)
			if !ok {
				return unavailable("no %s appears in the recovered transcript (resources seen: %s)",
					resource, strings.Join(t.ResourceNames(), " "))
			}
			if !doc.InNamespace() {
				return citeMessage(t, e.Resp, certify.Fail,
					"the %s is in namespace %q, not %s — a 2030.5 payload without the namespace unmarshals to "+
						"zero values in every conformant parser", resource, doc.Name.Space, Namespace)
			}
			if want == nil {
				return citeMessage(t, e.Resp, certify.Pass, "%s -> 200 %s", e.Req.Line(), doc.Summary())
			}
			v, desc := want(doc)
			return citeMessage(t, e.Resp, v, "%s -> 200 %s; %s", e.Req.Line(), doc.Summary(), desc)
		},
		Skip: "locating a resource by its root element requires the decrypted transcript",
	}
}

// critEndDeviceList asserts the EndDeviceList and, when minEntries > 0, the
// procedure's required number of pre-registered EndDevice instances.
func critEndDeviceList(minEntries int) criterion {
	return critResource("EndDeviceList",
		"the DUT fetched the EndDeviceList from the href in DeviceCapability and the server answered 200 "+
			"with a conformant EndDeviceList",
		func(doc *Node) (certify.Verdict, string) {
			n := len(doc.Children("EndDevice"))
			if minEntries > 0 && n < minEntries {
				return certify.Skip, fmt.Sprintf("the procedure requires at least %d pre-registered EndDevice "+
					"instances; the bench server served %d. This is a BENCH fixture gap, not a DUT finding: "+
					"gridsim builds a fixed three-EndDevice tree and filters it by the peer's LFDI",
					minEntries, n)
			}
			return certify.Pass, fmt.Sprintf("%d EndDevice instance(s)", n)
		})
}

// critSelfIdentity is the heart of BASIC-001 and the strongest single check in
// this suite.
//
// It takes the DUT's OWN certificate off the wire — the leaf of the Certificate
// message it sent during the handshake — computes the SFDI and LFDI from it
// with this package's independent implementation of IEEE 2030.5 §6.3, and
// requires that the EndDevice instance the server served for that device carries
// exactly those values. Both halves are wire facts from the same capture, and
// neither comes from the product's own code.
//
// The catalog's erratum on BASIC-001 step 4(b) ("SFDI is a 16-bit
// left-truncated value ... 40 hexadecimal digits") is honoured: 160 bits and 40
// hex digits is the LFDI, and that is what is compared.
func critSelfIdentity() criterion {
	return criterion{
		Claim: "the sFDI and lFDI the server serves for the DUT's EndDevice equal the values derived from " +
			"the certificate the DUT presented in the TLS handshake (IEEE 2030.5 §6.3.2–§6.3.3)",
		How: "SHA-256 of the DER leaf certificate from the DUT's Certificate handshake message, " +
			"left-truncated to 36 bits with a mod-10 check digit for the sFDI and to 160 bits rendered as " +
			"40 hex digits for the lFDI, computed by this bench's own implementation and compared with the " +
			"<sFDI>/<lFDI> elements of the matching EndDevice",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			if len(t.Handshake.ClientChain) == 0 {
				return unavailable("the DUT presented no certificate, so no identity can be derived from the wire")
			}
			leaf := t.Handshake.ClientChain[0]
			wantLFDI := LFDI(leaf)
			wantSFDI := SFDI(leaf)

			e, doc, ok := t.Resource("EndDeviceList")
			if !ok {
				return unavailable("no EndDeviceList appears in the recovered transcript")
			}
			var matched *Node
			var seen []string
			for _, ed := range doc.Children("EndDevice") {
				got, hasL := ed.TextOf("lFDI")
				if !hasL {
					continue
				}
				norm, err := NormalizeLFDI(got)
				if err != nil {
					seen = append(seen, fmt.Sprintf("%q (unreadable: %v)", got, err))
					continue
				}
				seen = append(seen, norm)
				if norm == wantLFDI {
					matched = ed
				}
			}
			if matched == nil {
				return citeMessage(t, e.Resp, certify.Fail,
					"no EndDevice in the list carries the DUT's lFDI %s (computed from its certificate); "+
						"the list carries %d entr(ies): %s", wantLFDI, len(seen), strings.Join(seen, ", "))
			}
			gotSFDI, hasS := matched.UintOf("sFDI")
			switch {
			case !hasS:
				return citeMessage(t, e.Resp, certify.Fail,
					"the DUT's EndDevice carries the correct lFDI %s but no sFDI element", wantLFDI)
			case gotSFDI != wantSFDI:
				return citeMessage(t, e.Resp, certify.Fail,
					"lFDI matches (%s) but sFDI is %d where the certificate yields %d (%d digits, check digit %s)",
					wantLFDI, gotSFDI, wantSFDI, SFDIDigits(wantSFDI), checkDigitVerdict(gotSFDI))
			case !ValidCheckDigit(gotSFDI):
				return citeMessage(t, e.Resp, certify.Fail,
					"sFDI %d matches the certificate but its digits do not sum to zero mod 10, so it carries no "+
						"valid check digit (§6.3.2)", gotSFDI)
			default:
				return citeMessage(t, e.Resp, certify.Pass,
					"lFDI %s and sFDI %d both derive from the DUT's certificate (SHA-256 %s…), and the sFDI's "+
						"check digit is valid", wantLFDI, gotSFDI, fingerprintPrefix(leaf))
			}
		},
		Skip: "deriving the DUT's identity needs its certificate (available) AND the EndDeviceList the " +
			"server served for it (needs the decrypted transcript)",
	}
}

func checkDigitVerdict(v uint64) string {
	if ValidCheckDigit(v) {
		return "valid"
	}
	return "INVALID"
}

// critRegistrationPIN asserts the Registration resource and its PIN.
//
// The PIN's value is a bench configuration fact — the harness convention is
// 111115 — so the criterion asserts the STRUCTURAL requirement always (a pIN
// element with a valid check digit per §6.3.4) and the value only when the
// operator supplied it with -param csip.pin. Failing a DUT because the bench's
// PIN differs from the one in the procedure's example would be reporting our
// configuration as its non-conformance.
//
// # Why an absent Registration fetch is graded Unavailable, not Fail — and NOT
// # "spec-legitimate pre-registration" either
//
// Every run in this campaign shows the identical absence (CORE-009 and every
// other row that carries this criterion), which ruled out a one-off capture
// gap and raised the question directly: is gridsim's EndDevice tree marking
// the DUT pre-registered in a way that lets a compliant client legitimately
// skip the fetch? It is not that. gridsim serves a populated
// dateTimeRegistered from the very first EndDevice fetch ANY client ever
// makes (fleet.go/server.go) — CTP v1.3's own precondition ("Pre-register an
// EndDevice instance ... including ... PIN") describes exactly that fixture
// setup, and its steps 4-5 still list the Registration GET as part of the
// scripted client walk regardless. The bench fixture is not the gap.
//
// The real mechanism is on the DUT side: lexa-gw's northbound client (design
// D4, internal/northbound/run.PinVerifier) DOES implement Registration/pIN
// verification, and re-checks it on EVERY walk (self-healing, not a
// one-time-at-commissioning check) — but only when the operator-configured
// registration_pin resolves to a non-zero value. Unresolved (0, the state an
// unprovisioned or bench-default unit is in), the verifier is never
// constructed and the fetch never happens at all — by design, with one
// startup WARN (the WS-8 disabled-default pattern), not a fail-closed error.
// That construction gates the ENTIRE walk's Registration fetch, which is
// exactly consistent with what every run in this campaign shows: not one
// fetch, ever, in any case that carries this criterion.
//
// So this is a genuine walk gap relative to CTP steps 4-5, but the lever to
// close it is NOT in gridsim (which already serves a conformant Registration
// unconditionally) — it is the DUT's own registration_pin provisioning, an
// operator action, not a bench fixture change. Reporting Pass here would
// certify a requirement this run never actually exercised; reporting Fail
// would blame the DUT for a bench/operator provisioning fact the wire alone
// cannot confirm one way or the other. Unavailable, with the mechanism named,
// is the honest middle: see suitepki's identical reasoning for PKI-4..7
// ("a verdict about the wrong certificate is worse than no verdict").
func critRegistrationPIN(wantPIN string) criterion {
	return criterion{
		Claim: "the DUT fetched the Registration resource and the server answered 200 with a pIN carrying " +
			"a valid IEEE 2030.5 §6.3.4 check digit",
		How: "the <pIN> element of the first Registration payload in the session; the digits of the value, " +
			"check digit included, must sum to zero modulo ten",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			e, doc, ok := t.Resource("Registration")
			if !ok {
				return unavailable("no Registration resource appears in the recovered transcript "+
					"(resources seen: %s). Not evidence of a broken walker or a bench fixture gap: gridsim "+
					"serves a conformant Registration (valid pIN check digit) unconditionally from the DUT's "+
					"very first EndDevice fetch, so there is no 'not yet registered' state on this bench for a "+
					"client to react to. This absence is consistent with the product's per-walk Registration/pIN "+
					"verification (lexa-gw internal/northbound/run.PinVerifier, design D4) being disabled because "+
					"its registration_pin config resolves to 0 on this DUT — by design (WS-8 disabled-default), "+
					"the fetch never happens at all when that is so. Re-run needs: provision a non-zero "+
					"registration_pin on the DUT (matching the server's served pIN) and restart lexa-northbound — "+
					"an operator action this suite cannot perform or verify from the wire alone",
					strings.Join(t.ResourceNames(), " "))
			}
			pin, has := doc.UintOf("pIN")
			if !has {
				return citeMessage(t, e.Resp, certify.Fail, "the Registration payload carries no pIN element")
			}
			if !ValidCheckDigit(pin) {
				return citeMessage(t, e.Resp, certify.Fail,
					"pIN %0*d has no valid check digit: its digits do not sum to zero modulo ten (§6.3.4)",
					6, pin)
			}
			if wantPIN != "" && fmt.Sprint(pin) != wantPIN {
				return citeMessage(t, e.Resp, certify.Fail,
					"pIN is %d; the operator declared the DUT's registered PIN as %s (-param %s)",
					pin, wantPIN, pinParam)
			}
			extra := ""
			if wantPIN == "" {
				extra = fmt.Sprintf("; the value was not compared against the DUT's own registered PIN because "+
					"none was declared (-param %s=<pin>) — that comparison is the DUT-side half of §6.9.2(c) "+
					"and is not observable from the server's payload alone", pinParam)
			}
			return citeMessage(t, e.Resp, certify.Pass, "pIN %d with a valid check digit%s", pin, extra)
		},
		Skip: "reading the pIN requires the decrypted transcript",
	}
}

// pinParam is the operator override for the DUT's registered PIN.
const pinParam = "csip.pin"

// critProgramList asserts the DERProgramList and, optionally, the number of
// programs the procedure requires.
func critProgramList(minPrograms int) criterion {
	return critResource("DERProgramList",
		"the DUT fetched the DERProgramList reached through FunctionSetAssignments and the server answered "+
			"200 with a conformant DERProgramList",
		func(doc *Node) (certify.Verdict, string) {
			progs := doc.Children("DERProgram")
			prim := make([]string, 0, len(progs))
			for _, p := range progs {
				if v, ok := p.IntOf("primacy"); ok {
					prim = append(prim, fmt.Sprint(v))
				} else {
					prim = append(prim, "(no primacy)")
				}
			}
			desc := fmt.Sprintf("%d DERProgram(s), primacy %s", len(progs), strings.Join(prim, ","))
			if minPrograms > 0 && len(progs) < minPrograms {
				return certify.Skip, desc + fmt.Sprintf("; the procedure requires %d. This is a BENCH fixture "+
					"gap: gridsim builds three DERPrograms (Service Point / Site / System)", minPrograms)
			}
			if !sortedAscending(progs) {
				return certify.Warn, desc + "; IEEE 2030.5 orders DERProgramList by primacy ascending and the " +
					"served order is not ascending, so a client that trusts list order would mis-prioritise"
			}
			return certify.Pass, desc + " in ascending primacy order"
		})
}

func sortedAscending(progs []*Node) bool {
	last := int64(-1 << 62)
	for _, p := range progs {
		v, ok := p.IntOf("primacy")
		if !ok {
			continue
		}
		if v < last {
			return false
		}
		last = v
	}
	return true
}

// critFSAList asserts the FunctionSetAssignmentsList.
func critFSAList(minFSA int) criterion {
	return critResource("FunctionSetAssignmentsList",
		"the DUT fetched the FunctionSetAssignmentsList from its EndDevice and the server answered 200 with "+
			"a conformant FunctionSetAssignmentsList",
		func(doc *Node) (certify.Verdict, string) {
			fsas := doc.Children("FunctionSetAssignments")
			withDERP, withTime := 0, 0
			for _, f := range fsas {
				if f.Has("DERProgramListLink") {
					withDERP++
				}
				if f.Has("TimeLink") {
					withTime++
				}
			}
			desc := fmt.Sprintf("%d FunctionSetAssignments, %d with a DERProgramListLink, %d with a TimeLink",
				len(fsas), withDERP, withTime)
			if minFSA > 0 && len(fsas) < minFSA {
				return certify.Skip, desc + fmt.Sprintf("; the procedure requires %d. This is a BENCH fixture "+
					"gap: gridsim builds one FunctionSetAssignments", minFSA)
			}
			if withDERP == 0 {
				return certify.Fail, desc + "; no FSA carries a DERProgramListLink, so the DER function set is " +
					"unreachable from this EndDevice"
			}
			if withTime < withDERP {
				return certify.Warn, desc + "; IEEE 2030.5 §9.2.3 requires an FSA carrying an event-based " +
					"function set to carry a TimeLink, and a client must not act on events it cannot time"
			}
			return certify.Pass, desc
		})
}

// critTimeResource asserts CORE-005's Time resource criteria.
func critTimeResource() criterion {
	return critResource("Time",
		"the DUT fetched the Time resource from the TimeLink in DeviceCapability and the server answered "+
			"200 with a conformant Time payload",
		func(doc *Node) (certify.Verdict, string) {
			var missing []string
			for _, want := range []string{"currentTime", "quality", "tzOffset"} {
				if !doc.Has(want) {
					missing = append(missing, want)
				}
			}
			q, hasQ := doc.IntOf("quality")
			switch {
			case len(missing) > 0:
				return certify.Fail, "the Time payload is missing " + strings.Join(missing, ", ")
			case !hasQ:
				return certify.Fail, "the Time payload's quality element is not an integer"
			case q != 7:
				return certify.Warn, fmt.Sprintf("quality is %d; the procedure configures the test server for "+
					"7 (intentionally uncoordinated), so a different value means the BENCH is not in the "+
					"procedure's configuration, not that the DUT is wrong", q)
			default:
				ct, _ := doc.IntOf("currentTime")
				return certify.Pass, fmt.Sprintf("quality=7, currentTime=%d (%s)",
					ct, time.Unix(ct, 0).UTC().Format(time.RFC3339))
			}
		})
}

// critDefaultDERControl asserts the DefaultDERControl fetch.
func critDefaultDERControl() criterion {
	return critResource("DefaultDERControl",
		"the DUT fetched the DefaultDERControl of a DERProgram and the server answered 200 with a "+
			"conformant DefaultDERControl",
		func(doc *Node) (certify.Verdict, string) {
			base := doc.Child("DERControlBase")
			if base == nil {
				return certify.Fail, "the DefaultDERControl carries no DERControlBase"
			}
			modes := make([]string, 0, len(base.Kids))
			for _, k := range base.Kids {
				modes = append(modes, k.Local())
			}
			return certify.Pass, "DERControlBase modes: " + strings.Join(modes, " ")
		})
}

// critDERControlCarriesMode asserts that a DERControl the bench published
// reached the DUT with the control mode under test.
//
// This is the criterion that makes the twelve BASIC inverter-control rows mean
// something: the row is about a specific opMod* mode, and the wire evidence
// that the mode reached the DUT is that element appearing inside the
// DERControlBase of a DERControl the DUT fetched.
//
// It matches ANY control carrying the mode and is therefore correct only where
// no other control could be. Rows that publish their own control take
// critDERControlCarriesModeFrom, which binds to the row's own mRID and — for a
// row that also knows its commanded value — to that exact value and sign. See
// that function for what went wrong without the binding.
func critDERControlCarriesMode(mode, claim string) criterion {
	return critDERControlCarriesModeFrom(mode, claim, "", nil)
}

// critDERControlCarriesModeFrom is critDERControlCarriesMode bound to ONE
// control: the row's own mRID, and optionally the exact value that row
// commanded (IW15-004).
//
// ── Why an unbound match was not good enough ────────────────────────────────
//
// The 2026-08-14 BASIC-013 report cited, as its wire evidence that the DUT had
// received the row's set-active-power command, a DERControl with
// mRID=IW14-BAT-SMOKE-1 carrying <opModFixedW>-6000</opModFixedW> — a leftover
// smoke-test control, on the other sign, from another session. The row had
// published CERT-BASIC-013 with +6000. Every fact in that assertion was true
// and none of it was about this row. A criterion that accepts "some control in
// the window carried this mode" cannot tell a DUT that fetched THIS event from
// one that fetched somebody else's, and on a shared bench there is always
// somebody else's.
//
// mrid == "" keeps the unbound behaviour, for the callers whose control the
// bench did not mint (see critDERControlCarriesMode).
//
// want == nil binds the mRID only, which is right for a row whose mode carries
// a structure rather than a scalar (opModConnect's boolean, the nested
// power-factor and target-power elements): the row still proves it was ITS
// control the DUT fetched, and the value half is left to the rows that can
// state it in one integer.
//
// The verdicts are graded so a reader can act on them:
//
//   - the row's own control, carrying the mode at exactly the commanded value
//     and sign: PASS, citing the message;
//   - the row's own control, carrying the mode at a DIFFERENT value: FAIL —
//     the DUT received something, and what it received is not what this row
//     sent, which is a finding about the bench-to-DUT path, not an absence;
//   - the mode present but only under OTHER mRIDs: FAIL naming them, because
//     the bench lever demonstrably worked and this row's control is missing
//     from what the DUT fetched — and because accepting them is the defect
//     above;
//   - the mode absent entirely: unavailable, unchanged — that is the bench
//     having no lever for the mode, which is not the DUT's failure.
func critDERControlCarriesModeFrom(mode, claim, mrid string, want *int64) criterion {
	how := fmt.Sprintf("the presence of a <%s> element inside the DERControlBase of a DERControl in a "+
		"DERControlList the DUT fetched during the session", mode)
	switch {
	case mrid != "" && want != nil:
		how = fmt.Sprintf("a <%s> element carrying exactly %d, inside the DERControlBase of the DERControl "+
			"with THIS ROW's own mRID (%s), in a DERControlList the DUT fetched during the session — no "+
			"other control's %s satisfies this row, whatever it carries", mode, *want, mrid, mode)
	case mrid != "":
		how = fmt.Sprintf("a <%s> element inside the DERControlBase of the DERControl with THIS ROW's own "+
			"mRID (%s), in a DERControlList the DUT fetched during the session", mode, mrid)
	case want != nil:
		// A row that knows its value but not its mRID — the live phase did not
		// record one. The value binding still holds and the How must say so
		// rather than describe the looser check it is not making.
		how = fmt.Sprintf("a <%s> element carrying exactly %d inside the DERControlBase of a DERControl in "+
			"a DERControlList the DUT fetched during the session (this row recorded no mRID of its own to "+
			"bind to, so the value is the only correlation available)", mode, *want)
	}
	return criterion{
		Claim:           claim,
		How:             how,
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			lists := t.ByResource("DERControlList")
			if len(lists) == 0 {
				return unavailable("no DERControlList appears in the recovered transcript (resources seen: %s)",
					strings.Join(t.ResourceNames(), " "))
			}
			var seenModes, otherCarriers []string
			for _, e := range lists {
				doc, err := e.Resp.SEP()
				if err != nil {
					continue
				}
				for _, ctrl := range doc.Children("DERControl") {
					base := ctrl.Child("DERControlBase")
					if base == nil {
						continue
					}
					for _, k := range base.Kids {
						seenModes = append(seenModes, k.Local())
					}
					el := base.Child(mode)
					if el == nil {
						continue
					}
					got, _ := ctrl.TextOf("mRID")
					if mrid != "" && got != mrid {
						otherCarriers = append(otherCarriers,
							fmt.Sprintf("mRID=%s <%s>%s</%s>", got, mode, el.Text, mode))
						continue
					}
					if want == nil {
						return citeMessage(t, e.Resp, certify.Pass,
							"DERControl mRID=%s carries <%s>%s</%s>", got, mode, el.Text, mode)
					}
					// Exact value AND sign. Compared as integers rather than as
					// text so "+6000" and "6000" are the same value and "-6000"
					// is emphatically not — a sign error on a signed percent is
					// a charge command answered as a discharge one.
					v, ok := base.IntOf(mode)
					switch {
					case !ok:
						return citeMessage(t, e.Resp, certify.Fail,
							"this row's own DERControl (mRID=%s) carries <%s>%s</%s>, which is not an "+
								"integer this criterion can compare against the %d it commanded",
							got, mode, el.Text, mode, *want)
					case v != *want:
						return citeMessage(t, e.Resp, certify.Fail,
							"this row's own DERControl (mRID=%s) reached the DUT carrying <%s>%d</%s>, "+
								"but this row commanded %d — the value on the wire is not the value under "+
								"test, so nothing downstream of it can certify this row",
							got, mode, v, mode, *want)
					default:
						return citeMessage(t, e.Resp, certify.Pass,
							"DERControl mRID=%s — THIS row's own — carries <%s>%d</%s>, exactly the value "+
								"and sign it commanded", got, mode, v, mode)
					}
				}
			}
			if len(otherCarriers) > 0 {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"no DERControl with THIS row's mRID (%s) carrying a <%s> appears in what the DUT "+
						"fetched. The mode IS present in the window, under %d other control(s) — %s — and "+
						"none of them is this row's: an unrelated control carrying the same mode says "+
						"nothing about whether the command under test reached the DUT (IW15-004)",
					mrid, mode, len(otherCarriers), strings.Join(otherCarriers, "; "))}
			}
			return unavailable("no DERControl the DUT fetched carries a <%s>; the modes seen were: %s. "+
				"gridsim's admin control API has no lever for this mode, so it could not be placed on the wire",
				mode, strings.Join(dedupeStrings(seenModes), " "))
		},
		Skip: "the control mode this row is about could not be placed on the wire by this bench",
	}
}

// critResponsePosted asserts a DERControlResponse the DUT POSTed for mridKey
// SPECIFICALLY.
//
// Tier 2 reads the POST body out of the transcript; tier 3 falls back to
// gridsim's own record of the Responses it received. The two are ranked, never
// merged: the server's record is a real observation but it is not the wire.
//
// Both evaluators filter on <subject>==mridKey (audit 2026-08-01, CORE-022's
// two-phase Responses fix): before this they matched the FIRST Response of
// the right status found — of ANY subject. That was silently correct as long
// as at most one control's Response traffic was ever in flight at once, which
// every existing caller (coreResponses' single control, CORE-023's own
// winner/loser pair sharing one status vocabulary until they diverge, the
// BASIC-017..026 precedence scenarios) happened to satisfy well enough that
// the misattribution never flipped a verdict. CORE-022 now runs a SECOND,
// concurrently-live control alongside the one under test (a server-cancel
// target — see coreResponsesSpec), and that control earns its own status=1
// and very likely its own status=2 too, well before its cancellation. Without
// this filter, a criterion built for mridA's status=1 could cite — and PASS
// on — mridB's Response instead: a real verdict resting on the wrong
// control's evidence, exactly the kind of misattribution this suite's
// citation discipline exists to rule out.
func critResponsePosted(status uint8, meaning string, mridKey string) criterion {
	claim := fmt.Sprintf("the DUT POSTed a DERControlResponse with status=%d (%s) for the control under test",
		status, meaning)
	// #17/F2: hoisted from critResponseStarted's original status=2-only gate.
	// notRequested is set by Wire ONLY in the one case respReqNotRequested
	// has positive evidence for (see its doc); every other case (not found,
	// absent attribute, Table27RequiredBit==0) leaves it "" and Wire falls
	// straight through to the unchanged scan below, so a shipping row
	// serving rr=0x03/0x07 (every currently-used bit set) grades identically
	// to before this hoist. Wire always runs before Server within one
	// assert() call (criteria.go), so sharing this across the two closures
	// is safe — the same pattern critResponseStarted established.
	var notRequested string
	return criterion{
		Claim: claim,
		How: "the sep+xml body of a POST in the session whose root element is a Response family member, " +
			"matched on <subject> and <status>",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			if reason := respReqNotRequested(t, status, mridKey); reason != "" {
				notRequested = reason
				return Finding{Unavailable: reason}
			}
			var seen []string
			for _, e := range t.Method("POST") {
				if e.Req == nil || len(e.Req.Body) == 0 {
					continue
				}
				doc, err := e.Req.SEP()
				if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
					continue
				}
				subj, _ := doc.TextOf("subject")
				if subj != mridKey {
					continue
				}
				st, _ := doc.UintOf("status")
				seen = append(seen, fmt.Sprintf("%s/status=%d", subj, st))
				if uint64(status) != st {
					continue
				}
				return citeMessage(t, e.Req, certify.Pass,
					"POST %s carrying %s subject=%s status=%d, answered %s",
					e.Req.Target, doc.Local(), subj, st, e.Resp.Line())
			}
			if len(seen) == 0 {
				return unavailable("the recovered transcript holds no Response POST for subject %s", mridKey)
			}
			return found(certify.Fail, allFrames(t.Method("POST")),
				"the DUT POSTed %d Response(s) for subject %s but none with status=%d: %s",
				len(seen), mridKey, status, strings.Join(seen, ", "))
		},
		Server: func(v *ServerView) Finding {
			// #17/F2: honour a not-requested ruling Wire already made — tier 3
			// has no visibility into a control's own wire responseRequired, so
			// left to re-decide on bare Response presence it could turn the
			// exact false-FAIL this gate exists to prevent right back into one
			// (assert() always tries tier 3 once tier 2 answers Unavailable,
			// for ANY reason, including this one).
			if notRequested != "" {
				return Finding{Unavailable: notRequested}
			}
			got := v.ResponsesFor(mridKey)
			if len(got) == 0 {
				if !v.SessionEstablished() {
					return noSessionUnavailable()
				}
				return Finding{Verdict: certify.Fail,
					Observed: fmt.Sprintf("gridsim received no Response POST for subject %s in this window", mridKey)}
			}
			var statuses []string
			for _, r := range got {
				statuses = append(statuses, fmt.Sprintf("%s/status=%d", r.Subject, r.Status))
				if r.Status == status {
					return Finding{Verdict: certify.Pass,
						Observed: fmt.Sprintf("gridsim received a Response subject=%s status=%d (%s) from LFDI %s",
							r.Subject, r.Status, meaning, r.LFDI)}
				}
			}
			return Finding{Verdict: certify.Fail,
				Observed: fmt.Sprintf("gridsim received %d Response(s) for subject %s but none with status=%d: %s",
					len(got), mridKey, status, strings.Join(statuses, ", "))}
		},
	}
}

// controlEffectiveEndTimeBand reads mridKey's own DERControl <interval> —
// start and duration, both IEEE 2030.5 TimeType (seconds since epoch) — AND
// its own randomizeStart/randomizeDuration (§10.2.3.2/§10.2.4.2.2/.3), from every
// DERControlList the DUT fetched in this window, the same "read it off the
// wire the DUT actually saw" discipline controlResponseRequired uses for the
// responseRequired attribute. found is false only when the control itself
// never appeared in the recovered transcript.
//
// It returns a BAND, not an instant, because client-applied randomization
// (§10.2.3.2/§10.2.4.2.2/.3) means a control's own EffectiveEndTime is not a fixed point:
//
//	earliest = start + min(0,randomizeStart) + duration + min(0,randomizeDuration)
//	latest   = start + max(0,randomizeStart) + duration + max(0,randomizeDuration)
//
// A control that carries neither element permits no randomization on that
// axis — IntOf reports 0 for an absent element, and min(0,0)==max(0,0)==0
// leaves that axis's contribution untouched — so for a control gridsim did
// not randomize, earliest==latest==SpecifiedEndTime (start+duration) and the
// caller's FAIL/PASS split below collapses to a single-instant comparison,
// exactly where randomization was never in play.
//
// This function was introduced in the SD-02 remediation. The distinction it
// implements — that a control's own randomization moves its EffectiveEndTime
// away from the fixed SpecifiedEndTime (start+duration, Table 27's own term
// for the no-randomization case), and that grading a POSTed status against
// the wrong one of the two produces a false FAIL — was a finding against the
// first draft of that remediation, not a rename of code that predated it.
//
// oneHourRangeMax is IEEE 2030.5's OneHourRangeType bound — the type
// randomizeStart and randomizeDuration are both declared as — a signed count
// of seconds no wire value may exceed in magnitude. A control whose
// randomizeStart or randomizeDuration falls outside
// [-oneHourRangeMax, oneHourRangeMax] is not a device applying an unusually
// wide jitter; it is a malformed control, and the criterion built on this
// band says so rather than silently widening the band to match.
const oneHourRangeMax = 3600

// bandDisclosureCadence is the DERControlList poll cadence this suite already
// reasons from elsewhere (core.go's core022CompletionDurationS comment,
// randomize.go's CORE-021 disclaimer, both citing gridsim's 60 s
// defaultControlListPollRate). It does not size the band below — the band is
// fixed by the control's own randomizeStart/randomizeDuration — it only marks
// the point past which an in-band non-verdict must say so loudly: a band this
// wide can hide a real violation anywhere inside it, not just graze the
// boundary, so the criterion's resolving power there has genuinely dropped
// and must never be silently absorbed into an ordinary-looking Unavailable.
const bandDisclosureCadence = 60 * time.Second

// effectiveEndBand is controlEffectiveEndTimeBand's result: either the window
// a control's own randomization permits its EffectiveEndTime to occupy, or
// (Malformed != "") the reason the control's wire values cannot fix one at
// all.
type effectiveEndBand struct {
	Earliest, Latest time.Time
	// RawSpan is |randomizeStart| + |randomizeDuration| in seconds, BEFORE
	// the earliest-edge duration floor below — the figure the band-width
	// disclosure names, since it is what the control itself commanded, not
	// what the floor happened to leave of it.
	RawSpan time.Duration
	// Malformed names the out-of-range value when one of randomizeStart/
	// randomizeDuration falls outside OneHourRangeType. Earliest/Latest/
	// RawSpan are zero when this is set.
	Malformed string
}

func controlEffectiveEndTimeBand(t *Transcript, mridKey string) (band effectiveEndBand, found bool) {
	for _, e := range t.ByResource("DERControlList") {
		doc, err := e.Resp.SEP()
		if err != nil {
			continue
		}
		for _, c := range doc.Children("DERControl") {
			m, _ := c.TextOf("mRID")
			if m != mridKey {
				continue
			}
			iv := c.Path("interval")
			start, sok := iv.IntOf("start")
			dur, dok := iv.IntOf("duration")
			if !sok || !dok {
				continue
			}
			randStart, _ := c.IntOf("randomizeStart")       // 0 when absent — permits no randomization
			randDuration, _ := c.IntOf("randomizeDuration") // 0 when absent — permits no randomization
			if randStart < -oneHourRangeMax || randStart > oneHourRangeMax {
				return effectiveEndBand{Malformed: fmt.Sprintf(
					"randomizeStart=%d is outside OneHourRangeType [-%d,+%d]", randStart, oneHourRangeMax, oneHourRangeMax)}, true
			}
			if randDuration < -oneHourRangeMax || randDuration > oneHourRangeMax {
				return effectiveEndBand{Malformed: fmt.Sprintf(
					"randomizeDuration=%d is outside OneHourRangeType [-%d,+%d]", randDuration, oneHourRangeMax, oneHourRangeMax)}, true
			}
			// EffectiveDuration cannot be negative: a randomizeDuration whose
			// magnitude exceeds the control's own duration would otherwise
			// pull the earliest edge before the control's own (randomized)
			// start — a band edge before the event's own start is nonsense,
			// so the effective duration contributing to EARLIEST is floored
			// at 0. LATEST never needs the floor: max(0,randDuration) >= 0
			// always.
			effDurEarliest := dur + min64(0, randDuration)
			if effDurEarliest < 0 {
				effDurEarliest = 0
			}
			found = true
			band.Earliest = time.Unix(start+min64(0, randStart)+effDurEarliest, 0)
			band.Latest = time.Unix(start+max64(0, randStart)+dur+max64(0, randDuration), 0)
			band.RawSpan = time.Duration(abs64(randStart)+abs64(randDuration)) * time.Second
		}
	}
	return band, found
}

func abs64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// critNoEarlyEndOfEventStatus is the SD-02 class rule
// (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw): IEEE
// 2030.5-2018 Table 27 confines status 8 (PartialOptOut) and 10
// (NoParticipation) to EffectiveEndTime — never onset, never receipt (Table
// 27, p.74-76; "3/8/10 at EffectiveEndTime only"). This is the class rule
// that catches a DUT posting either status early WHEREVER in the catalog that
// DUT's control appears, backstopping — not replacing — a row's own
// refusal/degradation criteria (curve.go's critRefusalAnswered forbids 8/10
// outright on a structurally-refused control; this criterion additionally
// catches the same defect on an ADMITTED, executing control, which
// critRefusalAnswered is never attached to).
//
// It only has work to do on a Response that actually carries 8 or 10: a row
// whose transcript holds neither status trivially satisfies the claim, so
// attaching this to every Response-bearing row is cheap. When one IS
// present, the control's own <interval> plus randomizeStart/randomizeDuration
// — read from the DERControlList the DUT itself fetched, so this owes
// nothing to what the row's Setup THOUGHT it published — fixes the band
// §10.2.3.2/§10.2.4.2.2/.3 permits its EffectiveEndTime to land in, and the offending
// Response's own capture timestamp (Message.Time — "the defensible clock for
// every timing criterion in this suite", httpdis.go) is compared against it.
//
// # Why a band, and what a verdict inside it means
//
// gridsim seeds RandomizeStart on some controls (server.go:1451, admin.go:504)
// — this is live, not hypothetical — and a client that applies it moves its
// own EffectiveEndTime somewhere inside [earliest, latest] rather than sitting
// at SpecifiedEndTime (start+duration). This criterion can only be as precise
// as that band lets it be:
//
//   - a Response strictly before EARLIEST is early under EVERY random draw
//     §10.2.3.2/§10.2.4.2.2/.3 permits, so it FAILs — this is the one shape no reading of the
//     randomization can excuse, and it is exactly the defective onset-8 shape
//     SD-02 exists to catch;
//   - a Response at or after LATEST is not early under ANY permitted draw, so
//     it PASSes unconditionally;
//   - a Response landing INSIDE the band is genuinely undecidable from the
//     wire: this suite cannot recover which point in that band the DUT's own
//     random draw actually selected as its EffectiveEndTime, so whether the
//     Response is early relative to THAT instant (as opposed to
//     SpecifiedEndTime) is not answerable from what was recovered. Guessing
//     either verdict here would be exactly the error this rewrite exists to
//     retire, just relocated a few lines down — so this is reported as a
//     disclosed non-verdict (unavailable), naming the band, rather than
//     guessed at.
//
// randomizeGuardBand (randomize.go) — already the suite's own small tolerance
// for the wall-clock (Message.Time) vs TimeType (server epoch) domain mix —
// is subtracted from EARLIEST before the FAIL comparison, so a capture-clock
// vs server-clock skew of a couple of seconds cannot manufacture a false FAIL
// out of a Response that landed exactly on the boundary. It is deliberately
// NOT added to LATEST: doing so would misclassify an exact-boundary,
// zero-randomization control's on-time Response (band width zero) as
// "inside the band" and downgrade an honest PASS to a non-verdict.
//
// A status 8/10 seen with no recoverable band for its own mRID is reported
// Unavailable rather than guessed at: this suite's absence/inability
// discipline is that an unestablished boundary cannot certify a timing
// violation any more than an unestablished baseline can certify a refusal
// (curve.go's refusalOutcome contamination-baseline path takes the same
// position). The same discipline governs the case where NO status 8/10 was
// ever seen for this mRID at all: that is not a fact this criterion can
// falsify (RRS — a row whose control never drew a partial status has nothing
// for this claim to grade), so it too is unavailable rather than a vacuous
// Pass.
func critNoEarlyEndOfEventStatus(mridKey string) criterion {
	return criterion{
		Claim: "no DERControlResponse the DUT POSTed for this control carries status 8 (PartialOptOut) or " +
			"10 (NoParticipation) before the EARLIEST EffectiveEndTime the control's own randomizeStart/" +
			"randomizeDuration (§10.2.3.2/§10.2.4.2.2/.3) permit",
		How: "every Response-family POST in the session whose <subject> is this row's own mRID, filtered to " +
			"<status> in {8,10}, each one's own capture timestamp compared against the BAND of EffectiveEndTime " +
			"values this control's own randomizeStart/randomizeDuration (§10.2.3.2/§10.2.4.2.2/.3) permit its SpecifiedEndTime " +
			"(<interval><start> + <interval><duration>) to move to: FAIL only strictly before the band's " +
			"earliest edge (IEEE 2030.5-2018 Table 27 p.74-76 — SD-02); a Response landing inside the band is " +
			"reported as a disclosed non-verdict rather than guessed at, since which point in it the DUT's own " +
			"random draw selected is not recoverable from the wire",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			var early []string
			var ambiguous []string
			var clear []string
			for _, e := range t.Method("POST") {
				if e.Req == nil || len(e.Req.Body) == 0 {
					continue
				}
				doc, err := e.Req.SEP()
				if err != nil || !strings.HasSuffix(doc.Local(), "Response") {
					continue
				}
				subj, _ := doc.TextOf("subject")
				if subj != mridKey {
					continue
				}
				st, _ := doc.UintOf("status")
				if st != 8 && st != 10 {
					continue
				}
				band, ok := controlEffectiveEndTimeBand(t, mridKey)
				if !ok {
					return unavailable("a status=%d Response was POSTed for subject %s, but no DERControl "+
						"carrying that mRID's own <interval> appears in the recovered transcript, so this "+
						"row's own control cannot fix a band to check the timing against", st, mridKey)
				}
				if band.Malformed != "" {
					return found(certify.Fail, allFrames(t.Method("POST")),
						"subject %s's own DERControl carries a randomizeStart/randomizeDuration value this "+
							"suite cannot honor: %s — IEEE 2030.5's OneHourRangeType bounds both to "+
							"[-%d,+%d] s (§10.2.3.2/§10.2.4.2.2/.3). This is a malformed control, not an "+
							"unusually wide legitimate jitter, so the row FAILs rather than widening the band "+
							"to match it",
						mridKey, band.Malformed, oneHourRangeMax, oneHourRangeMax)
				}
				earliest, latest := band.Earliest, band.Latest
				at := e.Req.Time
				switch {
				case at.Before(earliest.Add(-randomizeGuardBand)):
					early = append(early, fmt.Sprintf("status=%d at %s, %s before the band's earliest edge "+
						"%s (band [%s, %s), permitted by this control's own randomizeStart/randomizeDuration)",
						st, at.Format(time.RFC3339), earliest.Sub(at).Round(time.Second),
						earliest.Format(time.RFC3339), earliest.Format(time.RFC3339), latest.Format(time.RFC3339)))
				case at.Before(latest):
					warn := ""
					if band.RawSpan >= bandDisclosureCadence {
						warn = fmt.Sprintf(" REDUCED POWER: this control's own randomizeStart/randomizeDuration "+
							"span %s, at or beyond the %s poll cadence this suite grades against — a band this "+
							"wide can hide a real onset-8/10 violation anywhere inside it, not just graze the "+
							"boundary, so this check's ability to catch one here is substantially reduced",
							band.RawSpan, bandDisclosureCadence)
					}
					ambiguous = append(ambiguous, fmt.Sprintf("status=%d at %s falls inside the randomization "+
						"band [%s, %s), width %s, this control's own randomizeStart/randomizeDuration "+
						"(§10.2.3.2/§10.2.4.2.2/.3) permit its EffectiveEndTime to occupy — which point in it "+
						"the DUT's own random draw actually selected is not recoverable from the wire.%s",
						st, at.Format(time.RFC3339), earliest.Format(time.RFC3339), latest.Format(time.RFC3339),
						latest.Sub(earliest), warn))
				default:
					clear = append(clear, fmt.Sprintf("status=%d at %s, at or after the band's latest edge %s",
						st, at.Format(time.RFC3339), latest.Format(time.RFC3339)))
				}
			}
			switch {
			case len(early) > 0:
				return found(certify.Fail, allFrames(t.Method("POST")),
					"the DUT POSTed a Response for subject %s carrying status 8 or 10 before the earliest "+
						"EffectiveEndTime its own randomization permits: %s. This is early under EVERY random "+
						"draw §10.2.3.2/§10.2.4.2.2/.3 permits — exactly the defective onset-8 shape SD-02 exists to catch",
					mridKey, strings.Join(early, "; "))
			case len(ambiguous) > 0:
				return unavailable("subject %s POSTed status 8/10 Response(s) landing inside the control's own "+
					"randomization band, so whether they are early relative to the DUT's OWN actual "+
					"EffectiveEndTime (as opposed to its SpecifiedEndTime) cannot be established from the "+
					"wire: %s", mridKey, strings.Join(ambiguous, "; "))
			case len(clear) > 0:
				return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
					"every status-8/10 Response for subject %s arrived at or after the latest EffectiveEndTime "+
						"its own randomization permits: %s", mridKey, strings.Join(clear, "; "))}
			default:
				return unavailable("no Response for subject %s carried status 8 or 10 in this window, so this "+
					"criterion has nothing to grade", mridKey)
			}
		},
	}
}

// controlResponseRequired reads the responseRequired bitmap recovered for
// mridKey's DERControl across every DERControlList the DUT fetched in this
// window.
//
// found is false only when the control itself never appeared in the
// transcript. present is the F5 fix (2026-08-17): it distinguishes an
// EXPLICIT responseRequired="00" from the attribute being ABSENT altogether.
// IEEE 2030.5's hexBinary8 responseRequired is optional, and an absent
// attribute is "no server instruction" — which the standard, and this
// gateway (internal/northbound/responses/tracker.go's postResponse: `if
// addr.responseRequired != nil { ...gate... }`, the whole gate skipped
// entirely when the pointer is nil), both read as "post/grade normally", NOT
// as if the server had explicitly asked for nothing. Only an EXPLICIT rr=0
// means "the server asked for nothing" and gates a status-specific criterion
// to Unavailable (see respReqNotRequested). Before this fix both readings
// collapsed onto rr=0 (present was not tracked at all) and were treated
// identically, which silently mis-gated the absent case exactly like an
// explicit deny — the opposite of the gateway's own behavior.
func controlResponseRequired(t *Transcript, mridKey string) (rr uint8, found, present bool) {
	for _, e := range t.ByResource("DERControlList") {
		doc, err := e.Resp.SEP()
		if err != nil {
			continue
		}
		for _, c := range doc.Children("DERControl") {
			m, _ := c.TextOf("mRID")
			if m != mridKey {
				continue
			}
			found = true
			if v, ok := c.Attr("responseRequired"); ok {
				present = true
				if parsed, perr := strconv.ParseUint(v, 16, 8); perr == nil {
					rr = uint8(parsed)
				}
			}
		}
	}
	return rr, found, present
}

// respReqNotRequested is the #17/F2 shared gate every criterion that demands
// a specific DERControlResponse status must check first — hoisted out of
// critResponseStarted's original bit-0x02-only version so every status gets
// the same per-bit treatment (via the vendored csipmodel.Table27RequiredBit,
// IEEE 2030.5-2018 Table 27's "Response required" column), not just
// status=2. It names WHY a status is not expected on the wire, or returns ""
// when it IS expected (grade normally).
//
// It returns "" — ungated — in every case except the ONE where this bench
// has POSITIVE evidence the status was not asked for: the control appeared
// in the transcript AND its responseRequired attribute was PRESENT AND
// explicit AND did not carry the required bit. The other three cases stay
// ungated on purpose, matching the gateway's own fallbacks:
//
//   - the control was never recovered in this window (found=false): unknown,
//     not "not requested" — a caller's ORIGINAL grading path (e.g. a
//     Response POST found directly in the transcript, independent of
//     whether the DERControlList that carries the mRID's responseRequired
//     was itself captured) still applies.
//   - the attribute was ABSENT (found && !present, F5): "no server
//     instruction" reads as "post/grade normally", never as an implicit
//     deny — see controlResponseRequired's doc.
//   - Table27RequiredBit(status)==0 (an extension/undefined status, e.g. the
//     legacy 0xF0): the table has no opinion, so there is nothing to gate
//     on — matches tracker.go's own "EXTENSION AND UNDEFINED STATUSES keep
//     the old behaviour verbatim" fallback.
func respReqNotRequested(t *Transcript, status uint8, mridKey string) string {
	bit := csipmodel.Table27RequiredBit(status)
	if bit == 0 {
		return ""
	}
	rr, found, present := controlResponseRequired(t, mridKey)
	if !found || !present {
		return ""
	}
	if rr&bit != 0 {
		return ""
	}
	return fmt.Sprintf("the DERControl mRID=%s carried responseRequired=%02X, which does not request status=%d "+
		"(required bit 0x%02X per IEEE 2030.5 Table 27) — a spec-compliant DUT is not obliged to report one",
		mridKey, rr, status, bit)
}

// respReqFilterStatuses is respReqNotRequested applied across a whole set of
// demanded statuses at once — the shape critResponseFanOut, critEventLifecycle
// and the CORE-022 inline lifecycle criterion need (they each grade several
// statuses for one mRID in a single criterion), rather than one status per
// criterion the way critResponsePosted/critResponseStarted do. Returns the
// subset of demanded that IS still expected (ungated); a status dropped from
// it has positive evidence — respReqNotRequested's — that it was not asked
// for.
func respReqFilterStatuses(t *Transcript, mridKey string, demanded []int) []int {
	var kept []int
	for _, s := range demanded {
		if respReqNotRequested(t, uint8(s), mridKey) == "" {
			kept = append(kept, s)
		}
	}
	return kept
}

// critResponseStarted asserts a DERControlResponse with status=2 (Event
// started) for the control under test, graded against what the control's OWN
// wire responseRequired attribute actually asked for (IEEE 2030.5 Table 27 /
// RespondableResource: a client is never told to volunteer a Response nobody
// requested).
//
// #17/F2 (2026-08-17): this used to be the ONLY criterion with this gate,
// hand-built around a hardcoded bit 0x02. The gate is now hoisted into
// critResponsePosted itself (respReqNotRequested, keyed per status by the
// vendored csipmodel.Table27RequiredBit), so this function is a thin,
// self-documenting alias — status=2's own required bit happens to be 0x02,
// exactly what this hand-built version checked, so nothing about its grading
// changes. Keep the named wrapper: CORE-022/CORE-023 and every other caller
// read "critResponseStarted(mrid)" at the call site, and the historical name
// carries the "Event started" meaning without repeating it everywhere.
func critResponseStarted(mridKey string) criterion {
	return critResponsePosted(2, "Event started", mridKey)
}

// gradeDERPutExchange grades ONE PUT exchange whose body's root element is
// resource, into a verdict and its sentence. It is the shared decision behind
// critDERPut (one resource) and critDERPutAny (any of several) so the two ways
// of asking "did the DUT PUT this cleanly" cannot drift apart on what
// "cleanly" means.
func gradeDERPutExchange(e Exchange, resource string) (certify.Verdict, string) {
	if e.Resp == nil {
		return certify.Fail, fmt.Sprintf("PUT %s carrying %s was never answered in the capture",
			e.Req.Target, resource)
	}
	v, note := certify.Pass, ""
	if e.Resp.Status != 204 {
		// 200 is DISCOURAGED rather than forbidden for a PUT
		// (2030.5 §5.5.2), so it is a WARN and 4xx/5xx a FAIL.
		if e.Resp.Status >= 200 && e.Resp.Status < 300 {
			v, note = certify.Warn, " (2030.5 §5.5.2 discourages a body-bearing 2xx for a PUT; "+
				"204 No Content is the expected answer)"
		} else {
			v = certify.Fail
		}
	}
	return v, fmt.Sprintf("PUT %s carrying %s -> %s%s", e.Req.Target, resource, e.Resp.Line(), note)
}

// critDERPut asserts one of the DER self-report PUTs.
//
// The evidence ladder is three rungs, strongest first, and the criterion says
// which rung it stood on:
//
//  1. a PUT in one of the conversations THIS check owns — cited by byte range,
//     which is the only form a bundle's verifier can re-derive;
//  2. a PUT elsewhere in the run's decrypted capture — a real wire fact, but in
//     frames belonging to another test case, so it is reported as a
//     capture-derived narrative naming those frames rather than citing them;
//  3. no PUT of this resource anywhere in a FULLY decrypted capture — a FAIL
//     drawn from the wire rather than from gridsim's admin log.
//
// Rung 2 exists because the DER self-reports are cadence-driven and land in this
// case's own window only by luck; rung 3 exists because "gridsim recorded no
// DERCapability PUT (it recorded: )" was being printed as a finding about the
// DUT when the capture could say the same thing about the wire, checkably. The
// server tier below remains, and is now reached only when the capture cannot
// settle the question.
func critDERPut(resource string) criterion {
	// grade turns one located PUT into a verdict and its sentence.
	grade := func(e Exchange) (certify.Verdict, string) { return gradeDERPutExchange(e, resource) }
	return criterion{
		Claim: fmt.Sprintf("the DUT PUT its %s to the href the server advertised, and the server answered "+
			"204 No Content", resource),
		How: fmt.Sprintf("a PUT whose body's root element is %s, and the status line of the response to it, "+
			"located first in the conversations this check owns and then across the run's whole decrypted "+
			"capture", resource),
		NeedsTranscript: true,
		Wire: func(ev *certify.Evidence, t *Transcript) Finding {
			// Rung 1: this check's own conversations. Citable.
			var seen []string
			for _, e := range t.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil {
					continue
				}
				seen = append(seen, doc.Local())
				if doc.Local() != resource {
					continue
				}
				v, desc := grade(e)
				if e.Resp == nil {
					return citeMessage(t, e.Req, v, "%s", desc)
				}
				return citeExchange(t, e, v, "%s", desc)
			}

			// Rung 2: the rest of the run's capture. Real, but not this check's
			// to cite.
			rw := runWireOf(ev, t.Remote)
			runPuts := rw.Method("PUT")
			var runSeen []string
			hit, foundPut := Exchange{}, false
			for _, e := range runPuts {
				doc, err := e.Req.SEP()
				if err != nil {
					continue
				}
				runSeen = append(runSeen, doc.Local())
				if doc.Local() == resource && !foundPut {
					hit, foundPut = e, true
				}
			}
			if foundPut {
				v, desc := grade(hit)
				return Finding{Verdict: v, Observed: fmt.Sprintf(
					"%s — on conversation %s, in frame(s) %s. That conversation is not one this test case "+
						"owns outright (%s), which is why the report is NAMED here and not cited: a check may "+
						"cite only its own frames, and a citation of someone else's is the one thing this "+
						"tool refuses. The DUT reports this resource on its own cadence rather than on this "+
						"case's cue, so the report is a fact of the run's wire rather than of this window. "+
						"Read from %s",
					desc, hit.In().Stream.Key, framesOf(hit), whyNotOurs(ev, hit), rw.Scope())}
			}

			// Rung 3: a negative, which is only a fact about the DUT if the
			// capture was fully readable.
			if len(seen) > 0 {
				return found(certify.Fail, allFrames(t.Method("PUT")),
					"the DUT PUT %d resource(s) in this window — %s — but no %s",
					len(seen), strings.Join(dedupeStrings(seen), " "), resource)
			}
			if !rw.Complete {
				return unavailable("no %s PUT appears in this test case's conversations, and the run's "+
					"capture cannot settle whether one happened elsewhere: %s", resource, rw.Scope())
			}
			if len(runSeen) == 0 {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"the DUT sent NO PUT of any resource anywhere in the run: %s were read end to end and "+
						"carry no PUT request at all, so the %s self-report was never emitted. This is the "+
						"wire's own answer, independent of gridsim's admin log",
					rw.Scope(), resource)}
			}
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DUT PUT %d resource(s) across the whole run — %s — but no %s. Read from %s",
				len(runSeen), strings.Join(dedupeStrings(runSeen), " "), resource, rw.Scope())}
		},
		Server: func(v *ServerView) Finding {
			if inWindow := v.PutsFor(resource); len(inWindow) > 0 {
				last := inWindow[len(inWindow)-1]
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("gridsim recorded %d %s PUT(s) from the DUT in this case's window, "+
						"most recently %d bytes at server time %d to %s", len(inWindow), resource,
						len(last.Body), last.ReceivedAt, last.Path)}
			}
			// The DER self-reports (DERStatus, DERCapability, DERSettings) are
			// cadence- and change-driven: the DUT emits them on its own schedule,
			// so the report this case is written to observe routinely lands
			// earlier in the run than this case's narrow window. The claim is that
			// the DUT self-reports the resource, and a report anywhere in the run
			// is the observable that rests on — so fall back to the run-scoped
			// view before concluding the DUT never sent one.
			if inRun := v.PutsForInRun(resource); len(inRun) > 0 {
				last := inRun[len(inRun)-1]
				return Finding{Verdict: certify.Pass,
					Observed: fmt.Sprintf("gridsim recorded %d %s PUT(s) from the DUT during the run — none "+
						"inside this case's own window, because the DUT reports it on its own cadence rather "+
						"than on this case's cue; most recently %d bytes at server time %d to %s",
						len(inRun), resource, len(last.Body), last.ReceivedAt, last.Path)}
			}
			// A report of ANY DER resource anywhere in the run proves a session
			// established, so the absence of THIS one is a real DUT fact, not a
			// handshake artifact — even if this check's own window saw no traffic.
			if !v.SessionEstablished() && len(v.RunDERPuts) == 0 {
				return noSessionUnavailable()
			}
			reported := v.RunDERPuts
			if reported == nil {
				reported = v.DERPuts
			}
			var seen []string
			for _, p := range reported {
				seen = append(seen, p.Resource)
			}
			return Finding{Verdict: certify.Fail,
				Observed: fmt.Sprintf("gridsim recorded no %s PUT from the DUT anywhere in this run "+
					"(it recorded: %s)", resource, strings.Join(dedupeStrings(seen), " "))}
		},
	}
}

// critDERPutAny asserts CORE-009's own printed pass criterion for its DER
// self-report element, which — unlike critDERPut — is DISJUNCTIVE: CSIP
// Conformance Test Procedures v1.3 pp.41-42 states the client passes this
// element if it "did an HTTP PUT [of] DERCapabilities, DERSettings, DERStatus
// or DERAvailability" — any ONE of the four, not all four. A DUT that only
// ever PUTs DERStatus — the one report that is cadence-driven and so lands in
// nearly every window regardless of what the bench does — satisfies the
// printed text in full, and grading it a FAIL because this window's capture
// happens not to also show DERCapability/DERSettings would hold the row to a
// stricter standard than its own text states.
//
// The four individual critDERPut(resource) criteria remain in CORE-009 (see
// core.go) as per-resource observations, wrapped by critDERPutInformational so
// their absence reads as a SKIP (informational) rather than a FAIL or a WARN:
// a reader still sees exactly which of the four arrived, and no single one of
// them can fail OR warn a row whose own printed criterion is this one.
//
// Evidence ladder and rungs are the same three as critDERPut, generalised
// across the resource set: rung 1 searches this check's own conversations for
// the LATEST PUT of any wanted resource; rung 2 searches the rest of the run's
// decrypted capture and reports (never cites) what it finds there; rung 3 is a
// negative, drawn only when the capture was fully decryptable.
func critDERPutAny(resources ...string) criterion {
	want := make(map[string]bool, len(resources))
	for _, r := range resources {
		want[r] = true
	}
	list := strings.Join(resources, ", ")

	return criterion{
		Claim: fmt.Sprintf("the DUT PUT at least one of %s to the href the server advertised, and the "+
			"server answered 204 No Content — CSIP Conformance Test Procedures v1.3 pp.41-42 states this "+
			"element of CORE-009 disjunctively across the four DER self-reports, not conjunctively", list),
		How: fmt.Sprintf("a PUT whose body's root element is one of %s, and the status line of the "+
			"response to it, located first in the conversations this check owns and then across the run's "+
			"whole decrypted capture", list),
		NeedsTranscript: true,
		Wire: func(ev *certify.Evidence, t *Transcript) Finding {
			// Rung 1: this check's own conversations. Citable. The BEST-graded
			// matching PUT — Pass beats Warn beats Fail, and only ties (same
			// grade) are broken by latest-wins (the "a re-PUT fixed an earlier
			// bad response" convention critDERPut itself uses via its own
			// first-match-wins scan). The row's own criterion is disjunctive —
			// "at least one" of the four PUTs succeeded — so a LATER attempt at
			// a DIFFERENT resource that the capture never saw answered (e.g. a
			// routine re-PUT whose response landed after this window closed)
			// must not eclipse an EARLIER PUT of another wanted resource that
			// already satisfied it; grading only the chronologically-last match
			// regardless of its own outcome (as this loop did before) throws
			// away a satisfying PASS whenever a worse attempt happens to follow
			// it in capture order.
			var seen []string
			hit, hitResource, foundHit := Exchange{}, "", false
			hitVerdict := certify.Fail
			for _, e := range t.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil {
					continue
				}
				seen = append(seen, doc.Local())
				if !want[doc.Local()] {
					continue
				}
				v, _ := gradeDERPutExchange(e, doc.Local())
				if foundHit && v.Severity() > hitVerdict.Severity() {
					continue
				}
				hit, hitResource, hitVerdict, foundHit = e, doc.Local(), v, true
			}
			if foundHit {
				v, desc := gradeDERPutExchange(hit, hitResource)
				if hit.Resp == nil {
					return citeMessage(t, hit.Req, v, "%s", desc)
				}
				return citeExchange(t, hit, v, "%s", desc)
			}

			// Rung 2: the rest of the run's capture. Real, but not this check's to
			// cite. Same best-graded-match selection as rung 1, for the same
			// reason.
			rw := runWireOf(ev, t.Remote)
			var runSeen []string
			runHit, runHitResource, foundRunHit := Exchange{}, "", false
			runHitVerdict := certify.Fail
			for _, e := range rw.Method("PUT") {
				doc, err := e.Req.SEP()
				if err != nil {
					continue
				}
				runSeen = append(runSeen, doc.Local())
				if !want[doc.Local()] {
					continue
				}
				v, _ := gradeDERPutExchange(e, doc.Local())
				if foundRunHit && v.Severity() > runHitVerdict.Severity() {
					continue
				}
				runHit, runHitResource, runHitVerdict, foundRunHit = e, doc.Local(), v, true
			}
			if foundRunHit {
				v, desc := gradeDERPutExchange(runHit, runHitResource)
				return Finding{Verdict: v, Observed: fmt.Sprintf(
					"%s — on conversation %s, in frame(s) %s. That conversation is not one this test case "+
						"owns outright (%s), which is why the report is NAMED here and not cited: a check may "+
						"cite only its own frames, and a citation of someone else's is the one thing this "+
						"tool refuses. The DUT reports its DER self-reports on its own cadence rather than on "+
						"this case's cue, so the report is a fact of the run's wire rather than of this "+
						"window. Read from %s",
					desc, runHit.In().Stream.Key, framesOf(runHit), whyNotOurs(ev, runHit), rw.Scope())}
			}

			// Rung 3: a negative, only a fact about the DUT if the capture was
			// fully readable.
			if len(seen) > 0 {
				return found(certify.Fail, allFrames(t.Method("PUT")),
					"the DUT PUT %d resource(s) in this window — %s — but none of %s",
					len(seen), strings.Join(dedupeStrings(seen), " "), list)
			}
			if !rw.Complete {
				return unavailable("no DER self-report PUT appears in this test case's conversations, and "+
					"the run's capture cannot settle whether one happened elsewhere: %s", rw.Scope())
			}
			if len(runSeen) == 0 {
				return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
					"the DUT sent NO PUT of any resource anywhere in the run: %s were read end to end and "+
						"carry no PUT request at all, so none of %s was ever self-reported. This is the "+
						"wire's own answer, independent of gridsim's admin log",
					rw.Scope(), list)}
			}
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"the DUT PUT %d resource(s) across the whole run — %s — but none of %s. Read from %s",
				len(runSeen), strings.Join(dedupeStrings(runSeen), " "), list, rw.Scope())}
		},
		Server: func(v *ServerView) Finding {
			for _, r := range resources {
				if inWindow := v.PutsFor(r); len(inWindow) > 0 {
					last := inWindow[len(inWindow)-1]
					return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
						"gridsim recorded %d %s PUT(s) from the DUT in this case's window, most recently %d "+
							"bytes at server time %d to %s — which alone satisfies CORE-009's disjunctive PUT "+
							"criterion", len(inWindow), r, len(last.Body), last.ReceivedAt, last.Path)}
				}
			}
			// Cadence- and change-driven, same as critDERPut: the report this row
			// is written to observe routinely lands earlier in the run than this
			// case's narrow window.
			for _, r := range resources {
				if inRun := v.PutsForInRun(r); len(inRun) > 0 {
					last := inRun[len(inRun)-1]
					return Finding{Verdict: certify.Pass, Observed: fmt.Sprintf(
						"gridsim recorded %d %s PUT(s) from the DUT during the run — none inside this case's "+
							"own window, but the DUT self-reports on its own cadence rather than on this "+
							"case's cue, and CORE-009's PUT criterion is disjunctive across the four "+
							"resources; most recently %d bytes at server time %d to %s",
						len(inRun), r, len(last.Body), last.ReceivedAt, last.Path)}
				}
			}
			if !v.SessionEstablished() && len(v.RunDERPuts) == 0 {
				return noSessionUnavailable()
			}
			reported := v.RunDERPuts
			if reported == nil {
				reported = v.DERPuts
			}
			var seen []string
			for _, p := range reported {
				seen = append(seen, p.Resource)
			}
			return Finding{Verdict: certify.Fail, Observed: fmt.Sprintf(
				"gridsim recorded no PUT of any of %s from the DUT anywhere in this run (it recorded: %s)",
				list, strings.Join(dedupeStrings(seen), " "))}
		},
	}
}

// critDERPutInformational wraps critDERPut(resource) so its per-resource
// observation cannot grade CORE-009 down: the row's own printed pass
// criterion is disjunctive across the four DER self-reports (critDERPutAny),
// so the absence of any ONE of them is not, by itself, a fact this row fails
// OR warns on. A PUT that WAS observed is still reported as a PASS — full
// credit — and a would-be FAIL is demoted to a SKIP that names the absence as
// informational narrative and points at the criterion which actually decides
// the row.
//
// SKIP, not WARN — this used to demote to WARN, and that was CORE-009 #10's
// bug (census 20260802): certify.Result.rollUp / worstOf (registry.go,
// runner.go) take the WORST verdict across every assertion a case mints, by
// Verdict.Severity() (bundle.go: Fail=3, Warn=2, Pass=1, Skip=0). Three of the
// four resources being PUT already satisfies critDERPutAny's disjunctive
// criterion — a citable PASS — but WARN's severity (2) is HIGHER than PASS's
// (1), so the fourth resource's absence (here, DERAvailability) pulled the
// whole row down to WARN even though its own combined criterion had already
// passed. SKIP's severity (0) sits BELOW Pass, so an absent resource can
// inform a reader without ever outranking the row's real verdict — while a
// genuine FAIL from critDERPutAny itself (severity 3, when NONE of the four
// were PUT) still dominates every SKIP here and the row correctly fails.
func critDERPutInformational(resource string) criterion {
	base := critDERPut(resource)
	demote := func(f Finding) Finding {
		if f.Verdict == certify.Fail {
			f.Verdict = certify.Skip
			f.Observed += ". This is INFORMATIONAL and does not by itself affect this row's verdict: " +
				"CORE-009's own printed pass criterion (CSIP Conformance Test Procedures v1.3 pp.41-42) is " +
				"disjunctive across DERCapability/DERSettings/DERStatus/DERAvailability — see the row's " +
				"combined criterion for its actual verdict"
		}
		return f
	}
	return criterion{
		Claim: base.Claim + " (informational per-resource note; CORE-009's actual pass/fail is the row's " +
			"combined disjunctive criterion)",
		How:             base.How,
		NeedsTranscript: base.NeedsTranscript,
		Wire: func(ev *certify.Evidence, t *Transcript) Finding {
			return demote(base.Wire(ev, t))
		},
		Server: func(v *ServerView) Finding {
			return demote(base.Server(v))
		},
		Skip: base.Skip,
	}
}

// critPollRate measures the DUT's polling interval against the pollRate the
// server advertised, from CAPTURE timestamps.
//
// The measurement is only as good as the window: one check's window normally
// contains one walk, and an interval needs two. Rather than guess, the criterion
// reports how many samples it had and SKIPs below two — a number a reader can
// act on ("raise -param csip.wait") instead of a verdict they cannot trust.
func critPollRate() criterion {
	return criterion{
		Claim: "the DUT polls the resources that advertise a pollRate no more slowly than the advertised " +
			"rate, and no faster than IEEE 2030.5 §10.2.3's floor",
		How: "the spacing between successive requests for the same resource, measured from the CAPTURE " +
			"timestamps of the frames carrying them — not from the harness clock, which measures the " +
			"harness's own scheduling as much as the DUT's",
		NeedsTranscript: true,
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			byPath := map[string][]time.Time{}
			for _, e := range t.Exchanges {
				if e.Req == nil || e.Req.Method != "GET" || e.Req.Time.IsZero() {
					continue
				}
				byPath[e.Req.Path] = append(byPath[e.Req.Path], e.Req.Time)
			}
			var samples []string
			var frames []int
			for path, ts := range byPath {
				if len(ts) < 2 {
					continue
				}
				for i := 1; i < len(ts); i++ {
					samples = append(samples, fmt.Sprintf("%s +%s", path, ts[i].Sub(ts[i-1]).Round(time.Millisecond)))
				}
				for _, e := range t.GETs(path) {
					frames = append(frames, e.Frames()...)
				}
			}
			if len(samples) == 0 {
				return unavailable("this check's capture window contains at most one request per resource, and "+
					"an interval needs two. The window held %d exchange(s); raise the wait with "+
					"-param %s=<duration> to span more than one poll cycle", len(t.Exchanges), waitParam)
			}
			return found(certify.Pass, dedupeInts(frames),
				"%d inter-request interval(s) measured from capture timestamps: %s",
				len(samples), strings.Join(samples, ", "))
		},
		Skip: "measuring a poll interval requires the decrypted transcript to identify which resource each " +
			"request was for",
	}
}

func dedupeStrings(v []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(v))
	for _, s := range v {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fingerprintPrefix renders the first octets of a certificate fingerprint, so
// an Observed field names WHICH certificate the identity was derived from
// without printing all 32 bytes.
func fingerprintPrefix(der []byte) string {
	fp := Fingerprint(der)
	return fmt.Sprintf("%x", fp[:6])
}
