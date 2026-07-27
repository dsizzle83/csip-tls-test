package suitepki

// checks_chain.go implements PKI-11, PKI-19 and PKI-20: the rows about the
// certificate authority hierarchy and the chains built on it.
//
//	PKI-11  the DUT should be provisioned on the deepest valid chain
//	PKI-19  SERCA / MCA / MICA and the three valid device chains
//	PKI-20  deliberate-error certificates, and the DUT's refusal of them
//
// PKI-19 is the only case in this document that tests the DUT in BOTH
// directions, and both halves are needed for the row to mean anything:
//
//   - as a PRESENTER, the chain the DUT sends is dissected from the capture and
//     every link is checked three ways — issuer DN, authority/subject key
//     identifier, and the actual signature. Reporting those separately matters:
//     a mis-assembled chain has matching DNs and a signature that does not
//     verify, and a boolean would not tell an operator which failure they have.
//   - as a VERIFIER, the DUT is offered a leaf at each of the three chain
//     depths IEEE 2030.5 defines, all anchored at the trust anchor it is
//     already configured with, and its acceptance of each is the observable.
//     That half needs the bench root's PRIVATE KEY; without it a check can
//     only mint material the DUT must reject, never material it must accept,
//     and the half SKIPs saying exactly that.
//
// PKI-20's expected DUT reaction is deliberately NOT specified by the test-PKI
// document — the catalog flags this as a gap and points at the CSIP 2030.5 Test
// Procedures for the alert code. So this check asserts the fact the document
// does support (a conformant peer must not complete a handshake with an error
// certificate) and files an explicit SKIP for the alert-code question rather
// than inventing a criterion.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdis"
)

// ---------------------------------------------------------------------------
// PKI-11 — the deepest valid chain
// ---------------------------------------------------------------------------

const (
	claimDeepestChain = "the DUT is provisioned on the mca-mica-dev chain — device certificate issued by a " +
		"MICA, itself issued by an MCA — which is the most complex compliant chain and therefore the best " +
		"demonstration of compliant chain support"
	claimChainLinksHold = "every link of the chain the DUT presented holds: the issuer DN, the authority/subject " +
		"key identifier pair, and the signature"
)

func checkDeepestChain(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	ident, _ := benchIdentity(rc)
	s, err := dialDUT(ctx, rc, "PKI-11 provisioned chain depth", HandshakeOptions{Identity: ident.TLS()})
	if err != nil {
		return certify.Result{}, err
	}

	depth, shape := 0, ShapeUnknown
	if s.Facts.Chain != nil {
		depth, shape = s.Facts.Chain.Depth, s.Facts.Chain.Shape
	}
	verdict := certify.Warn
	notes := fmt.Sprintf("the DUT presented a %d-certificate chain (%s), not the 3-certificate mca-mica-dev "+
		"chain the document recommends", depth, shape)
	if shape == ShapeSERCAMCAMICADevice {
		verdict = certify.Pass
		notes = "the DUT presented the 3-certificate mca-mica-dev chain"
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			w, why := s.wire(ev)
			if w == nil {
				return []certify.Assertion{ev.SkipAssertion(claimDeepestChain, certificateCitationMethod, why)}, nil
			}
			if w.ServerCertificate == nil || w.ServerCertificate.Chain == nil {
				return []certify.Assertion{ev.SkipAssertion(claimDeepestChain, certificateCitationMethod,
					"the DUT's Certificate message carried no parseable chain; "+joinNotes(w.Notes))}, nil
			}
			chain := w.ServerCertificate.Chain

			v := certify.Warn
			observed := fmt.Sprintf("the Certificate message carries %d certificate(s) (%s); mca-mica-dev is "+
				"3 (device <- MICA <- MCA, with the root anchored out of band)", chain.Depth, chain.Shape)
			if chain.Shape == ShapeSERCAMCAMICADevice {
				v = certify.Pass
				observed = "the Certificate message carries 3 certificates: " + chain.Describe()
			}
			a, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimDeepestChain, v, observed)
			if err != nil {
				return nil, err
			}
			if v != certify.Pass {
				a.Note = joinNote(a.Note, "SHOULD-strength, and the constraint is the BENCH's PKI, not the "+
					"DUT: the bench is anchored on a two-tier CA (root + one intermediate), so a three-deep "+
					"chain does not exist to be installed. certmgr's rotation lifecycle installs whatever "+
					"chain PEM it is handed, so re-running this row after rebuilding the bench PKI with an "+
					"MCA tier is what would settle it")
			}
			out := []certify.Assertion{a}

			b, err := chainLinkAssertion(ev, w)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
			return out, nil
		},
	}, nil
}

// chainLinkAssertion reports the three-way link check over a presented chain.
func chainLinkAssertion(ev *certify.Evidence, w *WireHandshake) (certify.Assertion, error) {
	chain := w.ServerCertificate.Chain
	if len(chain.Links) == 0 {
		return ev.SkipAssertion(claimChainLinksHold,
			"issuer DN, authority/subject key identifier and signature check over each chain link",
			fmt.Sprintf("the chain carries %d certificate and therefore no link to check; its issuer is the "+
				"out-of-band trust anchor, which is not in the capture", chain.Depth)), nil
	}
	v := certify.Pass
	parts := make([]string, 0, len(chain.Links))
	for _, l := range chain.Links {
		if !l.OK() {
			v = certify.Fail
		}
		parts = append(parts, fmt.Sprintf("%q <- %q: issuer DN %v, key id %v, signature %v%s",
			nameOr(l.ChildSubject), nameOr(l.IssuerSubject), l.IssuerDNMatches,
			keyIDText(l), l.SignatureValid, suffixIf(l.SignatureErr, " ("+l.SignatureErr+")")))
	}
	return citeCert(ev, w.ServerDir, w.ServerCertificate, claimChainLinksHold, v, strings.Join(parts, "; "))
}

func nameOr(s string) string {
	if s == "" {
		return "<empty Subject>"
	}
	return s
}

func keyIDText(l ChainLink) string {
	if !l.KeyIDPresent {
		return "absent"
	}
	return fmt.Sprint(l.KeyIDMatches)
}

// ---------------------------------------------------------------------------
// PKI-19 — the CA hierarchy and the three valid chains
// ---------------------------------------------------------------------------

const (
	claimHierarchyShape = "the chain the DUT presents is one of the three valid IEEE 2030.5 chains " +
		"(serca-device, serca-mica-device, serca-mca-mica-device) and each CA in it is issued by the CA above it"
	claimAcceptsAllDepths = "the DUT validates device certificates at all three IEEE 2030.5 chain depths when " +
		"they are anchored at the trust anchor it is configured with"
)

func checkCAHierarchy(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	ident, _ := benchIdentity(rc)
	presenter, err := dialDUT(ctx, rc, "PKI-19 chain the DUT presents", HandshakeOptions{Identity: ident.TLS()})
	if err != nil {
		return certify.Result{}, err
	}

	// The verifier half. It needs the bench root's private key; without it the
	// half is skipped with the reason rather than quietly dropped.
	type depthProbe struct {
		shape ChainShape
		want  int
		s     *session
	}
	var probes []depthProbe
	var probeSkip string
	if root, why := benchRoot(rc); root == nil {
		probeSkip = why
	} else {
		h, herr := HierarchyUnder(root, "suitepki chain-depth")
		if herr != nil {
			return certify.Result{}, fmt.Errorf("build a hierarchy under the bench root: %w", herr)
		}
		for _, shape := range []ChainShape{ShapeSERCADevice, ShapeSERCAMICADevice, ShapeSERCAMCAMICADevice} {
			leaf, lerr := h.Mint(shape, LeafSpec{
				Name:       string(shape),
				CommonName: "suitepki " + string(shape) + " client",
				Roles:      []string{"ReadOnlySunSpec"},
				Client:     true, Server: true,
			})
			if lerr != nil {
				return certify.Result{}, fmt.Errorf("mint the %s leaf: %w", shape, lerr)
			}
			tc := leaf.TLSCertificate()
			s, derr := dialDUT(ctx, rc, "PKI-19 present a "+string(shape)+" chain", HandshakeOptions{Identity: &tc})
			if derr != nil {
				return certify.Result{}, derr
			}
			probes = append(probes, depthProbe{shape: shape, want: len(leaf.ChainDER()), s: s})
		}
	}

	accepted, refused := 0, []string{}
	for _, p := range probes {
		if p.s.Facts.Completed {
			accepted++
		} else {
			refused = append(refused, string(p.shape)+" ("+p.s.Facts.HandshakeErr+")")
		}
	}
	verdict := certify.Pass
	notes := "the DUT's own chain was dissected from the capture"
	switch {
	case probeSkip != "":
		notes += "; the accept-all-three-depths half was not exercised: " + probeSkip
	case len(refused) > 0:
		verdict = certify.Fail
		notes += fmt.Sprintf("; the DUT refused %d of %d chain depths anchored at its own trust anchor: %s",
			len(refused), len(probes), strings.Join(refused, ", "))
	default:
		notes += fmt.Sprintf("; the DUT accepted all %d chain depths anchored at its own trust anchor", accepted)
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion

			w, why := presenter.wire(ev)
			switch {
			case w == nil:
				out = append(out, ev.SkipAssertion(claimHierarchyShape, certificateCitationMethod, why))
			case w.ServerCertificate == nil || w.ServerCertificate.Chain == nil:
				out = append(out, ev.SkipAssertion(claimHierarchyShape, certificateCitationMethod,
					"the DUT's Certificate message carried no parseable chain; "+joinNotes(w.Notes)))
			default:
				chain := w.ServerCertificate.Chain
				v := certify.Pass
				if chain.Shape == ShapeUnknown {
					v = certify.Fail
				}
				observed := fmt.Sprintf("presented shape %s at depth %d: %s", chain.Shape, chain.Depth, chain.Describe())
				if len(chain.Problems) > 0 {
					observed += " — " + strings.Join(chain.Problems, "; ")
					v = certify.Warn
				}
				a, err := citeCert(ev, w.ServerDir, w.ServerCertificate, claimHierarchyShape, v, observed)
				if err != nil {
					return nil, err
				}
				out = append(out, a)

				b, err := chainLinkAssertion(ev, w)
				if err != nil {
					return nil, err
				}
				out = append(out, b)
			}

			if probeSkip != "" {
				out = append(out, ev.SkipAssertion(claimAcceptsAllDepths,
					"present a leaf at each of the three IEEE 2030.5 chain depths and observe the handshake",
					probeSkip))
				return out, nil
			}

			var results []string
			ok := true
			for _, p := range probes {
				pw, pwhy := p.s.wire(ev)
				status := "accepted"
				if !p.s.Facts.Completed {
					status, ok = "REFUSED: "+p.s.Facts.HandshakeErr, false
					if pw != nil {
						if al, found := pw.FatalAlert(); found {
							status += " — " + AlertText(al)
						}
					}
				}
				detail := fmt.Sprintf("%s (%d certificate(s) presented)", p.shape, p.want)
				if pw == nil {
					detail += " [not recoverable from the capture: " + pwhy + "]"
				} else if pw.ClientCertificate != nil && pw.ClientCertificate.Chain != nil {
					detail = fmt.Sprintf("%s (%s)", p.shape, pw.ClientCertificate.Chain.Describe())
					c, err := citeCert(ev, pw.ClientDir, pw.ClientCertificate,
						fmt.Sprintf("the bench presented a %s chain to the DUT", p.shape),
						certify.Pass, pw.ClientCertificate.Chain.Describe())
					if err != nil {
						return nil, err
					}
					out = append(out, c)
				}
				results = append(results, detail+": "+status)
			}
			v := certify.Pass
			if !ok {
				v = certify.Fail
			}
			frames := ev.Frames()
			if len(frames) == 0 {
				out = append(out, ev.NoEvidence(claimAcceptsAllDepths))
				return out, nil
			}
			d, err := ev.CiteFrames(claimAcceptsAllDepths,
				"a leaf presented at each of the three IEEE 2030.5 chain depths, all anchored at the bench "+
					"root the DUT's trust domain is configured with; the handshake outcome is the observable",
				v, strings.Join(results, "; "), frames)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
			return out, nil
		},
	}, nil
}

// ---------------------------------------------------------------------------
// PKI-20 — deliberate-error certificates
// ---------------------------------------------------------------------------

const (
	claimErrorCertsRefused = "the DUT refuses a device certificate carrying a deliberate error, terminating " +
		"the handshake rather than completing it"
	claimErrorCertsAvailable = "deliberate-error device certificates were available to present to the DUT"
	claimAlertCode           = "the DUT's rejection used the specific TLS alert the applicable test procedure requires"
)

// errorFixture is one piece of deliberate-error material and the session that
// presented it.
type errorFixture struct {
	name   string
	defect string
	source string
	s      *session
}

func checkErrorCertificates(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	var fixtures []errorFixture

	// The committed matrix first: it is what the bench actually ships, and a
	// report that used only freshly minted material would be describing a
	// capability nobody can reproduce from the repository.
	if rc.PKI != nil {
		for _, name := range []string{"expired", "wrong-ca"} {
			kp, err := rc.PKI.NegativeFixture(name)
			if err != nil {
				rc.Logf("negative fixture %q is unavailable: %v", name, err)
				continue
			}
			cert, err := loadKeyPair(kp.Cert, kp.Key)
			if err != nil {
				rc.Logf("negative fixture %q does not load: %v", name, err)
				continue
			}
			s, err := dialDUT(ctx, rc, "PKI-20 present the "+name+" fixture",
				HandshakeOptions{Identity: &cert})
			if err != nil {
				return certify.Result{}, err
			}
			fixtures = append(fixtures, errorFixture{
				name: name, defect: committedDefect(name),
				source: "committed fixture " + kp.Cert, s: s,
			})
		}
	}

	// Then the shape the document actually describes: a device certificate on
	// the serca-mica-device chain with an error introduced. Minting it under
	// the bench root means the ONLY thing wrong with it is the deliberate
	// error, so a refusal is attributable to that error and not to an
	// unrecognised issuer.
	if root, why := benchRoot(rc); root == nil {
		rc.Logf("no minted error certificates: %s", why)
	} else {
		h, herr := HierarchyUnder(root, "suitepki error-cert")
		if herr != nil {
			return certify.Result{}, fmt.Errorf("build a hierarchy under the bench root: %w", herr)
		}
		mica, merr := h.IssuerFor(ShapeSERCAMICADevice)
		if merr != nil {
			return certify.Result{}, merr
		}
		set, serr := NegativeFixtures(mica, "suitepki error certificate")
		if serr != nil {
			return certify.Result{}, fmt.Errorf("mint the error-certificate set: %w", serr)
		}
		for _, f := range set.HandshakeFatal() {
			if f.Name == "wrong-ca" {
				continue // already covered by the committed fixture
			}
			tc := f.Leaf.TLSCertificate()
			s, derr := dialDUT(ctx, rc, "PKI-20 present the minted "+f.Name+" fixture",
				HandshakeOptions{Identity: &tc})
			if derr != nil {
				return certify.Result{}, derr
			}
			fixtures = append(fixtures, errorFixture{
				name: "minted " + f.Name, defect: f.Defect,
				source: "minted on a serca-mica-device chain under the bench root", s: s,
			})
		}
	}

	if len(fixtures) == 0 {
		return certify.Skipped("no deliberate-error certificate material is available: the committed negative " +
			"fixtures could not be loaded and the bench root's private key is not present, so nothing could be " +
			"presented to the DUT"), nil
	}

	var accepted []string
	for _, f := range fixtures {
		if f.s.Facts.Completed {
			accepted = append(accepted, f.name)
		}
	}
	verdict, notes := certify.Pass, fmt.Sprintf("the DUT refused all %d error certificates presented", len(fixtures))
	if len(accepted) > 0 {
		verdict = certify.Fail
		notes = fmt.Sprintf("the DUT COMPLETED a handshake with %d of %d error certificates: %s",
			len(accepted), len(fixtures), strings.Join(accepted, ", "))
	}

	return certify.Result{
		Verdict: verdict,
		Notes:   notes,
		Cite: func(_ context.Context, ev *certify.Evidence) ([]certify.Assertion, error) {
			var out []certify.Assertion
			var lines []string
			var alerts []string
			ok := true

			for _, f := range fixtures {
				w, _ := f.s.wire(ev)
				outcome := "refused: " + f.s.Facts.HandshakeErr
				if f.s.Facts.Completed {
					outcome, ok = "ACCEPTED — the handshake completed", false
				}
				if w != nil {
					if al, found := w.FatalAlert(); found {
						outcome += " — " + AlertText(al)
						alerts = append(alerts, fmt.Sprintf("%s: %s",
							f.name, tlsdis.AlertDescriptionName(al.Description)))
					}
					frames := sessionFrames(w)
					if len(frames) > 0 {
						v := certify.Pass
						if f.s.Facts.Completed {
							v = certify.Fail
						}
						a, err := ev.CiteFrames(
							fmt.Sprintf("the DUT refused the %s error certificate (%s)", f.name, f.defect),
							"present the fixture as the bench's client certificate and observe the handshake "+
								"outcome and any TLS alert in the capture",
							v, outcome, frames)
						if err != nil {
							return nil, err
						}
						a.Note = joinNote(a.Note, "material: "+f.source)
						out = append(out, a)
					}
				}
				lines = append(lines, fmt.Sprintf("%s (%s): %s", f.name, f.defect, outcome))
			}

			frames := ev.Frames()
			if len(frames) == 0 {
				out = append(out, ev.NoEvidence(claimErrorCertsRefused))
				return out, nil
			}
			v := certify.Pass
			if !ok {
				v = certify.Fail
			}
			roll, err := ev.CiteFrames(claimErrorCertsRefused,
				"each deliberate-error certificate presented in turn as the bench's client certificate; the "+
					"handshake outcome and any fatal alert are the observables",
				v, strings.Join(lines, "; "), frames)
			if err != nil {
				return nil, err
			}
			out = append(out, roll)

			avail, err := ev.Narrative(claimErrorCertsAvailable,
				"inventory of the deliberate-error material this run presented",
				certify.Pass,
				fmt.Sprintf("%d fixture(s): %s", len(fixtures), strings.Join(fixtureNames(fixtures), ", ")),
				"certs/mbaps/negative (committed, generated by `make gen-mbaps-certs`) and material minted in "+
					"memory under the bench root for this run")
			if err != nil {
				return nil, err
			}
			out = append(out, avail)

			// The gap the catalog flags: this document names neither the errors
			// to inject nor the expected alert. Observing the alerts and NOT
			// grading them is the only honest thing to do with that.
			skip := ev.SkipAssertion(claimAlertCode,
				"TLS alert records in the capture, read in the clear",
				"the SunSpec Test PKI document defines neither which errors are injected nor the alert a "+
					"conformant device must answer with; that criterion belongs to the SunSpec CSIP 2030.5 "+
					"Test Procedures and is not gradeable from this document")
			if len(alerts) > 0 {
				skip.Observed += ". Alerts observed, for the record: " + strings.Join(alerts, ", ")
			}
			out = append(out, skip)
			return out, nil
		},
	}, nil
}

func fixtureNames(fs []errorFixture) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.name)
	}
	return out
}

// committedDefect names what is wrong with a committed negative fixture, from
// the fixture tree's own manifest vocabulary.
func committedDefect(name string) string {
	switch name {
	case "expired":
		return "validity window ended in the past"
	case "wrong-ca":
		return "issued by a root outside the DUT's trust domain"
	default:
		return "deliberate error"
	}
}

// sessionFrames returns the capture frames that carried a conversation's bytes,
// ascending.
//
// Pure-ACK, SYN and FIN frames carry no payload and are deliberately left out:
// nothing here is asserted about them, and a citation should cover the frames
// whose bytes back the claim and no more.
func sessionFrames(w *WireHandshake) []int {
	seen := map[int]bool{}
	for _, d := range []*netdis.Direction{w.ClientDir, w.ServerDir} {
		if d == nil || d.Bytes.Len() == 0 {
			continue
		}
		for _, f := range d.Bytes.PacketsFor(0, d.Bytes.Len()) {
			seen[f] = true
		}
	}
	out := make([]int, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Ints(out)
	return out
}
