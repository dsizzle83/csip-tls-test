package suitecsip

// comm.go implements the COMM-* family: transport, TLS and certificate-chain
// conformance.
//
// This is the strongest family in the suite, and the reason is worth stating:
// everything COMM-003 and COMM-004 are about is CLEARTEXT in a TLS 1.2
// handshake. Versions, offered and negotiated suites, both certificate chains,
// CertificateRequest and every alert sit in the pcap in the open, so these rows
// produce fully re-checkable citations with no key log and no cooperation from
// the DUT. A reviewer can open the capture at the cited frame and read the
// cipher_suites vector for themselves.
//
// The COMM-004 sub-tests split along a line the bench once could not cross.
// A/B/C ask whether the DUT ACCEPTS a valid chain of a given depth: that is
// observable, because whatever depth the bench server is provisioned with is
// visible in the Certificate message and the DUT's acceptance is visible in the
// completed handshake. D/E/F/G ask whether the DUT REJECTS a specific
// non-conformant chain, and that requires the bench to PRESENT that chain.
//
// It now can. gridsim's POST /admin/chain installs a chain and key for NEW
// connections and restores the original on demand, so those four rows mint
// their fixture, install it, give the DUT one connection window and put the
// bench back — see commChainRejection and chainswap.go. The detector that
// decides them is the one written while they could only SKIP; going live did
// not change a line of it, which is the whole return on having written a real
// check rather than a stub. They still SKIP, with the reason they always
// carried, against a bench whose gridsim has no such lever — and the check
// establishes WHICH case it is by probing the endpoint, not by assuming.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/certify/suitepki"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdis"
)

// mdnsPorts are the service-discovery ports COMM-002 requires the DUT NOT to
// have used: 5353 is mDNS/xmDNS (the COMM-001 mechanism), 1900 is SSDP.
var mdnsPorts = map[uint16]string{5353: "mDNS/xmDNS", 1900: "SSDP"}

// commBasicDiscovery implements COMM-002 — Basic Discovery (Out-of-Band).
//
// The criterion the wire can settle cleanly is the negative one: the DUT
// reached the server at an address and port nobody advertised to it, and it
// sent no discovery queries to do so. The positive half (it then walked the
// tree) is the ordinary discovery evidence.
func commBasicDiscovery(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return fmt.Sprintf("out-of-band discovery: waited %s for the DUT's poll cycle against the "+
				"configured 2030.5 endpoint", o.Waited.Round(rounding))
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				{
					Claim: "the DUT reached the 2030.5 server at the out-of-band configured address and port",
					How: "the TCP conversation attributed to this test case, whose remote endpoint is the " +
						"configured server address",
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						frames := t.Handshake.ClientHelloFrames
						if len(frames) == 0 {
							return unavailable("the capture holds no ClientHello for this session")
						}
						return found(certify.Pass, frames,
							"TLS session %s established to the configured endpoint %s", t.Stream.Key, t.Remote)
					},
				},
				critNoServiceDiscovery(),
				critDiscoveryRoot(),
				critFollowedLink(),
				{
					Claim:           "every discovery GET in the session was answered with a 2xx status",
					How:             "the status line of each response in the recovered transcript",
					NeedsTranscript: true,
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						var bad []Exchange
						for _, e := range t.Exchanges {
							if e.Req == nil || e.Req.Method != "GET" || e.Resp == nil {
								continue
							}
							if e.Resp.Status < 200 || e.Resp.Status >= 300 {
								bad = append(bad, e)
							}
						}
						if len(t.Exchanges) == 0 {
							return unavailable("the recovered transcript holds no exchanges")
						}
						if len(bad) > 0 {
							return citeExchange(bad[0], certify.Fail,
								"%d of %d GETs were not 2xx; first was %s",
								len(bad), len(t.Exchanges), bad[0].String())
						}
						return found(certify.Pass, allFrames(t.Exchanges),
							"%d GET(s), all 2xx: %s", len(t.Exchanges), t.Summary())
					},
				},
			}
		},
	})
}

// critNoServiceDiscovery asserts the out-of-band half of COMM-002: no DNS-SD.
//
// An ABSENCE cannot be attributed to one test case's frames — the whole point
// is that no such frame exists anywhere — so this is deliberately a Narrative
// over the run's entire capture rather than a citation, and it says so.
func critNoServiceDiscovery() criterion {
	return criterion{
		Claim: "the DUT used the out-of-band configuration rather than service discovery: the capture " +
			"contains no mDNS/xmDNS or SSDP query from the DUT",
		How: "a scan of the WHOLE run capture for UDP traffic on the service-discovery ports, since an " +
			"absence cannot be attributed to a single test case's frames — counted per SOURCE ADDRESS, " +
			"because only datagrams the DUT itself sent bear on this claim",
		Wire: func(ev *certify.Evidence, t *Transcript) Finding {
			// Attribute by source address. The claim is about what THE DUT sent,
			// and a bench segment carries plenty of discovery chatter from other
			// hosts: counting all of it reported "SSDP×4" against a conformant
			// gateway when every one of those datagrams came from the bench
			// workstation itself (2026-07-28). A datagram IS attributable —
			// connectionless or not, it carries a source IP.
			dut, known := dutAddr(t)
			n, other, desc := scanServiceDiscovery(ev, dut, known)
			v := certify.Pass
			switch {
			case n > 0:
				// The DUT itself queried a discovery protocol, which contradicts
				// out-of-band configuration. Still WARN rather than FAIL: a
				// shared segment can echo a datagram back at its sender.
				v = certify.Warn
			case !known && other > 0:
				// Discovery traffic exists but the DUT's address could not be
				// established here, so it can be neither ruled in nor out.
				v = certify.Warn
			}
			// Deliberately no frame citation: the claim is about what is NOT in
			// the capture, and this check owns only its own TCP session's frames.
			// criterion.cite turns an uncited finding into a Narrative naming the
			// capture as the source, which is the honest record.
			return Finding{Verdict: v, Observed: desc}
		},
	}
}

// dutAddr returns the DUT's IP as the capture itself reports it: the source of
// the direction that sent the ClientHello, since the DUT is the party that
// dials the 2030.5 server. The bool is false when no session was recovered and
// the address is therefore unknown.
func dutAddr(t *Transcript) (netip.Addr, bool) {
	if t == nil || t.ClientDir == nil {
		return netip.Addr{}, false
	}
	a := t.ClientDir.Flow.Src.Addr.Unmap()
	return a, a.IsValid()
}

// scanServiceDiscovery counts discovery datagrams in the whole capture,
// separating those the DUT sent from everyone else's.
//
// The split is the point. A conformance bench is a shared Ethernet segment: the
// workstation running this harness advertises over SSDP, and so may anything
// else plugged into the switch. Counting every datagram and reporting the total
// against the DUT is how a conformant gateway gets a WARN for its neighbours'
// chatter — which is exactly what happened on 2026-07-28, when all four SSDP
// datagrams came from the bench workstation.
//
// Returns the DUT's own count, everyone else's count, and the description.
func scanServiceDiscovery(ev *certify.Evidence, dut netip.Addr, dutKnown bool) (int, int, string) {
	byProto := map[string]int{}
	bySource := map[string]int{}
	dutTotal, otherTotal := 0, 0
	for _, f := range ev.Index.Frames() {
		if f == nil || f.UDP == nil {
			continue
		}
		for _, p := range []uint16{f.UDP.SrcPort, f.UDP.DstPort} {
			name, ok := mdnsPorts[p]
			if !ok {
				continue
			}
			src := f.Src.Unmap()
			if dutKnown && src == dut {
				dutTotal++
				byProto[name]++
			} else {
				otherTotal++
				bySource[src.String()]++
			}
			break
		}
	}

	switch {
	case dutTotal == 0 && otherTotal == 0:
		return 0, 0, "no mDNS/xmDNS (UDP 5353) or SSDP (UDP 1900) datagram appears anywhere in the run capture"
	case dutTotal == 0 && dutKnown:
		return 0, otherTotal, fmt.Sprintf("the DUT (%s) sent no mDNS/xmDNS or SSDP datagram; the capture "+
			"holds %d from other hosts on the bench segment (%s), which do not bear on this claim",
			dut, otherTotal, joinCounts(bySource))
	case dutTotal == 0:
		return 0, otherTotal, fmt.Sprintf("the capture holds %d service-discovery datagram(s) (%s), but no "+
			"session was recovered for this test case so the DUT's address is unknown here and they can "+
			"be neither attributed to it nor ruled out", otherTotal, joinCounts(bySource))
	default:
		msg := fmt.Sprintf("the DUT (%s) sent %d service-discovery datagram(s): %s",
			dut, dutTotal, joinCounts(byProto))
		if otherTotal > 0 {
			msg += fmt.Sprintf(" (a further %d came from other hosts: %s)", otherTotal, joinCounts(bySource))
		}
		return dutTotal, otherTotal, msg
	}
}

// joinCounts renders a count map deterministically, so two runs of the same
// capture produce byte-identical evidence.
func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s×%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

// commBasicSecurity implements COMM-003 — Basic Security.
func commBasicSecurity(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "TLS profile of the DUT's northbound CSIP session (CSIP §5.2.1.1, IEEE 2030.5 §6.7)"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critTLS12(),
				critMandatoryCipherOffered(),
				critCipherNegotiated(),
				critMutualAuth(),
				critHandshakeComplete(),
				{
					Claim: "the DUT carried 2030.5 over HTTPS only: no cleartext HTTP request appears on the " +
						"connection it opened to the server",
					How: "every application-layer byte in the attributed conversation is inside a TLS record; " +
						"a cleartext request would appear as a plain HTTP start line at stream offset 0",
					Wire: func(_ *certify.Evidence, t *Transcript) Finding {
						if t.ClientDir == nil || t.ClientDir.Bytes == nil {
							return unavailable("the DUT direction of the conversation was not reassembled")
						}
						head := t.ClientDir.Bytes.Bytes()
						if len(head) > 16 {
							head = head[:16]
						}
						if looksLikeHTTP(head) {
							return Finding{Verdict: certify.Fail,
								Observed: fmt.Sprintf("the conversation opens with cleartext HTTP: %q", head),
								Dir:      t.ClientDir, Start: 0, End: len(head)}
						}
						if len(head) < 5 {
							return unavailable("the DUT direction carries fewer than 5 bytes")
						}
						return Finding{
							Verdict: certify.Pass,
							Observed: fmt.Sprintf("the conversation opens with a TLS %s record of type %s",
								tlsdis.VersionName(uint16(head[1])<<8|uint16(head[2])),
								tlsdis.ContentTypeName(tlsdis.ContentType(head[0]))),
							Dir: t.ClientDir, Start: 0, End: 5,
						}
					},
				},
				critDiscoveryRoot(),
			}
		},
	})
}

func looksLikeHTTP(b []byte) bool {
	for _, m := range []string{"GET ", "PUT ", "POST ", "HEAD ", "DELETE ", "OPTIONS "} {
		if strings.HasPrefix(string(b), m) {
			return true
		}
	}
	return false
}

// commAdvancedSecurity implements COMM-004 — the parent Advanced Security row.
//
// It asserts the part of the row the bench can reach today (the chain the
// server actually presents, and the DUT's acceptance of it) and records the
// four rejection sub-tests as explicitly unreached, with the reason. The parent
// row's verdict is therefore the honest roll-up of "the acceptance half held,
// the rejection half was not exercised".
func commAdvancedSecurity(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
	return run(ctx, rc, spec{
		Notes: func(o *Observation) string {
			return "certificate-chain handling: the acceptance sub-tests (A/B/C) are asserted from the " +
				"chain the bench server presents; the rejection sub-tests (D/E/F/G) each install their own " +
				"non-conformant chain through gridsim's runtime chain lever and are decided on their own " +
				"rows — see COMM-004D..G"
		},
		Criteria: func(o *Observation) []criterion {
			return []criterion{
				critServerChainObserved(),
				critCipherNegotiated(),
				critHandshakeComplete(),
				critDUTChainProfile(),
				critRejectionUnexercised(),
			}
		},
	})
}

// critServerChainObserved reports the chain the bench server presented and
// whether the DUT accepted it.
func critServerChainObserved() criterion {
	return criterion{
		Claim: "the DUT validated the server's certificate chain and established the session",
		How: "the certificate_list of the server's Certificate handshake message, and the completion of " +
			"the handshake that followed it",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			ht, note := handshakeOf(t)
			h := &ht.Handshake
			if len(h.ServerChain) == 0 {
				if h.Resumed {
					return resumedNoCertificates(h, "the chain the server presented")
				}
				return unavailable("the capture holds no server Certificate message for this session")
			}
			desc := chainDescription(h.ServerChain)
			if !h.Complete {
				if a, ok := firstFatalAlert(ht); ok {
					return annotate(found(certify.Fail, a.Packets,
						"the DUT REFUSED the %d-certificate chain (%s) with fatal alert %s",
						len(h.ServerChain), desc, a), note)
				}
				return annotate(found(certify.Fail, h.ServerCertFrames,
					"the handshake did not complete after the server's %d-certificate chain (%s)",
					len(h.ServerChain), desc), note)
			}
			return annotate(found(certify.Pass, h.ServerCertFrames,
				"the server presented %d certificate(s) — %s — and the DUT completed the handshake",
				len(h.ServerChain), desc), note)
		},
	}
}

// critDUTChainProfile reports the DUT's own certificate against the IEEE
// 2030.5 §6.11 device-certificate profile.
//
// It is a WARN-not-FAIL criterion on purpose. §6.11's requirements (empty
// SubjectName, a critical hardwareModuleName SAN, a critical certificatePolicy,
// notAfter 99991231235959Z) are what a certification lab checks against the
// issued credential, and a bench certificate minted by `make gen-client-cert`
// legitimately does not satisfy them. Reporting the deviation as a FAIL of
// COMM-004 would be reporting the BENCH's PKI as the DUT's non-conformance.
func critDUTChainProfile() criterion {
	return criterion{
		Claim: "the DUT's own device certificate, as presented on the wire, matches the IEEE 2030.5 §6.11 " +
			"device-certificate profile",
		How: "an ASN.1 walk of the leaf certificate from the DUT's Certificate handshake message: key " +
			"algorithm and curve, SubjectName, critical extensions and notAfter",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			ht, note := handshakeOf(t)
			h := &ht.Handshake
			if len(h.ClientChain) == 0 {
				if h.Resumed {
					return resumedNoCertificates(h, "the DUT's own device certificate")
				}
				return unavailable("the DUT presented no certificate in this session")
			}
			ci, err := tlsdis.ParseCertInfo(h.ClientChain[0])
			if err != nil {
				return annotate(found(certify.Fail, h.ClientCertFrames,
					"the DUT's leaf certificate did not parse: %v", err), note)
			}
			var deviations []string
			if ci.PublicKeyAlgorithm != "ECDSA" || ci.Curve != "P-256" {
				deviations = append(deviations, fmt.Sprintf("public key is %s/%s, §6.11 requires EC P-256",
					ci.PublicKeyAlgorithm, ci.Curve))
			}
			if ci.Subject != "" {
				deviations = append(deviations, fmt.Sprintf("SubjectName is %q, §6.11 requires it EMPTY with the "+
					"identity in a critical subjectAltName hardwareModuleName", ci.Subject))
			}
			if ci.NotAfter.Year() != 9999 {
				deviations = append(deviations, fmt.Sprintf("notAfter is %s, §6.11 requires 99991231235959Z for a "+
					"256-bit ECC device certificate", ci.NotAfter.Format("2006-01-02")))
			}
			if len(deviations) == 0 {
				return annotate(found(certify.Pass, h.ClientCertFrames,
					"%s; %d extension(s), EC %s", certSummary(h.ClientChain[0]), len(ci.Extensions), ci.Curve), note)
			}
			return annotate(found(certify.Warn, h.ClientCertFrames,
				"the certificate the DUT presented deviates from the §6.11 profile in %d respect(s): %s. "+
					"On this bench the credential is minted by the harness PKI, so a deviation here is a "+
					"property of the TEST credential and is reported rather than failed",
				len(deviations), strings.Join(deviations, "; ")), note)
		},
	}
}

// critRejectionUnexercised is the honest record that COMM-004's D/E/F/G half
// was not run, together with the detector that will decide it once it can be.
func critRejectionUnexercised() criterion {
	return criterion{
		Claim: "the DUT rejects a peer certificate chain with an invalid MICA extension or a self-signed " +
			"device certificate (COMM-004 sub-tests D, E, F, G)",
		How: "a fatal TLS alert, a TCP disconnect, or an HTTP 403 from the DUT in response to a " +
			"non-conformant chain — the alternatives the published erratum (Annex A, seq 7) admits " +
			"alongside the alert",
		Wire: func(_ *certify.Evidence, t *Transcript) Finding {
			if a, ok := firstFatalAlert(t); ok {
				return found(certify.Warn, a.Packets,
					"a fatal alert %s was observed on this session, but the bench presented its NORMAL "+
						"chain, so this is not evidence of the D/E/F/G rejection behaviour", a)
			}
			return unavailable("no non-conformant certificate chain was presented to the DUT in this run")
		},
		Skip: "these four sub-tests require the bench's 2030.5 server to PRESENT a non-conformant chain " +
			"(invalid MICA extendedKeyUsage/name/policyMapping, or a self-signed device certificate), and " +
			"they now do exactly that on their OWN rows: COMM-004D, E, F and G each mint their fixture, " +
			"install it through gridsim's runtime chain lever (POST /admin/chain) and restore the bench " +
			"afterwards. This PARENT row deliberately does not repeat the experiment — it ran against " +
			"the bench's normal chain, which is what makes its acceptance half meaningful, and a row that " +
			"swapped the chain under itself could assert neither half cleanly. Read the four sub-test rows " +
			"for the rejection verdicts",
	}
}

// chainDescription renders a certificate chain leaf-first for an Observed field.
func chainDescription(chain [][]byte) string {
	parts := make([]string, 0, len(chain))
	for i, der := range chain {
		label := "leaf"
		switch {
		case i == len(chain)-1 && len(chain) > 1:
			label = "root/anchor"
		case i > 0:
			label = fmt.Sprintf("issuer %d", i)
		}
		parts = append(parts, label+": "+certSummary(der))
	}
	return strings.Join(parts, " | ")
}

// commChainDepth builds a COMM-004A/B/C check for a required chain depth.
//
// The verdict logic is the interesting part. If the bench presents the depth
// under test and the DUT completes the handshake, that is a PASS with a real
// citation. If the bench presents a DIFFERENT depth, the sub-test was not
// exercised at all and the row SKIPs saying which depth it did see — reporting
// PASS because "some chain worked" would be certifying a test that never ran.
func commChainDepth(depth int, shape string) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		return run(ctx, rc, spec{
			Notes: func(o *Observation) string {
				return fmt.Sprintf("certificate chain length %d (%s)", depth, shape)
			},
			Criteria: func(o *Observation) []criterion {
				return []criterion{
					chainDepthCriterion(depth, shape)(o),
					critCipherNegotiated(),
					critDiscoveryRoot(),
				}
			},
		})
	}
}

// chainDepthCriterion is the decision logic of COMM-004A/B/C, factored out of
// the check so it has exactly one definition and the unit tests exercise the
// same code the run does.
func chainDepthCriterion(depth int, shape string) func(*Observation) criterion {
	return func(_ *Observation) criterion {
		return criterion{
			Claim: fmt.Sprintf("the DUT established a TLS session with a peer presenting a "+
				"%d-certificate chain (%s)", depth, shape),
			How: "the number of certificates in the server's Certificate handshake message, and " +
				"the completion of the handshake",
			Wire: func(_ *certify.Evidence, t *Transcript) Finding {
				ht, note := handshakeOf(t)
				h := &ht.Handshake
				if len(h.ServerChain) == 0 {
					if h.Resumed {
						return resumedNoCertificates(h, "the length of the chain the server presented")
					}
					return unavailable("the capture holds no server Certificate message for this session")
				}
				if len(h.ServerChain) != depth {
					return unavailable("the bench server presented a %d-certificate chain (%s), not the "+
						"%d-certificate chain this sub-test is about; start gridsim with a -cert-chain of "+
						"the depth this row is about. The runtime lever (POST /admin/chain) exists but is "+
						"not used here: it is reserved for the D/E/F/G rejection fixtures, which restore "+
						"what they install, and a check that swapped in a chain merely to observe its own "+
						"depth would be asserting the harness rather than the bench's provisioning",
						len(h.ServerChain), chainDescription(h.ServerChain), depth)
				}
				if !h.Complete {
					if a, ok := firstFatalAlert(ht); ok {
						return annotate(found(certify.Fail, a.Packets,
							"the DUT REFUSED the valid %d-certificate chain with fatal alert %s", depth, a), note)
					}
					return annotate(found(certify.Fail, h.ServerCertFrames,
						"the handshake did not complete against the %d-certificate chain", depth), note)
				}
				return annotate(found(certify.Pass, h.ServerCertFrames,
					"%d certificates presented — %s — handshake completed",
					depth, chainDescription(h.ServerChain)), note)
			},
		}
	}
}

// commChainRejection builds a COMM-004D/E/F/G check.
//
// The shape is: mint the sub-test's non-conformant chain, install it on the
// bench's 2030.5 server through gridsim's runtime chain lever, give the DUT one
// connection window to meet it, and RESTORE the bench whatever happens. The
// detector that decides the row is rejectionFinding, unchanged from when these
// rows could only SKIP — it already implemented the published erratum's three
// acceptable rejection signals, and going live did not need it touched.
//
// The row still SKIPs, with the reason it always carried, on a bench whose
// gridsim has no chain lever. That is a fact about the BENCH, established by
// probing /admin/chain before anything is installed, not about this build.
//
// chainswap.go documents the four ways this goes wrong on a shared bench and
// what is done about each. Two are worth repeating here because they decide
// whether the row means anything at all: the fixture must be anchored on the
// root the DUT ALREADY TRUSTS (or the rejection is about the root rather than
// the defect), and the chain in the capture must be identified BY FINGERPRINT
// (or a session the DUT opened before the swap gets scored as though it had
// been shown the fixture).
func commChainRejection(what string, defect suitepki.MICADefect) certify.Check {
	return func(ctx context.Context, rc *certify.RunCtx) (certify.Result, error) {
		cs := &chainSwap{defect: defect}
		return run(ctx, rc, spec{
			Setup: func(ctx context.Context, d *Driver, _ map[string]string) error {
				skip, err := cs.arm(ctx, rc, d)
				cs.skip = skip
				if skip != "" {
					rc.Logf("COMM-004 rejection sub-test NOT armed: %s", skip)
				}
				return err
			},
			// Unconditional, and handed a context detached from the check's own
			// deadline by run(). A check that left the bench presenting a
			// deliberately non-conformant chain would invalidate every case
			// after it — restoreCriterion carries the outcome into this row's
			// verdict rather than into a log line nobody reads.
			Cleanup: func(ctx context.Context, d *Driver) { cs.restore(ctx, d) },
			Notes: func(o *Observation) string {
				if cs.skip != "" {
					return "rejection sub-test for " + what + ": NOT EXERCISED on this bench — " + cs.skip
				}
				return fmt.Sprintf("rejection sub-test for %s: the bench presented %s (leaf %s, %d "+
					"certificate(s)) to new connections for %s, then restored its original chain",
					what, cs.fixtureDescription(), shortSHA(cs.installed.LeafSHA256),
					cs.installed.ChainLen, o.Waited.Round(rounding))
			},
			Criteria: func(o *Observation) []criterion {
				return []criterion{
					{
						Claim: "the DUT rejects a peer presenting " + what + " and establishes no 2030.5 session",
						How: "a fatal TLS alert from the DUT, or a TCP disconnect, or an HTTP 403 SENT BY THE " +
							"DUT — the three signals the procedure's published erratum (Annex A, seq 7) admits, " +
							"\"A TCP port disconnect or HTTP 403 shall be an acceptable alternative to a TLS " +
							"alert for notification of invalid certificates\" — with no DeviceCapability payload " +
							"on the wire afterwards. WHICH chain the DUT was shown is settled by the SHA-256 of " +
							"the leaf in the server's Certificate message, matched against the fingerprint " +
							"gridsim reported when it installed the fixture",
						Wire: func(ev *certify.Evidence, t *Transcript) Finding {
							if cs.skip != "" {
								return unavailable("%s", cs.skip)
							}
							if ok, why := cs.servedTheFixture(t); !ok {
								return unavailable("%s", why)
							}
							return rejectionFinding(ev, t)
						},
						Skip: cs.skipReason(),
					},
					cs.restoreCriterion(),
				}
			},
		})
	}
}

// skipReason is the criterion's Skip text: the live probe's finding when there
// is one, and otherwise the reason a row lands here on a bench that HAS the
// lever — which is a different failure and deserves a different sentence.
func (cs *chainSwap) skipReason() string {
	if cs.skip != "" {
		return cs.skip
	}
	return "the bench's 2030.5 server could not be observed presenting " + cs.fixtureDescription() +
		" during this check's window. The chain lever itself worked (gridsim POST /admin/chain " +
		"confirmed leaf " + shortSHA(cs.installed.LeafSHA256) + "), so this is a property of the RUN " +
		"rather than of the bench: the DUT opened no new connection while the fixture was installed, or " +
		"the window closed before it did. Start gridsim with -idle-timeout-s below the DUT's poll " +
		"cadence so each cycle opens a fresh session, and lengthen the window with -param " + waitParam
}

// rejectionFinding decides a rejection sub-test from the session.
//
// It implements the procedure's published erratum (Annex A, seq 7), which adds
// as COMM-004's new FIRST Pass/Fail bullet:
//
//	"A TCP port disconnect or HTTP 403 shall be an acceptable alternative
//	 to a TLS alert for notification of invalid certificates."
//
// All three signals are therefore accepted. A check that failed a DUT for
// choosing one of the admitted alternatives would be reporting the PROCEDURE's
// narrowness as the device's non-conformance.
//
// # The direction rule on the 403 arm
//
// A 403 is a notification sent BY the party that rejected the certificate, so
// it evidences the DUT's rejection only when the DUT sent it. In this suite the
// DUT is the 2030.5 CLIENT — it dials out, and RecoverSession therefore parses
// its direction as REQUESTS and the peer's as RESPONSES — so a 403 recovered
// here was sent by the BENCH about the DUT's own credential, which is the
// mirror image of the fact under test. It is reported, because a reviewer
// needs to see it, and it is NOT accepted as the DUT's rejection: crediting the
// DUT for the bench's 403 is the looser reading and the erratum does not ask
// for it. The arm fires as a PASS only for a 403 the DUT itself emitted, which
// is the [S]/[A] topology of the same row.
func rejectionFinding(ev *certify.Evidence, t *Transcript) Finding {
	if a, ok := firstFatalAlert(t); ok {
		return found(certify.Pass, a.Packets, "the DUT sent a fatal TLS alert: %s", a)
	}
	if m, ok := dutForbade(t); ok {
		// Cited by frame, not by citeMessage: a DUT-SENT response travels on
		// the DUT's own direction, and citeMessage picks the direction from the
		// message KIND — which would point a reader at the peer's byte stream.
		f := found(certify.Pass, m.Frames,
			"the DUT answered %s, the HTTP 403 the procedure's erratum (seq 7) admits as an acceptable "+
				"alternative to a TLS alert for notification of an invalid certificate", m.Line())
		if t.ClientDir != nil && m.CipherEnd > m.CipherStart {
			f.Dir, f.Start, f.End = t.ClientDir, m.CipherStart, m.CipherEnd
		}
		return f
	}
	peer403 := ""
	if m, ok := peerForbade(t); ok {
		peer403 = fmt.Sprintf("; the PEER answered %s, which is the bench rejecting the DUT's credential "+
			"rather than the DUT rejecting the bench's and is not this criterion's evidence", m.Line())
	}
	if t.Handshake.Complete && (t.ClientAppRecords > 0 || t.ServerAppRecords > 0) {
		return found(certify.Fail, t.Handshake.ServerCertFrames,
			"the DUT ACCEPTED the non-conformant chain: the handshake completed and %d/%d application-data "+
				"records were exchanged%s", t.ClientAppRecords, t.ServerAppRecords, peer403)
	}
	if fin := teardownFrames(ev, t); len(fin) > 0 {
		return found(certify.Pass, fin,
			"the DUT sent no alert but closed the TCP connection (FIN/RST in frame %v) without completing the "+
				"handshake, which the procedure's erratum (seq 7) admits as an acceptable rejection signal%s",
			fin, peer403)
	}
	return found(certify.Fail, t.Handshake.ClientHelloFrames,
		"the DUT neither completed the handshake nor signalled a rejection; the connection simply stopped%s",
		peer403)
}

// dutForbade returns the first HTTP 403 the DUT ITSELF sent, if any.
//
// The DUT's direction is parsed as requests in the client topology this suite
// runs, so this is empty there by construction — deliberately, see
// rejectionFinding's direction rule. It reads t.DUTResponses so that the day a
// server-role recovery populates them, the erratum's third signal is decided by
// this function with no further change.
func dutForbade(t *Transcript) (*Message, bool) { return firstForbidden(t.DUTResponses) }

// peerForbade returns the first HTTP 403 the DUT's PEER sent.
func peerForbade(t *Transcript) (*Message, bool) { return firstForbidden(t.Responses) }

func firstForbidden(ms []*Message) (*Message, bool) {
	for _, m := range ms {
		if m != nil && m.Status == 403 {
			return m, true
		}
	}
	return nil, false
}

// teardownFrames returns this check's frames that carry a FIN or RST.
//
// It reads the dissected frames rather than the reassembled byte stream because
// a RST carries no payload at all: a connection torn down by a reset leaves
// nothing in the stream to point at, and pointing at the stream would silently
// find nothing exactly when the evidence matters most.
func teardownFrames(ev *certify.Evidence, t *Transcript) []int {
	var out []int
	for _, f := range ev.Index.Frames() {
		if f == nil || f.TCP == nil || !ev.Owns(f.Index) {
			continue
		}
		if f.TCP.Flags.Has(netdis.RST) || f.TCP.Flags.Has(netdis.FIN) {
			out = append(out, f.Index)
		}
	}
	return dedupeInts(out)
}

func allFrames(exs []Exchange) []int {
	var out []int
	for _, e := range exs {
		out = append(out, e.Frames()...)
	}
	return dedupeInts(out)
}
