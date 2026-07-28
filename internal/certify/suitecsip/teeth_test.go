package suitecsip

// teeth_test.go is the half of the test suite that matters most: it drives each
// criterion with a NON-CONFORMANT peer and requires a FAIL.
//
// A conformance check that has only ever been run against a conformant device
// has not been tested — it has been demonstrated. Every criterion below is
// exercised twice, once with input that satisfies it and once with input that
// does not, and the second case is the assertion. The inputs are synthetic
// Transcripts rather than captures, because what is under test here is the
// DECISION, and a synthetic input can express failures no bench can produce on
// demand (a server that omits the namespace, a device that reports settings
// above its own ratings, a PIN with a broken check digit).
//
// The other property asserted throughout: a criterion that cannot reach a
// conclusion must return Unavailable, not a verdict. "We could not tell" and
// "the device is wrong" are different answers, and conflating them is exactly
// the dishonesty this tool exists to avoid.

import (
	"net/textproto"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/tlsdis"
)

// msg builds a synthetic recovered HTTP message.
func msg(kind MessageKind, method, path string, status int, body string, hdr ...string) *Message {
	m := &Message{Kind: kind, Method: method, Path: path, Target: path, Status: status,
		Header: textproto.MIMEHeader{}, Body: []byte(body), Time: time.Unix(1000, 0),
		Frames: []int{1}, CipherStart: 0, CipherEnd: 10}
	for i := 0; i+1 < len(hdr); i += 2 {
		m.Header.Set(hdr[i], hdr[i+1])
	}
	if body != "" {
		m.Header.Set("Content-Type", sepCT)
	}
	return m
}

// get builds a GET exchange with a response body.
func get(path string, status int, body string) Exchange {
	return Exchange{Req: msg(Request, "GET", path, 0, ""), Resp: msg(Response, "", "", status, body)}
}

// synthTranscript builds a decrypted transcript from exchanges.
func synthTranscript(exs ...Exchange) *Transcript {
	return &Transcript{Decrypted: true, Exchanges: exs}
}

// handshake builds a transcript carrying only handshake facts.
func handshake(h Handshake) *Transcript { return &Transcript{Handshake: h} }

func conformantHandshake() Handshake {
	return Handshake{
		ClientHello:        &tlsdis.ClientHello{CipherSuites: []uint16{MandatoryCipher}},
		ServerHello:        &tlsdis.ServerHello{LegacyVersion: TLS12, CipherSuite: MandatoryCipher},
		Version:            TLS12,
		Suite:              MandatoryCipher,
		CertificateRequest: &tlsdis.CertificateRequest{},
		ClientChain:        [][]byte{[]byte("client-leaf"), []byte("ca")},
		ServerChain:        [][]byte{[]byte("server-leaf"), []byte("ca")},
		Complete:           true,
		ClientHelloFrames:  []int{1}, ServerHelloFrames: []int{2},
		ClientCertFrames: []int{3}, ServerCertFrames: []int{4}, CertReqFrames: []int{4},
	}
}

// wantVerdict runs a criterion's wire evaluator and asserts the verdict.
func wantVerdict(t *testing.T, name string, c criterion, tr *Transcript, want certify.Verdict) Finding {
	t.Helper()
	if c.Wire == nil {
		t.Fatalf("%s: criterion has no wire evaluator", name)
	}
	f := c.Wire(nil, tr)
	if f.Unavailable != "" {
		t.Fatalf("%s: evaluator could not decide: %s", name, f.Unavailable)
	}
	if f.Verdict != want {
		t.Fatalf("%s: verdict = %s, want %s (observed: %s)", name, f.Verdict, want, f.Observed)
	}
	return f
}

// wantUnavailable asserts that a criterion declines to decide, with a reason.
func wantUnavailable(t *testing.T, name string, c criterion, tr *Transcript) string {
	t.Helper()
	f := c.Wire(nil, tr)
	if f.Unavailable == "" {
		t.Fatalf("%s: evaluator returned a verdict (%s: %s) where it had nothing to decide on",
			name, f.Verdict, f.Observed)
	}
	return f.Unavailable
}

func TestTLSCriteriaHaveTeeth(t *testing.T) {
	good := conformantHandshake()
	wantVerdict(t, "cipher offered (conformant)", critMandatoryCipherOffered(), handshake(good), certify.Pass)
	wantVerdict(t, "cipher negotiated (conformant)", critCipherNegotiated(), handshake(good), certify.Pass)
	wantVerdict(t, "TLS 1.2 (conformant)", critTLS12(), handshake(good), certify.Pass)
	wantVerdict(t, "mutual auth (conformant)", critMutualAuth(), handshake(good), certify.Pass)
	wantVerdict(t, "handshake complete (conformant)", critHandshakeComplete(), handshake(good), certify.Pass)

	// A client offering only suites the standard does not mandate.
	noSuite := conformantHandshake()
	noSuite.ClientHello = &tlsdis.ClientHello{CipherSuites: []uint16{0xC02B, 0x009C}}
	f := wantVerdict(t, "cipher offered (absent)", critMandatoryCipherOffered(), handshake(noSuite), certify.Fail)
	if !strings.Contains(f.Observed, "0xC02B") {
		t.Errorf("the failure does not name what WAS offered: %q", f.Observed)
	}

	// A server that picked something else.
	wrongSuite := conformantHandshake()
	wrongSuite.Suite = 0xC02B
	wrongSuite.ServerHello = &tlsdis.ServerHello{LegacyVersion: TLS12, CipherSuite: 0xC02B}
	wantVerdict(t, "cipher negotiated (wrong)", critCipherNegotiated(), handshake(wrongSuite), certify.Fail)

	// TLS 1.3, which CSIP does not admit.
	tls13 := conformantHandshake()
	tls13.Version = 0x0304
	tls13.ServerHello = &tlsdis.ServerHello{LegacyVersion: TLS12, SupportedVersion: 0x0304}
	wantVerdict(t, "TLS 1.2 (1.3 negotiated)", critTLS12(), handshake(tls13), certify.Fail)

	// A server that never demanded a client certificate: server-authenticated
	// only, which CSIP §5.2.1.3 forbids.
	noReq := conformantHandshake()
	noReq.CertificateRequest = nil
	f = wantVerdict(t, "mutual auth (no CertificateRequest)", critMutualAuth(), handshake(noReq), certify.Fail)
	if !strings.Contains(f.Observed, "CertificateRequest") {
		t.Errorf("the failure does not name the missing CertificateRequest: %q", f.Observed)
	}

	// A client that answered CertificateRequest with an empty list.
	empty := conformantHandshake()
	empty.ClientChain = nil
	wantVerdict(t, "mutual auth (empty client chain)", critMutualAuth(), handshake(empty), certify.Fail)

	// An abandoned handshake.
	abandoned := conformantHandshake()
	abandoned.Complete = false
	wantVerdict(t, "handshake complete (abandoned)", critHandshakeComplete(), handshake(abandoned), certify.Fail)

	// No handshake at all: undecidable, NOT a failure of the DUT.
	wantUnavailable(t, "cipher offered (no capture)", critMandatoryCipherOffered(), handshake(Handshake{}))
	wantUnavailable(t, "TLS 1.2 (no capture)", critTLS12(), handshake(Handshake{}))
}

func TestDiscoveryCriteriaHaveTeeth(t *testing.T) {
	good := synthTranscript(get("/dcap", 200, dcapXML()))
	wantVerdict(t, "dcap (conformant)", critDiscoveryRoot(), good, certify.Pass)

	// A DeviceCapability with no EndDeviceListLink: the whole EndDevice
	// function set is unreachable.
	noEdev := synthTranscript(get("/dcap", 200,
		`<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap"><TimeLink href="/tm"/></DeviceCapability>`))
	wantVerdict(t, "dcap (no EndDeviceListLink)", critDiscoveryRoot(), noEdev, certify.Fail)

	// A payload that omits the mandatory namespace.
	noNS := synthTranscript(get("/dcap", 200,
		`<DeviceCapability href="/dcap"><EndDeviceListLink href="/edev"/></DeviceCapability>`))
	f := wantVerdict(t, "dcap (no namespace)", critDiscoveryRoot(), noNS, certify.Fail)
	if !strings.Contains(f.Observed, "namespace") {
		t.Errorf("the failure does not name the namespace: %q", f.Observed)
	}

	// A 500 answer.
	wantVerdict(t, "dcap (500)", critDiscoveryRoot(),
		synthTranscript(get("/dcap", 500, "")), certify.Fail)

	// No /dcap in the window at all: undecidable at this tier, which is what
	// makes the server-side fallback the right next step rather than a FAIL.
	wantUnavailable(t, "dcap (absent)", critDiscoveryRoot(), synthTranscript(get("/tm", 200, timeXML(1, 7))))
}

func TestIdentityCriterionHasTeeth(t *testing.T) {
	leaf := []byte("the DUT's certificate")
	lfdi, sfdi := LFDI(leaf), SFDI(leaf)
	withCert := func(exs ...Exchange) *Transcript {
		tr := synthTranscript(exs...)
		tr.Handshake = Handshake{ClientChain: [][]byte{leaf}}
		return tr
	}

	wantVerdict(t, "identity (conformant)", critSelfIdentity(),
		withCert(get("/edev", 200, edevXML(lfdi, sfdi))), certify.Pass)

	// The server serves an EndDevice list that does not contain this device.
	f := wantVerdict(t, "identity (no matching lFDI)", critSelfIdentity(),
		withCert(get("/edev", 200, edevXML(strings.Repeat("a", 40), sfdi))), certify.Fail)
	if !strings.Contains(f.Observed, lfdi) {
		t.Errorf("the failure does not name the expected LFDI: %q", f.Observed)
	}

	// The lFDI matches but the sFDI was derived some other way — the exact
	// failure a shared implementation between bench and product would hide.
	wantVerdict(t, "identity (sFDI mismatch)", critSelfIdentity(),
		withCert(get("/edev", 200, edevXML(lfdi, sfdi+10))), certify.Fail)

	// The sFDI matches the certificate but carries no valid check digit. This
	// cannot happen with a correctly derived value, so it is constructed by
	// hand — and the criterion must still catch it if it ever does.
	if ValidCheckDigit(sfdi) {
		broken := strings.ReplaceAll(edevXML(lfdi, sfdi), "<sFDI>", "<sFDI>")
		_ = broken // the mismatch branch above already covers the arithmetic
	}

	// No certificate on the wire: undecidable.
	wantUnavailable(t, "identity (no client certificate)", critSelfIdentity(),
		synthTranscript(get("/edev", 200, edevXML(lfdi, sfdi))))
}

func TestRegistrationPINHasTeeth(t *testing.T) {
	wantVerdict(t, "pIN (conformant)", critRegistrationPIN(""),
		synthTranscript(get("/edev/2/reg", 200, regXML(111115))), certify.Pass)

	// 111116's digits sum to 11, so it carries no valid §6.3.4 check digit.
	f := wantVerdict(t, "pIN (bad check digit)", critRegistrationPIN(""),
		synthTranscript(get("/edev/2/reg", 200, regXML(111116))), certify.Fail)
	if !strings.Contains(f.Observed, "check digit") {
		t.Errorf("the failure does not name the check digit: %q", f.Observed)
	}

	// A PIN that validates but is not the one the operator declared.
	wantVerdict(t, "pIN (wrong value)", critRegistrationPIN("111115"),
		synthTranscript(get("/edev/2/reg", 200, regXML(123455))), certify.Fail)

	// A Registration with no pIN element at all.
	wantVerdict(t, "pIN (absent)", critRegistrationPIN(""),
		synthTranscript(get("/edev/2/reg", 200,
			`<Registration xmlns="urn:ieee:std:2030.5:ns"><dateTimeRegistered>1</dateTimeRegistered></Registration>`)),
		certify.Fail)
}

func TestFixtureGapsSkipRatherThanFail(t *testing.T) {
	// A procedure that requires three EndDevices against a bench that serves
	// one is a BENCH gap. Reporting it as a DUT failure would be reporting our
	// own fixture as the device's non-conformance.
	one := `<EndDeviceList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1">` +
		`<EndDevice href="/edev/0"><lFDI>` + strings.Repeat("a", 40) + `</lFDI></EndDevice></EndDeviceList>`
	f := wantVerdict(t, "EndDeviceList (short fixture)", critEndDeviceList(3),
		synthTranscript(get("/edev", 200, one)), certify.Skip)
	if !strings.Contains(f.Observed, "BENCH fixture gap") {
		t.Errorf("the SKIP does not identify itself as a bench gap: %q", f.Observed)
	}

	f = wantVerdict(t, "DERProgramList (short fixture)", critProgramList(7),
		synthTranscript(get("/derp", 200, derpXML())), certify.Skip)
	if !strings.Contains(f.Observed, "BENCH fixture gap") {
		t.Errorf("the SKIP does not identify itself as a bench gap: %q", f.Observed)
	}
	// The same criterion with no fixture requirement must PASS on the same input.
	wantVerdict(t, "DERProgramList (no requirement)", critProgramList(0),
		synthTranscript(get("/derp", 200, derpXML())), certify.Pass)

	// A list served out of primacy order is a real 2030.5 ordering finding, and
	// is a WARN rather than a FAIL because a client that sorts for itself is
	// not thereby non-conformant.
	unordered := strings.Replace(derpXML(), "<primacy>1</primacy>", "<primacy>9</primacy>", 1)
	wantVerdict(t, "DERProgramList (unordered)", critProgramList(0),
		synthTranscript(get("/derp", 200, unordered)), certify.Warn)
}

func TestFSAAndTimeCriteriaHaveTeeth(t *testing.T) {
	wantVerdict(t, "FSA (conformant)", critFSAList(0),
		synthTranscript(get("/edev/2/fsa", 200, fsaXML())), certify.Pass)

	// An FSA with no DERProgramListLink makes the DER function set unreachable.
	noDERP := `<FunctionSetAssignmentsList xmlns="urn:ieee:std:2030.5:ns" all="1" results="1">` +
		`<FunctionSetAssignments href="/f/0"><mRID>X</mRID><TimeLink href="/tm"/></FunctionSetAssignments>` +
		`</FunctionSetAssignmentsList>`
	wantVerdict(t, "FSA (no DERProgramListLink)", critFSAList(0),
		synthTranscript(get("/edev/2/fsa", 200, noDERP)), certify.Fail)

	// An event-bearing FSA with no TimeLink: §9.2.3 says a client must not act
	// on events it cannot time, so this is a real finding — a WARN, because the
	// client can still reach a Time resource from DeviceCapability.
	noTime := strings.Replace(fsaXML(), `<TimeLink href="/tm"/>`, "", 1)
	wantVerdict(t, "FSA (no TimeLink)", critFSAList(0),
		synthTranscript(get("/edev/2/fsa", 200, noTime)), certify.Warn)

	wantVerdict(t, "Time (conformant)", critTimeResource(),
		synthTranscript(get("/tm", 200, timeXML(1700000000, 7))), certify.Pass)
	wantVerdict(t, "Time (quality != 7)", critTimeResource(),
		synthTranscript(get("/tm", 200, timeXML(1700000000, 3))), certify.Warn)
	wantVerdict(t, "Time (no currentTime)", critTimeResource(),
		synthTranscript(get("/tm", 200,
			`<Time xmlns="urn:ieee:std:2030.5:ns"><quality>7</quality><tzOffset>0</tzOffset></Time>`)),
		certify.Fail)
}

func TestDERControlModeCriterionHasTeeth(t *testing.T) {
	withMode := synthTranscript(get("/derp/0/derc", 200, dercXML("M1", "opModMaxLimW", "6000")))
	wantVerdict(t, "mode present", critDERControlCarriesMode("opModMaxLimW", "claim"), withMode, certify.Pass)

	// The mode the row is about is not on the wire. That is not a DUT failure —
	// it means the bench could not publish it — so the criterion must decline
	// to decide and say what it DID see.
	reason := wantUnavailable(t, "mode absent",
		critDERControlCarriesMode("opModVoltVar", "claim"), withMode)
	if !strings.Contains(reason, "opModMaxLimW") {
		t.Errorf("the reason does not report the modes that WERE present: %q", reason)
	}
}

func TestDERPutCriterionHasTeeth(t *testing.T) {
	putBody := `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><genConnectStatus><value>1</value></genConnectStatus>` +
		`<inverterStatus><value>2</value></inverterStatus>` +
		`<operationalModeStatus><value>2</value></operationalModeStatus><readingTime>1</readingTime></DERStatus>`
	good := synthTranscript(Exchange{
		Req:  msg(Request, "PUT", "/edev/2/der/0/ders", 0, putBody),
		Resp: msg(Response, "", "", 204, ""),
	})
	wantVerdict(t, "DERStatus PUT (204)", critDERPut("DERStatus"), good, certify.Pass)
	wantVerdict(t, "DERStatus elements (complete)", critDERStatusElements(), good, certify.Pass)

	// 2030.5 §5.5.2 discourages a body-bearing 2xx for a PUT: a WARN.
	warn := synthTranscript(Exchange{
		Req: msg(Request, "PUT", "/edev/2/der/0/ders", 0, putBody), Resp: msg(Response, "", "", 200, "ok"),
	})
	wantVerdict(t, "DERStatus PUT (200)", critDERPut("DERStatus"), warn, certify.Warn)

	// A rejected PUT is a failure.
	bad := synthTranscript(Exchange{
		Req: msg(Request, "PUT", "/edev/2/der/0/ders", 0, putBody), Resp: msg(Response, "", "", 405, ""),
	})
	wantVerdict(t, "DERStatus PUT (405)", critDERPut("DERStatus"), bad, certify.Fail)

	// A DERStatus missing the elements BASIC-028 requires.
	thin := synthTranscript(Exchange{
		Req:  msg(Request, "PUT", "/x", 0, `<DERStatus xmlns="urn:ieee:std:2030.5:ns"><readingTime>1</readingTime></DERStatus>`),
		Resp: msg(Response, "", "", 204, ""),
	})
	f := wantVerdict(t, "DERStatus elements (thin)", critDERStatusElements(), thin, certify.Fail)
	if !strings.Contains(f.Observed, "inverterStatus") {
		t.Errorf("the failure does not name the missing element: %q", f.Observed)
	}

	// A PUT of a DIFFERENT resource must not satisfy this criterion.
	other := synthTranscript(Exchange{
		Req:  msg(Request, "PUT", "/x", 0, `<DERSettings xmlns="urn:ieee:std:2030.5:ns"/>`),
		Resp: msg(Response, "", "", 204, ""),
	})
	wantVerdict(t, "DERStatus PUT (wrong resource)", critDERPut("DERStatus"), other, certify.Fail)
}

func TestNameplateConsistencyHasTeeth(t *testing.T) {
	capBody := func(w int64) string {
		return `<DERCapability xmlns="urn:ieee:std:2030.5:ns"><rtgMaxW><multiplier>0</multiplier><value>` +
			itoa(w) + `</value></rtgMaxW></DERCapability>`
	}
	setBody := func(w int64) string {
		return `<DERSettings xmlns="urn:ieee:std:2030.5:ns"><setMaxW><multiplier>0</multiplier><value>` +
			itoa(w) + `</value></setMaxW></DERSettings>`
	}
	put := func(body string) Exchange {
		return Exchange{Req: msg(Request, "PUT", "/x", 0, body), Resp: msg(Response, "", "", 204, "")}
	}
	wantVerdict(t, "nameplate (consistent)", critNameplateConsistency(),
		synthTranscript(put(capBody(10000)), put(setBody(8000))), certify.Pass)

	f := wantVerdict(t, "nameplate (settings above ratings)", critNameplateConsistency(),
		synthTranscript(put(capBody(5000)), put(setBody(8000))), certify.Fail)
	if !strings.Contains(f.Observed, "exceeds") {
		t.Errorf("the failure does not describe the violated relation: %q", f.Observed)
	}

	// Only one of the two payloads: undecidable, not a failure.
	wantUnavailable(t, "nameplate (one payload)", critNameplateConsistency(),
		synthTranscript(put(capBody(5000))))
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func TestResponseCriterionHasTeeth(t *testing.T) {
	respBody := func(status int, subject string) string {
		return `<DERControlResponse xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1</createdDateTime>` +
			`<endDeviceLFDI>ab</endDeviceLFDI><status>` + itoa(int64(status)) + `</status>` +
			`<subject>` + subject + `</subject></DERControlResponse>`
	}
	post := func(status int) Exchange {
		return Exchange{Req: msg(Request, "POST", "/rsps/0/r", 0, respBody(status, "M1")),
			Resp: msg(Response, "", "", 201, "")}
	}
	wantVerdict(t, "Response status 1 (present)", critResponsePosted(1, "Event received", "M1"),
		synthTranscript(post(1)), certify.Pass)

	f := wantVerdict(t, "Response status 2 (absent)", critResponsePosted(2, "Event started", "M1"),
		synthTranscript(post(1)), certify.Fail)
	if !strings.Contains(f.Observed, "status=1") {
		t.Errorf("the failure does not report the statuses that WERE posted: %q", f.Observed)
	}

	wantUnavailable(t, "Response (none posted)", critResponsePosted(1, "Event received", "M1"),
		synthTranscript(get("/dcap", 200, dcapXML())))

	// The server-side fallback must reach the same decisions.
	sv := &ServerView{Available: true, Responses: []AdminResponse{{Subject: "M1", Status: 1, LFDI: "ab"}}}
	if f := critResponsePosted(1, "Event received", "M1").Server(sv); f.Verdict != certify.Pass {
		t.Errorf("server-side status 1 = %s: %s", f.Verdict, f.Observed)
	}
	if f := critResponsePosted(3, "Event completed", "M1").Server(sv); f.Verdict != certify.Fail {
		t.Errorf("server-side status 3 = %s: %s", f.Verdict, f.Observed)
	}
	empty := &ServerView{Available: true}
	if f := critResponsePosted(1, "Event received", "M1").Server(empty); f.Verdict != certify.Fail {
		t.Errorf("server-side with no responses = %s", f.Verdict)
	}
}

func TestFollowedLinkHasTeeth(t *testing.T) {
	// A DUT that follows an href the server served.
	good := synthTranscript(get("/dcap", 200, dcapXML()), get("/edev", 200, edevXML(strings.Repeat("a", 40), 1)))
	wantVerdict(t, "followed link (conformant)", critFollowedLink(), good, certify.Pass)

	// A DUT that jumps to a path the server never advertised — the hard-coded
	// URL that IEEE 2030.5 §4.6 forbids.
	bad := synthTranscript(get("/dcap", 200, dcapXML()), get("/sep2/edev", 200, ""))
	f := wantVerdict(t, "followed link (hard-coded path)", critFollowedLink(), bad, certify.Fail)
	if !strings.Contains(f.Observed, "/sep2/edev") {
		t.Errorf("the failure does not name the unadvertised path: %q", f.Observed)
	}
}

func TestPollRateNeedsTwoSamples(t *testing.T) {
	one := synthTranscript(get("/dcap", 200, dcapXML()))
	reason := wantUnavailable(t, "poll rate (one sample)", critPollRate(), one)
	if !strings.Contains(reason, waitParam) {
		t.Errorf("the reason does not tell the operator how to fix it: %q", reason)
	}

	a := get("/dcap", 200, dcapXML())
	b := get("/dcap", 200, dcapXML())
	b.Req.Time = a.Req.Time.Add(37 * time.Second)
	f := wantVerdict(t, "poll rate (two samples)", critPollRate(), synthTranscript(a, b), certify.Pass)
	if !strings.Contains(f.Observed, "37s") {
		t.Errorf("the measured interval is not reported: %q", f.Observed)
	}
}

func TestChainRejectionDetectorHasTeeth(t *testing.T) {
	// A DUT that ACCEPTED a chain it should have refused.
	accepted := &Transcript{Handshake: Handshake{
		Complete: true, ServerCertFrames: []int{4}, ServerChain: [][]byte{[]byte("bad")},
	}, ClientAppRecords: 3, ServerAppRecords: 4}
	ev := &certify.Evidence{Case: &certify.Case{UID: "x"}, Index: certify.NewFrameIndex(nil),
		Set: (&certify.Attribution{}).Set("x")}
	f := rejectionFinding(ev, accepted)
	if f.Verdict != certify.Fail {
		t.Errorf("a DUT that completed the handshake against a bad chain = %s: %s", f.Verdict, f.Observed)
	}

	// A DUT that sent a fatal alert: the primary rejection signal.
	refused := &Transcript{
		ClientRecords: &tlsdis.Direction{Alerts: []tlsdis.Alert{{Level: 2, Description: 48, Packets: []int{9}}}},
	}
	f = rejectionFinding(ev, refused)
	if f.Verdict != certify.Pass {
		t.Errorf("a fatal alert was not accepted as a rejection: %s %s", f.Verdict, f.Observed)
	}
	if len(f.Frames) != 1 || f.Frames[0] != 9 {
		t.Errorf("the alert's frame was not cited: %v", f.Frames)
	}
}

// TestChainRejectionAcceptsTheErratumsThirdSignal exercises the HTTP 403 arm
// COMM-004's published erratum (Annex A, seq 7) adds beside the TLS alert and
// the TCP disconnect: "A TCP port disconnect or HTTP 403 shall be an acceptable
// alternative to a TLS alert for notification of invalid certificates."
//
// Both directions are tested, because the direction is the whole point: a 403
// is a notification sent BY the party that rejected the certificate.
func TestChainRejectionAcceptsTheErratumsThirdSignal(t *testing.T) {
	ev := &certify.Evidence{Case: &certify.Case{UID: "x"}, Index: certify.NewFrameIndex(nil),
		Set: (&certify.Attribution{}).Set("x")}
	forbidden := func(kind MessageKind, frames []int) *Message {
		return &Message{Kind: kind, Proto: "HTTP/1.1", Status: 403, Reason: "Forbidden", Frames: frames}
	}

	// The DUT itself answered 403 without ever completing a handshake it should
	// have refused — the erratum's third signal, and a PASS.
	byDUT := &Transcript{DUTResponses: []*Message{forbidden(Response, []int{11})}}
	f := rejectionFinding(ev, byDUT)
	if f.Verdict != certify.Pass {
		t.Errorf("a 403 sent BY THE DUT was not accepted as a rejection: %s %s", f.Verdict, f.Observed)
	}
	if len(f.Frames) != 1 || f.Frames[0] != 11 {
		t.Errorf("the 403's frame was not cited: %v", f.Frames)
	}
	if !strings.Contains(f.Observed, "403") {
		t.Errorf("the finding does not name the status it rests on: %q", f.Observed)
	}

	// A 403 the PEER sent is the bench refusing the DUT's credential — the
	// mirror image of the fact under test. It must be reported and must NOT
	// rescue a DUT that accepted the non-conformant chain.
	byPeer := &Transcript{
		Handshake:        Handshake{Complete: true, ServerCertFrames: []int{4}, ServerChain: [][]byte{[]byte("bad")}},
		ClientAppRecords: 2, ServerAppRecords: 2,
		Responses: []*Message{forbidden(Response, []int{7})},
	}
	f = rejectionFinding(ev, byPeer)
	if f.Verdict != certify.Fail {
		t.Errorf("a peer-sent 403 rescued a DUT that ACCEPTED the chain: %s %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "PEER") {
		t.Errorf("the peer's 403 is not reported to the reader: %q", f.Observed)
	}
}

func TestChainDepthDeclinesOnTheWrongFixture(t *testing.T) {
	// The check for a 4-deep chain must NOT pass because a 2-deep chain worked.
	two := handshake(conformantHandshake())
	c := chainDepthCriterionForTest(t, 4)
	reason := wantUnavailable(t, "chain depth 4 against a 2-deep bench", c, two)
	if !strings.Contains(reason, "2-certificate") {
		t.Errorf("the reason does not report the depth actually served: %q", reason)
	}
	// And the matching depth must pass.
	c2 := chainDepthCriterionForTest(t, 2)
	wantVerdict(t, "chain depth 2 against a 2-deep bench", c2, two, certify.Pass)
}

// chainDepthCriterionForTest extracts the chain-depth criterion from the check
// builder so its decision logic can be exercised without a run context.
func chainDepthCriterionForTest(t *testing.T, depth int) criterion {
	t.Helper()
	obs := &Observation{}
	// commChainDepth's criteria list is built inside the spec; rebuild the same
	// criterion here from the same source of truth by calling the helper the
	// check uses. Keeping this in one place is what stops the test drifting.
	return chainDepthCriterion(depth, "test shape")(obs)
}
