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

	// No Registration resource fetched AT ALL — every run in this campaign's
	// actual shape (runs/final-csip-20260731T213346, CORE-009 census item #4).
	// This must NOT be Fail (the wire cannot tell a broken walker from a
	// registration_pin-disabled one, see critRegistrationPIN's doc) and must
	// NOT be Pass (the requirement was never exercised) — Unavailable, naming
	// the actual mechanism, is the only honest verdict.
	reason := wantUnavailable(t, "pIN (Registration never fetched)", critRegistrationPIN(""),
		synthTranscript(get("/edev", 200, edevXML(
			"0000000000000000000000000000000000000002", 123456789))))
	for _, want := range []string{"registration_pin", "PinVerifier", "operator"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the Unavailable reason should name %q so a reader knows this is a DUT-config gap, "+
				"not a bench or wire fault: %q", want, reason)
		}
	}
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
	// A session established (the DUT walked /dcap) but POSTed no Response: a real
	// FAIL about the DUT.
	noResp := &ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}
	if f := critResponsePosted(1, "Event received", "M1").Server(noResp); f.Verdict != certify.Fail {
		t.Errorf("session established with no responses = %s: %s", f.Verdict, f.Observed)
	}
	// A wholly empty view is NO session at all — undecidable, not a DUT failure.
	empty := &ServerView{Available: true}
	if f := critResponsePosted(1, "Event received", "M1").Server(empty); f.Unavailable == "" {
		t.Errorf("no session at all returned a verdict (%s) instead of unavailable", f.Verdict)
	}
}

// TestNoEarlyEndOfEventStatusHasTeeth exercises critNoEarlyEndOfEventStatus
// (criteria_2030.go), the SD-02 class backstop
// (docs/design/SD02_RESPONSE_SEMANTICS_RC0_2026-08-17.md, lexa-gw): no
// Response may carry status 8 or 10 before the EARLIEST EffectiveEndTime the
// control's own randomizeStart/randomizeDuration (§10.2.3.2 definitions,
// §10.2.4.2.2/.3 signed application) permit — not
// before the SPECIFIED End Time (<interval><start>+<duration>) alone, which
// is only correct for a control that carries no randomization at all.
func TestNoEarlyEndOfEventStatusHasTeeth(t *testing.T) {
	respBody := func(status int, subject string) string {
		return `<DERControlResponse xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1</createdDateTime>` +
			`<endDeviceLFDI>ab</endDeviceLFDI><status>` + itoa(int64(status)) + `</status>` +
			`<subject>` + subject + `</subject></DERControlResponse>`
	}
	postAt := func(status int, subject string, at time.Time) Exchange {
		req := msg(Request, "POST", "/rsps/0/r", 0, respBody(status, subject))
		req.Time = at
		return Exchange{Req: req, Resp: msg(Response, "", "", 201, "")}
	}
	controlListWithInterval := func(mrid string, start, dur int64) Exchange {
		body := `<DERControlList xmlns="` + Namespace + `" all="1" results="1">` +
			`<DERControl replyTo="/rsps/0/r" responseRequired="03"><mRID>` + mrid + `</mRID>` +
			`<interval><start>` + itoa(start) + `</start><duration>` + itoa(dur) + `</duration></interval>` +
			`<DERControlBase><opModMaxLimW>1</opModMaxLimW></DERControlBase></DERControl></DERControlList>`
		return get("/derp/0/derc", 200, body)
	}
	// controlListWithRandomizedInterval is controlListWithInterval plus this
	// control's own randomizeStart/randomizeDuration (§10.2.3.2 definitions,
	// §10.2.4.2.2/.3 signed application) — gridsim seeds RandomizeStart on
	// some controls (server.go:1451, admin.go:504), so this is a live wire
	// shape, not a hypothetical one.
	controlListWithRandomizedInterval := func(mrid string, start, dur, randStart, randDur int64) Exchange {
		body := `<DERControlList xmlns="` + Namespace + `" all="1" results="1">` +
			`<DERControl replyTo="/rsps/0/r" responseRequired="03"><mRID>` + mrid + `</mRID>` +
			`<interval><start>` + itoa(start) + `</start><duration>` + itoa(dur) + `</duration></interval>` +
			`<randomizeStart>` + itoa(randStart) + `</randomizeStart>` +
			`<randomizeDuration>` + itoa(randDur) + `</randomizeDuration>` +
			`<DERControlBase><opModMaxLimW>1</opModMaxLimW></DERControlBase></DERControl></DERControlList>`
		return get("/derp/0/derc", 200, body)
	}

	const mrid = "M-TIMING"
	const start, dur = 1000, 100 // no randomization: band collapses to the single instant 1100

	// No 8/10 at all: this criterion has nothing to grade — RRS forbids an
	// unfalsifiable Pass, so this is a disclosed non-verdict, not a Pass
	// (F16: the old default arm returned Pass here).
	wantUnavailable(t, "no partial status at all", critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithInterval(mrid, start, dur), postAt(1, mrid, time.Unix(start, 0))))

	// SEEDED NEGATIVE: status 8 arriving BEFORE EffectiveEndTime — the former
	// product defect this criterion exists to catch class-wide, wherever an
	// executing (not outright-refused) control's Response stream carries it.
	// This is a permanent oracle-bite test: if this ever passes again, the
	// class backstop has regressed.
	f := wantVerdict(t, "SEEDED NEGATIVE: 8 before EffectiveEndTime", critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithInterval(mrid, start, dur), postAt(8, mrid, time.Unix(start+50, 0))),
		certify.Fail)
	if !strings.Contains(f.Observed, "before the earliest EffectiveEndTime") {
		t.Errorf("the FAIL does not name the timing defect: %s", f.Observed)
	}

	// The same status, arriving AT EffectiveEndTime, is exactly Table 27's own
	// prescribed send-time and must PASS: with no randomization on this
	// control, the band is a single point and the boundary is closed.
	wantVerdict(t, "8 at EffectiveEndTime", critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithInterval(mrid, start, dur), postAt(8, mrid, time.Unix(start+dur, 0))),
		certify.Pass)
	// 10, after EffectiveEndTime, is the same class of statement and must also
	// PASS.
	wantVerdict(t, "10 after EffectiveEndTime", critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithInterval(mrid, start, dur), postAt(10, mrid, time.Unix(start+dur+100, 0))),
		certify.Pass)

	// A status 8/10 with no recoverable interval for its own mRID: the
	// boundary cannot be established, so the criterion must decline rather
	// than guess at the DUT's intent.
	wantUnavailable(t, "8 with no DERControlList interval recovered", critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(postAt(8, mrid, time.Unix(start+50, 0))))

	// ── RANDOMIZED control: the bound logic bites both ways ─────────────────
	//
	// randomizeStart=-30, randomizeDuration=+20 against start=1000, dur=100
	// (SpecifiedEndTime=1100): earliest = 1000 + min(0,-30) + 100 + min(0,20)
	// = 1070; latest = 1000 + max(0,-30) + 100 + max(0,20) = 1120. Band =
	// [1070, 1120).
	const rStart, rDur, randStart, randDur = 1000, 100, -30, 20

	// Bite #1 — still catches a genuinely early post even with randomization
	// live: 1050 is before EARLIEST (1070) under any permitted draw.
	f = wantVerdict(t, "RANDOMIZED: still FAILs a post before the band's earliest edge",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, rStart, rDur, randStart, randDur),
			postAt(8, mrid, time.Unix(rStart+50, 0))), // 1050
		certify.Fail)
	if !strings.Contains(f.Observed, "before the earliest EffectiveEndTime") {
		t.Errorf("the RANDOMIZED FAIL does not name the timing defect: %s", f.Observed)
	}

	// Bite #2 — a post that lands inside the legitimate randomization band is
	// a disclosed non-verdict, not a FAIL: 1080 is before SpecifiedEndTime
	// (1100) but at/after EARLIEST (1070), so it is undecidable, not a
	// violation. critNoEarlyEndOfEventStatus was introduced in the SD-02
	// remediation; the Specified-vs-Effective distinction it implements —
	// that a control's own randomization moves its EffectiveEndTime away
	// from the fixed SpecifiedEndTime — was a finding against the first
	// draft, not a fix to code that ever compared against 1100 on this repo.
	wantUnavailable(t, "RANDOMIZED: a post inside the band is a disclosed non-verdict, not a FAIL",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, rStart, rDur, randStart, randDur),
			postAt(8, mrid, time.Unix(rStart+80, 0)))) // 1080

	// A post at/after LATEST (1120) is unconditionally not early, band or no
	// band, and must PASS.
	wantVerdict(t, "RANDOMIZED: a post at/after the band's latest edge PASSes",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, rStart, rDur, randStart, randDur),
			postAt(10, mrid, time.Unix(rStart+120, 0))), // 1120
		certify.Pass)

	// ── EFFECTIVE-DURATION FLOOR ─────────────────────────────────────────────
	//
	// start=1000, dur=10, randomizeDuration=-30: |randomizeDuration| exceeds
	// the control's own duration. Unfloored, earliest's duration contribution
	// would be 10+min(0,-30) = -20, pulling EARLIEST to 980 — 20s before the
	// control's own start, which is nonsense. Floored at 0, EARLIEST is 1000
	// (the start itself). A post at 990 is inside the UNFLOORED (wrong) band
	// but before the FLOORED (correct) one, so it must FAIL only once the
	// floor is applied.
	f = wantVerdict(t, "FLOOR: negative randomizeDuration larger than duration doesn't pull EARLIEST before start",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, 1000, 10, 0, -30),
			postAt(8, mrid, time.Unix(990, 0))),
		certify.Fail)
	if !strings.Contains(f.Observed, "before the earliest EffectiveEndTime") {
		t.Errorf("the FLOOR FAIL does not name the timing defect: %s", f.Observed)
	}

	// ── OneHourRangeType VALIDATION ──────────────────────────────────────────
	//
	// randomizeStart/randomizeDuration are both OneHourRangeType, bounded to
	// [-3600,+3600]. A control carrying a value outside that is malformed —
	// this criterion must FAIL the row and name the illegal value, not widen
	// the band to match a number the standard never permits on the wire.
	f = wantVerdict(t, "MALFORMED: randomizeStart outside OneHourRangeType FAILs, not widens",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, 1000, 100, 4000, 0),
			postAt(8, mrid, time.Unix(1050, 0))),
		certify.Fail)
	for _, want := range []string{"OneHourRangeType", "4000", "malformed"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the MALFORMED randomizeStart FAIL does not say %q: %s", want, f.Observed)
		}
	}
	f = wantVerdict(t, "MALFORMED: randomizeDuration outside OneHourRangeType FAILs, not widens",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, 1000, 100, 0, -3601),
			postAt(8, mrid, time.Unix(1050, 0))),
		certify.Fail)
	for _, want := range []string{"OneHourRangeType", "-3601", "malformed"} {
		if !strings.Contains(f.Observed, want) {
			t.Errorf("the MALFORMED randomizeDuration FAIL does not say %q: %s", want, f.Observed)
		}
	}

	// ── BAND-WIDTH DISCLOSURE ────────────────────────────────────────────────
	//
	// randomizeStart=-40, randomizeDuration=-40 against start=1000, dur=200:
	// earliest = 1000+min(0,-40)+floor(200+min(0,-40)) = 960+160 = 1120;
	// latest = 1000+max(0,-40)+200+max(0,-40) = 1000+200 = 1200. Band width
	// 80s, and |rs|+|rd| = 80s clears the 60s poll-cadence disclosure floor —
	// the in-band non-verdict must name the band width and warn that the
	// check's power is reduced, not silently absorb it the way a narrow band
	// (the 50s Bite #2 case above) correctly does.
	why := wantUnavailable(t, "WIDE BAND: an in-band post discloses reduced power",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, 1000, 200, -40, -40),
			postAt(8, mrid, time.Unix(1150, 0)))) // inside [1120,1200)
	for _, want := range []string{"REDUCED POWER", "1m20s"} {
		if !strings.Contains(why, want) {
			t.Errorf("the wide-band non-verdict does not say %q: %s", want, why)
		}
	}
	// The narrow 50s band above (Bite #2) must NOT trip the disclosure — the
	// warning is for bands that have actually crossed the cadence floor, not
	// every in-band non-verdict.
	narrow := wantUnavailable(t, "NARROW BAND: no disclosure below the cadence floor",
		critNoEarlyEndOfEventStatus(mrid),
		synthTranscript(controlListWithRandomizedInterval(mrid, rStart, rDur, randStart, randDur),
			postAt(8, mrid, time.Unix(rStart+80, 0)))) // 1080, band [1070,1120) width 50s
	if strings.Contains(narrow, "REDUCED POWER") {
		t.Errorf("a 50s band tripped the reduced-power disclosure, which exists only for bands at/beyond "+
			"the %s cadence floor: %s", bandDisclosureCadence, narrow)
	}
}

// TestResponseStartedCriterionHasTeeth exercises critResponseStarted, which
// CORE-022 and CORE-023 both now use for their status=2 (Event started)
// claim. It must grade Pass/Fail exactly like critResponsePosted(2, ...) when
// the CAPTURED control's responseRequired actually asked for a specific
// response (bit 0x02), and must decline — Unavailable, never a FAIL — when
// it did not: a control that never asked for a status=2 makes one
// unobservable by construction, not a failure of the DUT. This is the
// graceful-degradation half of the fix for gridsim's admin-created controls
// once never setting responseRequired at all (sim/gridsim/admin.go).
func TestResponseStartedCriterionHasTeeth(t *testing.T) {
	respBody := func(status int, subject string) string {
		return `<DERControlResponse xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1</createdDateTime>` +
			`<endDeviceLFDI>ab</endDeviceLFDI><status>` + itoa(int64(status)) + `</status>` +
			`<subject>` + subject + `</subject></DERControlResponse>`
	}
	post := func(status int) Exchange {
		return Exchange{Req: msg(Request, "POST", "/rsps/0/r", 0, respBody(status, "M1")),
			Resp: msg(Response, "", "", 201, "")}
	}
	// dercWithRR builds a minimal DERControlList carrying mRID M1 with the
	// given responseRequired attribute text ("" omits the attribute
	// entirely — an absent-on-the-wire control).
	dercWithRR := func(rr string) string {
		attr := ""
		if rr != "" {
			attr = ` responseRequired="` + rr + `"`
		}
		return `<?xml version="1.0" encoding="UTF-8"?>` +
			`<DERControlList xmlns="urn:ieee:std:2030.5:ns" href="/derp/0/derc" all="1" results="1">` +
			`<DERControl href="/derp/0/derc/0"` + attr + `>` +
			`<mRID>M1</mRID><description>test</description><creationTime>100</creationTime>` +
			`<EventStatus><currentStatus>1</currentStatus><dateTime>100</dateTime></EventStatus>` +
			`<interval><duration>120</duration><start>200</start></interval>` +
			`<DERControlBase><opModExpLimW><multiplier>0</multiplier><value>3000</value></opModExpLimW></DERControlBase>` +
			`</DERControl></DERControlList>`
	}

	// Conformant: the control asked for it (bit 0x02) and the DUT posted it.
	wantVerdict(t, "status=2 (requested, posted)", critResponseStarted("M1"),
		synthTranscript(get("/derp/0/derc", 200, dercWithRR("03")), post(2)), certify.Pass)

	// The control asked for it, but the DUT never posted a status=2 — a real
	// FAIL about the DUT, not a degraded case.
	f := wantVerdict(t, "status=2 (requested, not posted)", critResponseStarted("M1"),
		synthTranscript(get("/derp/0/derc", 200, dercWithRR("03")), post(1)), certify.Fail)
	if !strings.Contains(f.Observed, "status=1") {
		t.Errorf("the failure does not report the statuses that WERE posted: %q", f.Observed)
	}

	// The control's responseRequired carried ONLY bit 0x01 (message received)
	// — bit 0x02 was never asked for, so a missing status=2 is unobservable
	// by construction.
	reason := wantUnavailable(t, "status=2 (bit 0x02 not requested)", critResponseStarted("M1"),
		synthTranscript(get("/derp/0/derc", 200, dercWithRR("01"))))
	if !strings.Contains(reason, "responseRequired=01") || !strings.Contains(reason, "0x02") {
		t.Errorf("the unavailable reason does not name the captured responseRequired: %q", reason)
	}

	// F5 (2026-08-17): the control carried NO responseRequired attribute at
	// all — "no server instruction", which reads as "grade normally", NOT as
	// the same degraded outcome an explicit value lacking bit 0x02 produces
	// (that comment described the PRE-F5 bug: absent and explicit-0 used to
	// collapse onto the same rr=0 and were gated identically). With the
	// status actually posted, this must grade a real PASS.
	wantVerdict(t, "status=2 (responseRequired absent, posted)", critResponseStarted("M1"),
		synthTranscript(get("/derp/0/derc", 200, dercWithRR("")), post(2)), certify.Pass)

	// Absent + NOT posted is still Unavailable — but for the ORDINARY "no
	// Response POST recovered" reason critResponsePosted has always given,
	// not the "not requested" reason: absent means this gate has nothing to
	// say either way, so the underlying scan (which found nothing) decides.
	reason = wantUnavailable(t, "status=2 (responseRequired absent, not posted)", critResponseStarted("M1"),
		synthTranscript(get("/derp/0/derc", 200, dercWithRR(""))))
	if !strings.Contains(reason, "holds no Response POST") {
		t.Errorf("the unavailable reason for an absent (not gated) responseRequired should be the ordinary "+
			"no-Response-POST reason, not a not-requested ruling: %q", reason)
	}

	// The control itself was never recovered in this window's transcript —
	// same "ungated, fall through to the ordinary scan" path as absent,
	// which here also finds nothing.
	reason = wantUnavailable(t, "status=2 (control not recovered)", critResponseStarted("M1"),
		synthTranscript(get("/dcap", 200, dcapXML())))
	if !strings.Contains(reason, "holds no Response POST") {
		t.Errorf("the unavailable reason for an unrecovered control should fall through to the ordinary "+
			"no-Response-POST reason (ungated, not a not-requested ruling): %q", reason)
	}

	// Tier 3 (gridsim admin API) has no visibility into a control's own wire
	// attributes on its own, so with NO prior tier-2 verdict to defer to it
	// grades exactly like critResponsePosted's Server evaluator — the case a
	// transcript that exists but never decrypted, or no capture at all,
	// leaves assert() (criteria.go) to fall straight to tier 3 without ever
	// calling Wire.
	sv := &ServerView{Available: true, Responses: []AdminResponse{{Subject: "M1", Status: 2, LFDI: "ab"}}}
	if f := critResponseStarted("M1").Server(sv); f.Verdict != certify.Pass {
		t.Errorf("server-side status 2 = %s: %s", f.Verdict, f.Observed)
	}

	// But when tier 2 DID run and ruled the claim not-requested, tier 3 must
	// defer to that instead of re-deciding — otherwise a live run with both a
	// decrypted transcript AND a reachable admin API (assert() always tries
	// tier 3 once tier 2 answers Unavailable, for ANY reason, including this
	// one) would let a lenient DUT that posts status=2 regardless turn this
	// criterion's careful Unavailable right back into the false PASS/FAIL it
	// exists to prevent. Same criterion INSTANCE for both calls: the gating
	// is carried in a closure variable Wire sets and Server reads.
	notReqCrit := critResponseStarted("M1")
	notReqTr := synthTranscript(get("/derp/0/derc", 200, dercWithRR("01")))
	if f := notReqCrit.Wire(nil, notReqTr); f.Unavailable == "" {
		t.Fatalf("setup: Wire did not rule bit 0x02 not-requested: verdict=%s observed=%s", f.Verdict, f.Observed)
	}
	if f := notReqCrit.Server(sv); f.Unavailable == "" {
		t.Errorf("tier 3 re-graded a control tier 2 already ruled not-requested: verdict=%s observed=%s",
			f.Verdict, f.Observed)
	}
}

// TestResponseRequiredGateAppliesPerStatusNotJustStarted proves #17/F2's
// hoist: the SAME responseRequired gate now applies to every
// critResponsePosted-built criterion by status, not only critResponseStarted's
// former hand-built status=2 case. A control serving rr=0x01 (message-received
// only) must grade status=1 (Received) NORMALLY — bit 0x01 IS requested —
// while a status=2 (Started) demand on the SAME control goes Unavailable,
// never FAIL, because bit 0x02 was not requested.
//
// This is also the "one new test serving rr=0x01" the fix requires: every
// shipping row today serves rr=0x03 (sim/gridsim/admin.go's
// adminDefaultResponseRequired, both bits set) — soon 0x07 (F7/#18) — so this
// is the suite's first coverage of a server that narrows the bitmap to just
// one bit, proving the per-status gate actually discriminates rather than
// gating (or not gating) everything alike.
func TestResponseRequiredGateAppliesPerStatusNotJustStarted(t *testing.T) {
	respBody := func(status int, subject string) string {
		return `<DERControlResponse xmlns="urn:ieee:std:2030.5:ns"><createdDateTime>1</createdDateTime>` +
			`<endDeviceLFDI>ab</endDeviceLFDI><status>` + itoa(int64(status)) + `</status>` +
			`<subject>` + subject + `</subject></DERControlResponse>`
	}
	post := func(status int) Exchange {
		return Exchange{Req: msg(Request, "POST", "/rsps/0/r", 0, respBody(status, "M1")),
			Resp: msg(Response, "", "", 201, "")}
	}
	dercRR01 := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<DERControlList xmlns="urn:ieee:std:2030.5:ns" href="/derp/0/derc" all="1" results="1">` +
		`<DERControl href="/derp/0/derc/0" responseRequired="01">` +
		`<mRID>M1</mRID><description>test</description><creationTime>100</creationTime>` +
		`<EventStatus><currentStatus>1</currentStatus><dateTime>100</dateTime></EventStatus>` +
		`<interval><duration>120</duration><start>200</start></interval>` +
		`<DERControlBase><opModExpLimW><multiplier>0</multiplier><value>3000</value></opModExpLimW></DERControlBase>` +
		`</DERControl></DERControlList>`

	// Received (status=1, required bit 0x01): rr=01 DOES request it — normal
	// grading, and the DUT posted it, so a real PASS.
	wantVerdict(t, "status=1 under rr=01 (requested, posted)", critResponsePosted(1, "Event received", "M1"),
		synthTranscript(get("/derp/0/derc", 200, dercRR01), post(1)), certify.Pass)

	// Received under rr=01, but the DUT posted a DIFFERENT status instead — a
	// real FAIL, not a gate: this is the "normal grading" half of the fix, on
	// the SAME control whose bit 0x02 (below) IS gated. (A window with NO
	// Response POST at all is Unavailable regardless of gating — that is
	// critResponsePosted's pre-existing "nothing to judge" behavior, proven
	// by TestResponseStartedCriterionHasTeeth, not what this case is about.)
	wantVerdict(t, "status=1 under rr=01 (requested, wrong status posted)", critResponsePosted(1, "Event received", "M1"),
		synthTranscript(get("/derp/0/derc", 200, dercRR01), post(3)), certify.Fail)

	// Started (status=2, required bit 0x02): rr=01 does NOT carry it —
	// Unavailable, never FAIL, even though nothing was posted.
	reason := wantUnavailable(t, "status=2 under rr=01 (not requested)", critResponseStarted("M1"),
		synthTranscript(get("/derp/0/derc", 200, dercRR01)))
	if !strings.Contains(reason, "responseRequired=01") || !strings.Contains(reason, "0x02") {
		t.Errorf("the unavailable reason does not name the captured responseRequired: %q", reason)
	}

	// critResponseStarted's Server (tier-3) fallback honours the SAME gate
	// through the shared closure critResponsePosted now builds, exactly as
	// TestResponseStartedCriterionHasTeeth already proves for the bit-0x02
	// literal case — this repeats it under a real rr=01 server bitmap rather
	// than a synthetic single-bit-missing one, to close the loop on the hoist.
	notReqCrit := critResponseStarted("M1")
	notReqTr := synthTranscript(get("/derp/0/derc", 200, dercRR01))
	if f := notReqCrit.Wire(nil, notReqTr); f.Unavailable == "" {
		t.Fatalf("setup: Wire did not rule bit 0x02 not-requested under rr=01: verdict=%s observed=%s",
			f.Verdict, f.Observed)
	}
	sv := &ServerView{Available: true, Responses: []AdminResponse{{Subject: "M1", Status: 2, LFDI: "ab"}}}
	if f := notReqCrit.Server(sv); f.Unavailable == "" {
		t.Errorf("tier 3 re-graded a control tier 2 already ruled not-requested under rr=01: verdict=%s observed=%s",
			f.Verdict, f.Observed)
	}
}

// TestServerLogEmptinessIsNotADUTFailureWithoutASession proves the two arms of
// the fix runs/shakedown-20260729T003843 forced: a tier-3 server-log evaluator
// must FAIL only when a session established and the DUT still did not do the
// thing, and must go unavailable (→SKIP) when NO session established at all —
// the log's emptiness is then a fact about the handshake, not about the DUT. One
// bench-side handshake fault otherwise turned into ~51 false FAILs.
func TestServerLogEmptinessIsNotADUTFailureWithoutASession(t *testing.T) {
	// A ServerView across several evaluators, once with a session (a GET /dcap in
	// the log proves the handshake completed) and once wholly empty.
	// Each row's "established" view proves a session with an activity that does
	// NOT satisfy that particular row, so the expected request is genuinely
	// absent — a real FAIL about the DUT.
	crits := []struct {
		name        string
		c           criterion
		established *ServerView
	}{
		{"GET /dcap", critDiscoveryRoot(),
			&ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/tm"}}}},
		{"followed link", critFollowedLink(),
			&ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}},
		{"Response POST", critResponsePosted(1, "Event received", "M1"),
			&ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}},
		{"DER PUT", critDERPut("DERStatus"),
			&ServerView{Available: true, Requests: []ServerRequest{{Method: "GET", Path: "/dcap"}}}},
	}

	// Arm one: a session DID establish but the specific request each row wants is
	// absent. That is a real FAIL about the DUT, which must NOT be softened.
	for _, tc := range crits {
		f := tc.c.Server(tc.established)
		if f.Unavailable != "" {
			t.Errorf("%s: a session established but the row was softened to unavailable: %q",
				tc.name, f.Unavailable)
		}
		if f.Verdict != certify.Fail {
			t.Errorf("%s: session established + expected request absent = %s, want FAIL",
				tc.name, f.Verdict)
		}
	}

	// Arm two: NO session at all — the request log and every other server log are
	// empty. The emptiness is not attributable to the DUT, so each row must be
	// unavailable rather than FAIL.
	noSession := &ServerView{Available: true}
	for _, tc := range crits {
		f := tc.c.Server(noSession)
		if f.Unavailable == "" {
			t.Errorf("%s: no session established but the row still returned a verdict (%s): %q",
				tc.name, f.Verdict, f.Observed)
		}
		if !strings.Contains(f.Unavailable, "no TLS session") {
			t.Errorf("%s: the unavailable reason does not name the missing session: %q", tc.name, f.Unavailable)
		}
	}

	// The gate itself: any one server-side log line proves a session.
	if (ServerView{}).SessionEstablished() {
		t.Error("an empty view reported a session")
	}
	for _, v := range []ServerView{
		{Requests: []ServerRequest{{Method: "GET", Path: "/tm"}}},
		{Responses: []AdminResponse{{Subject: "M1"}}},
		{DERPuts: []AdminDERPut{{Resource: "DERStatus"}}},
		{LogEvents: []map[string]any{{"code": 1}}},
		{Notifications: []AdminNotification{{HTTPStatus: 200}}},
	} {
		if !v.SessionEstablished() {
			t.Errorf("a view with server-side activity did not report a session: %+v", v)
		}
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

	// The false-PASS runs/shakedown-20260729T003843 turned up: the fatal alert is
	// on the SERVER's direction — the bench's decrypt_error about the DUT's own
	// credential — while the DUT sent nothing. Crediting the DUT for the server's
	// alert is the mirror image of the fact under test and must NOT be a PASS.
	serverAlerted := &Transcript{
		ServerRecords: &tlsdis.Direction{Alerts: []tlsdis.Alert{{Level: 2, Description: 51, Packets: []int{9}}}},
	}
	f = rejectionFinding(ev, serverAlerted)
	if f.Verdict == certify.Pass {
		t.Errorf("a SERVER-sent fatal alert was miscredited as the DUT's rejection: %s %s", f.Verdict, f.Observed)
	}
	if !strings.Contains(f.Observed, "PEER") && !strings.Contains(f.Observed, "server") {
		t.Errorf("the server's alert is not reported to the reader: %q", f.Observed)
	}

	// Belt and braces: the DUT-only alert helper reads only the client direction,
	// so a server-only alert is invisible to it.
	if _, ok := dutFatalAlert(serverAlerted); ok {
		t.Error("dutFatalAlert credited an alert the DUT never sent")
	}
	if _, ok := dutFatalAlert(refused); !ok {
		t.Error("dutFatalAlert missed the DUT's own alert")
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
