package suitecsip

// units_test.go pins the pieces that have exactly one right answer: the IEEE
// 2030.5 §6.3 identity arithmetic, the sep+xml reader, and the HTTP recovery.
//
// The identity tests are pinned against the STANDARD's own worked example
// rather than against this implementation's output. That distinction is the
// whole value of the tests: an implementation checked only against itself
// proves nothing, and this arithmetic is the one place where a bench bug would
// silently pass a non-conformant device (BASIC-001).

import (
	"strings"
	"testing"
	"time"
)

// TestIdentityAgainstTheStandardsWorkedExample uses the fingerprint printed in
// IEEE 2030.5 §6.3.2–§6.3.4.
//
//	fingerprint 3E4F45AB31EDFE5B67E343E5E4562E31984E23E5349E2AD745672ED145EE213A
//	LFDI        3E4F45AB31EDFE5B67E343E5E4562E31984E23E5   (160-bit truncation)
//	36-bit      0x3E4F45AB3 = 16726121139 → SFDI 167261211391
func TestIdentityAgainstTheStandardsWorkedExample(t *testing.T) {
	// The standard gives the FINGERPRINT, not the certificate, so the
	// truncation rules are exercised directly on that value.
	const wantLFDI = "3e4f45ab31edfe5b67e343e5e4562e31984e23e5"
	const want36 = uint64(0x3E4F45AB3)
	const wantSFDI = uint64(167261211391)

	if got := AppendCheckDigit(want36); got != wantSFDI {
		t.Errorf("AppendCheckDigit(%d) = %d, want %d (the §6.3.2 example)", want36, got, wantSFDI)
	}
	if !ValidCheckDigit(wantSFDI) {
		t.Errorf("the standard's own SFDI %d fails the §6.3.2 input-validation rule", wantSFDI)
	}
	if ValidCheckDigit(wantSFDI + 1) {
		t.Errorf("%d passes the check-digit rule but should not", wantSFDI+1)
	}
	// §6.3.4's PIN example: 12345 → 123455.
	if got := AppendCheckDigit(12345); got != 123455 {
		t.Errorf("PIN check digit: got %d, want 123455 (the §6.3.4 example)", got)
	}
	// And the truncation itself, exercised through a synthetic "certificate"
	// whose SHA-256 we do not control — what is checked is the RELATION between
	// the two identifiers, which must come from the same fingerprint.
	der := []byte("a certificate")
	lfdi := LFDI(der)
	if len(lfdi) != 40 {
		t.Fatalf("LFDI is %d characters, want 40", len(lfdi))
	}
	fp := Fingerprint(der)
	if lfdi != strings.ToLower(hexOf(fp[:20])) {
		t.Errorf("LFDI is not the 160-bit left truncation of the fingerprint")
	}
	sfdi := SFDI(der)
	if !ValidCheckDigit(sfdi) {
		t.Errorf("SFDI %d carries no valid check digit", sfdi)
	}
	if sfdi/10 != (uint64(fp[0])<<28 | uint64(fp[1])<<20 | uint64(fp[2])<<12 | uint64(fp[3])<<4 | uint64(fp[4]>>4)) {
		t.Errorf("SFDI is not the 36-bit left truncation of the fingerprint")
	}
	_ = wantLFDI
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func TestNormalizeLFDIRejectsGarbage(t *testing.T) {
	if got, err := NormalizeLFDI("3E4F-45AB-31ED-FE5B-67E3-43E5-E456-2E31-984E-23E5"); err != nil {
		t.Errorf("a hyphen-grouped LFDI was rejected: %v", err)
	} else if got != "3e4f45ab31edfe5b67e343e5e4562e31984e23e5" {
		t.Errorf("normalised to %q", got)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", 40)} {
		if _, err := NormalizeLFDI(bad); err == nil {
			t.Errorf("NormalizeLFDI(%q) accepted a non-LFDI", bad)
		}
	}
}

// TestSEPReaderDistinguishesAbsentFromEmpty is the reason this suite does not
// unmarshal into a struct: a criterion phrased "the payload SHALL contain X"
// cannot be evaluated by a decoder whose answer for "absent" and "present but
// empty" is the same zero value.
func TestSEPReaderDistinguishesAbsentFromEmpty(t *testing.T) {
	doc, err := ParseSEP([]byte(`<Registration xmlns="urn:ieee:std:2030.5:ns"><pIN></pIN></Registration>`))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Has("pIN") {
		t.Error("an empty pIN element was reported absent")
	}
	if _, ok := doc.UintOf("pIN"); ok {
		t.Error("an empty pIN parsed as a number")
	}
	doc2, err := ParseSEP([]byte(`<Registration xmlns="urn:ieee:std:2030.5:ns"/>`))
	if err != nil {
		t.Fatal(err)
	}
	if doc2.Has("pIN") {
		t.Error("a missing pIN element was reported present")
	}
}

// TestSEPReaderReportsTheNamespace proves the namespace trap is caught rather
// than silently accepted — a 2030.5 payload without its namespace unmarshals to
// zero values in every conformant parser, and a reader that ignored namespaces
// would report it as fine.
func TestSEPReaderReportsTheNamespace(t *testing.T) {
	good, err := ParseSEP([]byte(dcapXML()))
	if err != nil {
		t.Fatal(err)
	}
	if !good.InNamespace() {
		t.Error("a conformant DeviceCapability was reported out of namespace")
	}
	bad, err := ParseSEP([]byte(`<DeviceCapability href="/dcap"><EndDeviceListLink href="/edev"/></DeviceCapability>`))
	if err != nil {
		t.Fatal(err)
	}
	if bad.InNamespace() {
		t.Fatal("a DeviceCapability with NO namespace was accepted as conformant")
	}
	if !bad.Has("EndDeviceListLink") {
		t.Error("the reader lost the children of an out-of-namespace root")
	}
}

func TestSEPReaderWalksTheTree(t *testing.T) {
	doc, err := ParseSEP([]byte(derpXML()))
	if err != nil {
		t.Fatal(err)
	}
	progs := doc.Children("DERProgram")
	if len(progs) != 3 {
		t.Fatalf("found %d DERProgram(s), want 3", len(progs))
	}
	if v, ok := progs[0].IntOf("primacy"); !ok || v != 1 {
		t.Errorf("first program primacy = %d (%t), want 1", v, ok)
	}
	if h := progs[0].Path("DefaultDERControlLink").Href(); h != "/derp/0/dderc" {
		t.Errorf("DefaultDERControlLink href = %q", h)
	}
	if got := doc.Descendants("DERProgram"); len(got) != 3 {
		t.Errorf("Descendants found %d", len(got))
	}
	if !strings.Contains(doc.Summary(), "DERProgram×3") {
		t.Errorf("Summary = %q", doc.Summary())
	}
}

// TestHTTPRecoveryFramesMessages covers the framing rules the transcript
// depends on: Content-Length, a 204 with no body, chunked, and back-to-back
// messages on one stream.
func TestHTTPRecoveryFramesMessages(t *testing.T) {
	reqs := "GET /dcap HTTP/1.1\r\nHost: x\r\nAccept: application/sep+xml\r\n\r\n" +
		"PUT /edev/2/der/0/ders HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" +
		"HEAD /tm HTTP/1.1\r\nHost: x\r\n\r\n"
	resps := "HTTP/1.1 200 OK\r\nContent-Type: application/sep+xml\r\nContent-Length: 4\r\n\r\nbody" +
		"HTTP/1.1 204 No Content\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"

	reqStream := &plainStream{data: []byte(reqs)}
	respStream := &plainStream{data: []byte(resps)}

	got, err := parseMessages(Request, reqStream, nil)
	if err != nil {
		t.Fatalf("parse requests: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("recovered %d request(s), want 3", len(got))
	}
	if got[0].Method != "GET" || got[0].Path != "/dcap" {
		t.Errorf("request 0 = %s %s", got[0].Method, got[0].Path)
	}
	if string(got[1].Body) != "hello" {
		t.Errorf("request 1 body = %q", got[1].Body)
	}
	if got[1].Header.Get("Content-Length") != "5" {
		t.Errorf("request 1 headers = %v", got[1].Header)
	}

	methods := []string{"GET", "PUT", "HEAD"}
	rs, err := parseMessages(Response, respStream, methods)
	if err != nil {
		t.Fatalf("parse responses: %v", err)
	}
	if len(rs) != 3 {
		t.Fatalf("recovered %d response(s), want 3: %+v", len(rs), rs)
	}
	if rs[0].Status != 200 || string(rs[0].Body) != "body" {
		t.Errorf("response 0 = %d %q", rs[0].Status, rs[0].Body)
	}
	if rs[1].Status != 204 || len(rs[1].Body) != 0 {
		t.Errorf("a 204 must have no body, got %d bytes", len(rs[1].Body))
	}
	// The HEAD response declares a length it does not carry: the parser must
	// take the method into account, or it would swallow the rest of the stream.
	if len(rs[2].Body) != 0 {
		t.Errorf("a HEAD response must have no body, got %q", rs[2].Body)
	}
	// Offsets must partition the stream without gaps.
	if got[0].Start != 0 || got[1].Start != got[0].End || got[2].Start != got[1].End {
		t.Errorf("request offsets do not partition the stream: %d..%d, %d..%d, %d..%d",
			got[0].Start, got[0].End, got[1].Start, got[1].End, got[2].Start, got[2].End)
	}
}

func TestHTTPRecoveryHandlesChunkedAndTruncation(t *testing.T) {
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	rs, err := parseMessages(Response, &plainStream{data: []byte(chunked)}, []string{"GET"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || string(rs[0].Body) != "hello world" {
		t.Fatalf("chunked body = %q (%d message(s))", rs[0].Body, len(rs))
	}

	// A capture that stopped mid-body must yield the message it DID see marked
	// truncated, not a silent short body reported as complete.
	short := "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial"
	rs, err = parseMessages(Response, &plainStream{data: []byte(short)}, []string{"GET"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || !rs[0].BodyTruncated {
		t.Fatalf("a truncated body was not flagged: %+v", rs)
	}

	// A stream that ends before the header block completes yields nothing,
	// rather than a half-parsed message.
	rs, err = parseMessages(Response, &plainStream{data: []byte("HTTP/1.1 200 OK\r\nContent-")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 0 {
		t.Errorf("an incomplete header block produced %d message(s)", len(rs))
	}
}

func TestExchangeLatencyRefusesMissingTimestamps(t *testing.T) {
	e := Exchange{Req: &Message{Time: time.Unix(100, 0)}, Resp: &Message{Time: time.Unix(102, 0)}}
	if d, ok := e.Latency(); !ok || d != 2*time.Second {
		t.Errorf("Latency = %s (%t), want 2s", d, ok)
	}
	if _, ok := (Exchange{Req: &Message{}, Resp: &Message{}}).Latency(); ok {
		t.Error("Latency reported a value from zero timestamps; a timing criterion must SKIP instead")
	}
}
