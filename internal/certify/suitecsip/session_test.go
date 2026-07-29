package suitecsip

// session_test.go is the proof that the transcript machinery works against a
// real TLS session rendered into a real pcap — the whole chain a bench run
// exercises, minus dumpcap.
//
// The assertions that matter are the provenance ones. Recovering the HTTP
// exchanges is table stakes; what a bundle's honesty rests on is that each
// recovered message names the TLS records that carried it, that those records'
// frame numbers are frames this check owns, and that a citation of them
// survives the framework's ownership check.

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

func newBufReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// walkRequests is the request sequence the fixture's "DUT" makes: the discovery
// walk, a DER self-report PUT and a Response POST, all on one keep-alive
// connection.
func walkRequests(t *testing.T) []*http.Request {
	t.Helper()
	mk := func(method, path, body string) *http.Request {
		var r *http.Request
		var err error
		if body == "" {
			r, err = http.NewRequest(method, "https://localhost"+path, nil)
		} else {
			r, err = http.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
			r.Header.Set("Content-Type", sepCT)
		}
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Accept", sepCT)
		return r
	}
	return []*http.Request{
		mk("GET", "/dcap", ""),
		mk("GET", "/tm", ""),
		mk("GET", "/edev", ""),
		mk("GET", "/edev/2/reg", ""),
		mk("GET", "/edev/2/fsa", ""),
		mk("GET", "/edev/2/fsa/0/derp", ""),
		mk("GET", "/derp/0/dderc", ""),
		mk("GET", "/derp/0/derc", ""),
		mk("PUT", "/edev/2/der/0/derstat", `<?xml version="1.0"?><DERStatus xmlns="urn:ieee:std:2030.5:ns">`+
			`<genConnectStatus><value>1</value></genConnectStatus><inverterStatus><value>2</value></inverterStatus>`+
			`<operationalModeStatus><value>2</value></operationalModeStatus><readingTime>1</readingTime></DERStatus>`),
		mk("POST", "/rsps/0/r", `<?xml version="1.0"?><DERControlResponse xmlns="urn:ieee:std:2030.5:ns">`+
			`<createdDateTime>1</createdDateTime><endDeviceLFDI>ab</endDeviceLFDI><status>1</status>`+
			`<subject>CERT-TEST</subject></DERControlResponse>`),
	}
}

func recordWalk(t *testing.T) (*testPKI, recorded) {
	t.Helper()
	p := newTestPKI(t)
	rec := recordSession(t, p, walkHandler(p.clientLFDI, p.clientSFDI, 111115, time.Now().Unix()),
		walkRequests(t))
	return p, rec
}

// TestRecoverSessionRecoversTheTranscript is the end-to-end proof: a real TLS
// session, rendered to a pcap, read back into HTTP exchanges with provenance.
func TestRecoverSessionRecoversTheTranscript(t *testing.T) {
	p, rec := recordWalk(t)
	ev, remote := evidenceFrom(t, rec, true)

	tr, err := RecoverSession(ev, remote)
	if err != nil {
		t.Fatalf("RecoverSession: %v", err)
	}
	if !tr.Decrypted {
		t.Fatalf("the session did not decrypt: %s", tr.Undecryptable)
	}
	if len(tr.Problems) > 0 {
		t.Errorf("recovery problems: %v", tr.Problems)
	}

	// The handshake tier.
	if tr.Handshake.Version != TLS12 {
		t.Errorf("negotiated version = 0x%04X, want TLS 1.2", tr.Handshake.Version)
	}
	if len(tr.Handshake.ClientChain) != 2 {
		t.Errorf("the DUT's chain has %d certificate(s), want 2", len(tr.Handshake.ClientChain))
	}
	if tr.Handshake.CertificateRequest == nil {
		t.Error("no CertificateRequest was recovered, but the fixture's server requires a client certificate")
	}
	if !tr.Handshake.Complete {
		t.Error("the handshake was not recorded as complete")
	}

	// The transcript tier.
	want := []string{"/dcap", "/tm", "/edev", "/edev/2/reg", "/edev/2/fsa", "/edev/2/fsa/0/derp",
		"/derp/0/dderc", "/derp/0/derc", "/edev/2/der/0/derstat", "/rsps/0/r"}
	if len(tr.Exchanges) != len(want) {
		t.Fatalf("recovered %d exchange(s), want %d: %s", len(tr.Exchanges), len(want), tr.Summary())
	}
	for i, w := range want {
		if tr.Exchanges[i].Req.Path != w {
			t.Errorf("exchange %d path = %q, want %q", i, tr.Exchanges[i].Req.Path, w)
		}
		if tr.Exchanges[i].Resp == nil {
			t.Fatalf("exchange %d (%s) has no response", i, w)
		}
	}

	// Resources are found by root element, which is how the criteria look.
	if _, doc, ok := tr.Resource("EndDeviceList"); !ok {
		t.Error("no EndDeviceList was located by root element")
	} else if got, _ := doc.TextOf("lFDI"); got == "" {
		t.Error("the EndDeviceList carries no lFDI")
	}

	// Statuses: the PUT must be 204 and the POST 201, which is what the
	// DER-report and LogEvent criteria turn on.
	put := tr.Method("PUT")
	if len(put) != 1 || put[0].Resp.Status != 204 {
		t.Errorf("PUT exchanges = %+v, want one answered 204", put)
	}
	post := tr.Method("POST")
	if len(post) != 1 || post[0].Resp.Status != 201 {
		t.Errorf("POST exchanges = %+v, want one answered 201", post)
	}
	if loc := post[0].Resp.Header.Get("Location"); loc == "" {
		t.Error("the 201 carries no Location header")
	}

	// PROVENANCE: every message must name frames this check owns, and a
	// citation of them must survive the framework's ownership check.
	for i, e := range tr.Exchanges {
		for _, m := range []*Message{e.Req, e.Resp} {
			if len(m.Frames) == 0 {
				t.Fatalf("exchange %d %s carries no frames", i, m.Line())
			}
			for _, f := range m.Frames {
				if !ev.Owns(f) {
					t.Fatalf("exchange %d %s cites frame %d, which this check does not own", i, m.Line(), f)
				}
			}
			if m.CipherEnd <= m.CipherStart {
				t.Errorf("exchange %d %s has an empty ciphertext range [%d,%d)",
					i, m.Line(), m.CipherStart, m.CipherEnd)
			}
			if m.Time.IsZero() {
				t.Errorf("exchange %d %s has no capture timestamp", i, m.Line())
			}
		}
	}
	first := tr.Exchanges[0]
	if _, err := ev.CiteBytes("test", "test", certify.Pass, "test",
		tr.ServerDir, first.Resp.CipherStart, first.Resp.CipherEnd); err != nil {
		t.Errorf("a citation of the first response's ciphertext was refused: %v", err)
	}

	// The DUT's identity must be derivable from the certificate on the wire and
	// must match what the fixture's server served.
	if got := LFDI(tr.Handshake.ClientChain[0]); got != p.clientLFDI {
		t.Errorf("LFDI from the wire = %s, want %s", got, p.clientLFDI)
	}
}

// TestRecoverSessionWithoutKeyLogIsHonest is the branch that keeps the suite
// honest on the bench as it stands today: no key log means no payload, and the
// transcript must say so rather than produce an empty exchange list that reads
// like "the DUT sent nothing".
func TestRecoverSessionWithoutKeyLogIsHonest(t *testing.T) {
	_, rec := recordWalk(t)
	ev, remote := evidenceFrom(t, rec, false)

	tr, err := RecoverSession(ev, remote)
	if err != nil {
		t.Fatalf("RecoverSession: %v", err)
	}
	if tr.Decrypted {
		t.Fatal("the session decrypted without a key log")
	}
	if !strings.Contains(tr.Undecryptable, "key log") {
		t.Errorf("Undecryptable = %q, want it to name the missing key log", tr.Undecryptable)
	}
	if len(tr.Exchanges) != 0 {
		t.Errorf("recovered %d exchange(s) without secrets", len(tr.Exchanges))
	}
	// The handshake tier must still be fully populated: this is what makes
	// COMM-003 assertable on a bench with no key export.
	if tr.Handshake.ClientHello == nil || tr.Handshake.ServerHello == nil {
		t.Fatal("the cleartext handshake was not recovered")
	}
	if len(tr.Handshake.ServerChain) == 0 || len(tr.Handshake.ClientChain) == 0 {
		t.Error("the certificate chains were not recovered from the cleartext handshake")
	}
	if tr.ClientAppRecords == 0 || tr.ServerAppRecords == 0 {
		t.Errorf("application-data records were not counted: %d/%d",
			tr.ClientAppRecords, tr.ServerAppRecords)
	}
	// And a payload criterion must SKIP with that reason rather than fail.
	obs := &Observation{Case: ev.Case, Transcript: tr}
	as, err := mint(ev, obs, []criterion{critDiscoveryRoot()})
	if err != nil {
		t.Fatal(err)
	}
	if as[0].Verdict != certify.Skip {
		t.Fatalf("verdict = %s, want SKIP; observed %q", as[0].Verdict, as[0].Observed)
	}
	if !strings.Contains(as[0].Observed, "key log") {
		t.Errorf("the SKIP does not name the missing key log: %q", as[0].Observed)
	}
}

// TestRecoverSessionWithNoFramesRefuses proves the first branch of every check:
// a capture that does not contain the session yields an error naming that, not
// an empty transcript that a criterion might read as "nothing happened".
func TestRecoverSessionWithNoFramesRefuses(t *testing.T) {
	_, rec := recordWalk(t)
	ev, remote := evidenceFrom(t, rec, true)
	// A frame set with nothing in it, which is what a check that claimed
	// nothing — or whose window missed the traffic — receives.
	empty := &certify.Evidence{Case: ev.Case, Index: ev.Index, Attribution: ev.Attribution,
		Set: ev.Attribution.Set("nobody")}
	if _, err := RecoverSession(empty, remote); err == nil {
		t.Fatal("RecoverSession accepted an empty frame set")
	}
}

// TestCheckPipelineProducesAssertions runs the criteria the way the runner
// does — through mint, against a real Evidence — and requires that the cited
// assertions carry a digest a verifier can re-derive.
func TestCheckPipelineProducesAssertions(t *testing.T) {
	p, rec := recordWalk(t)
	ev, remote := evidenceFrom(t, rec, true)
	tr, err := RecoverSession(ev, remote)
	if err != nil {
		t.Fatal(err)
	}
	obs := &Observation{Case: ev.Case, Transcript: tr, Params: map[string]string{}}

	crits := []criterion{
		critTLS12(),
		critMutualAuth(),
		critHandshakeComplete(),
		critDiscoveryRoot(),
		critEndDeviceList(0),
		critSelfIdentity(),
		critRegistrationPIN("111115"),
		critFSAList(0),
		critProgramList(0),
		critTimeResource(),
		critDefaultDERControl(),
		critDERPut("DERStatus"),
		critDERStatusElements(),
		critDERControlCarriesMode("opModMaxLimW", "the DUT fetched a max active power limit"),
		critResponsePosted(1, "Event received", "CERT-TEST"),
		critFollowedLink(),
	}
	as, err := mint(ev, obs, crits)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(as) != len(crits) {
		t.Fatalf("minted %d assertion(s) for %d criteria", len(as), len(crits))
	}
	cited := 0
	for _, a := range as {
		if a.Verdict != certify.Pass {
			t.Errorf("criterion %q = %s: %s", a.Claim, a.Verdict, a.Observed)
		}
		if a.Citable() {
			cited++
		}
	}
	if cited < len(crits)-1 {
		t.Errorf("only %d of %d assertions carry a re-checkable digest", cited, len(crits))
	}
	// The identity assertion must actually name the certificate's LFDI, or it
	// is asserting something other than what it claims.
	for _, a := range as {
		if strings.Contains(a.Claim, "sFDI and lFDI") && !strings.Contains(a.Observed, p.clientLFDI) {
			t.Errorf("the identity assertion does not name the derived LFDI: %q", a.Observed)
		}
	}
}

// TestNotApplicableIsOffWireWithAReason proves the rows bound to the stub
// produce an auditable record rather than a silent absence. (It builds its own
// case rather than reading one from the catalog, because the property under
// test is the stub's, not any particular row's.)
func TestNotApplicableIsOffWireWithAReason(t *testing.T) {
	rc := &certify.RunCtx{Case: &certify.Case{
		UID: "csip-conf-v1.3::AGG-001", ID: "AGG-001", DUTRole: certify.RoleNotApplicable,
		ApplicabilityReason: "the DUT is a direct DER client, not an aggregator client",
	}}
	res, err := notApplicable(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != certify.Skip {
		t.Errorf("verdict = %s, want SKIP", res.Verdict)
	}
	if !res.OffWire || res.OffWireReason == "" {
		t.Error("an inapplicable row must declare itself off-wire WITH a reason")
	}
	if !strings.Contains(res.Notes, "aggregator client") {
		t.Errorf("the notes do not carry the catalog's reason: %q", res.Notes)
	}
}
