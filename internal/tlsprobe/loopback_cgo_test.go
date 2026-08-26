//go:build cgo

package tlsprobe

// loopback_cgo_test.go drives the probe against a REAL mbaps server — the same
// stack sim/mbapsdev is made of: internal/mbtls's wolfSSL listener in front of
// sim/southbound's animated SunSpec register world, dispatched over
// lexa-proto/mbap exactly as sim/mbapsdev/dispatch.go does it.
//
// The acceptance bar is the one SSM-CONF-v0.8 §2.5.1.3 states and the previous
// Go-only probe could not reach: for EVERY mandated suite, including the two
// that use AES-CCM, a session is ESTABLISHED and a SunSpec Model 1 read is
// carried inside it and answered. A ServerHello is not enough.
//
// The negative half is the point of the pair: a server that does not offer the
// pinned suite must produce a REFUSAL the probe reports as such, not a session
// on some other suite. Without it, "the probe completed" would be a fact about
// the probe's willingness to accept anything.

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/mbtls"
	"csip-tls-test/internal/wolfssl"
	sim "csip-tls-test/sim/southbound"
	"lexa-proto/mbap"

	modbuslib "github.com/simonvetter/modbus"
)

// TestMain initialises wolfSSL once for the whole test binary, which is the
// library's own lifecycle rule (internal/wolfssl's package doc) and what every
// other wolfSSL-linking test package in this repository does.
func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

// device is the loopback peer: an mbaps listener serving a real SunSpec chain.
type device struct {
	addr string
	pki  probePKI
}

// startDevice stands up the server half, with the suites it should offer. An
// empty suite list means the whole mandated set.
func startDevice(t *testing.T, offer []Suite) *device {
	t.Helper()
	pki := mintPKI(t)

	// A real SunSpec model chain — Common Model 1 first, at 40000 — so the
	// probe's Model 1 read reads a device rather than a fixture.
	srv, err := sim.NewSolarServerAdvanced("tcp://127.0.0.1:0", 5000, "PROBE-LOOPBACK-01")
	if err != nil {
		t.Fatalf("stand up the SunSpec register world: %v", err)
	}
	t.Cleanup(srv.Stop)

	prof := mbtls.DefaultServerProfile(pki.caFile, pki.serverCert, pki.serverKey)
	if len(offer) > 0 {
		prof.Suites12, prof.Suites13 = nil, nil
		for _, s := range offer {
			switch s.Version {
			case TLS12:
				prof.Suites12 = append(prof.Suites12, s.Wolf)
			case TLS13:
				prof.Suites13 = append(prof.Suites13, s.Wolf)
			}
		}
		// mbtls refuses a profile with no TLS 1.2 suite at all (TLS 1.2 is the
		// mbaps floor), so a 1.3-only restriction keeps the 1.2 list and caps
		// the version instead.
		if len(prof.Suites12) == 0 {
			prof.Suites12 = append([]string(nil), mbtls.Mandated12...)
		}
		if len(prof.Suites13) == 0 {
			prof.MaxTLS = mbtls.TLS12
		}
	}
	lis, err := mbtls.Listen("127.0.0.1:0", prof)
	if err != nil {
		t.Fatalf("mbtls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go serve(lis, srv.Regs)
	return &device{addr: lis.Addr().String(), pki: pki}
}

// serve is sim/mbapsdev/dispatch.go's accept-and-dispatch loop, reduced to the
// read path this package exercises. A rejected handshake is an ordinary event
// here — it is what the refusal test provokes — so the loop continues.
func serve(lis *mbtls.Listener, regs *sim.RegisterMap) {
	for {
		sess, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go dispatch(sess, regs)
	}
}

func dispatch(sess *mbtls.Session, regs *sim.RegisterMap) {
	defer sess.Close()
	for {
		_ = sess.Conn.SetDeadline(time.Now().Add(20 * time.Second))
		// mbap.Decode rather than DecodeRequest: Decode is present in every
		// pinned revision of lexa-proto this repository has vendored, and this
		// loop needs to read one framed ADU, not to police request shapes —
		// handle below rejects anything it does not serve.
		req, err := mbap.Decode(sess.Conn)
		if err != nil {
			return
		}
		resp, err := handle(req, regs)
		if err != nil {
			return
		}
		raw, err := mbap.Encode(resp)
		if err != nil {
			return
		}
		if _, err := sess.Conn.Write(raw); err != nil {
			return
		}
	}
}

func handle(req mbap.ADU, regs *sim.RegisterMap) (mbap.ADU, error) {
	if regs == nil || len(req.PDU) == 0 || req.PDU[0] != mbap.FCReadHolding {
		return mbap.Exception(req, mbap.ExIllegalFunction), nil
	}
	rreq, err := mbap.ParseReadReq(req.PDU)
	if err != nil {
		return mbap.Exception(req, mbap.ExIllegalAddress), nil
	}
	values, herr := regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId: req.UnitID, Addr: rreq.Addr, Quantity: rreq.Count, IsWrite: false,
	})
	if herr != nil {
		return mbap.Exception(req, mbap.ExIllegalAddress), nil
	}
	pdu, err := mbap.BuildReadResp(rreq, values)
	if err != nil {
		return mbap.ADU{}, err
	}
	return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: pdu}, nil
}

func (d *device) spec(s Suite) Spec {
	return Spec{
		Target:   d.addr,
		CAFiles:  []string{d.pki.caFile},
		CertFile: d.pki.clientCert,
		KeyFile:  d.pki.clientKey,
		Suite:    s,
		Unit:     1,
		Deadline: 30 * time.Second,
	}
}

// TestEveryMandatedSuiteCompletesASessionAndAModel1Read is the acceptance bar.
//
// It runs all six because the CCM pair is only interesting beside the four that
// a Go stack could already do: if AES-CCM failed here while GCM passed, the
// finding would be about the suite; if all six failed, it would be about the
// bench.
func TestEveryMandatedSuiteCompletesASessionAndAModel1Read(t *testing.T) {
	dev := startDevice(t, nil)
	for _, s := range append(append([]Suite{}, Mandatory12...), Mandatory13...) {
		t.Run(s.IANA, func(t *testing.T) {
			rep, err := Complete(context.Background(), dev.spec(s))
			if err != nil {
				t.Fatalf("no session was established on %s: %v", s, err)
			}
			if rep.Negotiated.Suite.Code != s.Code {
				t.Errorf("negotiated 0x%04X %s, want the pinned 0x%04X %s",
					rep.Negotiated.Suite.Code, rep.Negotiated.SuiteName, s.Code, s.IANA)
			}
			if rep.Negotiated.Version != s.Version {
				t.Errorf("negotiated %s, want %s (a pinned suite pins its version)",
					rep.Negotiated.Version, s.Version)
			}
			if rep.Negotiated.Resumed {
				t.Error("the handshake RESUMED; every probe must be a full handshake or it is evidence " +
					"about an earlier session, possibly on another suite")
			}
			if len(rep.PeerLeafDER) == 0 {
				t.Error("no peer leaf was recovered, so the session authenticated nobody")
			}
			if !rep.Model1.OK() {
				t.Fatalf("the Model 1 read inside the session failed: %v", rep.Model1.Err)
			}
			if rep.Model1.Length == 0 || len(rep.Model1.Values) != int(rep.Model1.Length) {
				t.Errorf("Model 1 declared %d register(s) and %d were decoded",
					rep.Model1.Length, len(rep.Model1.Values))
			}
			if id := rep.Model1.Identity(); !strings.Contains(id, "PROBE-LOOPBACK-01") {
				t.Errorf("the Common Model identity is %q; the device this test stood up serves serial "+
					"PROBE-LOOPBACK-01", id)
			}
			t.Logf("%s: %s · %s", s, rep.Negotiated, rep.Model1.Summary())
		})
	}
}

// TestCCMSessionsAreTheOnesThatMatter states the regression this package
// exists to prevent, on its own, so a failure names it directly rather than
// arriving as one subtest among six.
func TestCCMSessionsAreTheOnesThatMatter(t *testing.T) {
	dev := startDevice(t, nil)
	for _, s := range CCMSuites {
		rep, err := Complete(context.Background(), dev.spec(s))
		if err != nil {
			t.Fatalf("%s: no session — this is exactly the gap the probe was written to close: %v", s, err)
		}
		if !rep.Model1.OK() {
			t.Fatalf("%s: session established but no Modbus was carried inside it: %v", s, rep.Model1.Err)
		}
	}
}

// TestAServerThatDoesNotOfferThePinnedSuiteIsReportedAsARefusal is the negative
// half. A probe that "completed" against a server offering something else would
// make every positive result meaningless.
func TestAServerThatDoesNotOfferThePinnedSuiteIsReportedAsARefusal(t *testing.T) {
	// Deliberately misconfigured: GCM only, in both versions. Disabling suites
	// is a legal server configuration (SunSpecTCP-20) — which is what makes it
	// a fair provocation rather than a broken peer.
	dev := startDevice(t, []Suite{TLS12GCM, TLS13GCM})
	for _, s := range []Suite{TLS12ChaCha, TLS12CCM8, TLS13CCM} {
		t.Run(s.IANA, func(t *testing.T) {
			rep, err := Complete(context.Background(), dev.spec(s))
			if err == nil {
				t.Fatalf("a session was established on %s against a server that does not offer it "+
					"(negotiated %s)", s, rep.Negotiated)
			}
			he, ok := Refused(err)
			if !ok {
				t.Fatalf("the failure is not reported as a handshake refusal: %v", err)
			}
			if he.Requested.Code != s.Code {
				t.Errorf("the refusal names suite 0x%04X, want the pinned 0x%04X", he.Requested.Code, s.Code)
			}
			if !strings.Contains(he.Error(), s.IANA) {
				t.Errorf("the refusal does not name what was offered: %v", he)
			}
		})
	}
}

// TestTheGCMControlStillCompletesAgainstTheMisconfiguredServer is the control
// that makes the refusals above attributable to the SUITE rather than to an
// unreachable peer — the same control CRYP-003 and CRYP-007 carry.
func TestTheGCMControlStillCompletesAgainstTheMisconfiguredServer(t *testing.T) {
	dev := startDevice(t, []Suite{TLS12GCM, TLS13GCM})
	rep, err := Complete(context.Background(), dev.spec(TLS12GCM))
	if err != nil {
		t.Fatalf("the control session on %s failed, so the refusals above prove nothing: %v", TLS12GCM, err)
	}
	if !rep.Model1.OK() {
		t.Fatalf("the control session carried no Modbus: %v", rep.Model1.Err)
	}
}

// TestOnConnectRunsBeforeTheHandshakeAndCanAbort holds the property the
// conformance runner's frame attribution depends on.
func TestOnConnectRunsBeforeTheHandshakeAndCanAbort(t *testing.T) {
	dev := startDevice(t, nil)

	var seen net.Conn
	spec := dev.spec(TLS12CCM8)
	spec.OnConnect = func(c net.Conn) error { seen = c; return nil }
	s, err := Dial(context.Background(), spec)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer s.Close()
	if seen == nil {
		t.Fatal("OnConnect never ran, so a refused handshake would produce no citable frames")
	}
	if seen.RemoteAddr().String() != dev.addr {
		t.Errorf("OnConnect saw %s, want the raw TCP connection to %s", seen.RemoteAddr(), dev.addr)
	}

	refuse := dev.spec(TLS12CCM8)
	sentinel := errors.New("the caller could not register this connection")
	refuse.OnConnect = func(net.Conn) error { return sentinel }
	if _, err := Dial(context.Background(), refuse); !errors.Is(err, sentinel) {
		t.Errorf("a refusing OnConnect gave %v, want the caller's own error", err)
	}
}

// TestAnUnpinnedProbeNegotiatesTheHighestMandatedSuite proves the unpinned
// offer is usable for the checks whose subject is not the suite.
func TestAnUnpinnedProbeNegotiatesTheHighestMandatedSuite(t *testing.T) {
	dev := startDevice(t, nil)
	spec := dev.spec(Suite{})
	rep, err := Complete(context.Background(), spec)
	if err != nil {
		t.Fatalf("the unpinned probe failed: %v", err)
	}
	if rep.Negotiated.Version != TLS13 {
		t.Errorf("negotiated %s; an unpinned offer leading with the TLS 1.3 suites must reach TLS 1.3 "+
			"against a 1.3-capable peer", rep.Negotiated.Version)
	}
	if !rep.Model1.OK() {
		t.Fatalf("the unpinned session carried no Modbus: %v", rep.Model1.Err)
	}
}

// TestUnitScanFindsThePopulatedSlot proves Spec.Unit == 0 discovers rather than
// assumes.
func TestUnitScanFindsThePopulatedSlot(t *testing.T) {
	dev := startDevice(t, nil)
	spec := dev.spec(TLS12CCM8)
	spec.Unit = 0
	rep, err := Complete(context.Background(), spec)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if !rep.Model1.OK() {
		t.Fatalf("the unit scan found nothing: %v", rep.Model1.Err)
	}
	if rep.Model1.Unit == 0 {
		t.Error("the report does not record which unit answered")
	}
}

// ── a throwaway PKI ─────────────────────────────────────────────────────────

// probePKI is a root CA, a server leaf and a role-bearing client leaf, minted
// into a temporary directory because the committed fixture set's private keys
// are gitignored and a checkout that has never run `make gen-mbaps-certs` has
// the certificates without them.
type probePKI struct {
	caFile                string
	serverCert, serverKey string
	clientCert, clientKey string
}

func mintPKI(t *testing.T) probePKI {
	t.Helper()
	dir := t.TempDir()
	ca, caKey := selfSignedCA(t, "tlsprobe test CA")
	p := probePKI{
		caFile:     filepath.Join(dir, "ca-cert.pem"),
		serverCert: filepath.Join(dir, "server-cert.pem"),
		serverKey:  filepath.Join(dir, "server-key.pem"),
		clientCert: filepath.Join(dir, "client-cert.pem"),
		clientKey:  filepath.Join(dir, "client-key.pem"),
	}
	writeCert(t, p.caFile, ca.Raw)

	sc, sk := leaf(t, "tlsprobe test server", ca, caKey, true, "")
	writeCert(t, p.serverCert, sc.Raw)
	writeKey(t, p.serverKey, sk)

	cc, ck := leaf(t, "tlsprobe test client", ca, caKey, false, "GridServiceSunSpec")
	writeCert(t, p.clientCert, cc.Raw)
	writeKey(t, p.clientKey, ck)
	return p
}

// TestAPeerCertificateThisSideRefusesIsNotReportedAsASuiteRefusal is the
// diagnosis test, and the reason reason_cgo.go exists.
//
// A cipher-suite procedure reads a failed handshake as "the DUT would not do a
// mandatory suite". When the real cause is that THIS side would not accept the
// peer's certificate, saying so is the difference between a bench-configuration
// note and a published finding about a device that did nothing wrong.
func TestAPeerCertificateThisSideRefusesIsNotReportedAsASuiteRefusal(t *testing.T) {
	dev := startDeviceWithClientAuthOnlyLeaf(t)
	_, err := Complete(context.Background(), dev.spec(TLS12CCM8))
	if err == nil {
		t.Fatal("a session completed against a server whose leaf names no serverAuth purpose")
	}
	he, ok := Refused(err)
	if !ok {
		t.Fatalf("not reported as a handshake failure: %v", err)
	}
	if !he.PeerRejectedByUs {
		t.Fatalf("the failure was not classified as this side refusing the peer (code %d, reason %q); "+
			"a cipher-suite row would publish it as the DUT refusing a mandatory suite:\n%v",
			he.Code, he.Reason, err)
	}
	if he.Code != -386 {
		t.Errorf("wolfSSL reason %d, want -386 EXTKEYUSE_AUTH_E", he.Code)
	}
	if !strings.Contains(he.Error(), "THIS SIDE") {
		t.Errorf("the message does not say whose refusal it was:\n%v", he)
	}
}

// TestReasonSurvivesTheWrappersFormat pins the string coupling reason_cgo.go
// documents: a real handshake failure must still yield a reason code.
func TestReasonSurvivesTheWrappersFormat(t *testing.T) {
	dev := startDevice(t, []Suite{TLS12GCM, TLS13GCM})
	_, err := Complete(context.Background(), dev.spec(TLS12CCM8))
	he, ok := Refused(err)
	if !ok {
		t.Fatalf("expected a handshake failure, got %v", err)
	}
	if he.Code == 0 || he.Reason == "" {
		t.Fatalf("no wolfSSL reason was recovered from %q — internal/wolfssl's error format has changed "+
			"and reason_cgo.go's parser no longer matches it", he.Err)
	}
	if he.PeerRejectedByUs {
		t.Errorf("a suite refusal (code %d, %s) was classified as a peer-certificate rejection",
			he.Code, he.Reason)
	}
}

// startDeviceWithClientAuthOnlyLeaf stands up a server whose leaf carries
// clientAuth and NOT serverAuth, which is what wolfSSL's EXTKEYUSE_AUTH_E is
// raised for.
func startDeviceWithClientAuthOnlyLeaf(t *testing.T) *device {
	t.Helper()
	dir := t.TempDir()
	ca, caKey := selfSignedCA(t, "tlsprobe wrong-eku CA")
	p := probePKI{
		caFile:     filepath.Join(dir, "ca-cert.pem"),
		serverCert: filepath.Join(dir, "server-cert.pem"),
		serverKey:  filepath.Join(dir, "server-key.pem"),
		clientCert: filepath.Join(dir, "client-cert.pem"),
		clientKey:  filepath.Join(dir, "client-key.pem"),
	}
	writeCert(t, p.caFile, ca.Raw)
	// server=false gives the leaf clientAuth only — the provocation.
	sc, sk := leaf(t, "tlsprobe wrong-eku server", ca, caKey, false, "")
	writeCert(t, p.serverCert, sc.Raw)
	writeKey(t, p.serverKey, sk)
	cc, ck := leaf(t, "tlsprobe wrong-eku client", ca, caKey, false, "GridServiceSunSpec")
	writeCert(t, p.clientCert, cc.Raw)
	writeKey(t, p.clientKey, ck)

	lis, err := mbtls.Listen("127.0.0.1:0", mbtls.DefaultServerProfile(p.caFile, p.serverCert, p.serverKey))
	if err != nil {
		t.Fatalf("mbtls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go serve(lis, nil)
	return &device{addr: lis.Addr().String(), pki: p}
}
