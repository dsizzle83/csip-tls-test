//go:build integration

package csipnotify

// notify_integration_test.go closes the loop the whole Notifier seam exists
// for: gridsim REFUSES an https:// notificationURI, this package makes one
// deliverable, and the only way to know it really did is to stand up a
// mutually-authenticated listener and watch a Notification arrive on it.
//
// It needs the wolfSSL sysroot, so it is behind the `integration` tag like
// every other test in this repo that links against it:
//
//	CGO_CFLAGS="-I$HOME/.local/wolfssl-amd64/include" \
//	CGO_LDFLAGS="-L$HOME/.local/wolfssl-amd64/lib -lwolfssl -lm" \
//	go test -tags integration ./internal/csipnotify/
//
// The fake DUT is sim/tlsserver, which pins the same CSIP-mandatory cipher the
// notifier dials with. That is deliberate: if the two ever disagreed about the
// suite, this test would fail at the handshake rather than in a conformance run
// three hours long, and the bench would have reported the disagreement as a
// gateway that ignored its Notifications.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"csip-tls-test/internal/wolfssl"
	"csip-tls-test/sim/gridsim"
	"csip-tls-test/sim/tlsserver"
)

func TestMain(m *testing.M) {
	wolfssl.Init()
	code := m.Run()
	wolfssl.Cleanup()
	os.Exit(code)
}

func certPath(rel string) string {
	abs, err := filepath.Abs(filepath.Join("..", "..", "sim", "tlsserver", "testdata", "certs", rel))
	if err != nil {
		panic(err)
	}
	return abs
}

// fakeDUTListener stands up the inbound Notification server a subscribing
// client would run: mTLS, the CSIP cipher, answering with the status the caller
// chooses.
func fakeDUTListener(t *testing.T, answer int) (addr string, got *int64, bodies chan []byte) {
	t.Helper()

	var count int64
	bodies = make(chan []byte, 8)
	srv, err := tlsserver.New(tlsserver.Config{
		CACertPath:     certPath("ca-cert.pem"),
		ServerCertPath: certPath("server-cert.pem"),
		ServerKeyPath:  certPath("server-key.pem"),
	})
	if err != nil {
		t.Fatalf("tlsserver.New: %v", err)
	}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<20)
		n, _ := r.Body.Read(buf)
		atomic.AddInt64(&count, 1)
		select {
		case bodies <- buf[:n]:
		default:
		}
		w.WriteHeader(answer)
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		srv.Close()
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(lis) }()
	t.Cleanup(func() {
		_ = lis.Close()
		<-done
		srv.Close()
	})
	return lis.Addr().String(), &count, bodies
}

func notifierUnderTest() *Notifier {
	return New(Config{
		CACertPath:     certPath("ca-cert.pem"),
		ClientCertPath: certPath("client-cert.pem"),
		ClientKeyPath:  certPath("client-key.pem"),
	})
}

// TestNotifierDeliversOverTheMandatedCipher is the test the pure-Go refusal
// exists to be replaced by.
func TestNotifierDeliversOverTheMandatedCipher(t *testing.T) {
	addr, count, bodies := fakeDUTListener(t, http.StatusCreated)

	status, err := notifierUnderTest().Notify(context.Background(),
		"https://"+addr+"/notif", []byte(`<Notification xmlns="urn:ieee:std:2030.5:ns"/>`))
	if err != nil {
		t.Fatalf("delivery over the CSIP-mandatory cipher failed: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("the notifier reported HTTP %d, want the 201 the listener answered", status)
	}
	if atomic.LoadInt64(count) != 1 {
		t.Fatalf("the listener saw %d Notification(s), want 1", *count)
	}
	select {
	case b := <-bodies:
		if !strings.Contains(string(b), "Notification") {
			t.Errorf("the delivered body is not a Notification: %s", b)
		}
	default:
		t.Error("no body reached the listener")
	}
}

// TestNotifierReportsTheClientsStatusRatherThanFailing pins the inverted
// contract. A 400 from the DUT is ERR-002's whole point; a transport that
// turned it into an error would destroy the measurement.
func TestNotifierReportsTheClientsStatusRatherThanFailing(t *testing.T) {
	addr, _, _ := fakeDUTListener(t, http.StatusBadRequest)

	status, err := notifierUnderTest().Notify(context.Background(),
		"https://"+addr+"/notif", []byte(`<Notification xmlns="urn:ieee:std:2030.5:ns"/>`))
	if err != nil {
		t.Fatalf("a non-2xx answer was reported as a delivery failure: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — the DUT's own answer", status)
	}
}

// TestNotifierRefusesWithoutAnIdentity guards the substitution nobody should
// make: dialling a 2030.5 notification connection without a client certificate
// would measure a handshake the standard does not describe.
func TestNotifierRefusesWithoutAnIdentity(t *testing.T) {
	_, err := New(Config{}).Notify(context.Background(), "https://127.0.0.1:1/notif", []byte("x"))
	if err == nil {
		t.Fatal("an anonymous TLS notification was attempted")
	}
	if !strings.Contains(err.Error(), "mutually authenticated") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// TestGridsimPushesOverTheNotifierSeam is the end-to-end one: the seam, the
// simulator's own dispatch, and the delivery record a conformance criterion
// reads. It is the difference between "this package can POST" and "installing
// it makes gridsim's Notifications arrive".
func TestGridsimPushesOverTheNotifierSeam(t *testing.T) {
	addr, count, _ := fakeDUTListener(t, http.StatusCreated)

	s := gridsim.NewServer("AABBCCDDEEFF00112233445566778899AABBCCDD")
	s.EnableSubscriptions()
	if err := s.EnableFleet(gridsim.FleetSize); err != nil {
		t.Fatal(err)
	}
	s.SetNotifier(notifierUnderTest())

	csip := httptest.NewServer(s.Handler())
	defer csip.Close()
	admin := httptest.NewServer(s.AdminHandler())
	defer admin.Close()

	// Subscribe exactly as the DUT would, naming the mTLS listener.
	body := `<Subscription xmlns="urn:ieee:std:2030.5:ns">` +
		`<subscribedResource>/edev</subscribedResource>` +
		`<notificationURI>https://` + addr + `/notif</notificationURI></Subscription>`
	resp, err := http.Post(csip.URL+"/edev/2/sub", "application/sep+xml", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Subscription POST answered %d, want 201", resp.StatusCode)
	}

	// Change the subscribed resource. Dispatch is synchronous with the
	// mutation, so by the time this returns the Notification is delivered.
	cresp, err := http.Post(admin.URL+"/admin/fleet", "application/json",
		strings.NewReader(`{"device":"EDA1","managed_by":"AABBCCDDEEFF00112233445566778899AABBCCDD"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = cresp.Body.Close()

	if atomic.LoadInt64(count) == 0 {
		t.Fatal("gridsim delivered no Notification over the installed wolfSSL notifier")
	}
	recs := s.SentNotifications()
	if len(recs) == 0 {
		t.Fatal("gridsim recorded no delivery")
	}
	for _, r := range recs {
		if r.Error != "" {
			t.Errorf("a delivery was recorded as failed: %s", r.Error)
		}
		if r.HTTPStatus != http.StatusCreated {
			t.Errorf("recorded HTTP status %d, want 201 — the delivery record is what the conformance "+
				"criteria read, so a wrong status there is a wrong verdict", r.HTTPStatus)
		}
	}
}
