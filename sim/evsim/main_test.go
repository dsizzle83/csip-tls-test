package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ocpp2 "github.com/lorenzodonini/ocpp-go/ocpp2.0.1"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/provisioning"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/remotecontrol"
	"github.com/lorenzodonini/ocpp-go/ocpp2.0.1/types"

	"lexa-proto/ocppserver"
)

func newStopReq(tx string) *remotecontrol.RequestStopTransactionRequest {
	return &remotecontrol.RequestStopTransactionRequest{TransactionID: tx}
}

func newStartReq() *remotecontrol.RequestStartTransactionRequest {
	return &remotecontrol.RequestStartTransactionRequest{
		RemoteStartID: 1,
		IDToken:       types.IdToken{IdToken: "test-tag", Type: types.IdTokenTypeISO14443},
	}
}

// syncBuf is a goroutine-safe log sink (handlers log from several goroutines).
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// newOCPP201Handler builds a wired-up csHandler + ocpp201Handlers pair for
// the 2.0.1 protocol — the same construction main.go does, factored out since
// several tests below need it.
func newOCPP201Handler(cs ocpp2.ChargingStation, stationID, csmsURL string, batt *evBattery, meterInterval, sessionDuration time.Duration) (*csHandler, *ocpp201Handlers) {
	h := &csHandler{
		stationID:       stationID,
		csmsURL:         csmsURL,
		batt:            batt,
		meterInterval:   meterInterval,
		sessionDuration: sessionDuration,
	}
	h.proto = newOCPP201Proto(cs)
	h201 := &ocpp201Handlers{h: h}
	cs.SetProvisioningHandler(h201)
	cs.SetAvailabilityHandler(h201)
	cs.SetRemoteControlHandler(h201)
	cs.SetSmartChargingHandler(h201)
	return h, h201
}

// TestSession_TransactionLifecycle runs a full charging session against an
// in-process CSMS and verifies the OCPP 2.0.1 transaction sequence — the
// regression for audit finding OCPP-1 (sessions previously consisted of bare
// StatusNotification + MeterValues with no TransactionEvent at all).
func TestSession_TransactionLifecycle(t *testing.T) {
	logs := &syncBuf{}
	log.SetOutput(logs)
	defer log.SetOutput(os.Stderr)

	port := freePort(t)
	srv := ocppserver.New(ocppserver.Config{Port: port})
	go srv.Start()
	defer srv.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cs := ocpp2.NewChargingStation("evsim-test", nil, nil)
	batt := newEVBattery(60000, 20, 230, 32, 60)
	csmsURL := fmt.Sprintf("ws://127.0.0.1:%d/ocpp", port)
	h, _ := newOCPP201Handler(cs, "evsim-test", csmsURL, batt, 500*time.Millisecond, time.Minute)
	h.setConnector(1, connAvailable)

	if err := cs.Start(csmsURL); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cs.Stop()
	if _, err := cs.BootNotification(provisioning.BootReasonPowerUp, stationModel, stationVendor); err != nil {
		t.Fatalf("BootNotification: %v", err)
	}

	// Start a session, let at least one periodic Updated go out, then stop.
	h.startSession(1, time.Minute, trigCablePluggedIn, txStartOpts{})

	// Wait for the session to be active and a transaction ID assigned.
	waitFor(t, time.Second, func() bool {
		st := h.Snapshot()
		return st.Session.Active && st.Session.TransactionID != ""
	}, "session active with transaction ID")

	st := h.Snapshot()
	if !st.CSMS.Connected {
		t.Error("Snapshot CSMS.Connected = false, want true (live IsConnected)")
	}

	time.Sleep(1200 * time.Millisecond) // ≥ 2 meter ticks
	h.stopSession(stopLocal, trigStopAuthorized)

	st = h.Snapshot()
	if st.Session.Active {
		t.Error("session still active after stopSession")
	}
	if st.Session.TransactionID != "" {
		t.Errorf("transaction ID %q not cleared after stopSession", st.Session.TransactionID)
	}

	// CSMS-side log proves each event arrived and was answered (an unhandled
	// feature would surface as a CallError on the station side instead).
	out := logs.String()
	for _, want := range []string{
		"[ocpp] TransactionEvent cs=evsim-test type=Started",
		"[ocpp] TransactionEvent cs=evsim-test type=Updated",
		"[ocpp] TransactionEvent cs=evsim-test type=Ended",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CSMS log missing %q", want)
		}
	}
	// Started must be seq 0 of a fresh transaction.
	if !strings.Contains(out, "type=Started tx=") || !strings.Contains(out, "seq=0") {
		t.Error("Started event missing transaction ID or seq=0")
	}
}

// TestRemoteStartStop verifies RequestStartTransaction / RequestStopTransaction
// act on the session instead of returning a hollow Accepted (finding OCPP-2).
func TestRemoteStartStop(t *testing.T) {
	logs := &syncBuf{}
	log.SetOutput(logs)
	defer log.SetOutput(os.Stderr)

	batt := newEVBattery(60000, 20, 230, 32, 60)
	h := &csHandler{
		batt:            batt,
		meterInterval:   time.Second,
		sessionDuration: time.Minute,
	}
	o := &ocpp201Handlers{h: h}

	// Stop with no active transaction → Rejected.
	resp, err := o.OnRequestStopTransaction(newStopReq("no-such-tx"))
	if err != nil {
		t.Fatalf("OnRequestStopTransaction: %v", err)
	}
	if string(resp.Status) != "Rejected" {
		t.Errorf("stop with no transaction = %s, want Rejected", resp.Status)
	}

	// Simulate an active transaction; mismatched ID → Rejected, matching → Accepted.
	h.setTxID("test-tx-id")
	h.mu.Lock()
	h.session.Active = true
	txID := h.txID
	h.mu.Unlock()

	resp, _ = o.OnRequestStopTransaction(newStopReq("wrong-id"))
	if string(resp.Status) != "Rejected" {
		t.Errorf("stop with wrong tx ID = %s, want Rejected", resp.Status)
	}
	resp, _ = o.OnRequestStopTransaction(newStopReq(txID))
	if string(resp.Status) != "Accepted" {
		t.Errorf("stop with matching tx ID = %s, want Accepted", resp.Status)
	}

	// Start while a session is active → Rejected.
	startResp, err := o.OnRequestStartTransaction(newStartReq())
	if err != nil {
		t.Fatalf("OnRequestStartTransaction: %v", err)
	}
	if string(startResp.Status) != "Rejected" {
		t.Errorf("start while active = %s, want Rejected", startResp.Status)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// genTestCert writes a self-signed ECDSA TLS cert + key for 127.0.0.1 into
// dir and returns their paths.
func genTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "csms-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, "csms-cert.pem")
	keyPath = filepath.Join(dir, "csms-key.pem")
	certOut, _ := os.Create(certPath)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.Create(keyPath)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()
	return certPath, keyPath
}

// TestSecurityProfile2 verifies the wss:// + HTTP Basic Auth path end to end
// (finding OCPP-3): a station with the right CA and credentials boots, and a
// station with the wrong password is refused at the WebSocket handshake.
func TestSecurityProfile2(t *testing.T) {
	certPath, keyPath := genTestCert(t, t.TempDir())

	port := freePort(t)
	srv := ocppserver.New(ocppserver.Config{
		Port:          port,
		CertPath:      certPath,
		KeyPath:       keyPath,
		BasicAuthUser: "evse-001",
		BasicAuthPass: "s3cret",
	})
	go srv.Start()
	defer srv.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	url := fmt.Sprintf("wss://127.0.0.1:%d/ocpp", port)

	// Correct CA + credentials → connect and boot.
	client, err := newWSClient(url, certPath, "evse-001", "s3cret")
	if err != nil {
		t.Fatalf("newWSClient: %v", err)
	}
	cs := ocpp2.NewChargingStation("sp2-ok", nil, client)
	if err := cs.Start(url); err != nil {
		t.Fatalf("wss connect with valid credentials: %v", err)
	}
	if _, err := cs.BootNotification(provisioning.BootReasonPowerUp, stationModel, stationVendor); err != nil {
		t.Fatalf("BootNotification over wss: %v", err)
	}
	cs.Stop()

	// Wrong password → handshake refused.
	badClient, err := newWSClient(url, certPath, "evse-001", "wrong")
	if err != nil {
		t.Fatalf("newWSClient (bad creds): %v", err)
	}
	bad := ocpp2.NewChargingStation("sp2-bad", nil, badClient)
	if err := bad.Start(url); err == nil {
		bad.Stop()
		t.Fatal("connection with wrong password succeeded, want refusal")
	}

	// -tls-ca with a ws:// URL is a config error.
	if _, err := newWSClient("ws://127.0.0.1/ocpp", certPath, "", ""); err == nil {
		t.Error("newWSClient accepted -tls-ca with ws:// URL, want error")
	}
}
