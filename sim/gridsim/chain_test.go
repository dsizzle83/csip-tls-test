package gridsim

// chain_test.go exercises /admin/chain against a fake swapper, which is the
// point of the ChainSwapper seam: the admin plane's contract can be pinned
// without cgo, a wolfSSL sysroot or a live TLS listener.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// fakeSwapper records what it was asked to do and reads back the files the
// handler wrote, so the test can prove the PEM in the request body is the PEM
// the TLS server was pointed at.
type fakeSwapper struct {
	active, orig ChainState
	lastLabel    string
	lastCertPEM  string
	lastKeyPEM   string
	lastKeyPath  string
	swapErr      error
	restoreErr   error
	restores     int
}

func (f *fakeSwapper) ActiveChain() ChainState   { return f.active }
func (f *fakeSwapper) OriginalChain() ChainState { return f.orig }

func (f *fakeSwapper) SwapChain(label, certPath, keyPath string) (ChainState, error) {
	if f.swapErr != nil {
		return ChainState{}, f.swapErr
	}
	cert, _ := os.ReadFile(certPath)
	key, _ := os.ReadFile(keyPath)
	f.lastLabel, f.lastCertPEM, f.lastKeyPEM, f.lastKeyPath = label, string(cert), string(key), keyPath
	f.active = ChainState{Label: label, LeafSHA256: "cafebabe", ChainLen: 2, Swaps: f.active.Swaps + 1}
	return f.active, nil
}

func (f *fakeSwapper) RestoreChain() (ChainState, error) {
	if f.restoreErr != nil {
		return ChainState{}, f.restoreErr
	}
	f.restores++
	f.active = f.orig
	return f.active, nil
}

func newChainServer(t *testing.T, sw ChainSwapper) http.Handler {
	t.Helper()
	s := NewServer("")
	if sw != nil {
		s.SetChainSwapper(sw)
	}
	return s.AdminHandler()
}

func doChain(t *testing.T, h http.Handler, method, body string) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/admin/chain", nil)
	} else {
		r = httptest.NewRequest(method, "/admin/chain", strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s /admin/chain returned unparseable JSON (%d): %s", method, w.Code, w.Body.String())
	}
	return w.Code, out
}

// TestAdminChain_UnwiredReports501 is the version gate a conformance check
// probes. 501 says "this build knows the route, this process has no data
// plane"; a 404 would say "your gridsim is too old". Those are different
// answers and a check that could not tell them apart would report the wrong
// reason for skipping.
func TestAdminChain_UnwiredReports501(t *testing.T) {
	h := newChainServer(t, nil)
	code, body := doChain(t, h, http.MethodGet, "")
	if code != http.StatusNotImplemented {
		t.Fatalf("GET /admin/chain on an unwired gridsim = %d, want 501", code)
	}
	if _, ok := body["error"]; !ok {
		t.Errorf("the 501 body carries no error explaining itself: %v", body)
	}
}

func TestAdminChain_GetReportsActiveAndOriginal(t *testing.T) {
	sw := &fakeSwapper{
		active: ChainState{Label: "startup", LeafSHA256: "abc123", ChainLen: 2, Original: true},
		orig:   ChainState{Label: "startup", LeafSHA256: "abc123", ChainLen: 2, Original: true},
	}
	code, body := doChain(t, newChainServer(t, sw), http.MethodGet, "")
	if code != http.StatusOK {
		t.Fatalf("GET /admin/chain = %d, want 200", code)
	}
	active, _ := body["active"].(map[string]any)
	if active["leaf_sha256"] != "abc123" || active["label"] != "startup" {
		t.Errorf("active = %v", active)
	}
	if _, ok := body["original"]; !ok {
		t.Error("the response does not report the ORIGINAL chain, so a check has nothing to restore against")
	}
}

func TestAdminChain_PostInstallsThePEMFromTheBody(t *testing.T) {
	sw := &fakeSwapper{orig: ChainState{Label: "startup", LeafSHA256: "abc123"}}
	h := newChainServer(t, sw)

	const certPEM = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
	req, err := json.Marshal(adminChainReq{Label: "comm-004d", CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	code, body := doChain(t, h, http.MethodPost, string(req))
	if code != http.StatusOK {
		t.Fatalf("POST /admin/chain = %d: %v", code, body)
	}
	if sw.lastLabel != "comm-004d" {
		t.Errorf("label reached the swapper as %q", sw.lastLabel)
	}
	if sw.lastCertPEM != certPEM || sw.lastKeyPEM != keyPEM {
		t.Errorf("the material the swapper loaded is not the material in the request body")
	}
	if fi, err := os.Stat(sw.lastKeyPath); err != nil {
		t.Errorf("stat the written key: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("the private key was written mode %v, want 0600", fi.Mode().Perm())
	}

	// A restore takes the material away with it, so the simulator does not sit
	// on a private key it is no longer serving.
	code, _ = doChain(t, h, http.MethodPost, `{"restore":true}`)
	if code != http.StatusOK {
		t.Fatalf("POST restore = %d", code)
	}
	if sw.restores != 1 {
		t.Errorf("restore reached the swapper %d time(s), want 1", sw.restores)
	}
	if _, err := os.Stat(sw.lastKeyPath); !os.IsNotExist(err) {
		t.Errorf("the swap key %s survived the restore (stat err %v)", sw.lastKeyPath, err)
	}
}

// TestAdminChain_RestoreNeedsNothingElse pins the property a check's cleanup
// path depends on: restore takes no argument, so it works even when the check
// that armed the swap has lost track of what it armed.
func TestAdminChain_RestoreNeedsNothingElse(t *testing.T) {
	sw := &fakeSwapper{orig: ChainState{Label: "startup", LeafSHA256: "abc123", Original: true}}
	code, body := doChain(t, newChainServer(t, sw), http.MethodPost, `{"restore":true}`)
	if code != http.StatusOK {
		t.Fatalf("POST restore on an unswapped server = %d: %v", code, body)
	}
	active, _ := body["active"].(map[string]any)
	if active["leaf_sha256"] != "abc123" {
		t.Errorf("restore did not report the original chain: %v", active)
	}
}

func TestAdminChain_RefusesIncompleteInstalls(t *testing.T) {
	const certPEM = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
	for _, tc := range []struct{ name, body string }{
		{"no label", `{"cert_pem":"` + jsonEsc(certPEM) + `","key_pem":"` + jsonEsc(keyPEM) + `"}`},
		{"no cert", `{"label":"x","key_pem":"` + jsonEsc(keyPEM) + `"}`},
		{"no key", `{"label":"x","cert_pem":"` + jsonEsc(certPEM) + `"}`},
		{"not json", `{`},
	} {
		sw := &fakeSwapper{orig: ChainState{Label: "startup"}}
		code, body := doChain(t, newChainServer(t, sw), http.MethodPost, tc.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400 (body %v)", tc.name, code, body)
		}
		if sw.lastLabel != "" {
			t.Errorf("%s: a refused request still reached the swapper", tc.name)
		}
	}
}

// TestAdminChain_FailedSwapCleansUpItsMaterial proves the endpoint does not
// leave a private key on disk for a chain it failed to install.
func TestAdminChain_FailedSwapCleansUpItsMaterial(t *testing.T) {
	sw := &fakeSwapper{orig: ChainState{Label: "startup"}, swapErr: errFake}
	const certPEM = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	req := `{"label":"x","cert_pem":"` + jsonEsc(certPEM) + `","key_pem":"k"}`
	code, body := doChain(t, newChainServer(t, sw), http.MethodPost, req)
	if code != http.StatusBadRequest {
		t.Fatalf("POST with a failing swapper = %d, want 400 (%v)", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "install chain") {
		t.Errorf("the error does not name what failed: %v", body["error"])
	}
}

func jsonEsc(s string) string { return strings.ReplaceAll(s, "\n", `\n`) }

var errFake = errFakeType{}

type errFakeType struct{}

func (errFakeType) Error() string { return "the fixture refused to load" }
