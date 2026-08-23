package certify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The bench is shared. A conformance run that changed the DUT it is measuring
// would invalidate every test case that ran before it, so the guard rail is
// tested as carefully as the evidence path.
func TestGatewayIsReadOnly(t *testing.T) {
	allowed := [][]string{
		{"cat", "/etc/lexa-release"},
		{"journalctl", "-u", "lexa-gw", "-n", "100"},
		{"systemctl", "is-active", "lexa-gw"},
		{"systemctl", "--no-pager", "show", "lexa-gw"},
		{"openssl", "x509", "-in", "/etc/ssl/dev.pem", "-noout", "-text"},
		{"wget", "-qO-", "http://127.0.0.1:9102/metrics"},
		{"wget", "-O-", "http://127.0.0.1:9102/metrics"},
		{"wget", "--output-document=-", "http://127.0.0.1:9102/metrics"},
	}
	for _, args := range allowed {
		if err := CheckReadOnly(args); err != nil {
			t.Errorf("CheckReadOnly(%v) = %v, want nil", args, err)
		}
	}
	refused := [][]string{
		{},
		{"rm", "-rf", "/var/lib/lexa"},
		{"systemctl", "restart", "lexa-gw"},
		{"systemctl", "stop", "lexa-gw"},
		{"reboot"},
		{"sh", "-c", "echo x > /etc/config"},
		{"fw_setenv", "bootcount", "0"},
		// wget's one caller is a plain GET to stdout (IW27-004); anything else
		// on the allowed head token must still be refused (comment-only
		// invariants don't hold a second caller to the same shape).
		{"wget", "http://127.0.0.1:9102/metrics"},                                 // no -O at all: wget defaults to writing a file
		{"wget", "--post-data=x", "http://127.0.0.1:9102/metrics"},                // verb change
		{"wget", "-qO", "/tmp/exfil", "http://127.0.0.1:9102/metrics"},            // writes to a file, not stdout
		{"wget", "-O", "/etc/lexa/modbus.json", "http://127.0.0.1:9102/metrics"},  // writes to a file, not stdout
		{"wget", "--output-document=/tmp/exfil", "http://127.0.0.1:9102/metrics"}, // writes to a file, not stdout
	}
	for _, args := range refused {
		err := CheckReadOnly(args)
		if err == nil {
			t.Errorf("CheckReadOnly(%v) was permitted", args)
			continue
		}
		if !errors.Is(err, ErrNotReadOnly) {
			t.Errorf("CheckReadOnly(%v) = %v, want ErrNotReadOnly", args, err)
		}
	}
}

func TestGatewayRunRefusesMutationBeforeExecuting(t *testing.T) {
	called := false
	g := &Gateway{SSH: "cc93", Runner: func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}}
	if _, err := g.Run(context.Background(), "systemctl", "restart", "lexa-gw"); err == nil {
		t.Fatal("a mutating command was accepted")
	}
	if called {
		t.Fatal("the mutating command was executed before the guard ran")
	}
	if _, err := g.Run(context.Background(), "uname", "-a"); err != nil {
		t.Fatalf("a read-only command failed: %v", err)
	}
	if !called {
		t.Fatal("the read-only command was not executed")
	}
}

func TestGatewayWithoutAnSSHDestination(t *testing.T) {
	g := &Gateway{}
	if g.Available() {
		t.Error("Available() with no destination")
	}
	if _, err := g.Run(context.Background(), "uname"); err == nil {
		t.Error("a command ran with no destination configured")
	}
}

func TestGatewayCommandsAreShaped(t *testing.T) {
	var got []string
	g := &Gateway{SSH: "cc93", Runner: func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte("active\n"), nil
	}}
	active, err := g.UnitActive(context.Background(), "lexa-gw")
	if err != nil || !active {
		t.Fatalf("UnitActive = %v, %v", active, err)
	}
	want := "ssh -o BatchMode=yes cc93 systemctl is-active lexa-gw"
	if strings.Join(got, " ") != want {
		t.Errorf("command = %q, want %q", strings.Join(got, " "), want)
	}
}

func TestAdminClientAndSimClient(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/admin/status":
			_, _ = w.Write([]byte(`{"clients":2}`))
		case "/admin/control":
			body, _ := json.Marshal(map[string]any{"mrid": "abc"})
			_, _ = w.Write(body)
		case "/state":
			_, _ = w.Write([]byte(`{"w":4200}`))
		case "/boom":
			http.Error(w, "the sim exploded", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	admin := NewAdminClient(srv.URL, nil)
	if !admin.Available() {
		t.Fatal("Available() = false")
	}
	var status struct{ Clients int }
	if err := admin.Status(context.Background(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Clients != 2 {
		t.Errorf("clients = %d", status.Clients)
	}
	var ctrl struct{ MRID string }
	if err := admin.Control(context.Background(), map[string]any{"w": 1}, &ctrl); err != nil {
		t.Fatal(err)
	}
	if ctrl.MRID != "abc" {
		t.Errorf("mrid = %q", ctrl.MRID)
	}

	sim := NewSimClient("modsim", srv.URL, nil)
	var st struct{ W int }
	if err := sim.State(context.Background(), &st); err != nil {
		t.Fatal(err)
	}
	if st.W != 4200 {
		t.Errorf("w = %d", st.W)
	}

	// A 500 must surface the status AND the body: a failure nobody printed is
	// a debugging session nobody needed to have.
	_, err := sim.Raw(context.Background(), http.MethodGet, "/boom", nil)
	if err == nil {
		t.Fatal("a 500 was not reported")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "exploded") {
		t.Errorf("err = %v", err)
	}
	if strings.Join(seen, ", ") != "GET /admin/status, POST /admin/control, GET /state, GET /boom" {
		t.Errorf("requests = %v", seen)
	}
}

func TestUnconfiguredClientsFailLoudly(t *testing.T) {
	if err := NewAdminClient("", nil).Status(context.Background(), nil); err == nil {
		t.Error("an unconfigured admin client succeeded")
	}
	if err := NewSimClient("modsim", "", nil).State(context.Background(), nil); err == nil {
		t.Error("an unconfigured sim client succeeded")
	}
}

func TestRunCtxSimNamesWhatIsAvailable(t *testing.T) {
	cat := loadTestCatalog(t)
	c, _ := cat.ByUID("doc-a::A-001")
	rc := &RunCtx{Case: c, Sims: map[string]*SimClient{
		"modsim":   NewSimClient("modsim", "http://127.0.0.1:1", nil),
		"mbapsdev": NewSimClient("mbapsdev", "", nil),
	}}
	if _, err := rc.Sim("modsim"); err != nil {
		t.Fatalf("Sim(modsim): %v", err)
	}
	_, err := rc.Sim("batsim")
	if err == nil {
		t.Fatal("an unconfigured sim was returned")
	}
	if !strings.Contains(err.Error(), "modsim") {
		t.Errorf("error should name what IS available: %v", err)
	}
	if strings.Contains(err.Error(), "mbapsdev") {
		t.Errorf("error names a sim that has no URL: %v", err)
	}
}

func TestLoadPKIDiscoversTheBenchFixtures(t *testing.T) {
	p, err := LoadPKI("../../certs/mbaps")
	if err != nil {
		t.Skipf("bench PKI fixtures not present: %v", err)
	}
	for _, role := range []string{"read-only", "grid-service", "net-admin", "super-admin"} {
		if _, err := p.Role(role); err != nil {
			t.Errorf("Role(%s): %v", role, err)
		}
	}
	for _, neg := range []string{"expired", "no-role", "two-role", "wrong-ca"} {
		if _, err := p.NegativeFixture(neg); err != nil {
			t.Errorf("NegativeFixture(%s): %v", neg, err)
		}
	}
	if _, err := p.Role("nonexistent"); err == nil {
		t.Error("a missing role fixture was returned")
	} else if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("error should list what IS available: %v", err)
	}
}

func TestLoadPKIMissingDirectory(t *testing.T) {
	if _, err := LoadPKI(""); err == nil {
		t.Error("an empty PKI directory was accepted")
	}
	if _, err := LoadPKI("/nonexistent/certs"); err == nil {
		t.Error("a nonexistent PKI directory was accepted")
	}
}
