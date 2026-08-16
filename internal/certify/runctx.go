package certify

// runctx.go is everything a Check is handed.
//
// The design rule here is that a check should never have to reach outside the
// RunCtx to do its job, and never be able to reach the things it must not touch.
// It gets the bench's addresses, the PKI fixtures, the sim control APIs,
// read-only gateway introspection, a logger, and — the part that makes its
// evidence citable — its own frame window, with the claiming calls right on the
// context so registering a connection is one line at the point it is opened:
//
//	conn, err := rc.DialTCP(ctx, rc.Targets.Gateway, "mbaps session")
//
// It does NOT get: a way to write to the gateway, a way to stop the capture, or
// the other checks' windows.

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Logger is the logging surface a check gets. *log.Logger satisfies it, which
// is what the rest of this bench uses.
type Logger interface {
	Printf(format string, v ...any)
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}

// DiscardLogger drops everything, for tests.
var DiscardLogger Logger = discardLogger{}

// NewLogger returns a prefixed logger writing to stderr.
func NewLogger(prefix string) Logger {
	return log.New(os.Stderr, prefix, log.LstdFlags|log.Lmicroseconds)
}

// Targets are the bench endpoints a check talks to.
//
// The defaults are the live bench topology from the repository's docs/BENCH.md
// and the certification bench's own layout: the desktop at 69.0.0.20 captures
// on enp1s0, the gateway at 69.0.0.2 exposes only :802 externally, and the sims
// the gateway polls run on the desktop.
type Targets struct {
	// Gateway is the DUT's northbound mbaps (Secure SunSpec Modbus) server.
	Gateway string
	// GatewayHost is the DUT's address without a port, for filters and
	// endpoint claims.
	GatewayHost string
	// GridSim is the bench's 2030.5 server the DUT's CSIP client dials;
	// GridSimAdmin is its admin API root.
	GridSim      string
	GridSimAdmin string
	// ModSim is the plain SunSpec Modbus device the gateway polls in cleartext
	// (which is what makes it capturable without decryption); ModSimAPI is its
	// simapi sidecar.
	ModSim    string
	ModSimAPI string
	// MBAPSDev is the secure Modbus device sim the gateway polls;
	// MBAPSDevAPI is its simapi sidecar.
	MBAPSDev    string
	MBAPSDevAPI string
	// Extra carries suite-specific endpoints without needing a framework
	// change every time a suite grows one. Read it through Endpoint, which
	// tolerates a nil map.
	Extra map[string]string
}

// Endpoint returns a suite-specific endpoint from Extra, or "".
func (t Targets) Endpoint(key string) string { return t.Extra[key] }

// WithEndpoint records a suite-specific endpoint, allocating Extra on first
// use so callers need not.
func (t *Targets) WithEndpoint(key, value string) {
	if value == "" {
		return
	}
	if t.Extra == nil {
		t.Extra = map[string]string{}
	}
	t.Extra[key] = value
}

// TargetMetrics is Extra's key for the DUT's own Prometheus endpoint.
//
// It lives in the framework rather than in the suite that reads it because the
// FLAG that populates it lives here (BindFlags), and a key spelled in two
// packages is a key that will one day be spelled two ways — which for this
// particular map fails silently, as a missing endpoint rather than an error.
// That is not hypothetical: the disclosure channel shipped reading
// Extra["metrics"] with nothing anywhere writing it, so the whole apparatus was
// unreachable from the operator's seat and every row reported "not configured"
// while the feature was recorded as delivered.
const TargetMetrics = "metrics"

// DefaultTargets is the live bench topology.
func DefaultTargets() Targets {
	return Targets{
		Gateway:      "69.0.0.2:802",
		GatewayHost:  "69.0.0.2",
		GridSim:      "69.0.0.20:11113",
		GridSimAdmin: "http://69.0.0.20:11114",
		ModSim:       "69.0.0.20:5020",
		ModSimAPI:    "http://69.0.0.20:6020",
		MBAPSDev:     "69.0.0.20:8021",
		MBAPSDevAPI:  "http://69.0.0.20:6031",
		// The DUT's own Prometheus endpoint. lexa-gw serves it on MetricsAddr,
		// whose default is the LOOPBACK 127.0.0.1:9102 (cmd/northbound's
		// config) — docs/BENCH.md binds it to the LAN address below, which is
		// what a desktop run can actually reach. A bench whose gateway keeps
		// the loopback default needs an ssh forward and -metrics-endpoint.
		Extra: map[string]string{TargetMetrics: "http://69.0.0.2:9102/metrics"},
	}
}

// Normalise derives the fields nobody types from the ones everybody does.
//
// GatewayHost exists because two suites need the DUT's address WITHOUT a port:
// suitessm tells a frame's direction by comparing its source address against
// it, and the capture filter is built from it. Nothing on the command line sets
// it — an operator types `-target 127.0.0.1:9502`, not a second host flag — so
// before this existed a run against any address other than the compiled-in
// bench default kept GatewayHost at 69.0.0.2 and every direction test silently
// compared against the wrong device. That is precisely the class of quiet wrong
// answer this tool exists not to produce, so the derivation happens once, in
// the runner's constructor, for every entry point.
//
// An explicitly-set GatewayHost that disagrees with Gateway's host is
// overwritten rather than honoured: Gateway is what the sockets actually dial,
// and a host field that does not name the device being dialled has no honest
// use.
func (t *Targets) Normalise() {
	if t.Gateway == "" {
		return
	}
	host, _, err := net.SplitHostPort(t.Gateway)
	if err != nil {
		// Not host:port. Leave whatever the caller set; the dial will fail with
		// a better message than anything invented here.
		return
	}
	t.GatewayHost = host
}

// AddrPort parses one of the host:port targets.
func AddrPort(target string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("certify: %q is not an ip:port: %w", target, err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// KeyPair is one certificate and its private key on disk.
type KeyPair struct {
	Name string
	Cert string
	Key  string
}

// Valid reports whether both files exist.
func (k KeyPair) Valid() bool {
	if k.Cert == "" || k.Key == "" {
		return false
	}
	_, ec := os.Stat(k.Cert)
	_, ek := os.Stat(k.Key)
	return ec == nil && ek == nil
}

// PKI is the bench's mbaps certificate fixture set (certs/mbaps), discovered by
// convention rather than configured, because the generator that produces it
// (make gen-mbaps-certs) already fixes the layout.
//
// The negative fixtures are as important as the positive ones: half the
// interesting conformance criteria are about what a conformant peer REFUSES,
// and a suite that cannot present an expired or role-less certificate cannot
// demonstrate a refusal.
type PKI struct {
	Dir string
	// CA is the trust anchor the bench's role certificates chain to.
	CA string
	// Intermediate is the issuing CA, present when the fixture set has a chain.
	Intermediate string
	// Server is the bench's own server certificate, for suites that stand up a
	// listener the DUT dials.
	Server KeyPair
	// Roles are the positive client fixtures keyed by their file stem, e.g.
	// "read-only", "grid-service", "net-admin", "super-admin".
	Roles map[string]KeyPair
	// Negative are the non-conformant fixtures keyed by stem, e.g. "expired",
	// "no-role", "two-role", "oversize-role", "wrong-ca", "bad-encoding".
	Negative map[string]KeyPair
}

// LoadPKI discovers the fixture set under dir. A missing directory is an error;
// a fixture set that is merely incomplete is not, because a suite that does not
// need the missing fixture should still run — Role and NegativeFixture report
// what is actually available when asked for something that is not.
func LoadPKI(dir string) (*PKI, error) {
	if dir == "" {
		return nil, fmt.Errorf("certify: no PKI directory configured")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("certify: PKI directory %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("certify: PKI path %s is not a directory", dir)
	}
	p := &PKI{
		Dir:      dir,
		Roles:    map[string]KeyPair{},
		Negative: map[string]KeyPair{},
	}
	if c := filepath.Join(dir, "ca-cert.pem"); fileExists(c) {
		p.CA = c
	}
	if c := filepath.Join(dir, "intermediate-cert.pem"); fileExists(c) {
		p.Intermediate = c
	}
	p.Server = KeyPair{
		Name: "server",
		Cert: filepath.Join(dir, "dev-server-cert.pem"),
		Key:  filepath.Join(dir, "dev-server-key.pem"),
	}
	scan := func(sub string, into map[string]KeyPair) {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			stem, ok := strings.CutSuffix(name, "-cert.pem")
			if !ok {
				continue
			}
			kp := KeyPair{
				Name: stem,
				Cert: filepath.Join(dir, sub, name),
				Key:  filepath.Join(dir, sub, stem+"-key.pem"),
			}
			into[stem] = kp
		}
	}
	scan("clients", p.Roles)
	scan("negative", p.Negative)
	return p, nil
}

// Role returns a positive client fixture by name.
func (p *PKI) Role(name string) (KeyPair, error) {
	if p == nil {
		return KeyPair{}, fmt.Errorf("certify: no PKI loaded")
	}
	kp, ok := p.Roles[name]
	if !ok {
		return KeyPair{}, fmt.Errorf("certify: no role fixture %q in %s (have: %s)",
			name, p.Dir, strings.Join(sortedMapKeys(p.Roles), ", "))
	}
	if !kp.Valid() {
		return KeyPair{}, fmt.Errorf("certify: role fixture %q is incomplete (%s / %s)", name, kp.Cert, kp.Key)
	}
	return kp, nil
}

// NegativeFixture returns a non-conformant fixture by name.
func (p *PKI) NegativeFixture(name string) (KeyPair, error) {
	if p == nil {
		return KeyPair{}, fmt.Errorf("certify: no PKI loaded")
	}
	kp, ok := p.Negative[name]
	if !ok {
		return KeyPair{}, fmt.Errorf("certify: no negative fixture %q in %s (have: %s)",
			name, p.Dir, strings.Join(sortedMapKeys(p.Negative), ", "))
	}
	if !kp.Valid() {
		return KeyPair{}, fmt.Errorf("certify: negative fixture %q is incomplete (%s / %s)", name, kp.Cert, kp.Key)
	}
	return kp, nil
}

func sortedMapKeys(m map[string]KeyPair) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// CaptureRef is the read-only view of the run's capture a check gets. It is
// deliberately not the *capture.Capture: a check must not be able to stop the
// capture the rest of the run depends on.
type CaptureRef struct {
	// Active reports whether a capture is running. When false, every wire
	// citation is impossible and a check should SKIP rather than pretend.
	Active bool
	// Path is where the capture is being written.
	Path string
	// Interface and Filter are what it was started with.
	Interface string
	Filter    string
	// Started is when it became live.
	Started time.Time
	// KeyLogPath is where TLS secrets are being exported, empty when they are
	// not — in which case encrypted payload claims are not assertable and a
	// check must say so.
	KeyLogPath string
}

// RunCtx is everything a check is handed.
type RunCtx struct {
	// Case is the catalog record being implemented. Read Case.Observables:
	// it is the list of wire facts the pass criteria rest on, and therefore
	// the list of assertions this check owes the bundle.
	Case *Case
	// Suite is the registering suite's name.
	Suite string
	// Registration is the full binding, including its capability requirements.
	Registration Registration

	// Targets are the bench endpoints.
	Targets Targets
	// PKI is the mbaps certificate fixture set; nil when none was configured.
	PKI *PKI
	// GridSim drives the 2030.5 server simulator.
	GridSim *AdminClient
	// Sims are the simapi sidecars, keyed by short name ("modsim",
	// "mbapsdev"). Use Sim to get one with a useful error when it is absent.
	Sims map[string]*SimClient
	// Gateway is READ-ONLY introspection of the DUT.
	Gateway *Gateway
	// Capture describes the run's capture.
	Capture CaptureRef
	// Params are operator-supplied -param key=value pairs, for the handful of
	// procedure parameters (a nameplate rating, a utility LFDI) that cannot be
	// discovered.
	Params map[string]string
	// Log is the run log.
	Log Logger

	// win is this check's frame window. It is not exported: the claiming
	// methods below are the whole intended surface, and a check that could
	// rewrite the window's interval could make its citations mean anything.
	win *Window
}

// Window returns the check's frame window. Prefer the ClaimConn / DialTCP
// helpers; this is for the cases that need the window itself.
func (rc *RunCtx) Window() *Window { return rc.win }

// AttachWindow gives a RunCtx its frame window, once.
//
// The runner calls it when it builds the context. It is exported so that a
// suite's own tests can drive a check's CLAIMING path — the part that decides
// which frames a check is entitled to cite — without standing up a whole run
// with a capture behind it. That path is worth testing directly: a claim that
// silently fails to register leaves a check with no citable evidence, which is
// the failure mode the whole attribution mechanism exists to prevent.
//
// It refuses to REPLACE an attached window rather than overwriting one. The
// reason win is unexported is that a check able to re-point its own window
// could make its citations mean anything, and an exported setter that
// overwrote would hand that back.
func (rc *RunCtx) AttachWindow(w *Window) error {
	if rc.win != nil {
		return fmt.Errorf("certify: %s already has a frame window; replacing one would let a check "+
			"re-point the interval its citations are attributed from", rc.Case.UID)
	}
	rc.win = w
	return nil
}

// ClaimConn registers a connection this check opened so its frames can be
// attributed. Call it immediately after the connection is established, for
// every connection, including ones the check only reads from.
//
// A failure to claim is returned rather than swallowed: an unclaimed connection
// means the check silently produces no citable evidence, which is precisely the
// failure this framework exists to make impossible.
func (rc *RunCtx) ClaimConn(c net.Conn, note string) error {
	if rc.win == nil {
		return fmt.Errorf("certify: %s: no frame window (a check running outside the runner?)", rc.Case.UID)
	}
	if err := rc.win.ClaimConn(c, note); err != nil {
		return err
	}
	rc.Logf("claimed %s <> %s (%s)", c.LocalAddr(), c.RemoteAddr(), note)
	return nil
}

// ClaimAddrs registers a connection by address, for connections whose socket
// the check cannot reach.
func (rc *RunCtx) ClaimAddrs(proto string, local, remote netip.AddrPort, note string) {
	if rc.win != nil {
		rc.win.ClaimAddrs(proto, local, remote, note)
	}
}

// ClaimEndpointDuring registers the weaker "everything to this endpoint during
// my window" claim, with the mandatory justification. See
// Window.ClaimEndpointDuring.
func (rc *RunCtx) ClaimEndpointDuring(proto string, remote netip.AddrPort, reason string) error {
	if rc.win == nil {
		return fmt.Errorf("certify: %s: no frame window", rc.Case.UID)
	}
	return rc.win.ClaimEndpointDuring(proto, remote, reason)
}

// DialTCP opens a TCP connection to target and claims it in one step. This is
// the call a check should reach for whenever it does not need TLS: it is not
// possible to use it and forget to claim.
func (rc *RunCtx) DialTCP(ctx context.Context, target, note string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("certify: %s: dial %s: %w", rc.Case.UID, target, err)
	}
	if err := rc.ClaimConn(conn, note); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Sim returns a sim's simapi client, with an error naming what IS configured
// when the requested one is not.
func (rc *RunCtx) Sim(name string) (*SimClient, error) {
	s, ok := rc.Sims[name]
	if !ok || !s.Available() {
		have := make([]string, 0, len(rc.Sims))
		for k, v := range rc.Sims {
			if v.Available() {
				have = append(have, k)
			}
		}
		sort.Strings(have)
		return nil, fmt.Errorf("certify: %s: sim %q is not configured (have: %s)",
			rc.Case.UID, name, strings.Join(have, ", "))
	}
	return s, nil
}

// Param returns an operator-supplied parameter.
func (rc *RunCtx) Param(key string) (string, bool) {
	v, ok := rc.Params[key]
	return v, ok
}

// RequireParam returns a parameter or an error naming it, so a check that needs
// an un-discoverable value fails with an actionable message instead of testing
// against a zero value.
func (rc *RunCtx) RequireParam(key string) (string, error) {
	if v, ok := rc.Params[key]; ok && v != "" {
		return v, nil
	}
	return "", fmt.Errorf("certify: %s needs -param %s=<value>", rc.Case.UID, key)
}

// Logf writes to the run log, prefixed with the test case.
func (rc *RunCtx) Logf(format string, v ...any) {
	if rc.Log == nil {
		return
	}
	rc.Log.Printf("[%s] "+format, append([]any{rc.Case.UID}, v...)...)
}

// Errata returns the published corrections for this case that a client-side
// implementation must honour. A check that runs the uncorrected procedure and
// calls the outcome a conformance failure is reporting our bug as the DUT's.
func (rc *RunCtx) Errata() []Erratum {
	var out []Erratum
	for _, e := range rc.Case.Errata {
		if e.ClientRelevant {
			out = append(out, e)
		}
	}
	return out
}

// Sleep waits, honouring cancellation. Checks that need a scheduled event to
// arrive should use it rather than time.Sleep, so -timeout and Ctrl-C work.
func (rc *RunCtx) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
