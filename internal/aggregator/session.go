// Package aggregator is the bench's Secure SunSpec Modbus (mbaps) aggregator
// emulator: a northbound mbaps CLIENT that plays the utility / VPP / aggregator,
// driving the lexa-gw gateway's northbound mbaps server (cmd/mbaps, :802) exactly
// as a real DERMS head-end would. It is the QA driver and demo star of the T06
// bench plan; this package is the CORE (T06.4 + T06.5 primitives): role sessions,
// the mbap transport adapter, device discovery, telemetry polling, the typed
// control / read-back / role-denial primitives, and JSON-serializable run state.
// The scenario-campaign engine (T06.6), readback-verification oracles (T06.7),
// TLS-fault probes (T06.8), and the interactive CLI (T06.9) compose these
// primitives and live in their own later tasks.
//
// # Referee independence (T06 PN-1 / T00 ruling C9)
//
// The emulator dials over the bench's OWN wolfSSL glue (internal/mbtls) and
// extracts / asserts roles with the bench's OWN parser (mbtls.RoleFromDER) —
// deliberately NOT lexa-platform/securemodbus. A conformance driver that shared
// its TLS-profile or role-assertion code with the gateway under test could not
// independently catch a profile or authz bug. The only thing shared with the
// product is lexa-proto/mbap (the pure-Go MBAP framing codec) and lexa-proto/
// {modbus,sunspec} (the transport interface + SunSpec model layouts): the wire
// format is the wire format, and a divergent framing/layout would be bugs, not
// independent verification. mbtls hands this package a decrypted net.Conn; this
// package rides mbap.Client on top and adapts it to modbus.Transport so the
// SunSpec codec drives the whole session unchanged.
package aggregator

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"csip-tls-test/internal/mbtls"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"
)

// Role is a Secure SunSpec Modbus client role, carried in the client
// certificate's role extension (OID 1.3.6.1.4.1.50316.802.1) and re-derived by
// the gateway on every request for authorization (design doc 04 Part C). The
// emulator connects AS one of these to exercise the gateway's grant/deny matrix.
type Role string

// The mandatory mbaps roles plus the LexaVolt vendor role (design doc 04 Part C;
// certs/mbaps/manifest.json is the file→role source of truth). GridService is
// the grid-service / curtailment identity; Super/Network administrators hold
// administrative rights; ReadOnly and LexaVoltReadOnly are read-only (the
// denial-probe subjects).
const (
	RoleGridService  Role = "GridServiceSunSpec"
	RoleSuperAdmin   Role = "SuperAdministratorSunSpec"
	RoleNetworkAdmin Role = "NetworkAdministratorSunSpec"
	RoleReadOnly     Role = "ReadOnlySunSpec"
	RoleLexaVolt     Role = "LexaVoltReadOnly"
)

// Roles returns the five bench roles in a stable order, for callers that sweep
// the whole matrix (the denial matrix in T06.8 and the CLI role picker in T06.9).
func Roles() []Role {
	return []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin, RoleReadOnly, RoleLexaVolt}
}

// RoleCred is one role's client-certificate credential: a full leaf-first chain
// (TCP-51) and the matching private key, referenced by file path because wolfSSL
// loads PEM from disk (CODING_PRINCIPLES §4 keeps key material out of Go memory
// and logs; the bench references certs by path, the gateway by certmgr handle).
type RoleCred struct {
	CertFile string
	KeyFile  string
}

// PKIRefs resolves a Role to its client credential and names the trust anchor
// that verifies the peer (gateway / device) server certificate. It is normally
// built by LoadPKI from a certs/mbaps manifest, but SetCred lets a test or a
// later task (e.g. T06.8's negative-fixture probes) register credentials
// programmatically.
type PKIRefs struct {
	// ServerCA is the CA file the emulator trusts to verify the peer's SERVER
	// certificate. For a loopback mbapsdev it is the device CA (dev-ca.pem, the
	// LoadPKI default); against the live gateway it is the gateway's owner CA,
	// which the CLI (T06.9) overrides. Peer verification is never optional.
	ServerCA string
	// MFLCode overrides the client Maximum Fragment Length selector; 0 keeps the
	// mbtls default (512-byte MFL, TCP-59/60).
	MFLCode int

	creds map[Role]RoleCred
}

// manifestFile is the subset of certs/mbaps/manifest.json this package reads:
// the device CA (default server trust anchor for loopback) and the happy-path
// role clients (name → cert/key). Negative fixtures and CA metadata are ignored
// here — they belong to the mbtls fixture tests and T06.8.
type manifestFile struct {
	Device struct {
		CA string `json:"ca"`
	} `json:"device"`
	Clients []struct {
		Name string `json:"name"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"clients"`
}

// LoadPKI reads dir/manifest.json (the T06.1 role-cert manifest, the file→role
// source of truth) and returns a PKIRefs mapping each client's role to its
// cert/key paths, resolved relative to dir. ServerCA defaults to the manifest's
// device CA — the correct anchor for a loopback mbapsdev; a caller targeting the
// live gateway overrides ServerCA with the gateway's owner CA.
//
// LoadPKI does NOT stat the key files: the bench commits public certs but
// gitignores *-key.pem (CLAUDE.md keys invariant), so a fresh checkout has no
// keys until `make gen-mbaps-certs` runs. A missing key surfaces later, at
// ConnectAs, as a wolfSSL load error naming the exact role — not as a load-time
// failure that would make the manifest unusable for inspection.
func LoadPKI(dir string) (PKIRefs, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return PKIRefs{}, fmt.Errorf("aggregator: read mbaps manifest: %w", err)
	}
	var mf manifestFile
	if err := json.Unmarshal(raw, &mf); err != nil {
		return PKIRefs{}, fmt.Errorf("aggregator: parse mbaps manifest %s: %w", dir, err)
	}
	p := PKIRefs{creds: make(map[Role]RoleCred, len(mf.Clients)), MFLCode: mbtls.DefaultClientProfile("", "", "").MFLCode}
	if mf.Device.CA != "" {
		p.ServerCA = resolve(dir, mf.Device.CA)
	}
	for _, c := range mf.Clients {
		if c.Name == "" || c.Cert == "" || c.Key == "" {
			continue
		}
		p.creds[Role(c.Name)] = RoleCred{
			CertFile: resolve(dir, c.Cert),
			KeyFile:  resolve(dir, c.Key),
		}
	}
	if len(p.creds) == 0 {
		return PKIRefs{}, fmt.Errorf("aggregator: mbaps manifest %s lists no client roles", dir)
	}
	return p, nil
}

// resolve joins a manifest-relative path onto dir; an already-absolute path is
// returned unchanged.
func resolve(dir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// Cred returns the credential registered for role r.
func (p PKIRefs) Cred(r Role) (RoleCred, bool) {
	c, ok := p.creds[r]
	return c, ok
}

// Roles returns the roles this PKIRefs actually has credentials for, in the
// stable Roles() order — the set a CLI role-picker (T06.9) offers and a matrix
// sweep iterates. It is a subset of the package Roles() (a manifest may omit a
// role, or a fresh checkout may lack its gitignored key).
func (p PKIRefs) Roles() []Role {
	var out []Role
	for _, r := range Roles() {
		if _, ok := p.creds[r]; ok {
			out = append(out, r)
		}
	}
	return out
}

// SetCred registers or overrides the credential for role r. Used by tests and by
// later tasks that mint fixtures programmatically (T06.8 negatives).
func (p *PKIRefs) SetCred(r Role, cred RoleCred) {
	if p.creds == nil {
		p.creds = make(map[Role]RoleCred)
	}
	p.creds[r] = cred
}

// SessionInfo is the JSON-serializable snapshot of a Conn's handshake facts and
// role — the building block a report (T06.9) or dashboard renders. It records
// both the role the emulator MEANT to present (Role) and the role its own client
// certificate actually carries as read by the bench's independent parser
// (Asserted): a mismatch is a PKI-wiring bug ConnectAs refuses to proceed past.
type SessionInfo struct {
	Role       Role   `json:"role"`
	Asserted   string `json:"asserted_role"`
	Cipher     string `json:"cipher"`
	TLSVersion string `json:"tls_version"`
	Resumed    bool   `json:"resumed"`
	MFLCode    int    `json:"mfl_code"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	Connected  bool   `json:"connected"`
}

// defaultOpTimeout bounds every request/response round trip. mbap.Client sets no
// deadlines (its documented contract), so the Conn owns them — a wedged peer or
// a lost southbound device must not hang a poll loop forever (CODING_PRINCIPLES
// §6 timeouts everywhere).
const defaultOpTimeout = 10 * time.Second

// Conn is one authenticated mbaps session to a gateway/device, presenting a
// single role. It owns an mbtls.Session (the decrypted transport) and an
// mbap.Client (single-outstanding-request framing) and serializes every op so
// at most one request is in flight — the discipline mbap.Client requires. On a
// transport-level break (a *FrameError, TID mismatch, or I/O error — never a
// protocol *ExceptionError) it marks itself broken and transparently redials on
// the next op; Reconnect drives a backoff+jitter reconnection loop for callers
// that want to wait out an outage.
type Conn struct {
	addr    string
	role    Role
	profile mbtls.Profile

	mu        sync.Mutex // serializes ops + guards sess/client/broken
	sess      *mbtls.Session
	client    *mbap.Client
	broken    bool
	opTimeout time.Duration

	readersMu sync.Mutex // guards readers (SunSpec block-layout cache, redial-safe)
	readers   map[uint8]*sunspec.Reader

	latestMu sync.Mutex // guards latest (most-recent telemetry snapshot per unit)
	latest   map[uint8]Snapshot
}

// ConnectAs dials addr presenting role r's client certificate over mbtls (the
// bench's own mbaps client profile) and wraps the decrypted session in an
// mbap.Client. Before dialing it self-checks that r's certificate actually
// carries role r, extracted by the bench's own referee (mbtls.RoleFromDER) — so
// a mis-wired manifest fails loudly here rather than silently presenting the
// wrong identity to the gateway and corrupting a conformance verdict.
func ConnectAs(addr string, r Role, pki PKIRefs) (*Conn, error) {
	cred, ok := pki.creds[r]
	if !ok {
		return nil, fmt.Errorf("aggregator: no client credential for role %q in PKI refs", r)
	}
	if pki.ServerCA == "" {
		return nil, fmt.Errorf("aggregator: PKI refs have no ServerCA to verify the peer (role %q)", r)
	}
	// Independent self-check: the cert we are about to present must carry the
	// role we intend (referee independence, PN-1) — a cheap guard against a
	// manifest that points role r at the wrong leaf.
	got, err := roleFromCertFile(cred.CertFile)
	if err != nil {
		return nil, fmt.Errorf("aggregator: role self-check for %q: %w", r, err)
	}
	if got != string(r) {
		return nil, fmt.Errorf("aggregator: cert %s carries role %q, not %q (PKI wiring bug)", cred.CertFile, got, r)
	}

	profile := mbtls.DefaultClientProfile(pki.ServerCA, cred.CertFile, cred.KeyFile)
	profile.RoleAsserted = string(r)
	if pki.MFLCode != 0 {
		profile.MFLCode = pki.MFLCode
	}

	c := &Conn{
		addr:      addr,
		role:      r,
		profile:   profile,
		opTimeout: defaultOpTimeout,
		readers:   make(map[uint8]*sunspec.Reader),
		latest:    make(map[uint8]Snapshot),
	}
	if err := c.dial(); err != nil {
		return nil, err
	}
	return c, nil
}

// roleFromCertFile extracts the mbaps role from the leaf of a PEM certificate
// file using the bench's own parser. It reads only the public certificate, never
// the key.
func roleFromCertFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("aggregator: read client cert %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("aggregator: client cert %q is not a PEM CERTIFICATE", path)
	}
	return mbtls.RoleFromDER(block.Bytes)
}

// dial performs one mbtls handshake and installs the fresh session/client. The
// caller holds c.mu or is in construction (ConnectAs, before c is shared).
func (c *Conn) dial() error {
	sess, err := mbtls.Dial(c.addr, c.profile)
	if err != nil {
		return fmt.Errorf("aggregator: connect %s as %s: %w", c.addr, c.role, err)
	}
	c.sess = sess
	c.client = mbap.NewClient(sess.Conn)
	c.broken = false
	return nil
}

// redial closes the broken session and dials a fresh one. Caller holds c.mu.
// This is the immediate, sleepless reconnect the raw ops perform when they find
// the session broken; Reconnect adds backoff for callers waiting out an outage.
func (c *Conn) redial() error {
	if c.sess != nil {
		_ = c.sess.Close()
		c.sess = nil
		c.client = nil
	}
	return c.dial()
}

// Reconnect re-establishes the session with exponential backoff and full jitter,
// stopping on success or when ctx is cancelled. Callers use it to ride out a
// gateway/device outage without spinning; the raw ops themselves only attempt a
// single immediate redial. The cached SunSpec block layouts survive a reconnect
// (they describe the device, not the connection), so discovery/poll state is not
// lost.
//
// TLS session resumption (T06.8): each reconnect goes through mbtls.Dial, which
// offers the cached TLS session for this peer+identity, so a reconnect RESUMES
// (Resumed=true) when the peer allows it (TCP-46) rather than always doing a full
// handshake — the resumeAfterDrop probe judges exactly this. Resumed is still
// reported honestly: a peer that declines resumption yields false.
func (c *Conn) Reconnect(ctx context.Context) error {
	const (
		base = 100 * time.Millisecond
		max  = 5 * time.Second
	)
	c.mu.Lock()
	defer c.mu.Unlock()
	delay := base
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.redial(); err == nil {
			return nil
		}
		// Full jitter over [0, delay): decorrelated retries under a fleet of
		// emulators, and no bare time.Sleep in the wait path (ctx-cancelable).
		wait := time.Duration(rand.Int63n(int64(delay) + 1))
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if delay < max {
			if delay *= 2; delay > max {
				delay = max
			}
		}
	}
}

// Close tears down the session. Safe to call once; idempotent thereafter.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil {
		return nil
	}
	err := c.sess.Close()
	c.sess = nil
	c.client = nil
	c.broken = true
	return err
}

// Role reports the role this connection presents.
func (c *Conn) Role() Role { return c.role }

// Addr reports the target address.
func (c *Conn) Addr() string { return c.addr }

// SetOpTimeout adjusts the per-op deadline. Call before starting concurrent ops
// (Poll); mid-flight changes only affect subsequent ops.
func (c *Conn) SetOpTimeout(d time.Duration) {
	c.mu.Lock()
	c.opTimeout = d
	c.mu.Unlock()
}

// Session exposes the live mbtls.Session for probes that operate at the TLS
// layer (Renegotiate, Resumed inspection — T06.8). Returns nil if closed. The
// caller must not close it directly; use Conn.Close.
func (c *Conn) Session() *mbtls.Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

// Resumed reports whether the current handshake resumed a cached TLS session
// (TCP-46). True after a reconnect to a peer+identity whose session was cached
// and the peer accepted resumption (see the Reconnect note); honest either way.
func (c *Conn) Resumed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess != nil && c.sess.Resumed
}

// SessionInfo returns a JSON-serializable snapshot of the handshake facts.
func (c *Conn) SessionInfo() SessionInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	si := SessionInfo{Role: c.role, Asserted: c.profile.RoleAsserted, Connected: c.sess != nil}
	if c.sess != nil {
		si.Cipher = c.sess.Cipher
		si.TLSVersion = c.sess.TLSVer
		si.Resumed = c.sess.Resumed
		si.MFLCode = c.sess.MFLCode
		if c.sess.Conn != nil {
			si.RemoteAddr = c.sess.Conn.RemoteAddr().String()
		}
	}
	return si
}
