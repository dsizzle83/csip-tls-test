package suitemodbusserver

// session.go opens a Modbus conversation with the DUT and makes it citable.
//
// Two transports, one interface. The live bench is mbaps: the DUT's northbound
// Modbus is TLS-only, so the conversation runs inside a mutually authenticated
// TLS session that this suite builds with the bench's OWN mbaps client
// (internal/mbtls, wolfSSL), never the product's securemodbus. The loopback
// tests — and any future DUT with a plain Modbus/TCP interface — use plain TCP.
// Everything above the socket is identical, which is exactly the property
// SunSpecTCP-9 asserts and this suite relies on.
//
// The one non-negotiable step: every session claims its connection with the
// framework the moment it is established. An unclaimed connection produces no
// citable evidence, which would leave every assertion in this suite resting on
// its own say-so.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
)

// Param keys. See the package doc for the defaults and what each one is for.
const (
	paramTransport   = "modbus.transport"
	paramRole        = "modbus.role"
	paramUnit        = "modbus.unit"
	paramUnitScanMax = "modbus.unit-scan-max"
	paramReversionS  = "modbus.reversion-s"
	paramNoEnumWrite = "modbus.no-enum-writes"
	paramPICSMn      = "pics.mn"
	paramPICSMd      = "pics.md"
	paramPICSSN      = "pics.sn"
	paramPICSModels  = "pics.models"
	param1547Models  = "1547.require-models"
	// paramPICSReversion declares that the PICS claims a reversion timer, which
	// is what turns §2.6's applicability gate off. See revertGateNote.
	paramPICSReversion = "pics.reversion-timer"
)

// defaultRole is the PKI role fixture the suite presents. The device-model
// procedures need reads AND writes; the read-only role would turn every write
// procedure into an authorization test, which is a different document's job.
const defaultRole = "super-admin"

// defaultUnitScanMax bounds the unit-identifier probe.
const defaultUnitScanMax = 16

// ioTimeout bounds one request/response exchange.
const ioTimeout = 8 * time.Second

// session is one claimed Modbus conversation with the DUT.
type session struct {
	*client

	// Transport is "mbaps" or "plain".
	Transport string
	// TLS describes the negotiated TLS session, empty for plain transport. It
	// is recorded in the report so a reader knows the tunnel the Modbus
	// procedure ran inside.
	TLS string
	// Local and Remote are the socket endpoints, captured while the connection
	// is still open (after Close they are gone, and they are what identifies
	// this check's frames in the capture).
	Local, Remote netip.AddrPort
	// UnitNotes records the unit-identifier probe, exception by exception.
	UnitNotes []string

	conn    net.Conn
	closeFn func() error
}

// Close tears the session down. It is safe to call twice.
func (s *session) Close() {
	if s == nil {
		return
	}
	if s.closeFn != nil {
		_ = s.closeFn()
		s.closeFn = nil
	}
}

// Encrypted reports whether the conversation ran inside TLS, which decides
// whether the citation phase has to decrypt to see the Modbus PDUs.
func (s *session) Encrypted() bool { return s.Transport == "mbaps" }

// dialer is a transport's connect function. The mbaps implementation lives in
// session_cgo.go and is absent from a CGO_ENABLED=0 build, where the stub in
// session_nocgo.go explains that rather than failing obscurely.
type dialer func(ctx context.Context, addr string, pki *certify.PKI, role string) (conn net.Conn, close func() error, describe string, err error)

// mbapsDial is the mbaps transport, installed by session_cgo.go and left nil by
// session_nocgo.go.
var mbapsDial dialer

// openSession dials the DUT, claims the connection, resolves the unit
// identifier, and returns a ready client.
//
// note is what appears against the claim in the attribution report; make it say
// which procedure opened the connection.
func openSession(ctx context.Context, rc *certify.RunCtx, note string) (*session, error) {
	target := rc.Targets.Gateway
	if target == "" {
		return nil, fmt.Errorf("no DUT address configured (-gateway)")
	}
	transport := paramOr(rc, paramTransport, "mbaps")

	var (
		conn     net.Conn
		closeFn  func() error
		describe string
		err      error
	)
	switch transport {
	case "plain":
		var c net.Conn
		c, err = rc.DialTCP(ctx, target, note)
		if err != nil {
			return nil, err
		}
		conn, closeFn, describe = c, c.Close, ""
	case "mbaps":
		if mbapsDial == nil {
			return nil, fmt.Errorf("this binary was built without cgo, so it has no mbaps (TLS) client; " +
				"rebuild with CGO_ENABLED=1 and the wolfSSL sysroot, or run with -param " +
				paramTransport + "=plain against a plain Modbus/TCP DUT")
		}
		role := paramOr(rc, paramRole, defaultRole)
		conn, closeFn, describe, err = mbapsDial(ctx, target, rc.PKI, role)
		if err != nil {
			return nil, fmt.Errorf("mbaps handshake to %s as role %q: %w", target, role, err)
		}
		if cerr := rc.ClaimConn(conn, note); cerr != nil {
			_ = closeFn()
			return nil, cerr
		}
	default:
		return nil, fmt.Errorf("unknown %s=%q (want \"mbaps\" or \"plain\")", paramTransport, transport)
	}

	local, lerr := addrPortOf(conn.LocalAddr())
	remote, rerr := addrPortOf(conn.RemoteAddr())
	if lerr != nil || rerr != nil {
		_ = closeFn()
		return nil, fmt.Errorf("read socket addresses: %v / %v", lerr, rerr)
	}

	s := &session{
		Transport: transport,
		TLS:       describe,
		Local:     local,
		Remote:    remote,
		conn:      conn,
		closeFn:   closeFn,
	}
	s.client = newClient(conn, 1, ioTimeout)

	unit, notes, err := resolveUnit(rc, s.client)
	s.UnitNotes = notes
	if err != nil {
		s.Close()
		return nil, err
	}
	s.client.unit = unit
	return s, nil
}

// resolveUnit honours an operator-supplied unit identifier or probes for one.
func resolveUnit(rc *certify.RunCtx, c *client) (uint8, []string, error) {
	if v, ok := rc.Param(paramUnit); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 247 {
			return 0, nil, fmt.Errorf("-param %s=%q is not a Modbus unit identifier in 1..247", paramUnit, v)
		}
		c.unit = uint8(n)
		regs, rerr := c.readHolding(standardBases[1], 2, fmt.Sprintf("operator-supplied unit %d", n))
		note := fmt.Sprintf("unit %d supplied by -param %s", n, paramUnit)
		if rerr != nil {
			return 0, []string{note + fmt.Sprintf(": %v", rerr)}, fmt.Errorf(
				"the operator-supplied unit %d does not answer a read at %d: %w", n, standardBases[1], rerr)
		}
		if len(regs) != 2 || regs[0] != sunSMarker0 || regs[1] != sunSMarker1 {
			return 0, []string{note + fmt.Sprintf(": read 0x%04x 0x%04x", regs[0], regs[1])}, fmt.Errorf(
				"the operator-supplied unit %d does not carry the SunSpec identifier at %d", n, standardBases[1])
		}
		return uint8(n), []string{note + ": SunSpec identifier present"}, nil
	}
	maxUnit := defaultUnitScanMax
	if v, ok := rc.Param(paramUnitScanMax); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 246 {
			return 0, nil, fmt.Errorf("-param %s=%q is not a unit ceiling in 1..246", paramUnitScanMax, v)
		}
		maxUnit = n
	}
	return probeUnit(c, maxUnit)
}

// addrPortOf converts a net.Addr to a comparable AddrPort with any IPv4-mapped
// IPv6 form unwrapped, which is what the framework's attribution compares.
func addrPortOf(a net.Addr) (netip.AddrPort, error) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("%q is not an ip:port", a.String())
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}
	addr, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%q has no IP", a.String())
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(ta.Port)), nil
}

// paramOr returns an operator parameter or a default.
func paramOr(rc *certify.RunCtx, key, def string) string {
	if v, ok := rc.Param(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

// paramBool reports whether a flag-shaped parameter is set to a true value.
func paramBool(rc *certify.RunCtx, key string) bool {
	switch strings.ToLower(paramOr(rc, key, "")) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// paramSeconds reads a whole-second duration parameter.
func paramSeconds(rc *certify.RunCtx, key string, def int) (int, error) {
	v := paramOr(rc, key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("-param %s=%q is not a positive whole number of seconds", key, v)
	}
	return n, nil
}
