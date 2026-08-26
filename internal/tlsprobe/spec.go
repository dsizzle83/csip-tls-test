package tlsprobe

// spec.go is the probe's whole vocabulary: what a caller asks for, what it gets
// back, and the errors that are FACTS ABOUT THE BENCH rather than about the DUT.
//
// Everything here is pure Go. The wolfSSL half lives in session_cgo.go behind
// the `cgo` constraint, so a CGO_ENABLED=0 build of cmd/certify still compiles
// this package and gets ErrUnavailable from Dial.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"
)

// ErrUnavailable is what Dial returns in a build without cgo. It is a fact
// about the BINARY, and a caller must report it as such — a probe that could
// not run says nothing about the device it could not reach.
var ErrUnavailable = errors.New(
	"tlsprobe: this binary was built without cgo, so the wolfSSL client is not linked in and no " +
		"CCM-capable session can be established; rebuild with CGO_ENABLED=1 against the wolfSSL sysroot " +
		"(see internal/tlsprobe's package doc)")

// defaultDeadline bounds one probe end to end: connect, handshake, discovery,
// and the Model 1 read. It is generous because a DUT under a conformance run is
// a busy device, and short because a wedged one must not hang the campaign.
const defaultDeadline = 20 * time.Second

// SunSpecBase is the first of the three base addresses the SunSpec Modbus
// specification permits, and the one the mbaps procedures read Model 1 from.
const SunSpecBase uint16 = 40000

// Spec is one probe: who to dial, as whom, pinned to what.
type Spec struct {
	// Target is the DUT's mbaps listener, host:port.
	Target string

	// CAFiles are the trust anchors the peer is verified against, in load
	// order. At least one is required: a "completed session" against a peer
	// nobody authenticated is not evidence of a mutual-auth handshake, which is
	// the whole subject of SunSpecTCP-6/10.
	CAFiles []string
	// CertFile is this client's certificate chain, leaf first (SunSpecTCP-51),
	// and KeyFile its private key. Both are required: every mbaps server sends
	// a CertificateRequest (SunSpecTCP-11) and a probe with no identity would
	// be measuring TLSF-004's negative instead.
	CertFile, KeyFile string

	// Suite pins the offer to exactly one cipher suite. The zero Suite offers
	// the whole mandated set for the version range.
	Suite Suite
	// MinVersion and MaxVersion bound the offered version range. Zero means
	// "derive from Suite" — a pinned suite fixes its own version — and, with no
	// pinned suite either, TLS 1.2..1.3.
	MinVersion, MaxVersion Version

	// ServerName sets SNI. Empty sends none, which is what the bench's own
	// probes do: the mbaps procedures never require it and PKI-005 (the one row
	// that would) is inapplicable to a single-identity DUT.
	ServerName string

	// KeylogPath appends this session's TLS secrets to an NSS key log so the
	// run's capture decrypts. It does something only in a `-tags keylog` build;
	// in any other build an explicitly-requested key log is an ERROR rather
	// than a silent no-op, because the alternative is an undecryptable capture
	// discovered at analysis time.
	KeylogPath string

	// Unit is the Modbus unit id to read Model 1 from. Zero scans 1..8 for the
	// "SunS" marker, which is what the rest of the bench does rather than
	// hardcoding the gateway's populated slot.
	Unit uint8
	// Base is the SunSpec base address. Zero means SunSpecBase.
	Base uint16

	// Deadline bounds the whole probe. Zero means defaultDeadline.
	Deadline time.Duration

	// OnConnect is called with the RAW TCP connection immediately after connect
	// and BEFORE the TLS handshake. Returning an error aborts the probe with
	// that error and closes the socket.
	//
	// This is the seam that makes a refused handshake citable: the conformance
	// runner attributes capture frames to the check that CLAIMED the connection,
	// and a claim registered after the handshake would miss every frame of a
	// handshake the DUT rejected — which for a negative procedure is all of the
	// evidence there is.
	OnConnect func(net.Conn) error

	// Logf, when set, receives progress lines. Nil discards them.
	Logf func(format string, a ...any)
}

func (s *Spec) log(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	}
}

// validate checks a Spec before any socket is opened, so a mistake in the call
// site fails loudly here rather than as a puzzling handshake failure that reads
// like a finding about the DUT.
func (s Spec) validate() error {
	var problems []string
	if s.Target == "" {
		problems = append(problems, "Target is empty")
	}
	if len(s.CAFiles) == 0 {
		problems = append(problems, "CAFiles is empty: a session against an unauthenticated peer is not "+
			"evidence of the mutual authentication SunSpecTCP-6/10 require")
	}
	for _, f := range s.CAFiles {
		if err := readable(f); err != nil {
			problems = append(problems, "CA file "+err.Error())
		}
	}
	switch {
	case s.CertFile == "" || s.KeyFile == "":
		problems = append(problems, "CertFile and KeyFile are both required: an mbaps server sends a "+
			"CertificateRequest (SunSpecTCP-11), and a probe with no identity measures TLSF-004's negative "+
			"instead of the suite it was pinned to")
	default:
		for _, f := range []string{s.CertFile, s.KeyFile} {
			if err := readable(f); err != nil {
				problems = append(problems, "client identity "+err.Error())
			}
		}
	}
	minV, maxV, err := s.versionRange()
	if err != nil {
		problems = append(problems, err.Error())
	} else if s.Suite.Pinned() && (s.Suite.Version < minV || s.Suite.Version > maxV) {
		problems = append(problems, fmt.Sprintf(
			"suite %s is a %s suite but the version range is %s..%s, so it could never be negotiated",
			s.Suite, s.Suite.Version, minV, maxV))
	}
	if len(problems) > 0 {
		return fmt.Errorf("tlsprobe: unusable probe specification:\n  - %s", joinLines(problems))
	}
	return nil
}

// versionRange resolves the offered version window. A pinned suite fixes it: a
// TLS 1.3 suite offered inside a 1.2..1.3 range would let the DUT answer at 1.2
// with something else entirely, and the procedure step ("offering only
// TLS_AES_128_CCM_SHA256") would not have been carried out.
func (s Spec) versionRange() (Version, Version, error) {
	minV, maxV := s.MinVersion, s.MaxVersion
	if minV == 0 && maxV == 0 && s.Suite.Pinned() {
		return s.Suite.Version, s.Suite.Version, nil
	}
	if minV == 0 {
		minV = TLS12
	}
	if maxV == 0 {
		maxV = TLS13
	}
	for _, v := range []Version{minV, maxV} {
		if v != TLS12 && v != TLS13 {
			return 0, 0, fmt.Errorf("version %s is not TLS 1.2 or TLS 1.3 (the mbaps floor is TLS 1.2, "+
				"SunSpecTCP-4)", v)
		}
	}
	if maxV < minV {
		return 0, 0, fmt.Errorf("MaxVersion %s is below MinVersion %s", maxV, minV)
	}
	return minV, maxV, nil
}

// offer resolves the cipher list to put in the ClientHello.
func (s Spec) offer() (string, []Suite) {
	if s.Suite.Pinned() {
		return s.Suite.Wolf, []Suite{s.Suite}
	}
	minV, maxV, _ := s.versionRange()
	var suites []Suite
	// TLS 1.3 first: wolfSSL 5.7.6 negotiates TLS 1.3 on a mixed list only when
	// a 1.3 suite leads it.
	if maxV >= TLS13 {
		suites = append(suites, Mandatory13...)
	}
	if minV <= TLS12 {
		suites = append(suites, Mandatory12...)
	}
	return wolfList(suites), suites
}

func (s Spec) deadline() time.Duration {
	if s.Deadline > 0 {
		return s.Deadline
	}
	return defaultDeadline
}

func (s Spec) base() uint16 {
	if s.Base != 0 {
		return s.Base
	}
	return SunSpecBase
}

// Negotiated is what the handshake actually settled on.
type Negotiated struct {
	// Version is the negotiated protocol version.
	Version Version
	// VersionName is wolfSSL's own spelling of it ("TLSv1.2"), kept beside the
	// code so a report quotes the stack rather than this package's mapping.
	VersionName string
	// SuiteName is wolfSSL's name for the negotiated suite.
	SuiteName string
	// Suite is the mandated suite it corresponds to, when it is one; the zero
	// Suite when the DUT negotiated something outside the mandated set, which
	// is itself a finding.
	Suite Suite
	// Resumed reports whether this handshake resumed a cached session. A probe
	// that resumed did not exercise the full handshake it was asked to.
	Resumed bool
}

// String renders the negotiated parameters for a report line.
func (n Negotiated) String() string {
	s := n.SuiteName
	if n.Suite.Pinned() {
		s = fmt.Sprintf("0x%04X %s", n.Suite.Code, n.SuiteName)
	}
	out := fmt.Sprintf("%s, %s", n.VersionName, s)
	if n.Resumed {
		out += " (RESUMED)"
	}
	return out
}

// Report is everything one completed probe establishes.
type Report struct {
	// Target is what was dialled, and Local/Remote the socket's own addresses —
	// captured at dial time, because after Close they are gone and the citation
	// phase could not find the stream.
	Target        string
	Local, Remote netip.AddrPort

	// Requested is the suite the probe was pinned to, or the zero Suite.
	Requested Suite
	// Negotiated is what the handshake settled on.
	Negotiated Negotiated

	// PeerLeafDER is the peer's LEAF certificate in DER, exactly as wolfSSL
	// recovered it. Raw DER rather than a parsed certificate because the
	// caller's own analysis is the referee, not this package's.
	//
	// It is the leaf only, deliberately. wolfSSL's retained peer chain is
	// reachable one certificate at a time and the whole-chain question —
	// SunSpecTCP-51's "send the entire chain down to the root CA" — is a
	// CAPTURE fact, asserted by PKI-004 from the Certificate message on the
	// wire. A second, weaker answer from the library here would invite a check
	// to assert chain delivery from something other than the bytes that
	// crossed.
	PeerLeafDER []byte

	// KeylogPath is where this session's secrets were exported, or "".
	KeylogPath string
	// KeylogNote says why KeylogPath is empty when a key log was asked for. A
	// probe whose session will not decrypt must say so where the caller reads
	// it, not leave a silent gap that only surfaces at analysis time.
	KeylogNote string

	// Model1 is the SunSpec Common Model read carried inside the tunnel. Its
	// zero value means no read was attempted (Handshake rather than Complete).
	Model1 ModelRead

	// Elapsed is how long the whole probe took.
	Elapsed time.Duration
}

// Summary is the one-line description an assertion's Observed field wants.
func (r *Report) Summary() string {
	if r == nil {
		return "(no probe report)"
	}
	peer := "the peer presented NO certificate"
	if len(r.PeerLeafDER) > 0 {
		peer = fmt.Sprintf("peer leaf %d byte(s) of DER", len(r.PeerLeafDER))
	}
	out := fmt.Sprintf("session established to %s: %s; %s", r.Target, r.Negotiated, peer)
	if r.Model1.Attempted {
		out += "; " + r.Model1.Summary()
	}
	if r.KeylogPath != "" {
		out += "; TLS secrets exported for capture decryption"
	}
	return out
}

func readable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s is not readable: %v", path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}

func joinLines(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n  - "
		}
		out += s
	}
	return out
}
