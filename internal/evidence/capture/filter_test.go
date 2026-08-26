package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// ---------------------------------------------------------------------------
// synthetic frames
//
// The dissector is netdis, so these have to be real bytes rather than a stub:
// a filter that agrees with a fake frame proves nothing about the ones dumpcap
// writes.
// ---------------------------------------------------------------------------

func ethHeader(etherType uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(b[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(b[12:14], etherType)
	return b
}

func ipv4Header(proto uint8, src, dst [4]byte, payloadLen int) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(20+payloadLen))
	b[8] = 64
	b[9] = proto
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	return b
}

func tcpHeader(sport, dport uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	b[12] = 5 << 4
	b[13] = 0x10 // ACK
	binary.BigEndian.PutUint16(b[14:16], 65535)
	return b
}

func udpHeader(sport, dport uint16, payloadLen int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+payloadLen))
	return b
}

var (
	addrDUT   = [4]byte{69, 0, 0, 2}
	addrBench = [4]byte{69, 0, 0, 20}
	addrOther = [4]byte{192, 168, 0, 188}
)

// tcpFrame is an Ethernet/IPv4/TCP frame with an empty payload.
func tcpFrame(src, dst [4]byte, sport, dport uint16) []byte {
	tcp := tcpHeader(sport, dport)
	out := ethHeader(0x0800)
	out = append(out, ipv4Header(ipProtoTCP, src, dst, len(tcp))...)
	return append(out, tcp...)
}

// udpFrame is an Ethernet/IPv4/UDP frame with a short payload.
func udpFrame(src, dst [4]byte, sport, dport uint16) []byte {
	payload := []byte("query")
	udp := udpHeader(sport, dport, len(payload))
	out := ethHeader(0x0800)
	out = append(out, ipv4Header(ipProtoUDP, src, dst, len(udp)+len(payload))...)
	out = append(out, udp...)
	return append(out, payload...)
}

// mdnsFrame is the shape that actually turns up on an unfiltered tap.
func mdnsFrame() []byte {
	return udpFrame([4]byte{192, 168, 0, 44}, [4]byte{224, 0, 0, 251}, 5353, 5353)
}

// arpFrame carries no IP at all, which is a decided NO for every port
// primitive and the one thing "arp" matches.
func arpFrame() []byte {
	out := ethHeader(0x0806)
	return append(out, make([]byte, 28)...)
}

// icmpFrame is IP with no ports.
func icmpFrame() []byte {
	body := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	out := ethHeader(0x0800)
	out = append(out, ipv4Header(ipProtoICMP, addrBench, addrDUT, len(body))...)
	return append(out, body...)
}

// truncatedTCPFrame stops inside the TCP header. netdis refuses it, so the
// filter cannot decide it, so it must be KEPT.
func truncatedTCPFrame() []byte {
	full := tcpFrame(addrDUT, addrBench, 802, 51422)
	return full[:len(full)-12]
}

// firstFragmentFrame is the first fragment of a fragmented TCP datagram: the
// ports are in it, but netdis stops at the fragment, so it is undecidable.
func firstFragmentFrame() []byte {
	tcp := tcpHeader(802, 51422)
	ip := ipv4Header(ipProtoTCP, addrDUT, addrBench, len(tcp))
	binary.BigEndian.PutUint16(ip[6:8], 0x2000) // MF set, offset 0
	out := ethHeader(0x0800)
	out = append(out, ip...)
	return append(out, tcp...)
}

// laterFragmentFrame is a non-first fragment: libpcap's port primitives test
// the offset first and never match one, so it is a decided NO.
func laterFragmentFrame() []byte {
	body := make([]byte, 20)
	ip := ipv4Header(ipProtoTCP, addrDUT, addrBench, len(body))
	binary.BigEndian.PutUint16(ip[6:8], 185) // offset 185*8 bytes, MF clear
	out := ethHeader(0x0800)
	out = append(out, ip...)
	return append(out, body...)
}

func framePacket(data []byte) pcapng.Packet {
	return pcapng.Packet{
		Index:    1,
		LinkType: netdis.LinkTypeEthernet,
		OrigLen:  len(data),
		Data:     data,
	}
}

// ---------------------------------------------------------------------------
// the grammar
// ---------------------------------------------------------------------------

// TestParseFilterAcceptsWhatTheBenchUses pins the expressions this repo's run
// drivers actually pass. Every -bpf in runs/ is some number of `tcp port N`
// joined by `or`; the rest are the shapes the task and libpcap's own manual
// make natural to reach for next.
func TestParseFilterAcceptsWhatTheBenchUses(t *testing.T) {
	for _, expr := range []string{
		"tcp port 802",
		"tcp port 802 or tcp port 11113",
		"tcp port 802 or tcp port 11113 or tcp port 11114 or tcp port 8021 or tcp port 5020",
		"tcp and (port 802 or port 11113)",
		"TCP PORT 802",
		"tcp port 802 && not host 192.168.0.188",
		"tcp src port 802",
		"udp dst port 5353",
		"ip host 69.0.0.2",
		"net 69.0.0.0/24",
		"src net 69.0.0.0 mask 255.255.255.0",
		"tcp portrange 800-810",
		"arp",
		"not (tcp or udp)",
		"ip6 host 2001:db8::1",
	} {
		if _, err := ParseFilter(expr); err != nil {
			t.Errorf("ParseFilter(%q) = %v, want it accepted", expr, err)
		}
	}
}

// TestParseFilterRefusesEverythingElse is the load-bearing half: an expression
// this package cannot re-apply must be REFUSED, because the alternative is a
// bundle that silently shipped whatever the kernel filter felt like arming.
func TestParseFilterRefusesEverythingElse(t *testing.T) {
	for _, tc := range []struct {
		expr string
		why  string
	}{
		{"tcp[13] & 2 != 0", "byte-offset expression"},
		{"port https", "service name"},
		{"host gateway.local", "hostname"},
		{"ether host 02:00:00:00:00:01", "link-layer primitive"},
		{"vlan 100", "vlan primitive"},
		{"greater 100", "length test"},
		{"net 10.1.2", "classful shorthand"},
		{"src or dst port 802", "compound direction"},
		{"tcp proto 6", "proto primitive"},
		{"tcp port 802 or", "expression ends after or"},
		{"tcp port", "expression ends after port"},
		{"(tcp port 802", "unclosed parenthesis"},
		{"tcp port 802)", "trailing parenthesis"},
		{"tcp & udp", "stray single ampersand"},
		{"not", "expression is only a negation"},
		{"tcp port 70000", "port out of range"},
		{"tcp portrange 900-800", "inverted range"},
		{"src tcp", "direction with nothing to apply to"},
		{"tcp udp", "two protocol qualifiers"},
		{"src dst port 802", "two direction qualifiers"},
		{"net 10.0.0.0 mask 255.0.255.0", "non-contiguous netmask"},
	} {
		f, err := ParseFilter(tc.expr)
		if err == nil {
			t.Errorf("ParseFilter(%q) = %v, want a refusal (%s)", tc.expr, f, tc.why)
			continue
		}
		if !errors.Is(err, ErrUnsupportedFilter) {
			t.Errorf("ParseFilter(%q) error %v does not wrap ErrUnsupportedFilter", tc.expr, err)
		}
		// The operator's next move is to rewrite the expression, so the
		// refusal has to say what is accepted rather than only what is not.
		if !strings.Contains(err.Error(), "Accepted:") && !strings.Contains(err.Error(), "ends where") {
			t.Errorf("ParseFilter(%q) error %q says neither what is accepted nor where it ran out", tc.expr, err)
		}
	}
}

// TestCompileFilterEmptyIsNotAnError: no filter is a decision, not a failure.
func TestCompileFilterEmptyIsNotAnError(t *testing.T) {
	for _, expr := range []string{"", "   ", "\t\n"} {
		f, err := compileFilter(expr)
		if err != nil {
			t.Fatalf("compileFilter(%q) = %v", expr, err)
		}
		if f != nil {
			t.Fatalf("compileFilter(%q) = %v, want nil (no filter)", expr, f)
		}
		// A nil filter keeps everything, including a frame nothing else would.
		if got := f.eval(framePacket(mdnsFrame())); got != matchYes {
			t.Fatalf("nil filter eval = %v, want %v", got, matchYes)
		}
	}
}

// TestFilterStringIsVerbatim: the bundle records the expression as written.
func TestFilterStringIsVerbatim(t *testing.T) {
	const expr = "tcp  and  ( port 802 or port 11113 )"
	f, err := ParseFilter(expr)
	if err != nil {
		t.Fatal(err)
	}
	if f.String() != expr {
		t.Errorf("String() = %q, want %q", f.String(), expr)
	}
	var nilFilter *Filter
	if nilFilter.String() != "" {
		t.Errorf("(*Filter)(nil).String() = %q, want empty", nilFilter.String())
	}
}

// ---------------------------------------------------------------------------
// the semantics
// ---------------------------------------------------------------------------

// TestFilterMatch is the table the hygiene pass rests on. The third column is
// three-valued on purpose: only a decided NO ever drops a frame.
func TestFilterMatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		expr  string
		frame []byte
		want  match
	}{
		{"tcp port hits dst", "tcp port 802", tcpFrame(addrBench, addrDUT, 51422, 802), matchYes},
		{"tcp port hits src", "tcp port 802", tcpFrame(addrDUT, addrBench, 802, 51422), matchYes},
		{"tcp port misses", "tcp port 802", tcpFrame(addrDUT, addrBench, 443, 51422), matchNo},
		{"tcp port rejects mdns", "tcp port 802", mdnsFrame(), matchNo},
		{"tcp port rejects arp", "tcp port 802", arpFrame(), matchNo},
		{"tcp port rejects icmp", "tcp port 802", icmpFrame(), matchNo},
		{"or reaches the second port", "tcp port 802 or tcp port 11113",
			tcpFrame(addrOther, addrDUT, 11113, 44444), matchYes},
		{"or rejects neither port", "tcp port 802 or tcp port 11113",
			tcpFrame(addrOther, addrDUT, 5353, 44444), matchNo},
		{"grouped form matches like the flat one", "tcp and (port 802 or port 11113)",
			tcpFrame(addrOther, addrDUT, 11113, 44444), matchYes},
		{"grouped form still requires tcp", "tcp and (port 802 or port 11113)",
			udpFrame(addrOther, addrDUT, 11113, 44444), matchNo},
		{"bare port matches udp too", "port 5353", mdnsFrame(), matchYes},
		{"src port is directional", "tcp src port 802", tcpFrame(addrDUT, addrBench, 802, 51422), matchYes},
		{"src port rejects the other direction", "tcp src port 802",
			tcpFrame(addrBench, addrDUT, 51422, 802), matchNo},
		{"dst port is directional", "tcp dst port 802", tcpFrame(addrBench, addrDUT, 51422, 802), matchYes},
		{"host matches either end", "host 69.0.0.2", tcpFrame(addrBench, addrDUT, 51422, 802), matchYes},
		{"host misses", "host 10.9.9.9", tcpFrame(addrBench, addrDUT, 51422, 802), matchNo},
		{"host rejects a frame with no ip", "host 69.0.0.2", arpFrame(), matchNo},
		{"net contains", "net 69.0.0.0/24", tcpFrame(addrBench, addrDUT, 51422, 802), matchYes},
		{"net excludes", "net 10.0.0.0/8", tcpFrame(addrBench, addrDUT, 51422, 802), matchNo},
		{"mask form equals the cidr form", "net 69.0.0.0 mask 255.255.255.0",
			tcpFrame(addrBench, addrDUT, 51422, 802), matchYes},
		{"portrange includes its bounds", "tcp portrange 800-810",
			tcpFrame(addrDUT, addrBench, 810, 51422), matchYes},
		{"portrange excludes just outside", "tcp portrange 800-810",
			tcpFrame(addrDUT, addrBench, 811, 51422), matchNo},
		{"udp primitive", "udp", mdnsFrame(), matchYes},
		{"tcp primitive rejects udp", "tcp", mdnsFrame(), matchNo},
		{"arp primitive", "arp", arpFrame(), matchYes},
		{"ip primitive", "ip", tcpFrame(addrDUT, addrBench, 802, 1), matchYes},
		{"ip primitive rejects arp", "ip", arpFrame(), matchNo},
		{"not inverts", "not tcp port 802", mdnsFrame(), matchYes},
		{"and narrows", "tcp port 802 and host 69.0.0.20",
			tcpFrame(addrBench, addrDUT, 51422, 802), matchYes},
		{"and rejects on the second conjunct", "tcp port 802 and host 10.9.9.9",
			tcpFrame(addrBench, addrDUT, 51422, 802), matchNo},

		// The undecidable shapes. Each of these is KEPT.
		{"a header the dissector rejects is undecided", "tcp port 802", truncatedTCPFrame(), matchUnknown},
		{"a first fragment is undecided", "tcp port 802", firstFragmentFrame(), matchUnknown},
		{"a later fragment is a decided no", "tcp port 802", laterFragmentFrame(), matchNo},
		{"undecided propagates through and", "tcp port 802 and host 69.0.0.2",
			firstFragmentFrame(), matchUnknown},
		{"a decided no still settles an and", "tcp port 802 and host 10.9.9.9",
			firstFragmentFrame(), matchNo},
		{"a decided yes still settles an or", "tcp port 802 or host 69.0.0.2",
			firstFragmentFrame(), matchYes},
		{"not leaves undecided undecided", "not tcp port 802", firstFragmentFrame(), matchUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseFilter(tc.expr)
			if err != nil {
				t.Fatalf("ParseFilter(%q) = %v", tc.expr, err)
			}
			if got := f.eval(framePacket(tc.frame)); got != tc.want {
				t.Errorf("%q against %s = %v, want %v", tc.expr, tc.name, got, tc.want)
			}
		})
	}
}

// TestFilterMatchExported covers the (matched, decided) form callers see.
func TestFilterMatchExported(t *testing.T) {
	f, err := ParseFilter("tcp port 802")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		frame          []byte
		match, decided bool
	}{
		{"match", tcpFrame(addrDUT, addrBench, 802, 1), true, true},
		{"miss", mdnsFrame(), false, true},
		{"undecidable", truncatedTCPFrame(), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, d := f.Match(framePacket(tc.frame))
			if m != tc.match || d != tc.decided {
				t.Errorf("Match = (%t, %t), want (%t, %t)", m, d, tc.match, tc.decided)
			}
		})
	}
}

// TestMatchLogic pins the three-valued connectives themselves, so a future
// edit to them fails here rather than in a bundle.
func TestMatchLogic(t *testing.T) {
	all := []match{matchNo, matchYes, matchUnknown}
	for _, a := range all {
		for _, b := range all {
			// De Morgan holds in Kleene logic and is the cheapest total check.
			if got, want := a.and(b).not(), a.not().or(b.not()); got != want {
				t.Errorf("not(%v and %v) = %v, want %v", a, b, got, want)
			}
			if got, want := a.or(b), b.or(a); got != want {
				t.Errorf("or is not commutative for %v, %v", a, b)
			}
			if got, want := a.and(b), b.and(a); got != want {
				t.Errorf("and is not commutative for %v, %v", a, b)
			}
		}
		if got := a.not().not(); got != a {
			t.Errorf("not(not(%v)) = %v", a, got)
		}
	}
	if got := matchUnknown.and(matchNo); got != matchNo {
		t.Errorf("unknown and no = %v, want no", got)
	}
	if got := matchUnknown.or(matchYes); got != matchYes {
		t.Errorf("unknown or yes = %v, want yes", got)
	}
}

// ---------------------------------------------------------------------------
// the refusal is enforced where it is cheap
// ---------------------------------------------------------------------------

// TestNewRefusesAFilterItCannotReapply: the whole defence rests on this. If a
// filter form nobody has thought about could be accepted here, the hygiene
// pass would be skipped for it at Stop and the bundle would ship whatever the
// kernel filter felt like arming — which is exactly the failure being closed.
func TestNewRefusesAFilterItCannotReapply(t *testing.T) {
	requireTool(t)
	out := filepath.Join(t.TempDir(), "x.pcapng")
	c, err := New("lo", "tcp[13] & 2 != 0", out)
	if err == nil {
		t.Fatalf("New accepted a filter that cannot be re-applied: %v", c.Args())
	}
	if !errors.Is(err, ErrUnsupportedFilter) {
		t.Fatalf("New error %v does not wrap ErrUnsupportedFilter", err)
	}
	// And it says so BEFORE creating anything, so a refused run leaves no
	// half-made evidence directory behind.
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("New created %s despite refusing the filter", out)
	}
}

// TestNewAcceptsTheBenchFilters is the other half: the expressions the run
// drivers pass every day must still work.
func TestNewAcceptsTheBenchFilters(t *testing.T) {
	requireTool(t)
	out := filepath.Join(t.TempDir(), "x.pcapng")
	for _, expr := range []string{
		"",
		"tcp port 802",
		"tcp port 802 or tcp port 11113 or tcp port 11114 or tcp port 8021 or tcp port 5020",
	} {
		if _, err := New("lo", expr, out); err != nil {
			t.Errorf("New(lo, %q) = %v", expr, err)
		}
	}
}

// TestStartRefusesAFilterItCannotReapply covers the struct-literal path New
// does not guard, on the same terms as checkToolInterfaces: the refusal has to
// happen before the tool is executed, not after a run's worth of traffic.
func TestStartRefusesAFilterItCannotReapply(t *testing.T) {
	out := filepath.Join(t.TempDir(), "x.pcapng")
	c := &Capture{
		// A path that cannot be executed, so a test that reaches exec fails
		// loudly rather than capturing something.
		tool:    Tool{Name: "dumpcap", Path: filepath.Join(t.TempDir(), "no-such-dumpcap")},
		ifaces:  []string{"lo"},
		filter:  "port https",
		outPath: out,
	}
	err := c.Start(context.Background())
	if err == nil {
		t.Fatal("Start ran a capture whose filter cannot be re-applied")
	}
	if !errors.Is(err, ErrUnsupportedFilter) {
		t.Fatalf("Start error %v does not wrap ErrUnsupportedFilter", err)
	}
	if c.running {
		t.Error("Start left the capture marked running after refusing it")
	}
}
