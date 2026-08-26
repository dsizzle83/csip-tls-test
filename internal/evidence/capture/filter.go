package capture

// filter.go compiles the capture filter the operator asked for into a predicate
// this package can run over frames it has already captured.
//
// # Why a second implementation of something the kernel already does
//
// The kernel filter is not reliably armed. dumpcap given more than one -i can
// leave the BPF program off the FIRST-listed interface for the whole capture
// while arming it correctly on the rest: reproduced on this bench with plain
// `dumpcap -i lo -i lo -f 'tcp port N'` (2446 unfiltered frames on tap 1, 0 on
// tap 2) and 4 times out of 4 with two real NICs. Both signals Start waits on
// are genuinely true when it happens, so no amount of waiting fixes it, and
// nothing in the tool's output says it happened. The result is an evidence
// bundle carrying mDNS, HTTP and whatever else was on that NIC — traffic the
// package doc's Promiscuous:false rationale exists to keep OUT, and traffic a
// lab would have to redact before the bundle could be handed over.
//
// So the filter is applied a second time, in this process, to the frames the
// tool actually wrote (see refilter.go). That needs the filter as a predicate,
// which is what this file builds.
//
// # Why not libpcap
//
// pcap_compile plus a BPF interpreter would be the exact same program the
// kernel runs, which is the strongest possible answer — and it needs cgo and
// libpcap headers, which the whole evidence engine is built to avoid (see the
// package doc). A pure-Go BPF assembler over the full libpcap grammar is a
// large thing to get subtly wrong. What is here instead is a small, explicit
// subset with the semantics written down, and a REFUSAL for everything else:
// an expression this file cannot compile is refused by New and by Start, so a
// filter form nobody has thought about cannot quietly turn the hygiene pass
// off. Widening the subset is a deliberate edit to this file, with a test.
//
// # The supported grammar
//
//	expr      := orExpr
//	orExpr    := andExpr { ("or" | "||") andExpr }
//	andExpr   := unary { ("and" | "&&") unary }
//	unary     := ["not" | "!"] primary
//	primary   := "(" expr ")" | primitive
//	primitive := [proto] [dir] "host" <ip-literal>
//	           | [proto] [dir] "net" <ip-literal>"/"<bits>
//	           | [proto] [dir] "net" <ip-literal> "mask" <ip-literal>
//	           | [proto] [dir] "port" <0..65535>
//	           | [proto] [dir] "portrange" <0..65535>"-"<0..65535>
//	           | proto
//	proto     := "ip" | "ip6" | "tcp" | "udp" | "icmp" | "icmp6" | "arp"
//	dir       := "src" | "dst"
//
// Everything the bench has ever passed is inside it: every -bpf in this repo's
// run drivers is some number of `tcp port N` joined by `or`.
//
// Refused on purpose, rather than approximated:
//
//   - hostnames and service names ("host gateway", "port https"), because they
//     resolve through /etc/hosts, DNS and /etc/services — a filter whose
//     meaning depends on the resolver of the day is not re-appliable evidence;
//   - byte-offset expressions ("tcp[13] & 2 != 0"), link-layer primitives
//     ("ether host", "vlan", "broadcast"), and length tests ("greater 100"),
//     because each is a separate dissection question;
//   - "src or dst" / "src and dst" compound directions, and libpcap's classful
//     shorthand ("net 10.1.2"), because both read as something they are not.
//
// # Where this deliberately differs from libpcap, and in which direction
//
// The rule this file obeys is that a frame is dropped ONLY when it provably
// does not match. Anything undecidable is KEPT and counted (refilter.go
// reports it as "undecided"), so the hygiene pass can add redaction but can
// never destroy evidence. The undecidable cases are:
//
//   - a frame the dissector rejects (a truncated or malformed header);
//   - the FIRST fragment of a fragmented TCP/UDP datagram, whose ports
//     libpcap's port primitives do read and netdis does not (it stops at the
//     fragment); later fragments are a decided NO, exactly as in libpcap;
//   - SCTP under a bare "port", which libpcap matches and this package does
//     not dissect. Under "tcp port"/"udp port" the proto conjunct decides it.
//
// In the other direction — keeping a frame libpcap would have dropped — there
// is one known case: netdis follows IPv6 extension headers to the real
// transport header and libpcap's port primitives do not, so "tcp port N" here
// matches a TCP segment behind a hop-by-hop header. That is the safe direction
// and the bench emits no such traffic.

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
)

// ErrUnsupportedFilter reports a capture filter this package cannot re-apply
// after the capture. It is returned by New and by Start rather than at Stop, so
// the refusal costs an operator a re-run of a command and never a run's worth
// of traffic.
var ErrUnsupportedFilter = errors.New("capture: filter is outside the subset this tool can re-apply after the capture")

// IP protocol numbers this file names. netdis keeps its own unexported copies;
// these are the ones the filter grammar can talk about.
const (
	ipProtoICMP  = 1
	ipProtoTCP   = 6
	ipProtoUDP   = 17
	ipProtoICMP6 = 58
	ipProtoSCTP  = 132
)

// etherTypeARP is the one non-IP ethertype the grammar can name.
const etherTypeARP = 0x0806

// Filter is a compiled capture filter: the expression as written, and a
// predicate over dissected frames that means the same thing.
type Filter struct {
	expr string
	root node
}

// String returns the expression the filter was compiled from, verbatim. It is
// what the bundle records, so it must not be a re-rendering of the parse tree.
func (f *Filter) String() string {
	if f == nil {
		return ""
	}
	return f.expr
}

// ParseFilter compiles a capture-filter expression.
//
// It returns an error wrapping ErrUnsupportedFilter for any expression outside
// the subset documented at the top of this file, naming the token that stopped
// it. An empty expression is an error too: "no filter" is a decision callers
// make by not calling here (see compileFilter).
func ParseFilter(expr string) (*Filter, error) {
	toks, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("capture: %q is not a filter expression: it is empty", expr)
	}
	p := &parser{expr: expr, toks: toks}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if tok, ok := p.peek(); ok {
		return nil, p.unsupported(tok, "trailing input")
	}
	return &Filter{expr: expr, root: root}, nil
}

// compileFilter is the form the rest of the package uses: an empty or
// whitespace-only expression is "no filter", which is not an error and yields a
// nil *Filter.
func compileFilter(expr string) (*Filter, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, nil
	}
	return ParseFilter(expr)
}

// match is the three-valued result of testing one frame: it matches, it does
// not, or this package cannot tell. See the direction rule in the file doc —
// only a decided NO ever drops a frame.
type match uint8

const (
	matchNo match = iota
	matchYes
	matchUnknown
)

func (m match) String() string {
	switch m {
	case matchYes:
		return "yes"
	case matchNo:
		return "no"
	default:
		return "undecided"
	}
}

// and, or and not are Kleene's strong three-valued connectives: unknown
// propagates unless the other operand already settles the answer.
func (m match) and(o match) match {
	switch {
	case m == matchNo || o == matchNo:
		return matchNo
	case m == matchUnknown || o == matchUnknown:
		return matchUnknown
	}
	return matchYes
}

func (m match) or(o match) match {
	switch {
	case m == matchYes || o == matchYes:
		return matchYes
	case m == matchUnknown || o == matchUnknown:
		return matchUnknown
	}
	return matchNo
}

func (m match) not() match {
	switch m {
	case matchYes:
		return matchNo
	case matchNo:
		return matchYes
	}
	return matchUnknown
}

func boolMatch(b bool) match {
	if b {
		return matchYes
	}
	return matchNo
}

// Match reports whether one captured frame satisfies the filter, and whether
// this package could decide the question at all. A frame it cannot decide is
// kept: see the file doc.
func (f *Filter) Match(p pcapng.Packet) (matched, decided bool) {
	m := f.eval(p)
	return m == matchYes, m != matchUnknown
}

func (f *Filter) eval(p pcapng.Packet) match {
	if f == nil || f.root == nil {
		return matchYes // no filter: everything the tool wrote was asked for
	}
	fr, err := netdis.DecodePacket(p)
	if err != nil {
		// Bytes the dissector rejects cannot be shown NOT to match.
		return matchUnknown
	}
	return f.root.eval(fr)
}

// node is one predicate in the compiled tree.
type node interface {
	eval(*netdis.Frame) match
}

type andNode struct{ l, r node }

func (n andNode) eval(f *netdis.Frame) match { return n.l.eval(f).and(n.r.eval(f)) }

type orNode struct{ l, r node }

func (n orNode) eval(f *netdis.Frame) match { return n.l.eval(f).or(n.r.eval(f)) }

type notNode struct{ n node }

func (n notNode) eval(f *netdis.Frame) match { return n.n.eval(f).not() }

// protoKind is a network- or transport-protocol qualifier.
type protoKind uint8

const (
	protoAny protoKind = iota
	protoIP
	protoIP6
	protoTCP
	protoUDP
	protoICMP
	protoICMP6
	protoARP
)

var protoWords = map[string]protoKind{
	"ip":    protoIP,
	"ip6":   protoIP6,
	"tcp":   protoTCP,
	"udp":   protoUDP,
	"icmp":  protoICMP,
	"icmp6": protoICMP6,
	"arp":   protoARP,
}

type protoNode struct{ kind protoKind }

func (n protoNode) eval(f *netdis.Frame) match {
	switch n.kind {
	case protoIP:
		return boolMatch(f.Net == netdis.NetIPv4)
	case protoIP6:
		return boolMatch(f.Net == netdis.NetIPv6)
	case protoTCP:
		return boolMatch(f.Net != netdis.NetNone && f.IPProto == ipProtoTCP)
	case protoUDP:
		return boolMatch(f.Net != netdis.NetNone && f.IPProto == ipProtoUDP)
	case protoICMP:
		return boolMatch(f.Net == netdis.NetIPv4 && f.IPProto == ipProtoICMP)
	case protoICMP6:
		return boolMatch(f.Net == netdis.NetIPv6 && f.IPProto == ipProtoICMP6)
	case protoARP:
		return boolMatch(f.Net == netdis.NetNone && f.EtherType == etherTypeARP)
	}
	return matchYes
}

// dirKind is a direction qualifier. The default is libpcap's: either end.
type dirKind uint8

const (
	dirEither dirKind = iota
	dirSrc
	dirDst
)

// portNode is "[src|dst] port N" or "[src|dst] portrange A-B". A proto
// qualifier in front of it compiles to a separate protoNode conjunct, so this
// node only ever answers the port question.
type portNode struct {
	dir    dirKind
	lo, hi uint16
}

func (n portNode) contains(p uint16) bool { return p >= n.lo && p <= n.hi }

func (n portNode) eval(f *netdis.Frame) match {
	var src, dst uint16
	switch {
	case f.TCP != nil:
		src, dst = f.TCP.SrcPort, f.TCP.DstPort
	case f.UDP != nil:
		src, dst = f.UDP.SrcPort, f.UDP.DstPort
	default:
		return n.evalNoPorts(f)
	}
	switch n.dir {
	case dirSrc:
		return boolMatch(n.contains(src))
	case dirDst:
		return boolMatch(n.contains(dst))
	}
	return boolMatch(n.contains(src) || n.contains(dst))
}

// evalNoPorts answers for a frame whose transport header the dissector did not
// produce. Most such frames are a decided NO — there are no ports to compare —
// but two shapes hold ports this package cannot read, and those are undecided
// rather than dropped.
func (n portNode) evalNoPorts(f *netdis.Frame) match {
	if f.Net == netdis.NetNone {
		return matchNo // ARP, LLC, an ethertype that leads nowhere
	}
	if f.Fragmented && f.FragOffset > 0 {
		// libpcap's port primitives test the fragment offset first: a later
		// fragment carries no transport header and never matches.
		return matchNo
	}
	switch f.IPProto {
	case ipProtoTCP, ipProtoUDP, ipProtoSCTP:
		// A first fragment (ports present in the datagram, not readable here),
		// an SCTP association this package does not dissect, or a header the
		// capture truncated. libpcap would answer; this cannot, so the frame
		// is kept and counted as undecided.
		return matchUnknown
	}
	return matchNo // ICMP, ESP, AH, OSPF, … carry no ports at all
}

// hostNode is "[src|dst] host <ip>".
type hostNode struct {
	dir  dirKind
	addr netip.Addr
}

func (n hostNode) eval(f *netdis.Frame) match {
	if f.Net == netdis.NetNone {
		return matchNo
	}
	switch n.dir {
	case dirSrc:
		return boolMatch(f.Src == n.addr)
	case dirDst:
		return boolMatch(f.Dst == n.addr)
	}
	return boolMatch(f.Src == n.addr || f.Dst == n.addr)
}

// netNode is "[src|dst] net <prefix>".
type netNode struct {
	dir    dirKind
	prefix netip.Prefix
}

func (n netNode) eval(f *netdis.Frame) match {
	if f.Net == netdis.NetNone {
		return matchNo
	}
	switch n.dir {
	case dirSrc:
		return boolMatch(n.prefix.Contains(f.Src))
	case dirDst:
		return boolMatch(n.prefix.Contains(f.Dst))
	}
	return boolMatch(n.prefix.Contains(f.Src) || n.prefix.Contains(f.Dst))
}

// token is one lexed word and where it started, so an error can point at it.
type token struct {
	text string
	pos  int
}

// tokenize splits an expression into words, treating parentheses and the
// operator punctuation as words of their own. Everything else runs to the next
// separator, which keeps "10.0.0.0/8" and "1024-2048" single tokens.
func tokenize(expr string) ([]token, error) {
	var toks []token
	for i := 0; i < len(expr); {
		c := expr[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == '!':
			toks = append(toks, token{text: string(c), pos: i})
			i++
		case c == '&' || c == '|':
			if i+1 >= len(expr) || expr[i+1] != c {
				return nil, fmt.Errorf("capture: %q: stray %q at offset %d. %s: %w",
					expr, string(c), i, filterHelp, ErrUnsupportedFilter)
			}
			toks = append(toks, token{text: expr[i : i+2], pos: i})
			i += 2
		default:
			j := i
			for j < len(expr) && !isSeparator(expr[j]) {
				j++
			}
			toks = append(toks, token{text: expr[i:j], pos: i})
			i = j
		}
	}
	return toks, nil
}

func isSeparator(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '(', ')', '!', '&', '|':
		return true
	}
	return false
}

// parser is a recursive-descent reader over the token list.
type parser struct {
	expr string
	toks []token
	i    int
}

func (p *parser) peek() (token, bool) {
	if p.i >= len(p.toks) {
		return token{}, false
	}
	return p.toks[p.i], true
}

func (p *parser) next() token {
	t := p.toks[p.i]
	p.i++
	return t
}

// acceptWord consumes the next token when it is one of want, compared
// case-insensitively (libpcap's lexer is case-insensitive for keywords).
func (p *parser) acceptWord(want ...string) bool {
	t, ok := p.peek()
	if !ok {
		return false
	}
	low := strings.ToLower(t.text)
	for _, w := range want {
		if low == w {
			p.i++
			return true
		}
	}
	return false
}

// filterHelp is the second half of every refusal: why the filter is being
// re-read at all, and what an operator can write instead. It is one string
// because the operator's next move is to rewrite the expression, and they
// should not have to read this file — or find the one error message that
// happens to carry the list — to do it.
const filterHelp = "This tool re-applies the capture filter to the captured frames before the " +
	"bundle is written, because the capture tool's kernel filter is not reliably armed on every " +
	"interface, and it refuses a filter it cannot re-apply rather than shipping unfiltered " +
	"evidence. Accepted: and/or/not, parentheses, the protocols ip ip6 tcp udp icmp icmp6 arp, " +
	"and [src|dst] host <ip> / net <ip>/<bits> / port <n> / portrange <a>-<b>, with numeric " +
	"ports and literal addresses only"

// unsupported builds the refusal, naming the offending token and its offset.
func (p *parser) unsupported(t token, why string) error {
	return fmt.Errorf("capture: %q: %s at offset %d (%q). %s: %w",
		p.expr, why, t.pos, t.text, filterHelp, ErrUnsupportedFilter)
}

func (p *parser) unexpectedEnd(what string) error {
	return fmt.Errorf("capture: %q: expression ends where %s was expected. %s: %w",
		p.expr, what, filterHelp, ErrUnsupportedFilter)
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.acceptWord("or", "||") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{l: left, r: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.acceptWord("and", "&&") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andNode{l: left, r: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	if p.acceptWord("not", "!") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{n: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	if p.acceptWord("(") {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.acceptWord(")") {
			return nil, p.unexpectedEnd("a closing parenthesis")
		}
		return inner, nil
	}
	return p.parsePrimitive()
}

// parsePrimitive reads libpcap's qualifier stack: an optional protocol, an
// optional direction, then the primitive's kind and its value. A protocol on
// its own is a primitive too ("tcp"), which is what makes "tcp and (port A or
// port B)" mean the same thing here as it does to libpcap.
func (p *parser) parsePrimitive() (node, error) {
	var (
		proto    protoKind
		dir      dirKind
		sawProto bool
		sawDir   bool
		dirTok   token
	)
	for {
		t, ok := p.peek()
		if !ok {
			break
		}
		low := strings.ToLower(t.text)
		if kind, isProto := protoWords[low]; isProto {
			if sawProto {
				return nil, p.unsupported(t, "a second protocol qualifier")
			}
			if sawDir {
				return nil, p.unsupported(t, "a protocol qualifier after a direction")
			}
			proto, sawProto = kind, true
			p.next()
			continue
		}
		if low == "src" || low == "dst" {
			if sawDir {
				return nil, p.unsupported(t, "a second direction qualifier")
			}
			dir, sawDir, dirTok = dirSrc, true, t
			if low == "dst" {
				dir = dirDst
			}
			p.next()
			continue
		}
		break
	}

	kindTok, haveKind := p.peek()
	kind := ""
	if haveKind {
		kind = strings.ToLower(kindTok.text)
	}

	var prim node
	switch kind {
	case "host":
		p.next()
		h, err := p.parseHost(dir)
		if err != nil {
			return nil, err
		}
		prim = h
	case "net":
		p.next()
		n, err := p.parseNet(dir)
		if err != nil {
			return nil, err
		}
		prim = n
	case "port", "portrange":
		p.next()
		n, err := p.parsePort(dir, kind == "portrange")
		if err != nil {
			return nil, err
		}
		prim = n
	default:
		// No kind keyword follows, so the primitive has to be the protocol word
		// on its own.
		switch {
		case sawDir:
			// "src tcp", "dst" alone: not a primitive in libpcap either.
			return nil, p.unsupported(dirTok, "a direction qualifier with no host, net or port to apply to")
		case sawProto:
			return protoNode{kind: proto}, nil
		case !haveKind:
			return nil, p.unexpectedEnd("a primitive")
		}
		return nil, p.unsupported(kindTok, "an unsupported primitive")
	}

	if !sawProto {
		return prim, nil
	}
	return andNode{l: protoNode{kind: proto}, r: prim}, nil
}

func (p *parser) parseHost(dir dirKind) (node, error) {
	t, ok := p.peek()
	if !ok {
		return nil, p.unexpectedEnd("an IP address after \"host\"")
	}
	addr, err := netip.ParseAddr(t.text)
	if err != nil {
		return nil, p.unsupported(t, "a host that is not a literal IP address (names are not re-appliable)")
	}
	p.next()
	return hostNode{dir: dir, addr: addr.Unmap()}, nil
}

func (p *parser) parseNet(dir dirKind) (node, error) {
	t, ok := p.peek()
	if !ok {
		return nil, p.unexpectedEnd("a network after \"net\"")
	}
	if strings.Contains(t.text, "/") {
		pfx, err := netip.ParsePrefix(t.text)
		if err != nil {
			return nil, p.unsupported(t, "a network that is not a valid CIDR prefix")
		}
		p.next()
		return netNode{dir: dir, prefix: pfx.Masked()}, nil
	}
	base, err := netip.ParseAddr(t.text)
	if err != nil {
		return nil, p.unsupported(t, "a network that is neither a CIDR prefix nor a literal address")
	}
	p.next()
	if !p.acceptWord("mask") {
		// libpcap would read a bare "net 10.1.2" as a classful /24. Guessing a
		// prefix length from an address is exactly the kind of silent
		// re-interpretation this file exists to avoid.
		return nil, p.unsupported(t, "a network with no prefix length (write it as a CIDR prefix, or add \"mask\")")
	}
	mt, ok := p.peek()
	if !ok {
		return nil, p.unexpectedEnd("a netmask after \"mask\"")
	}
	maskAddr, err := netip.ParseAddr(mt.text)
	if err != nil {
		return nil, p.unsupported(mt, "a netmask that is not a literal address")
	}
	bits, ok := contiguousMaskBits(maskAddr)
	if !ok {
		return nil, p.unsupported(mt, "a netmask that is not a contiguous run of leading 1 bits")
	}
	p.next()
	pfx := netip.PrefixFrom(base, bits)
	if !pfx.IsValid() {
		return nil, p.unsupported(mt, "a netmask whose width does not match the address family")
	}
	return netNode{dir: dir, prefix: pfx.Masked()}, nil
}

// contiguousMaskBits converts a dotted netmask into a prefix length, refusing
// the non-contiguous masks libpcap accepts and nobody means.
func contiguousMaskBits(mask netip.Addr) (int, bool) {
	b := mask.AsSlice()
	bits := 0
	for i, by := range b {
		if by == 0xFF {
			bits += 8
			continue
		}
		for by&0x80 != 0 {
			bits++
			by <<= 1
		}
		if by != 0 {
			return 0, false
		}
		for _, rest := range b[i+1:] {
			if rest != 0 {
				return 0, false
			}
		}
		break
	}
	return bits, true
}

func (p *parser) parsePort(dir dirKind, isRange bool) (node, error) {
	t, ok := p.peek()
	if !ok {
		return nil, p.unexpectedEnd("a port number")
	}
	if isRange {
		lo, hi, found := strings.Cut(t.text, "-")
		if !found {
			return nil, p.unsupported(t, "a port range that is not <a>-<b>")
		}
		lop, err := parsePortNumber(lo)
		if err != nil {
			return nil, p.unsupported(t, "a port range whose lower bound is not a number in 0..65535")
		}
		hip, err := parsePortNumber(hi)
		if err != nil {
			return nil, p.unsupported(t, "a port range whose upper bound is not a number in 0..65535")
		}
		if lop > hip {
			return nil, p.unsupported(t, "a port range whose bounds are inverted")
		}
		p.next()
		return portNode{dir: dir, lo: lop, hi: hip}, nil
	}
	n, err := parsePortNumber(t.text)
	if err != nil {
		return nil, p.unsupported(t, "a port that is not a number in 0..65535 (service names are not re-appliable)")
	}
	p.next()
	return portNode{dir: dir, lo: n, hi: n}, nil
}

func parsePortNumber(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
