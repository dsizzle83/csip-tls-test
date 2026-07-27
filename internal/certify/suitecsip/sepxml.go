package suitecsip

// sepxml.go is this suite's own reader for IEEE 2030.5 (sep+xml) payloads.
//
// # Why not unmarshal into the shared model
//
// lexa-proto/csipmodel is legitimately shared with the product — the wire
// format is the wire format — but unmarshalling is not reading. A struct with
// `xml:"lFDI"` tags silently yields a zero value for an element that is missing,
// misspelled, or in the wrong namespace, and a conformance criterion that says
// "the payload SHALL contain lFDI" cannot be evaluated by a decoder whose
// answer for "absent" and "present but empty" is the same string. Worse, a
// model shared with the DUT's own parser would let a mutual misreading of the
// standard pass both sides (this repository's PN-1 / AD-003(f) referee rule).
//
// So this file keeps the tree: element names WITH their namespace, attributes,
// text, children, in document order. Every question a check asks — is the
// element there, how many are there, what is its text, what is its href — is
// answered against what the bytes actually said.
//
// # The namespace trap
//
// Every 2030.5 root element must carry xmlns="urn:ieee:std:2030.5:ns". A
// payload that omits it is non-conformant, and a reader that ignores namespaces
// would report it as perfectly fine. ParseSEP therefore returns the root's
// namespace and lets the caller assert on it, rather than quietly accepting
// either.

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Namespace is the IEEE 2030.5 XML namespace every conformant payload's root
// element declares.
const Namespace = "urn:ieee:std:2030.5:ns"

// Node is one element of a parsed sep+xml document.
type Node struct {
	// Name carries the local name AND the namespace URI, so a check can tell
	// <lFDI> in the 2030.5 namespace from <lFDI> in no namespace at all.
	Name xml.Name
	// Attrs are the element's attributes in document order.
	Attrs []xml.Attr
	// Text is the element's own character data with surrounding space trimmed.
	Text string
	// Kids are the child elements in document order.
	Kids []*Node
}

// ParseSEP parses a sep+xml payload into a tree. A body that is not
// well-formed XML is an error; a body whose root is in the wrong namespace is
// NOT — that is a conformance observation the caller must be able to make, so
// the namespace is reported on the root node rather than rejected here.
func ParseSEP(body []byte) (*Node, error) {
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	var stack []*Node
	var root *Node
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return root, fmt.Errorf("suitecsip: sep+xml is not well formed: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &Node{Name: t.Name, Attrs: append([]xml.Attr(nil), t.Attr...)}
			if len(stack) == 0 {
				if root != nil {
					return root, fmt.Errorf("suitecsip: sep+xml has a second root element %q", t.Name.Local)
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.Kids = append(p.Kids, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				n.Text += string(t)
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("suitecsip: sep+xml payload has no elements (%d bytes)", len(body))
	}
	trimText(root)
	return root, nil
}

func trimText(n *Node) {
	n.Text = strings.TrimSpace(n.Text)
	for _, k := range n.Kids {
		trimText(k)
	}
}

// InNamespace reports whether the node is in the 2030.5 namespace.
func (n *Node) InNamespace() bool { return n != nil && n.Name.Space == Namespace }

// Local is the element's local name, or "" for a nil node so a check can chain
// lookups without nil-guarding every step.
func (n *Node) Local() string {
	if n == nil {
		return ""
	}
	return n.Name.Local
}

// Child returns the first direct child with the given local name, or nil.
func (n *Node) Child(name string) *Node {
	if n == nil {
		return nil
	}
	for _, k := range n.Kids {
		if k.Name.Local == name {
			return k
		}
	}
	return nil
}

// Children returns every direct child with the given local name.
func (n *Node) Children(name string) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, k := range n.Kids {
		if k.Name.Local == name {
			out = append(out, k)
		}
	}
	return out
}

// Path walks a chain of local names from this node.
func (n *Node) Path(names ...string) *Node {
	cur := n
	for _, name := range names {
		cur = cur.Child(name)
		if cur == nil {
			return nil
		}
	}
	return cur
}

// Descendants returns every element anywhere below (and including) this node
// with the given local name, in document order. Lists in 2030.5 nest their
// entries directly, but link elements can appear at several depths, and a
// criterion phrased "the payload contains a DERProgramListLink" is about the
// payload, not about one level of it.
func (n *Node) Descendants(name string) []*Node {
	var out []*Node
	var walk func(*Node)
	walk = func(cur *Node) {
		if cur == nil {
			return
		}
		if cur.Name.Local == name {
			out = append(out, cur)
		}
		for _, k := range cur.Kids {
			walk(k)
		}
	}
	walk(n)
	return out
}

// Has reports whether at least one descendant with that local name exists.
func (n *Node) Has(name string) bool { return len(n.Descendants(name)) > 0 }

// Attr returns an attribute's value by local name and whether it was present.
func (n *Node) Attr(name string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// Href is the shorthand for the link attribute every 2030.5 resource and link
// carries.
func (n *Node) Href() string {
	v, _ := n.Attr("href")
	return v
}

// TextOf returns the trimmed text of the first descendant with that local name.
func (n *Node) TextOf(name string) (string, bool) {
	ds := n.Descendants(name)
	if len(ds) == 0 {
		return "", false
	}
	return ds[0].Text, true
}

// IntOf returns the first descendant's text parsed as a signed decimal.
func (n *Node) IntOf(name string) (int64, bool) {
	s, ok := n.TextOf(name)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// UintOf returns the first descendant's text parsed as an unsigned decimal.
func (n *Node) UintOf(name string) (uint64, bool) {
	s, ok := n.TextOf(name)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// Summary renders a one-line description of a payload for an assertion's
// Observed field: the root element, its list counts if it is a list, and the
// number of entries actually served.
func (n *Node) Summary() string {
	if n == nil {
		return "(no payload)"
	}
	var b strings.Builder
	b.WriteString("<" + n.Name.Local)
	if n.Name.Space != Namespace {
		b.WriteString(" xmlns=" + strconv.Quote(n.Name.Space))
	}
	if v, ok := n.Attr("all"); ok {
		b.WriteString(" all=" + v)
	}
	if v, ok := n.Attr("results"); ok {
		b.WriteString(" results=" + v)
	}
	if v, ok := n.Attr("pollRate"); ok {
		b.WriteString(" pollRate=" + v)
	}
	b.WriteString(">")
	if len(n.Kids) > 0 {
		kinds := map[string]int{}
		var order []string
		for _, k := range n.Kids {
			if kinds[k.Name.Local] == 0 {
				order = append(order, k.Name.Local)
			}
			kinds[k.Name.Local]++
		}
		parts := make([]string, 0, len(order))
		for _, k := range order {
			parts = append(parts, fmt.Sprintf("%s×%d", k, kinds[k]))
		}
		b.WriteString(" " + strings.Join(parts, " "))
	}
	return b.String()
}
