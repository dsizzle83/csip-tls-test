package tlsdis

// Extension is one TLS extension, kept as raw bytes alongside its type.
//
// The raw Data is retained even for extensions the package decodes, because a
// conformance claim about an extension is a claim about the bytes on the wire —
// "renegotiation_info was present and empty" is checkable only if the empty
// vector is still there to be checked.
type Extension struct {
	Type uint16
	Data []byte
}

// Name returns the IANA name of the extension type.
func (e Extension) Name() string { return ExtensionName(e.Type) }

// parseExtensions decodes a bare extension list (no outer length prefix).
func parseExtensions(body []byte) []Extension {
	if body == nil {
		return nil
	}
	c := newCursor(body)
	var out []Extension
	for !c.empty() {
		t := c.u16("extension type")
		d := c.vector16("extension data")
		if c.err != nil {
			return out
		}
		out = append(out, Extension{Type: t, Data: d})
	}
	return out
}

// parseExtensionsCursor reads a u16-length-prefixed extension list from c,
// propagating errors into c so the caller checks once.
func parseExtensionsCursor(c *cursor, what string) []Extension {
	body := c.vector16(what)
	if c.err != nil {
		return nil
	}
	inner := newCursor(body)
	var out []Extension
	for !inner.empty() {
		t := inner.u16("extension type")
		d := inner.vector16("extension data")
		if inner.err != nil {
			c.err = inner.err
			return out
		}
		out = append(out, Extension{Type: t, Data: d})
	}
	return out
}

// findExtension returns the raw data of the first extension of type t.
func findExtension(exts []Extension, t uint16) ([]byte, bool) {
	for _, e := range exts {
		if e.Type == t {
			return e.Data, true
		}
	}
	return nil, false
}

// ExtensionTypes lists the extension types in wire order.
func ExtensionTypes(exts []Extension) []uint16 {
	out := make([]uint16, len(exts))
	for i, e := range exts {
		out[i] = e.Type
	}
	return out
}

// ExtensionNames lists the extension names in wire order.
func ExtensionNames(exts []Extension) []string {
	out := make([]string, len(exts))
	for i, e := range exts {
		out[i] = e.Name()
	}
	return out
}

// KeyShare is one key_share entry.
type KeyShare struct {
	Group uint16
	Key   []byte
}

func parseClientKeyShares(body []byte) []KeyShare {
	c := newCursor(body)
	list := c.vector16("key_share.client_shares")
	if c.err != nil {
		return nil
	}
	inner := newCursor(list)
	var out []KeyShare
	for !inner.empty() {
		g := inner.u16("key_share.group")
		k := inner.vector16("key_share.key_exchange")
		if inner.err != nil {
			return out
		}
		out = append(out, KeyShare{Group: g, Key: k})
	}
	return out
}

// parseServerNameList decodes RFC 6066 server_name, returning host names only.
func parseServerNameList(body []byte) []string {
	c := newCursor(body)
	list := c.vector16("server_name_list")
	if c.err != nil {
		return nil
	}
	inner := newCursor(list)
	var out []string
	for !inner.empty() {
		typ := inner.u8("server_name.name_type")
		name := inner.vector16("server_name.host_name")
		if inner.err != nil {
			return out
		}
		if typ == 0 {
			out = append(out, string(name))
		}
	}
	return out
}

// parseALPN decodes an application_layer_protocol_negotiation list.
func parseALPN(body []byte) []string {
	c := newCursor(body)
	list := c.vector16("alpn.protocol_name_list")
	if c.err != nil {
		return nil
	}
	inner := newCursor(list)
	var out []string
	for !inner.empty() {
		p := inner.vector8("alpn.protocol_name")
		if inner.err != nil {
			return out
		}
		out = append(out, string(p))
	}
	return out
}
