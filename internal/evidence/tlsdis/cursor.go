package tlsdis

import "fmt"

// cursor is a bounds-checked forward reader over a TLS structure.
//
// Every parser in this package is written against it rather than against raw
// slice indexing, for one reason: TLS is a format of nested length prefixes
// supplied by the peer, and a single unchecked `b[i:j]` in a dissector that
// runs over hostile captures is a panic in a verifier a third party is
// executing. The cursor latches its first error and then returns zero values,
// so a parser can be written as straight-line code and checked once at the end.
type cursor struct {
	b   []byte
	off int
	err error
}

func newCursor(b []byte) *cursor { return &cursor{b: b} }

func (c *cursor) fail(format string, args ...any) {
	if c.err == nil {
		c.err = fmt.Errorf(format, args...)
	}
}

// need reports whether n more bytes are available, recording an error if not.
func (c *cursor) need(n int, what string) bool {
	if c.err != nil {
		return false
	}
	if n < 0 || len(c.b)-c.off < n {
		c.fail("tlsdis: %s wants %d bytes at offset %d but only %d remain", what, n, c.off, len(c.b)-c.off)
		return false
	}
	return true
}

func (c *cursor) u8(what string) uint8 {
	if !c.need(1, what) {
		return 0
	}
	v := c.b[c.off]
	c.off++
	return v
}

func (c *cursor) u16(what string) uint16 {
	if !c.need(2, what) {
		return 0
	}
	v := uint16(c.b[c.off])<<8 | uint16(c.b[c.off+1])
	c.off += 2
	return v
}

func (c *cursor) u24(what string) int {
	if !c.need(3, what) {
		return 0
	}
	v := int(c.b[c.off])<<16 | int(c.b[c.off+1])<<8 | int(c.b[c.off+2])
	c.off += 3
	return v
}

func (c *cursor) u32(what string) uint32 {
	if !c.need(4, what) {
		return 0
	}
	v := uint32(c.b[c.off])<<24 | uint32(c.b[c.off+1])<<16 | uint32(c.b[c.off+2])<<8 | uint32(c.b[c.off+3])
	c.off += 4
	return v
}

// take returns the next n bytes as a sub-slice of the input (no copy).
func (c *cursor) take(n int, what string) []byte {
	if !c.need(n, what) {
		return nil
	}
	v := c.b[c.off : c.off+n]
	c.off += n
	return v
}

// vector8/16/24 read a length-prefixed opaque vector, the TLS presentation
// language's only aggregate.
func (c *cursor) vector8(what string) []byte  { return c.take(int(c.u8(what+" length")), what) }
func (c *cursor) vector16(what string) []byte { return c.take(int(c.u16(what+" length")), what) }
func (c *cursor) vector24(what string) []byte { return c.take(c.u24(what+" length"), what) }

// rest returns everything not yet consumed.
func (c *cursor) rest() []byte {
	if c.err != nil {
		return nil
	}
	v := c.b[c.off:]
	c.off = len(c.b)
	return v
}

func (c *cursor) remaining() int {
	if c.err != nil {
		return 0
	}
	return len(c.b) - c.off
}

func (c *cursor) empty() bool { return c.remaining() == 0 }

// u16List decodes a length-prefixed vector of 16-bit codepoints — cipher
// suites, supported groups, signature schemes, supported versions.
func (c *cursor) u16List(what string) []uint16 {
	body := c.vector16(what)
	if body == nil {
		return nil
	}
	if len(body)%2 != 0 {
		c.fail("tlsdis: %s is %d bytes, not a whole number of 16-bit values", what, len(body))
		return nil
	}
	out := make([]uint16, 0, len(body)/2)
	for i := 0; i < len(body); i += 2 {
		out = append(out, uint16(body[i])<<8|uint16(body[i+1]))
	}
	return out
}
