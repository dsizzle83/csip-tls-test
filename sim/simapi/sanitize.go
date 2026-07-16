package simapi

// sanitize.go — degraded JSON encoding for state payloads that fail to marshal.
//
// A simulator's ground-truth state can legitimately contain non-finite floats:
// a corrupted SunSpec register bank decodes to NaN (audit E1 — during a
// nan_sentinel fault window the hub's whole-block read-modify-write wrote
// 0x8000 over a model block, after which GET /state returned 500 permanently
// and the WS feed went silently mute until a sim restart). QA reads /state
// precisely to OBSERVE such corrupted states, so a marshal failure must
// degrade — non-finite floats become null — never take the endpoint down.

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"
	"sync"
)

// sanitizeMaxDepth bounds the recursive walk. State snapshots are shallow
// trees, so exceeding this means a cycle; the subtree degrades to null
// rather than recursing forever.
const sanitizeMaxDepth = 32

// SanitizeNonFinite returns a JSON-marshalable stand-in for v: any subtree
// that already marshals is kept byte-identical (tags, omitempty and custom
// marshalers like time.Time all preserved, via json.RawMessage), and only
// failing subtrees are decomposed — structs and maps into map[string]any,
// slices into []any — until the offending non-finite float leaves are
// replaced with nil. Exported so sim packages can assert their
// corrupted-state snapshots survive the /state encoding path.
func SanitizeNonFinite(v any) any {
	return sanitizeValue(reflect.ValueOf(v), 0)
}

func sanitizeValue(rv reflect.Value, depth int) any {
	if !rv.IsValid() || !rv.CanInterface() || depth > sanitizeMaxDepth {
		return nil
	}
	if b, err := json.Marshal(rv.Interface()); err == nil {
		return json.RawMessage(b)
	}
	switch rv.Kind() {
	case reflect.Float32, reflect.Float64:
		return nil // only a non-finite float reaches here — a finite one marshaled above
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return sanitizeValue(rv.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = sanitizeValue(rv.Index(i), depth+1)
		}
		return out
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		it := rv.MapRange()
		for it.Next() {
			out[fmt.Sprint(it.Key().Interface())] = sanitizeValue(it.Value(), depth+1)
		}
		return out
	case reflect.Struct:
		out := make(map[string]any)
		sanitizeStruct(rv, out, depth)
		return out
	}
	// A leaf that neither marshals nor decomposes (chan, func, a custom
	// Marshaler that errors): null it rather than fail the whole payload.
	return nil
}

// sanitizeStruct flattens rv's exported fields into out, honouring the json
// tag conventions the normal encoder would have applied (name, "-", omitempty,
// anonymous-embed inlining) so the degraded shape stays as close as possible
// to the healthy one.
func sanitizeStruct(rv reflect.Value, out map[string]any, depth int) {
	t := rv.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		fv := rv.Field(i)
		if f.Anonymous && name == "" {
			ev := fv
			if ev.Kind() == reflect.Pointer {
				if ev.IsNil() {
					continue
				}
				ev = ev.Elem()
			}
			if ev.Kind() == reflect.Struct {
				sanitizeStruct(ev, out, depth)
				continue
			}
		}
		if strings.Contains(opts, "omitempty") && isEmptyValue(fv) {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = sanitizeValue(fv, depth+1)
	}
}

// isEmptyValue mirrors encoding/json's omitempty test.
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}

// sanitizeLogged dedupes the degrade log by call site + payload type: a
// permanently-poisoned register bank would otherwise log on every 2 s WS tick
// and every /state poll.
var sanitizeLogged sync.Map

// logSanitizeOnce records — once per (where, payload type) — that a payload
// failed plain JSON marshaling and was served through SanitizeNonFinite,
// keeping the underlying corruption observable in the sim log without
// flooding it.
func logSanitizeOnce(where string, v any, err error) {
	key := fmt.Sprintf("%s %T", where, v)
	if _, dup := sanitizeLogged.LoadOrStore(key, struct{}{}); dup {
		return
	}
	log.Printf("[simapi] %s: %T is not directly JSON-marshalable (%v) — serving sanitized state (non-finite floats → null)", where, v, err)
}
