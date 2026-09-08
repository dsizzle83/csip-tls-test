// Command gen reads the independently-fetched SunSpec model JSON under
// ../testdata/models (see testdata/models/SOURCES.md for the pinned commit
// and checksums) and writes ../golden_gen.go: a table of sunspecgolden.Point
// lists keyed by model block name ("M120", "M705Hdr", "M705Crv", ...).
//
// WP4-T5 (REV0907-E8). Run via `go generate` from the sunspecgolden package
// directory (see the go:generate directive in golden_gen.go's header
// comment, or just `go run ./gen` from there). This program's OWN output is
// committed (golden_gen.go) — it does not run at build or test time.
//
// This program contains no lexa-proto import and reads nothing from
// vendor/lexa-proto: it is the referee-independence boundary the whole
// package exists to hold.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
)

// jsonPoint mirrors one "points" entry in a SunSpec model JSON group.
type jsonPoint struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int    `json:"size"`
	SF   string `json:"sf"`
}

// jsonGroup mirrors one "group" (or nested "groups" entry) in a SunSpec
// model JSON: an ordered point list plus zero or more repeating sub-groups.
type jsonGroup struct {
	Name   string      `json:"name"`
	Points []jsonPoint `json:"points"`
	Groups []jsonGroup `json:"groups"`
}

type jsonModel struct {
	Group jsonGroup `json:"group"`
}

// point is the generator's working representation of one golden.Point,
// before being rendered as Go source.
type point struct {
	Name   string
	Offset int
	Size   int
	Type   string
	SF     string
}

// flatten converts a group's OWN points (excluding the ID/L header pair, in
// order) into offset-assigned points. It does not descend into nested
// groups — callers that want a nested group's points ask for it explicitly
// (see modelBlocks below), because a repeating sub-group's offsets are
// relative to ITS OWN start, not the parent's.
func flatten(pts []jsonPoint) []point {
	out := make([]point, 0, len(pts))
	off := 0
	for _, p := range pts {
		if p.Name == "ID" || p.Name == "L" {
			continue
		}
		out = append(out, point{Name: p.Name, Offset: off, Size: p.Size, Type: p.Type, SF: p.SF})
		off += p.Size
	}
	return out
}

// blockSpec describes one named golden block to emit for a model: which
// JSON points make it up.
type blockSpec struct {
	key    string
	points []point
}

// modelBlocks decides, per model id, which named blocks to emit and how to
// derive their points from the parsed JSON tree. This mirrors exactly what
// lexa-proto's vendored sunspec package exposes as a comparable Go construct
// (a *Layout var, or a set of offset constants) for each model — see
// derlayout.go and models.go in vendor/lexa-proto/sunspec:
//
//   - 1, 103, 120, 121, 122, 123, 701, 702, 703, 802: a single flat block —
//     lexa-proto names these with raw M<id>_* offset constants (or, for 1,
//     unexported offset constants behind ReadCommon), never a *Layout.
//   - 704: ALSO a single flat block, but the golden must append its four
//     nested 2-point groups (PFWInj, PFWInjRvrt, PFWAbs, PFWAbsRvrt) after
//     the header points in DECLARED order — L704 in derlayout.go is one
//     NewLayout(...) call with those eight fields tacked on the end, not a
//     separate sub-layout.
//   - 705, 706, 712: a fixed "Hdr" block plus a repeating "Crv" block —
//     lexa-proto exposes L705Hdr/L705Crv, L706Hdr/L706Crv, L712Hdr/L712Crv.
//   - 711: "Hdr" + "Ctl" (L711Hdr/L711Ctl).
//   - 707, 708, 709, 710: "Hdr" ONLY. lexa-proto defines a single L707Hdr for
//     BOTH 707 and 708 (they are the identical shape — Ena, AdptCrvReq,
//     AdptCrvRslt, NPt, NCrvSet, V_SF, Tms_SF) and a single L709Hdr for BOTH
//     709 and 710, and holds no named layout at all for the trip-curve
//     MustTrip/MayTrip/MomCess sub-groups (those are computed by arithmetic
//     helpers — tripVSetSize/tripHzSetSize — not a Field list), so there is
//     no comparable Go construct to golden them against.
func modelBlocks(id int, root jsonGroup) []blockSpec {
	hdr := flatten(root.Points)
	switch id {
	case 704:
		// The four nested groups (PFWInj, PFWInjRvrt, PFWAbs, PFWAbsRvrt)
		// each declare their OWN "PF"/"Ext" points, so flattening them
		// verbatim would collide on name. lexa-proto's L704 resolves the
		// same collision by prefixing each with its group name
		// (PFWInj_PF, PFWInj_Ext, ...) and appending them, in declared
		// order, straight after the header fields in ONE flat Layout — so
		// the golden must continue the SAME running offset across the
		// header and every nested group, not restart at 0 per group.
		pts := append([]point{}, hdr...)
		off := 0
		for _, p := range hdr {
			if end := p.Offset + p.Size; end > off {
				off = end
			}
		}
		for _, g := range root.Groups {
			for _, p := range g.Points {
				pts = append(pts, point{Name: g.Name + "_" + p.Name, Offset: off, Size: p.Size, Type: p.Type, SF: p.SF})
				off += p.Size
			}
		}
		return []blockSpec{{key: fmt.Sprintf("M%d", id), points: pts}}
	case 705, 706, 712:
		blocks := []blockSpec{{key: fmt.Sprintf("M%dHdr", id), points: hdr}}
		if len(root.Groups) > 0 {
			blocks = append(blocks, blockSpec{key: fmt.Sprintf("M%dCrv", id), points: flatten(root.Groups[0].Points)})
		}
		return blocks
	case 711:
		blocks := []blockSpec{{key: "M711Hdr", points: hdr}}
		if len(root.Groups) > 0 {
			blocks = append(blocks, blockSpec{key: "M711Ctl", points: flatten(root.Groups[0].Points)})
		}
		return blocks
	case 707, 708, 709, 710:
		return []blockSpec{{key: fmt.Sprintf("M%dHdr", id), points: hdr}}
	default:
		return []blockSpec{{key: fmt.Sprintf("M%d", id), points: hdr}}
	}
}

// modelIDs is the candidate set this golden covers: models 1, 103, 120-123,
// 701-712 and 802 — exactly configs/candidate.json's servable set plus the
// battery detail model, per WP4-T5's task scope.
var modelIDs = []int{1, 103, 120, 121, 122, 123, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 802}

func main() {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen: getwd: %v\n", err)
		os.Exit(1)
	}
	// go:generate runs with the working directory set to the package
	// directory (sunspecgolden), so testdata lives one level down and the
	// output one level up from this program's own directory — but since this
	// program itself lives in gen/, resolve both relative to the package
	// root regardless of whether it was invoked via `go generate` (cwd =
	// package root) or `go run ./gen` from the package root (also cwd =
	// package root): both leave cwd at the sunspecgolden package directory.
	testdataDir := filepath.Join(dir, "testdata", "models")
	outPath := filepath.Join(dir, "golden_gen.go")

	all := map[string][]point{}
	for _, id := range modelIDs {
		path := filepath.Join(testdataDir, fmt.Sprintf("model_%d.json", id))
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen: read %s: %v\n", path, err)
			os.Exit(1)
		}
		var m jsonModel
		if err := json.Unmarshal(raw, &m); err != nil {
			fmt.Fprintf(os.Stderr, "gen: parse %s: %v\n", path, err)
			os.Exit(1)
		}
		for _, b := range modelBlocks(id, m.Group) {
			if _, dup := all[b.key]; dup {
				fmt.Fprintf(os.Stderr, "gen: duplicate block key %q\n", b.key)
				os.Exit(1)
			}
			all[b.key] = b.points
		}
	}

	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("// Code generated by gen/main.go from testdata/models/*.json. DO NOT EDIT.\n")
	buf.WriteString("// Regenerate with `go generate ./...` (or `go run ./gen`) from this package\n")
	buf.WriteString("// directory. Source: testdata/models/SOURCES.md.\n\n")
	buf.WriteString("//go:generate go run ./gen\n\n")
	buf.WriteString("package sunspecgolden\n\n")
	buf.WriteString("// Golden is the independently-sourced point table for every model block this\n")
	buf.WriteString("// package covers. See golden.go's package doc and testdata/models/SOURCES.md.\n")
	buf.WriteString("var Golden = map[string][]Point{\n")
	for _, k := range keys {
		fmt.Fprintf(&buf, "\t%q: {\n", k)
		for _, p := range all[k] {
			sf := "\"\""
			if p.SF != "" {
				sf = fmt.Sprintf("%q", p.SF)
			}
			fmt.Fprintf(&buf, "\t\t{Name: %q, Offset: %d, Size: %d, Type: %s, SF: %s},\n",
				p.Name, p.Offset, p.Size, typeConst(p.Type), sf)
		}
		buf.WriteString("\t},\n")
	}
	buf.WriteString("}\n")

	out, err := format.Source(buf.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen: gofmt output: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen: write %s: %v\n", outPath, err)
		os.Exit(1)
	}
}

// typeConst maps a model JSON "type" token onto this package's FieldType
// constant name.
func typeConst(t string) string {
	switch t {
	case "uint16":
		return "Uint16"
	case "int16":
		return "Int16"
	case "enum16":
		return "Enum16"
	case "bitfield16":
		return "Bitfield16"
	case "sunssf":
		return "Sunssf"
	case "uint32":
		return "Uint32"
	case "int32":
		return "Int32"
	case "enum32":
		return "Enum32"
	case "bitfield32":
		return "Bitfield32"
	case "acc32":
		return "Acc32"
	case "uint64":
		return "Uint64"
	case "int64":
		return "Int64"
	case "acc64":
		return "Acc64"
	case "string":
		return "String"
	case "pad":
		return "Pad"
	}
	fmt.Fprintf(os.Stderr, "gen: unknown SunSpec type token %q\n", t)
	os.Exit(1)
	return ""
}
