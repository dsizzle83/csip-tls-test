package main

// keylogpath.go keeps the live key log OUT of the evidence bundle directory.
//
// The bundle writer copies the key log to <bundle>/capture/keys.log so an
// assessor can decrypt the capture. If the operator ALSO points -keylog inside
// -out, the same secrets end up in the bundle twice: once where the run wrote
// them and once where the bundler copied them. Both land in MANIFEST.sha256, so
// the bundle still verifies — which is precisely why this is worth refusing
// rather than tolerating. Nothing complains, and the duplicate reads as though
// two distinct artefacts were collected.
//
// It is the same hazard already guarded for -report-out (see submissionDir):
// writing into a directory whose contents are themselves the evidence. The
// capture had a third instance of it — -out and the bundle path coinciding made
// os.Create truncate the run's own pcap to zero bytes — so this is a family of
// bugs, not a one-off, and the guard belongs at every entry point that takes a
// path from the operator.
//
// Refused rather than quietly relocated: the operator asked for a specific
// location, and a key log silently appearing somewhere else is worse than being
// told why it cannot go where they asked.

import (
	"fmt"
	"path/filepath"
	"strings"
)

// keylogOutsideBundle reports an error when keylogPath resolves inside outDir.
// An empty outDir (a run that writes no bundle) or an empty keylogPath is fine.
func keylogOutsideBundle(keylogPath, outDir string) error {
	if keylogPath == "" || outDir == "" {
		return nil
	}
	absKeylog, err := filepath.Abs(keylogPath)
	if err != nil {
		return fmt.Errorf("resolve -keylog %s: %w", keylogPath, err)
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return fmt.Errorf("resolve -out %s: %w", outDir, err)
	}
	rel, err := filepath.Rel(absOut, absKeylog)
	if err != nil {
		return nil // unrelated roots: not inside
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil // outside the bundle, which is what we want
	}
	return fmt.Errorf("-keylog %s is inside the evidence bundle %s. The bundler already copies the key "+
		"log into <bundle>/capture/, so writing the live one there too puts the same TLS session secrets "+
		"in the bundle twice, both listed in the manifest and neither flagged as a duplicate. Point "+
		"-keylog somewhere outside -out (a sibling path, or /tmp) and let the bundler place the copy",
		keylogPath, outDir)
}
