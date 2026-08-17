package main

// writes.go — the -writes mode: print the southbound register write set a
// captured leg holds, attributed to a named control.
//
// It exists because PC-001's supersession claims ("a supersession over
// byte-identical curves writes ONLY the admitted axes") had no bench-visible
// artefact: mbapref is library-only and builds a deduplicated fuzz corpus rather
// than a timeline, and the gateway's own logs are the gateway's account of its
// own writes rather than the wire.
//
// It is a READ of an existing bundle and nothing else — no DUT, no network, no
// mutation — which is what lets an operator run it against tonight's bundle
// while tonight's battery is still running. See internal/writeset.

import (
	"fmt"
	"io"

	"csip-tls-test/internal/writeset"
)

func (c *cli) runWrites(stdout, stderr io.Writer) int {
	res, err := writeset.Extract(writeset.Options{
		Path:       c.writes,
		KeyLogPath: c.opts.KeyLogPath,
		MRID:       c.writesMRID,
		Settle:     c.writesSettle,
	})
	if err != nil {
		fatal(stderr, err)
		return exitUsage
	}
	res.Render(stdout)

	// The counts go to STDERR so that stdout stays exactly the citable report:
	// a manifest quoting `certify -writes` should be quoting lines that are all
	// evidence, not a summary line that happens to be adjacent to them.
	n := len(res.Attributed())
	if res.Window != nil {
		fmt.Fprintf(stderr, "%d write(s) attributed to %s; %d excluded as outside the window\n",
			n, res.MRID, res.Excluded)
	} else {
		fmt.Fprintf(stderr, "%d write(s) in %s\n", n, res.Capture)
	}
	return exitOK
}
