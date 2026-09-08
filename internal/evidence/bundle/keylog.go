package bundle

// keylog.go scopes the run's NSS key log to the bundle's OWN capture before
// Write copies it into capture/ (REV0907-E5).
//
// # Why filtering is needed at all
//
// The bench sims run with one shared, append-mode key log
// (-keylog /tmp/bench-shared.keylog), written across every run and every
// leg — the other campaign that ran an hour ago, the other leg of a split
// bench, a developer poking the sim by hand. Builder.SetKeyLog only ever
// received that one shared path, so copying it verbatim into a bundle (the
// behavior this file replaces) shipped TLS master secrets for sessions that
// have nothing to do with the evidence a reviewer is looking at — a bundle
// that let a lab decrypt traffic outside its own claims. Scoping the copy to
// the client randoms this bundle's own capture actually contains is what
// makes "this bundle's key log" a true statement instead of "whatever the
// shared log happened to hold that day".
//
// # What a session's identity is, on this file
//
// A TLS ClientHello's random is unencrypted on the wire — TLS 1.2 and 1.3
// both send it in the clear — and the NSS key-log format keys every secret
// by it. So the capture can be scanned for the set of client randoms it
// carries with no key log needed at all, and that set is exactly what a key
// log line's own client random has to be a member of to belong in this
// bundle. See captureClientRandoms.
import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
	"csip-tls-test/internal/evidence/tlsdis"
)

// keyLogFilterCounts is how many source key-log lines survived
// writeFilteredKeyLog, and how many did not.
type keyLogFilterCounts struct {
	Kept, Dropped int
}

// writeFilteredKeyLog copies src to dst, keeping only the entries whose
// client random names a TLS session that capturePath actually contains.
//
// A malformed source line is dropped and counted, not fatal: keylog.Parse's
// "one bad line fails the whole file" policy is right for a caller that
// needs the WHOLE log or nothing (a suite decrypting a specific session), but
// wrong here — the shared log's other lines are still good evidence for
// their own sessions, and refusing to write ANY of them over one mangled
// line the bundle probably does not even need would make -keylog strictly
// worse than not asking for one.
//
// capturePath == "" (a bundle with a key log but no capture, which SetCapture
// never requires) is treated as a capture containing NO sessions: every
// kept line is a positive claim that its session is in the bundle's own
// capture, and with no capture to check that claim against, no line can
// honestly make it.
func writeFilteredKeyLog(src, capturePath, dst string) (keyLogFilterCounts, error) {
	randoms := map[string]bool{}
	if capturePath != "" {
		var err error
		randoms, err = captureClientRandoms(capturePath)
		if err != nil {
			return keyLogFilterCounts{}, fmt.Errorf("bundle: scan capture for TLS sessions: %w", err)
		}
	}

	in, err := os.Open(src)
	if err != nil {
		return keyLogFilterCounts{}, fmt.Errorf("bundle: open key log %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return keyLogFilterCounts{}, fmt.Errorf("bundle: create %s: %w", filepath.Dir(dst), err)
	}
	out, err := os.Create(dst)
	if err != nil {
		return keyLogFilterCounts{}, fmt.Errorf("bundle: create %s: %w", dst, err)
	}

	var counts keyLogFilterCounts
	w := bufio.NewWriter(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if keylog.IsCommentOrBlank(text) {
			continue
		}
		e, err := keylog.ParseEntry(text)
		if err != nil {
			counts.Dropped++
			continue
		}
		if !randoms[hex.EncodeToString(e.ClientRandom)] {
			counts.Dropped++
			continue
		}
		counts.Kept++
		if _, err := fmt.Fprintf(w, "%s %s %s\n", e.Label,
			hex.EncodeToString(e.ClientRandom), hex.EncodeToString(e.Secret)); err != nil {
			_ = out.Close()
			return keyLogFilterCounts{}, fmt.Errorf("bundle: write %s: %w", dst, err)
		}
	}
	if err := sc.Err(); err != nil {
		_ = out.Close()
		return keyLogFilterCounts{}, fmt.Errorf("bundle: read key log %s: %w", src, err)
	}
	if err := w.Flush(); err != nil {
		_ = out.Close()
		return keyLogFilterCounts{}, fmt.Errorf("bundle: write %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return keyLogFilterCounts{}, fmt.Errorf("bundle: close %s: %w", dst, err)
	}
	return counts, nil
}

// captureClientRandoms scans a pcap(ng) file for every TLS ClientHello it
// carries and returns the set of client randoms it saw, lowercase hex — the
// same form the NSS key-log format keys secrets by (keylog.Log.Sessions),
// so the two sets compare directly.
//
// Only the ClientHello is looked at. It is sent in the clear on every TLS
// handshake this bench does, 1.2 or 1.3, so finding it needs no key log
// itself — which is exactly why this can run before the filtering it feeds
// even has one to check against, and why it costs the same key log nothing
// it would otherwise want to keep secret.
//
// Every TCP stream in the capture is scanned, not just a fixed southbound or
// northbound port list: writeFilteredKeyLog's job is to keep a session that
// IS in the capture, on whatever port it actually rode, not to guess which
// ports carry TLS on this run.
func captureClientRandoms(capturePath string) (map[string]bool, error) {
	pkts, err := pcapng.ReadFile(capturePath)
	if err != nil {
		return nil, fmt.Errorf("bundle: read %s: %w", capturePath, err)
	}
	asm := netdis.NewAssembler()
	for _, p := range pkts {
		// A frame that does not dissect (not IP/TCP) carries no ClientHello.
		// The same posture as verify.go's reassemble: one odd frame does not
		// abort the scan, it is just not TCP.
		if _, err := asm.AddPacket(p); err != nil {
			continue
		}
	}

	out := map[string]bool{}
	for _, st := range asm.Streams() {
		for _, d := range st.Dirs {
			if d == nil || d.Bytes == nil || d.Bytes.Len() == 0 {
				continue
			}
			// ParseDirection can return a non-nil Direction alongside an
			// error (a stream that is not TLS at all, or one that runs into
			// bytes it cannot make sense of partway through); either way
			// what was recovered before that point is still checked for a
			// ClientHello rather than discarded.
			dir, _ := tlsdis.ParseDirection(d.Bytes.Bytes(), d.Bytes)
			if dir == nil || dir.Handshake == nil {
				continue
			}
			if m, ok := dir.Handshake.Find(tlsdis.HandshakeClientHello); ok && m.ClientHello != nil {
				out[hex.EncodeToString(m.ClientHello.Random[:])] = true
			}
		}
	}
	return out, nil
}
