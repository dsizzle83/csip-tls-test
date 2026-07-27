// Package keylog reads NSS key-log files — the SSLKEYLOGFILE format every TLS
// stack and every capture tool already agrees on.
//
// # Why a key log rather than a private key
//
// A conformance bundle has to let a third party decrypt the traffic it makes
// claims about, and it must do so WITHOUT handing over the device's long-term
// private key. A key log solves exactly that: it carries per-session secrets,
// so an auditor can reproduce the plaintext of the captured sessions and
// nothing else. Every entry is scoped to one client random, which is why this
// package is keyed that way throughout.
//
// The corollary is that a key log is itself sensitive. It belongs in the
// bundle, hashed by the manifest alongside the pcap, and it should never be
// committed to a source repository — the bundle is the artefact, the repo is
// not.
//
// # Format
//
// Each line is "<LABEL> <client_random_hex> <secret_hex>", with '#' comments
// and blank lines allowed. The labels this package understands are listed as
// constants below; unknown labels are RETAINED rather than dropped, so a log
// written by a future stack still round-trips through a bundle intact.
//
// Parsing is strict: a malformed line is an error naming the line number, not a
// silent skip. A key log that cannot be read exactly is a key log that will
// produce a decryption failure later, and a failure at parse time is far
// cheaper to diagnose than one at record 4,471.
package keylog

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// The labels defined by the NSS key-log format.
const (
	// LabelClientRandom carries the TLS 1.2 master secret.
	LabelClientRandom = "CLIENT_RANDOM"
	// LabelClientHandshake / LabelServerHandshake carry the TLS 1.3 handshake
	// traffic secrets — the ones that decrypt EncryptedExtensions, the
	// certificate chain, and Finished.
	LabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	LabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	// LabelClientTraffic0 / LabelServerTraffic0 carry the TLS 1.3 application
	// traffic secrets.
	LabelClientTraffic0 = "CLIENT_TRAFFIC_SECRET_0"
	LabelServerTraffic0 = "SERVER_TRAFFIC_SECRET_0"
	// LabelExporter carries the exporter master secret.
	LabelExporter = "EXPORTER_SECRET"
	// LabelEarlyTraffic carries the 0-RTT client early traffic secret.
	LabelEarlyTraffic = "CLIENT_EARLY_TRAFFIC_SECRET"
	// LabelRSA carries a premaster secret keyed by the first 8 bytes of the
	// encrypted premaster (the pre-TLS-1.2 static-RSA form).
	LabelRSA = "RSA"
)

// Entry is one key-log line.
type Entry struct {
	Line         int
	Label        string
	ClientRandom []byte
	Secret       []byte
}

// Log is a parsed key log, indexed by client random and label.
type Log struct {
	// byRandom maps hex(client_random) → label → secret.
	byRandom map[string]map[string][]byte
	entries  []Entry
	path     string
}

// Open reads a key log from disk.
func Open(path string) (*Log, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keylog: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	l, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("keylog: %s: %w", path, err)
	}
	l.path = path
	return l, nil
}

// Parse reads a key log from r.
func Parse(r io.Reader) (*Log, error) {
	l := &Log{byRandom: make(map[string]map[string][]byte)}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: got %d fields, want 3 (LABEL client_random secret)", line, len(fields))
		}
		label := fields[0]
		cr, err := hex.DecodeString(fields[1])
		if err != nil {
			return nil, fmt.Errorf("line %d: client random is not hex: %w", line, err)
		}
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			return nil, fmt.Errorf("line %d: secret is not hex: %w", line, err)
		}
		// Every label except the legacy RSA one is keyed by the 32-byte client
		// random; a shorter value means the log is not what it claims to be.
		if label != LabelRSA && len(cr) != 32 {
			return nil, fmt.Errorf("line %d: client random is %d bytes, want 32", line, len(cr))
		}
		if len(secret) == 0 {
			return nil, fmt.Errorf("line %d: empty secret", line)
		}
		key := strings.ToLower(fields[1])
		if l.byRandom[key] == nil {
			l.byRandom[key] = make(map[string][]byte, 4)
		}
		l.byRandom[key][label] = secret
		l.entries = append(l.entries, Entry{Line: line, Label: label, ClientRandom: cr, Secret: secret})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read key log: %w", err)
	}
	return l, nil
}

// Path returns the file the log was read from, if any.
func (l *Log) Path() string { return l.path }

// Entries returns every line in file order.
func (l *Log) Entries() []Entry { return l.entries }

// Len returns the number of entries.
func (l *Log) Len() int { return len(l.entries) }

// Sessions returns the client randoms present, hex-encoded and sorted, which is
// how a bundle reports which sessions it can decrypt.
func (l *Log) Sessions() []string {
	out := make([]string, 0, len(l.byRandom))
	for k := range l.byRandom {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Secret returns the secret for a label and client random.
func (l *Log) Secret(label string, clientRandom []byte) ([]byte, bool) {
	m := l.byRandom[hex.EncodeToString(clientRandom)]
	if m == nil {
		return nil, false
	}
	s, ok := m[label]
	return s, ok
}

// Labels returns the labels recorded for a client random, sorted.
func (l *Log) Labels(clientRandom []byte) []string {
	m := l.byRandom[hex.EncodeToString(clientRandom)]
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MasterSecret returns the TLS 1.2 master secret for a session.
func (l *Log) MasterSecret(clientRandom []byte) ([]byte, bool) {
	return l.Secret(LabelClientRandom, clientRandom)
}

// Has reports whether any secret is known for a client random.
func (l *Log) Has(clientRandom []byte) bool {
	_, ok := l.byRandom[hex.EncodeToString(clientRandom)]
	return ok
}
