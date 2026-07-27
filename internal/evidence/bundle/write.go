package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/capture"
)

// Builder accumulates a run's results and writes the bundle directory.
type Builder struct {
	run     RunMeta
	capture capture.Summary
	cases   []TestCaseResult

	capturePath string
	keylogPath  string
	extraPaths  []string
}

// NewBuilder starts a bundle.
func NewBuilder(run RunMeta) *Builder {
	if run.Started.IsZero() {
		run.Started = time.Now().UTC()
	}
	if run.Host == "" {
		if h, err := os.Hostname(); err == nil {
			run.Host = h
		}
	}
	return &Builder{run: run}
}

// SetCapture records the capture metadata and the file to copy into the bundle.
func (b *Builder) SetCapture(sum capture.Summary, path string) {
	b.capture = sum
	b.capturePath = path
	if path == "" {
		b.capturePath = sum.Path
	}
}

// SetKeyLog records the NSS key log to copy into the bundle.
//
// The key log belongs in the bundle because without it the claims about
// encrypted traffic cannot be re-checked. It is scoped to the captured
// sessions, so shipping it does not expose the device's long-term key — but it
// is still a secret, and a bundle containing one should be handled as such.
func (b *Builder) SetKeyLog(path string) { b.keylogPath = path }

// AddFile copies an extra artefact into the bundle and covers it with the
// manifest — a run log, a configuration dump, a certificate.
func (b *Builder) AddFile(path string) { b.extraPaths = append(b.extraPaths, path) }

// AddCase appends a test case. If its Verdict is empty it is rolled up from the
// assertions, so a caller cannot accidentally record a PASS over a failing
// assertion by forgetting to set it.
func (b *Builder) AddCase(tc TestCaseResult) {
	if tc.Verdict == "" {
		tc.Verdict = tc.RollUp()
	}
	b.cases = append(b.cases, tc)
}

// Cases returns what has been added so far.
func (b *Builder) Cases() []TestCaseResult { return b.cases }

// Write materialises the bundle in dir, which is created if needed and must
// otherwise be empty of a previous bundle's files.
//
// The write order matters: artefacts first, then bundle.json, then REPORT.md,
// and the manifest LAST over everything that ended up on disk. A manifest
// written from the in-memory file list instead of from the directory would miss
// a file that was added out of band — which is precisely the case it exists to
// catch.
func (b *Builder) Write(dir string) (*Bundle, error) {
	if dir == "" {
		return nil, errors.New("bundle: no output directory")
	}
	if err := os.MkdirAll(filepath.Join(dir, CaptureDir), 0o755); err != nil {
		return nil, fmt.Errorf("bundle: create %s: %w", dir, err)
	}

	out := &Bundle{
		Schema:  SchemaVersion,
		Run:     b.run,
		Capture: b.capture,
		Cases:   b.cases,
	}
	if out.Run.Finished.IsZero() {
		out.Run.Finished = time.Now().UTC()
	}

	if b.capturePath != "" {
		rel := path.Join(CaptureDir, filepath.Base(b.capturePath))
		if err := copyFile(b.capturePath, filepath.Join(dir, rel)); err != nil {
			return nil, fmt.Errorf("bundle: copy capture: %w", err)
		}
		out.Files.Capture = rel
		// The path inside the bundle is the one a reader can act on; the
		// original absolute path stays in the capture summary for provenance.
		out.Capture.Path = rel
	}
	if b.keylogPath != "" {
		rel := path.Join(CaptureDir, filepath.Base(b.keylogPath))
		if err := copyFile(b.keylogPath, filepath.Join(dir, rel)); err != nil {
			return nil, fmt.Errorf("bundle: copy key log: %w", err)
		}
		out.Files.KeyLog = rel
	}
	for _, p := range b.extraPaths {
		rel := filepath.Base(p)
		if err := copyFile(p, filepath.Join(dir, rel)); err != nil {
			return nil, fmt.Errorf("bundle: copy %s: %w", p, err)
		}
		out.Files.Extra = append(out.Files.Extra, rel)
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("bundle: encode %s: %w", BundleFile, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, BundleFile), data, 0o644); err != nil {
		return nil, fmt.Errorf("bundle: write %s: %w", BundleFile, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ReportFile), []byte(out.Report()), 0o644); err != nil {
		return nil, fmt.Errorf("bundle: write %s: %w", ReportFile, err)
	}
	if err := WriteManifest(dir); err != nil {
		return nil, err
	}
	return out, nil
}

// WriteManifest hashes every file in dir except the manifest itself and writes
// MANIFEST.sha256 in the format sha256sum(1) reads, so a reader with no Go
// toolchain can still check it:
//
//	cd bundle-dir && sha256sum -c MANIFEST.sha256
func WriteManifest(dir string) error {
	entries, err := manifestEntries(dir)
	if err != nil {
		return err
	}
	var sb strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&sb, "%s  %s\n", e.Sum, e.Name)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("bundle: write %s: %w", ManifestFile, err)
	}
	return nil
}

// ManifestEntry is one line of MANIFEST.sha256.
type ManifestEntry struct {
	Sum  string
	Name string // slash-separated, relative to the bundle directory
}

// manifestEntries walks dir and hashes everything but the manifest.
func manifestEntries(dir string) ([]ManifestEntry, error) {
	var out []ManifestEntry
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ManifestFile {
			return nil
		}
		sum, err := sha256File(p)
		if err != nil {
			return err
		}
		out = append(out, ManifestEntry{Sum: sum, Name: rel})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bundle: hash bundle contents: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ReadManifest parses a MANIFEST.sha256.
func ReadManifest(dir string) ([]ManifestEntry, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("bundle: read %s: %w", ManifestFile, err)
	}
	var out []ManifestEntry
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			return nil, fmt.Errorf("bundle: %s line %d is not '<sha256>  <path>'", ManifestFile, i+1)
		}
		if len(sum) != 64 {
			return nil, fmt.Errorf("bundle: %s line %d: %q is not a sha256 digest", ManifestFile, i+1, sum)
		}
		out = append(out, ManifestEntry{Sum: sum, Name: strings.TrimSpace(name)})
	}
	return out, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyFile copies src to dst, creating dst's directory.
//
// The same-file guard is not paranoia; it is the fix for a bug that destroyed
// evidence. The natural way to invoke a conformance run is `-out runs/<ts>/`,
// and the runner writes its capture to `<out>/capture/run-<ts>.pcapng` — which
// is EXACTLY where the bundle then copies it. Without this check os.Create
// truncates the destination first, the destination IS the source, and the run's
// entire packet capture becomes a zero-byte file: the console reports the
// frames it counted before the copy, the bundle looks complete, and every
// citation in it is unverifiable. Copying a file onto itself has one correct
// outcome — leave it alone and report success — and getting it wrong is silent
// right up until somebody tries to verify the bundle.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if si, serr := in.Stat(); serr == nil {
		if di, derr := os.Stat(dst); derr == nil && os.SameFile(si, di) {
			return nil
		}
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Load reads a bundle.json from a bundle directory.
func Load(dir string) (*Bundle, error) {
	data, err := os.ReadFile(filepath.Join(dir, BundleFile))
	if err != nil {
		return nil, fmt.Errorf("bundle: read %s: %w", BundleFile, err)
	}
	var b Bundle
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("bundle: parse %s: %w", BundleFile, err)
	}
	if b.Schema != SchemaVersion {
		return nil, fmt.Errorf("bundle: %s declares schema %q, this verifier understands %q",
			BundleFile, b.Schema, SchemaVersion)
	}
	return &b, nil
}
