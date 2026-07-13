// qa_reports.go — read-only HTTP access to the markdown run reports Mayhem
// already writes (writeReport in mayhem.go). Additive: it does not change
// what a report contains, only how it is listed/fetched over HTTP instead of
// only being readable on the dashboard host's filesystem (CONTRACTS.md §4).
//
//	GET /api/qa/reports        {"name":"qa-mayhem-….md","mtime":RFC3339,"bytes":N}[] newest-first
//	GET /api/qa/reports/{name} the report as text/markdown
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// qaReportNameRe is the entire defense against path traversal on the fetch
// route: it is exactly the filename shape writeReport produces
// (qa-mayhem-<YYYYMMDD-HHMMSS>.md), so "../../etc/passwd", an absolute path,
// a percent-encoded "..%2f", or any name with a path separator can never
// match — net/http already decodes the path before r.PathValue("name") sees
// it, so the regex is checked against the decoded value and rejects all of
// the above the same way. A rejected name never reaches the filesystem.
var qaReportNameRe = regexp.MustCompile(`^qa-mayhem-[0-9-]+\.md$`)

// qaReportEntry is one row of the GET /api/qa/reports listing.
type qaReportEntry struct {
	Name  string `json:"name"`
	MTime string `json:"mtime"` // RFC3339
	Bytes int64  `json:"bytes"`
}

// handleQAReports lists mayReportDir's saved run reports, newest-first. An
// absent directory (no run has completed since logs/qa/ existed) is an empty
// list, not an error — same "nothing to show yet" contract as a fresh
// mayhemStatus with no findings.
func handleQAReports(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(mayReportDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []qaReportEntry{})
			return
		}
		http.Error(w, "qa reports: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]qaReportEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !qaReportNameRe.MatchString(e.Name()) {
			continue // never lists anything writeReport would not itself have produced
		}
		info, err := e.Info()
		if err != nil {
			continue // gone between ReadDir and Stat (e.g. a concurrent report rotation) — skip, not fatal
		}
		out = append(out, qaReportEntry{
			Name:  e.Name(),
			MTime: info.ModTime().UTC().Format(time.RFC3339),
			Bytes: info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MTime > out[j].MTime })
	writeJSON(w, http.StatusOK, out)
}

// handleQAReportFetch serves one saved report's raw markdown. name is
// validated against qaReportNameRe BEFORE it ever touches filepath.Join or
// the filesystem — see the traversal note on that regex above.
func handleQAReportFetch(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !qaReportNameRe.MatchString(name) {
		http.Error(w, "qa reports: invalid report name", http.StatusBadRequest)
		return
	}
	b, err := os.ReadFile(filepath.Join(mayReportDir, name))
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "qa reports: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(b)
}
