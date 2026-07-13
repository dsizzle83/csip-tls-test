// Wire shape of one event on the merged SSE stream, GET /api/logs/all
// (CONTRACTS.md §6). One dashboard server merges every backend's own /logs
// stream — see cmd/dashboard/logmux.go.
export interface LogLine {
  /** Source id: hub | grid | solar | battery | meter | ev. */
  src: string;
  /** Raw log line text, already formatted by the source process. */
  line: string;
  /** ISO timestamp the dashboard server received/tagged the line. */
  at: string;
}
