import { EmptyStateCard } from '../components/EmptyStateCard';

// /logs — merged SSE stream. See DESIGN_BRIEF.md §4 (per-source color chips,
// level detection, regex/text filter, pause/resume, virtualized 10k ring,
// mono 12px). Backed by GET /api/logs/all (SSE, shape {src,line,at}) via
// src/lib/useSSE.ts (CONTRACTS.md §6).
//
// Named LogsView (not Logs) to avoid clashing with the DOM Console `Log`
// naming and any future `Logs` data type import.
export default function LogsView() {
  return (
    <div className="view-stack">
      <h1 className="page-title">Logs</h1>
      <EmptyStateCard
        title="Merged Logs"
        message="The live SSE log stream from every backend will appear here once wired to /api/logs/all."
      />
    </div>
  );
}
