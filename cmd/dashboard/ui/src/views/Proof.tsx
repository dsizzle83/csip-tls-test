import { EmptyStateCard } from '../components/EmptyStateCard';

// /proof — Proof Center. See DESIGN_BRIEF.md §4 for the full layout (safety
// case strip, scenario browser, run panel with live timeline, findings list,
// history). Backed by /api/qa/scenarios, /api/qa/start, /api/qa/status
// (1.5 s poll), /api/qa/reports (CONTRACTS.md §6).
export default function Proof() {
  return (
    <div className="view-stack">
      <h1 className="page-title">Proof</h1>
      <EmptyStateCard
        title="Proof Center"
        message="Safety-case invariants and Mayhem QA campaign results will appear here once wired to /api/qa/scenarios."
      />
    </div>
  );
}
