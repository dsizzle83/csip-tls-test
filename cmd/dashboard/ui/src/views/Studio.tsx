import { EmptyStateCard } from '../components/EmptyStateCard';

// /studio — Savings Studio (the money view). See DESIGN_BRIEF.md §4 for the
// full two-zone layout (scenario builder rail + hero strip/cost race/bill
// breakdown/TOU heatmap/day detail/plan comparison). Backed by
// POST /api/whatif/run, GET /api/scenarios, GET /api/tariffs (CONTRACTS.md §3).
export default function Studio() {
  return (
    <div className="view-stack">
      <h1 className="page-title">Studio</h1>
      <EmptyStateCard
        title="Savings Studio"
        message="Scenario builder and cost-comparison results will appear here once wired to /api/whatif/run."
      />
    </div>
  );
}
