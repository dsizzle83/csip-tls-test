import { EmptyStateCard } from '../components/EmptyStateCard';

// /ops — Live Ops (watch the hub think). See DESIGN_BRIEF.md §4 for the full
// layout (power flow diagram, hub brain feed, plan-vs-actual, CSIP Protocol
// Inspector, grid event console). Backed by /api/hub/status (1 s poll),
// /api/hub/plan, gridsim /admin/status + /admin/tariff (CONTRACTS.md §6).
export default function Ops() {
  return (
    <div className="view-stack">
      <h1 className="page-title">Live Ops</h1>
      <EmptyStateCard
        title="Live Ops"
        message="Power flow, hub decisions, and the CSIP protocol inspector will appear here once wired to /api/hub/status."
      />
    </div>
  );
}
