import { EmptyStateCard } from '../components/EmptyStateCard';

// /bench — per-sim detail panels (solar/battery/meter/EV): live state,
// inject/control forms, register tables. See DESIGN_BRIEF.md §4. Utility
// surface — plain, functional, still on-brand. Backed by /api/{solar,
// battery,meter,ev}/state + /inject + /control (simapi, CONTRACTS.md §6).
export default function Bench() {
  return (
    <div className="view-stack">
      <h1 className="page-title">Bench</h1>
      <EmptyStateCard
        title="Sim Bench"
        message="Solar, battery, meter, and EV sim panels will appear here once wired to their simapi endpoints."
      />
    </div>
  );
}
