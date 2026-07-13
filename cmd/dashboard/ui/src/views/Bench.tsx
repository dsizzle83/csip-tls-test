import { SolarCard } from './bench/SolarCard';
import { BatteryCard } from './bench/BatteryCard';
import { MeterCard } from './bench/MeterCard';
import { EVCard } from './bench/EVCard';

// /bench — per-sim detail panels (solar/battery/meter/EV): live state,
// inject/control forms, register tables. See DESIGN_BRIEF.md §4. Utility
// surface — plain, functional, still on-brand. Backed by /api/{solar,
// battery,meter,ev}/state + /inject + /control (simapi, CONTRACTS.md §6).
export default function Bench() {
  return (
    <div className="view-stack">
      <h1 className="page-title">Bench</h1>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
        <SolarCard />
        <BatteryCard />
        <MeterCard />
        <EVCard />
      </div>
    </div>
  );
}
