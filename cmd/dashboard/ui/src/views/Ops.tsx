import { getJSON } from '../lib/api';
import { usePoll } from '../lib/usePoll';
import { PowerFlow } from './ops/PowerFlow';
import { HubBrain } from './ops/HubBrain';
import { PlanVsActual } from './ops/PlanVsActual';
import { ProtocolInspector } from './ops/ProtocolInspector';
import { EventConsole } from './ops/EventConsole';
import { ScenarioConsole } from './ops/ScenarioConsole';
import { AdvancedConsole } from './ops/AdvancedConsole';
import type { HubStatus } from './ops/types';
import './ops/ops.css';

// /ops — Live Ops (watch the hub think). See DESIGN_BRIEF.md §4. One 1 s poll of
// /api/hub/status is owned here and passed to every panel so the whole view
// shares a single live spine (each panel keeps its own bounded buffers). The
// panels degrade to quiet empty states before the hub's first plan (503).
export default function Ops() {
  const { data: status, error } = usePoll<HubStatus>(() => getJSON<HubStatus>('/api/hub/status'), 1000);

  return (
    <div className="view-stack">
      <div className="ops-card-head" style={{ marginBottom: 0 }}>
        <h1 className="page-title">Live Ops</h1>
        {!!error && !status && <span className="ops-chip ops-chip-warn">⚠ hub unreachable — retrying</span>}
      </div>

      <ScenarioConsole status={status} />

      <AdvancedConsole status={status} />

      <div className="ops-flow-row">
        <PowerFlow status={status} />
        <HubBrain status={status} />
      </div>

      <PlanVsActual status={status} />

      <ProtocolInspector status={status} />

      <EventConsole status={status} />
    </div>
  );
}
