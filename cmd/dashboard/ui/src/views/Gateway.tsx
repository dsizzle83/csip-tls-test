import { useCallback } from 'react';
import './gateway/gateway.css';
import { usePoll } from '../lib/usePoll';
import { fetchGwStatus, fetchGwReport } from './gateway/api';
import type { GwStatus, GwBoard } from './gateway/types';
import { ProofBanner } from './gateway/ProofBanner';
import { InterfaceTopology } from './gateway/InterfaceTopology';
import { VerdictBoard } from './gateway/VerdictBoard';
import { LiveRunPanel } from './gateway/LiveRunPanel';

// /gateway — LEXA-GW proof tab. Undeniable, live evidence the secure DER gateway
// (the CC93 dev kit at 69.0.0.2) behaves as designed: the live 4-interface
// topology it bridges, a headline "as-designed" claim, a reproducible live run,
// and the full adversarial-QA verdict board with per-scenario evidence.
export default function Gateway() {
  // Live status ticks at 2s so telemetry visibly moves. The saved verdict board
  // changes only when a run finishes, so it polls slowly + on demand.
  const { data: status } = usePoll<GwStatus>(() => fetchGwStatus(), 2000);
  const { data: board, refresh: refreshBoard } = usePoll<GwBoard>(() => fetchGwReport(), 15000);
  const onRunDone = useCallback(() => refreshBoard(), [refreshBoard]);

  return (
    <div className="view-stack">
      <h1 className="page-title">LEXA-GW · Secure DER Gateway</h1>

      <ProofBanner board={board} />
      <InterfaceTopology status={status} />
      <LiveRunPanel onDone={onRunDone} />
      <VerdictBoard board={board} />
    </div>
  );
}
