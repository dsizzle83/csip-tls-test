import { useState } from 'react';
import { usePoll } from '../../lib/usePoll';
import { getJSON } from '../../lib/api';
import { formatWatts, formatWh } from '../../lib/format';
import { POWER_COLORS } from '../../lib/colors';
import type { MeterState } from './types';
import { SimCardShell, TelemRow } from './SimCardShell';
import { NumberField, ActionButton, InlineStatus } from './FormControls';
import { useInlineStatus } from './useInlineStatus';
import { simInject, simControl } from './simApi';

// "Meter" isn't in the brief's power-entity table (Solar/Battery/Grid/Home/EV)
// — it's the instrument measuring the grid connection point, so it wears the
// Grid entity's color.
const ACCENT = POWER_COLORS.grid;

// The meter sim has no server-side "mode" field (checked sim/southbound/meter.go,
// sim/metersim/main.go — no `mode` key anywhere in state/inject/control). The
// brief asks for "grid W, load W, mode" for this card; read as the natural
// derived flow direction off the signed grid W (positive = importing,
// negative = exporting — sim/southbound/meter.go).
function flowMode(w: number): { label: string; color: string } {
  if (w > 25) return { label: 'Importing', color: 'var(--c-blue)' };
  if (w < -25) return { label: 'Exporting', color: 'var(--c-green)' };
  return { label: 'Balanced', color: 'var(--ink-3)' };
}

export function MeterCard() {
  const { data, error, refresh } = usePoll(() => getJSON<MeterState>('/api/meter/state'), 1000);
  const { status, show } = useInlineStatus();

  const [w, setW] = useState('');
  const [v, setV] = useState('');
  const [hz, setHz] = useState('');
  const [loadW, setLoadW] = useState('');
  const [speed, setSpeed] = useState('');

  const doInject = async () => {
    const fields: Record<string, number> = {};
    if (w !== '') fields.W_W = parseFloat(w);
    if (v !== '') fields.V_V = parseFloat(v);
    if (hz !== '') fields.Hz_Hz = parseFloat(hz);
    if (loadW !== '') fields.LoadW_W = parseFloat(loadW);
    const ok = await simInject('meter', fields);
    show(ok ? '✓ injected' : '✗ failed', ok);
    if (ok) refresh();
  };

  const doControl = async (cmd: string) => {
    const ok = await simControl('meter', cmd);
    show(ok ? `✓ ${cmd}` : `✗ ${cmd} failed`, ok);
    if (ok) refresh();
  };

  const doSpeed = async () => {
    const val = parseFloat(speed);
    if (!Number.isFinite(val)) return;
    const ok = await simControl('meter', 'resume', val);
    show(ok ? `✓ speed ${val}×` : '✗ failed', ok);
    if (ok) refresh();
  };

  const reachable = !error || !!data;
  const m = data?.measurements;
  const eb = data?.energy_balance;
  const mode = m ? flowMode(m.W_W) : undefined;

  return (
    <SimCardShell title="Meter" accent={ACCENT} statusLabel={reachable ? 'live' : 'unreachable'} statusOk={reachable}>
      {!reachable ? (
        <div className="empty-state">Meter sim unreachable.</div>
      ) : (
        <div>
          <TelemRow label="Grid W" value={m ? formatWatts(m.W_W) : '—'} valueColor={ACCENT} />
          <TelemRow label="Mode" value={mode?.label ?? '—'} valueColor={mode?.color} />
          <TelemRow label="Load W" value={eb ? formatWatts(eb.load_W) : '—'} />
          <TelemRow label="From solar" value={eb ? formatWatts(eb.source_solar_W) : '—'} />
          <TelemRow label="From battery" value={eb ? formatWatts(eb.source_battery_W) : '—'} />
          <TelemRow label="EV load" value={eb ? formatWatts(eb.load_ev_W) : '—'} />
          <TelemRow label="Imported (total)" value={m ? formatWh(m.TotWhImp_Wh) : '—'} />
          <TelemRow label="Exported (total)" value={m ? formatWh(m.TotWhExp_Wh) : '—'} />
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <NumberField label="W_W override" value={w} onChange={setW} />
        <NumberField label="V_V override" value={v} onChange={setV} />
        <NumberField label="Hz_Hz override" value={hz} onChange={setHz} />
        <NumberField label="Load W (linked mode)" value={loadW} onChange={setLoadW} />
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
        <ActionButton onClick={doInject} primary>
          Inject
        </ActionButton>
        <ActionButton onClick={() => doControl('pause')}>Pause</ActionButton>
        <ActionButton onClick={() => doControl('resume')}>Resume</ActionButton>
      </div>
      <div style={{ display: 'flex', gap: 6, alignItems: 'flex-end' }}>
        <NumberField label="Speed multiplier" value={speed} onChange={setSpeed} placeholder="e.g. 5" min={0.1} step={0.1} />
        <ActionButton onClick={doSpeed}>Set</ActionButton>
      </div>
      {status && <InlineStatus text={status.text} ok={status.ok} />}
    </SimCardShell>
  );
}
