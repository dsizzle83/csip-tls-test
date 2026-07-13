import { useState } from 'react';
import { usePoll } from '../../lib/usePoll';
import { getJSON } from '../../lib/api';
import { formatWatts, formatPercent } from '../../lib/format';
import { POWER_COLORS } from '../../lib/colors';
import type { SolarState } from './types';
import { SimCardShell, TelemRow, Expander } from './SimCardShell';
import { NumberField, TriStateSelect, ActionButton, InlineStatus } from './FormControls';
import { useInlineStatus } from './useInlineStatus';
import { simInject, simControl } from './simApi';
import { RegisterPanel } from './RegisterPanel';
import { SOLAR_ANN, SOLAR_RANGES } from './registerAnnotations';

const ACCENT = POWER_COLORS.solar;

export function SolarCard() {
  const { data, error, refresh } = usePoll(() => getJSON<SolarState>('/api/solar/state'), 1000);
  const { status, show } = useInlineStatus();
  const [regsOpen, setRegsOpen] = useState(false);

  const [w, setW] = useState('');
  const [pct, setPct] = useState('');
  const [conn, setConn] = useState<'' | '1' | '0'>('');
  const [speed, setSpeed] = useState('');

  const doInject = async () => {
    const fields: Record<string, number> = {};
    if (w !== '') fields.W_W = parseFloat(w);
    if (pct !== '') fields.WMaxLimPct_pct = parseFloat(pct);
    if (conn !== '') fields.Conn = parseFloat(conn);
    const ok = await simInject('solar', fields);
    show(ok ? '✓ injected' : '✗ failed', ok);
    if (ok) refresh();
  };

  const doControl = async (cmd: string) => {
    const ok = await simControl('solar', cmd);
    show(ok ? `✓ ${cmd}` : `✗ ${cmd} failed`, ok);
    if (ok) refresh();
  };

  const doSpeed = async () => {
    const v = parseFloat(speed);
    if (!Number.isFinite(v)) return;
    const ok = await simControl('solar', 'resume', v);
    show(ok ? `✓ speed ${v}×` : '✗ failed', ok);
    if (ok) refresh();
  };

  const reachable = !error || !!data;
  const m = data?.measurements;
  const c = data?.controls;

  return (
    <SimCardShell
      title="Solar"
      accent={ACCENT}
      statusLabel={data?.animation.paused ? 'paused' : reachable ? 'live' : 'unreachable'}
      statusOk={reachable && !data?.animation.paused}
    >
      {!reachable ? (
        <div className="empty-state">Solar sim unreachable.</div>
      ) : (
        <div>
          <TelemRow label="W (current)" value={m ? formatWatts(m.W_W) : '—'} valueColor={ACCENT} />
          <TelemRow label="Possible W" value={m ? formatWatts(m.possible_W) : '—'} />
          <TelemRow label="Ceiling (nameplate)" value={data ? formatWatts(data.nameplate.wmax_W) : '—'} />
          <TelemRow label="State" value={m ? `${m.St} — ${m.St_text}` : '—'} />
          <TelemRow
            label="Conn"
            value={c ? (c.Conn ? 'connected' : 'disconnected') : '—'}
            valueColor={c?.Conn ? 'var(--s-good)' : 'var(--s-critical)'}
          />
          <TelemRow label="WMaxLimPct" value={c ? formatPercent(c.WMaxLimPct_pct) : '—'} />
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <NumberField label="W_W override" value={w} onChange={setW} placeholder="pause first" />
        <NumberField label="WMaxLimPct (0–100)" value={pct} onChange={setPct} min={0} max={100} />
        <TriStateSelect label="Conn" value={conn} onChange={setConn} />
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
        <ActionButton onClick={doInject} primary>
          Inject
        </ActionButton>
        <ActionButton onClick={() => doControl('pause')}>Pause</ActionButton>
        <ActionButton onClick={() => doControl('resume')}>Resume</ActionButton>
        <ActionButton onClick={() => doControl('reset')}>Reset</ActionButton>
      </div>
      <div style={{ display: 'flex', gap: 6, alignItems: 'flex-end' }}>
        <NumberField label="Speed multiplier" value={speed} onChange={setSpeed} placeholder="e.g. 5" min={0.1} step={0.1} />
        <ActionButton onClick={doSpeed}>Set</ActionButton>
      </div>
      {status && <InlineStatus text={status.text} ok={status.ok} />}

      <Expander label="Registers" open={regsOpen} onToggle={() => setRegsOpen((v) => !v)}>
        {regsOpen && <RegisterPanel sim="solar" annotations={SOLAR_ANN} ranges={SOLAR_RANGES} />}
      </Expander>
    </SimCardShell>
  );
}
