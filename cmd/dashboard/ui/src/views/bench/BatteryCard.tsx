import { useState } from 'react';
import { usePoll } from '../../lib/usePoll';
import { getJSON } from '../../lib/api';
import { formatWatts, formatPercent } from '../../lib/format';
import { POWER_COLORS } from '../../lib/colors';
import type { BatteryState } from './types';
import { SimCardShell, TelemRow, Expander } from './SimCardShell';
import { NumberField, TriStateSelect, ActionButton, InlineStatus } from './FormControls';
import { useInlineStatus } from './useInlineStatus';
import { simInject, simControl } from './simApi';
import { RegisterPanel } from './RegisterPanel';
import { BATTERY_ANN, BATTERY_RANGES } from './registerAnnotations';

const ACCENT = POWER_COLORS.battery;

function socColor(pct: number): string {
  if (pct < 20) return 'var(--s-critical)';
  if (pct < 50) return 'var(--s-warn)';
  return 'var(--s-good)';
}

export function BatteryCard() {
  const { data, error, refresh } = usePoll(() => getJSON<BatteryState>('/api/battery/state'), 1000);
  const { status, show } = useInlineStatus();
  const [regsOpen, setRegsOpen] = useState(false);

  const [soc, setSoc] = useState('');
  const [pct, setPct] = useState('');
  const [conn, setConn] = useState<'' | '1' | '0'>('');
  const [speed, setSpeed] = useState('');

  const doInject = async () => {
    const fields: Record<string, number> = {};
    if (soc !== '') fields.SoC_pct = parseFloat(soc);
    if (pct !== '') fields.WMaxLimPct_pct = parseFloat(pct);
    if (conn !== '') fields.Conn = parseFloat(conn);
    const ok = await simInject('battery', fields);
    show(ok ? '✓ injected' : '✗ failed', ok);
    if (ok) refresh();
  };

  const doControl = async (cmd: string) => {
    const ok = await simControl('battery', cmd);
    show(ok ? `✓ ${cmd}` : `✗ ${cmd} failed`, ok);
    if (ok) refresh();
  };

  const doSpeed = async () => {
    const v = parseFloat(speed);
    if (!Number.isFinite(v)) return;
    const ok = await simControl('battery', 'resume', v);
    show(ok ? `✓ speed ${v}×` : '✗ failed', ok);
    if (ok) refresh();
  };

  const reachable = !error || !!data;
  const m = data?.measurements;
  const b = data?.battery;
  const c = data?.controls;

  return (
    <SimCardShell
      title="Battery"
      accent={ACCENT}
      statusLabel={data?.animation.paused ? 'paused' : reachable ? 'live' : 'unreachable'}
      statusOk={reachable && !data?.animation.paused}
    >
      {!reachable ? (
        <div className="empty-state">Battery sim unreachable.</div>
      ) : (
        <div>
          <TelemRow
            label="W (+discharge / −charge)"
            value={m ? formatWatts(m.W_W) : '—'}
            valueColor={m && m.W_W > 50 ? ACCENT : m && m.W_W < -50 ? 'var(--c-blue)' : undefined}
          />
          <TelemRow label="SOC" value={b ? formatPercent(b.SoC_pct) : '—'} valueColor={b ? socColor(b.SoC_pct) : undefined} />
          <TelemRow label="SOH" value={b ? formatPercent(b.SoH_pct) : '—'} />
          <TelemRow label="Charge state" value={b ? `${b.ChaSt} — ${b.ChaSt_text}` : '—'} />
          <TelemRow
            label="Conn"
            value={c ? (c.Conn ? 'connected' : 'disconnected') : '—'}
            valueColor={c?.Conn ? 'var(--s-good)' : 'var(--s-critical)'}
          />
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <NumberField label="SoC_pct (0–100)" value={soc} onChange={setSoc} min={0} max={100} />
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
        {regsOpen && <RegisterPanel sim="battery" annotations={BATTERY_ANN} ranges={BATTERY_RANGES} />}
      </Expander>
    </SimCardShell>
  );
}
