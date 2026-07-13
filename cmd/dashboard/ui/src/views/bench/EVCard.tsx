import { useState } from 'react';
import { usePoll } from '../../lib/usePoll';
import { getJSON } from '../../lib/api';
import { formatWatts, formatPercent, formatClock } from '../../lib/format';
import { POWER_COLORS } from '../../lib/colors';
import type { EVState } from './types';
import { SimCardShell, TelemRow } from './SimCardShell';
import { NumberField, ActionButton, InlineStatus } from './FormControls';
import { useInlineStatus } from './useInlineStatus';
import { evInject } from './simApi';

const ACCENT = POWER_COLORS.ev;

function socColor(pct: number): string {
  if (pct < 20) return 'var(--s-critical)';
  if (pct < 50) return 'var(--s-warn)';
  return 'var(--s-good)';
}

export function EVCard() {
  const { data, error, refresh } = usePoll(() => getJSON<EVState>('/api/ev/state'), 1000);
  const { status, show } = useInlineStatus();
  const [soc, setSoc] = useState('');

  const doSetSoc = async () => {
    const v = parseFloat(soc);
    if (!Number.isFinite(v)) return;
    const ok = await evInject('set_soc', { soc_pct: v });
    show(ok ? `✓ SOC set to ${v}%` : '✗ failed', ok);
    if (ok) refresh();
  };

  const doSession = async (action: 'start_session' | 'stop_session') => {
    const ok = await evInject(action, { connector_id: 1 });
    show(ok ? `✓ ${action}` : `✗ ${action} failed`, ok);
    if (ok) setTimeout(refresh, 500);
  };

  const reachable = !error || !!data;
  const b = data?.battery;
  const session = data?.session;
  const connector = data?.connectors[0];
  const csmsOk = data?.csms.connected ?? false;

  return (
    <SimCardShell
      title="EV Charger"
      accent={ACCENT}
      statusLabel={csmsOk ? 'CSMS connected' : reachable ? 'CSMS offline' : 'unreachable'}
      statusOk={reachable && csmsOk}
    >
      {!reachable ? (
        <div className="empty-state">EV sim unreachable.</div>
      ) : (
        <div>
          <TelemRow label="Connector" value={connector?.status ?? '—'} />
          <TelemRow
            label="Session"
            value={session?.active ? 'active' : 'idle'}
            valueColor={session?.active ? 'var(--s-good)' : undefined}
          />
          <TelemRow label="SOC" value={b ? formatPercent(b.soc_pct) : '—'} valueColor={b ? socColor(b.soc_pct) : undefined} />
          <TelemRow label="Power" value={b ? formatWatts(b.power_W) : '—'} valueColor={ACCENT} />
          <TelemRow label="Current" value={b ? `${b.current_A.toFixed(1)} A` : '—'} />
          <TelemRow label="Phase" value={b?.phase ?? '—'} />
          {session?.started_at && <TelemRow label="Started" value={formatClock(session.started_at)} />}
          {data?.last_charging_profile && (
            <TelemRow label="Charging limit" value={`${data.last_charging_profile.limit_A.toFixed(1)} A`} />
          )}
        </div>
      )}

      <div style={{ display: 'flex', gap: 6, alignItems: 'flex-end' }}>
        <NumberField label="Set SOC (%)" value={soc} onChange={setSoc} min={0} max={100} placeholder="e.g. 20" />
        <ActionButton onClick={doSetSoc} primary>
          Set
        </ActionButton>
      </div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        <ActionButton onClick={() => doSession('start_session')}>Start Session</ActionButton>
        <ActionButton onClick={() => doSession('stop_session')}>Stop Session</ActionButton>
      </div>
      {status && <InlineStatus text={status.text} ok={status.ok} />}
    </SimCardShell>
  );
}
