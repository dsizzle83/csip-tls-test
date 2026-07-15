import { getJSON } from '../../lib/api';
import { usePoll } from '../../lib/usePoll';
import { formatWatts, formatClock } from '../../lib/format';
import type { AdminProgram, AdminStatus, DerBase, HubStatus, TariffResp } from './types';
import { evalLimit, formatCountdown, serverNowS } from './util';

// CSIP Protocol Inspector (brief §4.4): the "criteria the grid is using" proof
// surface. LEFT = what gridsim advertises, MIDDLE = what the hub adopted,
// RIGHT = what the meter measures against the adopted limit. mRID match links
// advertised↔adopted (sage highlight); a mismatch gets an --s-warn outline.

function baseKV(base?: DerBase): [string, string][] {
  if (!base) return [];
  const out: [string, string][] = [];
  const w = (label: string, v?: number) => { if (v != null) out.push([label, formatWatts(v)]); };
  w('exp', base.exp_lim_W);
  w('imp', base.imp_lim_W);
  w('gen', base.gen_lim_W);
  w('max', base.max_lim_W);
  w('load', base.load_lim_W);
  w('fixed', base.fixed_W);
  if (base.connect != null) out.push(['connect', base.connect ? 'on' : 'off']);
  if (base.energize != null) out.push(['energize', base.energize ? 'on' : 'off']);
  if (base.fixed_var_pct != null) out.push(['var%', String(base.fixed_var_pct)]);
  // Phase 3: when a DER function curve is bound to this control, name the mode
  // right beside the reactive-power setting it drives (absent until the curve
  // backend populates curve_mode).
  if (base.curve_mode) out.push(['curve', CURVE_MODE_LABEL[base.curve_mode] ?? String(base.curve_mode)]);
  return out;
}

// SunSpec curve-mode → human label for the Protocol Inspector KV rows.
const CURVE_MODE_LABEL: Record<string, string> = {
  volt_var: 'Volt-VAr',
  volt_watt: 'Volt-Watt',
  freq_watt: 'Freq-Watt',
  watt_pf: 'Watt-PF',
};

function KV({ pairs }: { pairs: [string, string][] }) {
  if (!pairs.length) return <span className="ops-col-sub" style={{ margin: 0 }}>no limits</span>;
  return (
    <div className="ops-kv">
      {pairs.map(([k, v]) => (
        <div key={k}><span className="k">{k} </span><span className="v">{v}</span></div>
      ))}
    </div>
  );
}

const CTRL_STATUS = ['Scheduled', 'Active', 'Cancelled', 'Cancelled w/ Randomization', 'Superseded'];

function AdvertisedProgram({ p, matched, serverNow }: { p: AdminProgram; matched: boolean; serverNow: number }) {
  const active = p.active ?? [];
  // gridsim keeps an active control in BOTH its derc (scheduled) and actderc
  // (active) lists; don't render the same mRID twice.
  const activeMrids = new Set(active.map((c) => c.mrid));
  const scheduled = (p.scheduled ?? []).filter((c) => !activeMrids.has(c.mrid));
  return (
    <div className={`ops-prog${matched ? ' matched' : ''}`}>
      <div className="ops-prog-head">
        <span className="ops-prog-mrid">{p.mrid}</span>
        <span className="ops-badge-primacy">primacy {p.primacy}</span>
      </div>
      <div className="ops-prog-desc">{p.description}</div>
      {p.default && baseKV(p.default).length > 0 && (
        <div className="ops-ctrl">
          <div className="ops-col-sub" style={{ margin: '0 0 2px' }}>DefaultDERControl</div>
          <KV pairs={baseKV(p.default)} />
        </div>
      )}
      {active.map((c) => (
        <div className="ops-ctrl is-active" key={c.mrid}>
          <div className="ops-ctrl-mrid">{c.mrid}</div>
          <KV pairs={baseKV(c.base)} />
          <div className="ops-kv">
            <div><span className="k">status </span><span className="v">{CTRL_STATUS[c.status] ?? c.status}</span></div>
            <div><span className="k">start </span><span className="v">{formatClock(c.start)}</span></div>
            <div><span className="k">dur </span><span className="v">{c.duration_s}s</span></div>
            <div><span className="k">ends in </span><span className="v">{formatCountdown(c.start + c.duration_s - serverNow)}</span></div>
          </div>
        </div>
      ))}
      {scheduled.map((c) => (
        <div className="ops-ctrl" key={c.mrid}>
          <div className="ops-ctrl-mrid">{c.mrid}</div>
          <KV pairs={baseKV(c.base)} />
          <div className="ops-kv">
            <div><span className="k">status </span><span className="v">{CTRL_STATUS[c.status] ?? c.status}</span></div>
            <div><span className="k">start </span><span className="v">{formatClock(c.start)}</span></div>
            <div><span className="k">dur </span><span className="v">{c.duration_s}s</span></div>
          </div>
        </div>
      ))}
    </div>
  );
}

function TariffBlock({ tariff, serverNow }: { tariff: TariffResp | null | undefined; serverNow: number }) {
  const intervals = Array.isArray(tariff?.intervals) ? tariff!.intervals! : [];
  if (intervals.length === 0) {
    return <div className="ops-prog"><div className="ops-col-sub" style={{ margin: 0 }}>No tariff loaded.</div></div>;
  }
  // Defensive: the endpoint ships later tonight with an unconfirmed shape.
  const price = (iv: { import_per_kwh?: number; price?: number }) => iv.import_per_kwh ?? iv.price;
  const next = intervals.find((iv) => (iv.start ?? 0) > serverNow);
  return (
    <div className="ops-prog">
      <div className="ops-col-sub" style={{ margin: '0 0 4px' }}>Tariff · {intervals.length} intervals</div>
      {next?.start != null && (
        <div className="ops-kv"><div><span className="k">next change in </span><span className="v">{formatCountdown(next.start - serverNow)}</span></div></div>
      )}
      <div className="ops-kv">
        {intervals.slice(0, 6).map((iv, i) => (
          <div key={i}><span className="k">{iv.start != null ? formatClock(iv.start) : `#${i}`} </span><span className="v">{price(iv) != null ? `$${price(iv)!.toFixed(3)}` : '—'}</span></div>
        ))}
      </div>
    </div>
  );
}

export function ProtocolInspector({ status }: { status?: HubStatus }) {
  const { data: admin } = usePoll<AdminStatus>(() => getJSON<AdminStatus>('/api/gridsim/admin/status'), 2000);
  const { data: tariff } = usePoll<TariffResp | null>(
    () => getJSON<TariffResp>('/api/gridsim/admin/tariff').catch(() => null),
    30000
  );

  const serverNow = serverNowS(status);
  const csip = status?.csip_control;
  const adoptedMrid = csip?.mrid;
  const isEvent = csip?.source === 'event';

  const matchedProgram = admin?.programs.find((p) => (p.active ?? []).some((c) => c.mrid === adoptedMrid));
  const matched = isEvent && !!matchedProgram;
  const mismatch = isEvent && !matchedProgram;

  const limit = evalLimit(csip?.base, status?.power);
  const grid = status?.power?.grid_W;
  const remaining = csip?.valid_until != null ? csip.valid_until - serverNow : null;

  return (
    <div className="ops-card">
      <div className="ops-card-head">
        <h2 className="card-title">CSIP Protocol Inspector</h2>
        <div className="ops-head-meta">the criteria the grid is enforcing</div>
      </div>
      <div className="ops-inspector">
        {/* LEFT — Advertised */}
        <div>
          <p className="ops-col-title">Advertised · gridsim</p>
          <p className="ops-col-sub">IEEE 2030.5 programs, controls &amp; default</p>
          <div className="ops-col-body">
            {!admin ? (
              <p className="ops-empty">gridsim admin unreachable.</p>
            ) : (
              <>
                {admin.programs.map((p) => (
                  <AdvertisedProgram key={p.id} p={p} matched={matched && matchedProgram?.id === p.id} serverNow={serverNow} />
                ))}
                <TariffBlock tariff={tariff} serverNow={serverNow} />
              </>
            )}
          </div>
        </div>

        {/* MIDDLE — Adopted */}
        <div>
          <p className="ops-col-title">Adopted · hub</p>
          <p className="ops-col-sub">the control the hub is honoring now</p>
          <div className="ops-col-body">
            {!csip ? (
              <p className="ops-empty">Hub has not reported an adopted control.</p>
            ) : (
              <div className={`ops-adopted${matched ? ' matched' : ''}${mismatch ? ' warn' : ''}`}>
                <div className="ops-prog-head">
                  <span className={`ops-chip ${isEvent ? 'ops-chip-rule' : 'ops-chip-neutral'}`}>{csip.source}</span>
                  {matched && <span className="ops-chip ops-chip-pass" title="mRID matches an advertised active control">✓ linked</span>}
                  {mismatch && <span className="ops-chip ops-chip-warn" title="Adopted mRID not found in advertised active controls">⚠ mismatch</span>}
                </div>
                <div className="ops-ctrl-mrid" style={{ marginTop: 6 }}>{csip.mrid}</div>
                <div style={{ marginTop: 8 }}><KV pairs={baseKV(csip.base)} /></div>
                <div style={{ marginTop: 12 }}>
                  <div className="ops-stat-label">Valid until</div>
                  {remaining != null ? (
                    <div className={`ops-countdown${remaining < 60 ? ' soon' : ''}`}>{formatCountdown(remaining)}</div>
                  ) : (
                    <div className="ops-col-sub" style={{ margin: '2px 0 0' }}>no expiry (default control)</div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT — Measured */}
        <div>
          <p className="ops-col-title">Measured · meter</p>
          <p className="ops-col-sub">real grid power vs the adopted limit</p>
          <div className="ops-col-body">
            {grid == null ? (
              <p className="ops-empty">No meter reading.</p>
            ) : (
              <div className="ops-adopted">
                <div className="ops-stat-label">Grid power</div>
                <div className="ops-meas-big">{formatWatts(grid)}</div>
                <div className="ops-meas-dir">{grid > 10 ? '▲ importing' : grid < -10 ? '▼ exporting' : 'balanced'}</div>
                {limit ? (
                  <>
                    <div className="ops-meter-bar">
                      <div
                        className="ops-meter-fill"
                        style={{
                          width: `${Math.min(100, (limit.metricW / Math.max(1, limit.limitW)) * 100).toFixed(0)}%`,
                          background: limit.within ? 'var(--s-good)' : 'var(--s-critical)',
                        }}
                      />
                    </div>
                    <div className="ops-kv" style={{ marginTop: 8 }}>
                      <div><span className="k">{limit.label}</span></div>
                      <div><span className="k">now </span><span className="v">{formatWatts(limit.metricW)}</span></div>
                    </div>
                    <div style={{ marginTop: 10 }}>
                      {limit.within ? (
                        <span className="ops-chip ops-chip-pass">✓ Within limit</span>
                      ) : (
                        <span className="ops-chip ops-chip-fail">✕ Breach</span>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="ops-col-sub" style={{ margin: '12px 0 0' }}>No active numeric limit — hub on {csip?.source === 'default' ? 'default control' : 'a non-limiting control'}.</div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
