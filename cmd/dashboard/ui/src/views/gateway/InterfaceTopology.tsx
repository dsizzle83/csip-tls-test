import type { GwStatus, GwIface } from './types';

// InterfaceTopology — the live wiring the gateway bridges: southbound DERs (one
// plain SunSpec Modbus, one Secure SunSpec Modbus/mTLS) on the left, the gateway
// in the middle, the northbound grid parties (Secure Modbus aggregator + IEEE
// 2030.5/CSIP) on the right. Each edge shows a live health dot + a moving metric
// so a viewer sees the gateway is genuinely polling and controlling, not mocked.
function IfaceCard({ iface }: { iface: GwIface }) {
  return (
    <div className={`gw-if${iface.up ? '' : ' gw-if-down'}`}>
      <div className="gw-if-head">
        <span className={`gw-dot${iface.up ? ' gw-dot-up' : ' gw-dot-down'}`} aria-hidden="true" />
        <span className="gw-if-proto">{iface.proto}</span>
        {iface.secure ? (
          <span className="gw-lock" title="mutual TLS">🔒</span>
        ) : (
          <span className="gw-lock gw-lock-off" title="plaintext">◌</span>
        )}
      </div>
      <div className="gw-if-detail">{iface.detail}</div>
      <div className="gw-if-metric gw-mono">{iface.metric || (iface.up ? 'live' : '—')}</div>
    </div>
  );
}

export function InterfaceTopology({ status }: { status: GwStatus | undefined }) {
  const ifaces = status?.interfaces ?? [];
  const south = ifaces.filter((i) => i.dir === 'south');
  const north = ifaces.filter((i) => i.dir === 'north');

  return (
    <section className="gw-card">
      <header className="gw-card-head">
        <h2>Live interface topology</h2>
        <span className="gw-card-sub">
          {status ? (
            <>
              gateway <span className="gw-mono">{status.host}</span> ·{' '}
              <span className={status.reachable ? 'gw-ok' : 'gw-bad'}>
                {status.reachable ? 'reachable' : 'unreachable'}
              </span>
            </>
          ) : (
            'connecting…'
          )}
        </span>
      </header>

      <div className="gw-topo">
        <div className="gw-topo-col">
          <div className="gw-topo-label">Southbound · DERs</div>
          {south.map((i) => (
            <IfaceCard key={i.id} iface={i} />
          ))}
        </div>

        <div className="gw-topo-core" aria-hidden="true">
          <div className="gw-topo-arrow">→</div>
          <div className={`gw-core${status?.reachable ? ' gw-core-up' : ''}`}>
            <div className="gw-core-name">LEXA-GW</div>
            <div className="gw-core-sub">secure DER gateway</div>
          </div>
          <div className="gw-topo-arrow">→</div>
        </div>

        <div className="gw-topo-col">
          <div className="gw-topo-label">Northbound · Grid</div>
          {north.map((i) => (
            <IfaceCard key={i.id} iface={i} />
          ))}
        </div>
      </div>
    </section>
  );
}
