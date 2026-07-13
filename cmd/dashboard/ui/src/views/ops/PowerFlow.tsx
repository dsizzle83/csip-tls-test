import { useEffect, useRef, useState } from 'react';
import { POWER_COLORS, token } from '../../lib/colors';
import { formatWatts } from '../../lib/format';
import type { HubStatus } from './types';
import { flowNodes, linkWidth, pushCapped } from './util';

// Power-flow diagram (brief §4.1) — the demo centerpiece. Five nodes on a
// hub-and-spoke around Home; SVG links whose width ∝ |W|, colored by the SOURCE
// entity at 70% opacity, with dash-flow animated in the real power direction.
// Battery charge/discharge and grid import/export flip their link direction.

const VB_W = 920;
const VB_H = 300;
const NODE_W = 190;
const NODE_H = 78;
const SPARK_N = 300; // 5 min @ 1 s

type NodeKey = 'solar' | 'grid' | 'battery' | 'home' | 'ev';

interface NodeDef {
  key: NodeKey;
  name: string;
  x: number;
  y: number;
  color: string;
}

function nodeDefs(): NodeDef[] {
  return [
    { key: 'solar', name: 'Solar', x: 24, y: 18, color: POWER_COLORS.solar },
    { key: 'grid', name: 'Grid', x: 24, y: 110, color: POWER_COLORS.grid },
    { key: 'battery', name: 'Battery', x: 24, y: 202, color: POWER_COLORS.battery },
    { key: 'home', name: 'Home', x: 376, y: 110, color: POWER_COLORS.home },
    { key: 'ev', name: 'EV', x: 706, y: 202, color: POWER_COLORS.ev },
  ];
}

interface LinkDef {
  key: string;
  from: [number, number]; // canonical draw start
  to: [number, number]; // canonical draw end
  watts: number; // signed in canonical sense (>0 flows from→to)
  color: string; // source-entity color
}

type Hist = Record<NodeKey, number[]>;
const EMPTY_HIST: Hist = { solar: [], grid: [], battery: [], home: [], ev: [] };

function sparkPoints(vals: number[], x: number, y: number, w: number, h: number): string {
  if (vals.length < 2) return '';
  let min = Infinity;
  let max = -Infinity;
  for (const v of vals) {
    if (v < min) min = v;
    if (v > max) max = v;
  }
  if (min === max) { min -= 1; max += 1; }
  const span = max - min;
  const n = vals.length;
  return vals
    .map((v, i) => {
      const px = x + (i / (n - 1)) * w;
      const py = y + h - ((v - min) / span) * h;
      return `${px.toFixed(1)},${py.toFixed(1)}`;
    })
    .join(' ');
}

/** Small filled triangle at the destination end, pointing along real flow. */
function arrowPoints(a: [number, number], b: [number, number]): string {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  // tip at 86% toward b, base 8px back, half-width 4.5px
  const tipX = a[0] + dx * 0.86;
  const tipY = a[1] + dy * 0.86;
  const bx = tipX - ux * 8;
  const by = tipY - uy * 8;
  const nx = -uy;
  const ny = ux;
  return `${tipX.toFixed(1)},${tipY.toFixed(1)} ${(bx + nx * 4.5).toFixed(1)},${(by + ny * 4.5).toFixed(1)} ${(bx - nx * 4.5).toFixed(1)},${(by - ny * 4.5).toFixed(1)}`;
}

export function PowerFlow({ status }: { status?: HubStatus }) {
  const [hist, setHist] = useState<Hist>(EMPTY_HIST);
  const lastTs = useRef<string>('');

  useEffect(() => {
    const ts = status?.timestamp;
    if (!ts || ts === lastTs.current || !status?.power) return;
    lastTs.current = ts;
    const n = flowNodes(status);
    setHist((prev) => ({
      solar: pushCapped(prev.solar, n.solar, SPARK_N),
      grid: pushCapped(prev.grid, n.grid, SPARK_N),
      battery: pushCapped(prev.battery, n.battery, SPARK_N),
      home: pushCapped(prev.home, n.home, SPARK_N),
      ev: pushCapped(prev.ev, n.ev, SPARK_N),
    }));
  }, [status]);

  const hasData = !!status?.power;
  const nodes = nodeDefs();
  const n = flowNodes(status);
  const vals: Record<NodeKey, number> = { solar: n.solar, grid: n.grid, battery: n.battery, home: n.home, ev: n.ev };

  const home = POWER_COLORS.home;
  const links: LinkDef[] = [
    // Solar always sources into the home bus.
    { key: 'solar', from: [214, 57], to: [376, 132], watts: n.solar, color: POWER_COLORS.solar },
    // Grid: canonical grid→home; import (>0) forward & grid-blue, export (<0) reverse & home-sourced.
    { key: 'grid', from: [214, 149], to: [376, 149], watts: n.grid, color: n.grid >= 0 ? POWER_COLORS.grid : home },
    // Battery: canonical battery→home; discharge (>0) forward & green, charge (<0) reverse & home-sourced.
    { key: 'battery', from: [214, 241], to: [376, 166], watts: n.battery, color: n.battery >= 0 ? POWER_COLORS.battery : home },
    // EV: always drawn from the home bus.
    { key: 'ev', from: [566, 166], to: [706, 224], watts: n.ev, color: home },
  ];

  const lineToken = token('--line');

  return (
    <div className="ops-card ops-flow-card">
      <div className="ops-card-head">
        <h2 className="card-title">Power Flow</h2>
        <div className="ops-head-meta">
          {hasData ? 'live · 1 s' : 'waiting for hub'}
        </div>
      </div>
      {!hasData ? (
        <p className="ops-empty">Waiting for the hub to report power — the flow lights up on the first status poll.</p>
      ) : (
        <svg className="ops-flow-svg" viewBox={`0 0 ${VB_W} ${VB_H}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label="Live power flow">
          {/* links behind nodes */}
          {links.map((l) => {
            const active = Math.abs(l.watts) >= 10;
            const forward = l.watts >= 0;
            const a = forward ? l.from : l.to; // real flow source
            const b = forward ? l.to : l.from; // real flow destination
            const mx = (l.from[0] + l.to[0]) / 2;
            const my = (l.from[1] + l.to[1]) / 2;
            const label = formatWatts(Math.abs(l.watts));
            const labelW = label.length * 6.6 + 10;
            return (
              <g key={l.key}>
                <path
                  d={`M ${l.from[0]} ${l.from[1]} L ${l.to[0]} ${l.to[1]}`}
                  fill="none"
                  stroke={active ? l.color : lineToken}
                  strokeOpacity={active ? 0.72 : 1}
                  strokeWidth={active ? linkWidth(l.watts) : 1.5}
                  strokeLinecap="round"
                  strokeDasharray={active ? '7 6' : undefined}
                  className={active ? `ops-link-live${forward ? '' : ' rev'}` : undefined}
                />
                {active && (
                  <polygon points={arrowPoints(a, b)} fill={l.color} fillOpacity={0.9} />
                )}
                {active && (
                  <>
                    <rect x={mx - labelW / 2} y={my - 9} width={labelW} height={18} rx={5} fill={token('--card')} stroke={lineToken} />
                    <text x={mx} y={my + 4} textAnchor="middle" className="ops-link-label">{label}</text>
                  </>
                )}
              </g>
            );
          })}

          {/* nodes */}
          {nodes.map((nd) => {
            const v = vals[nd.key];
            const sub =
              nd.key === 'battery' && status?.devices?.['battery-0']?.soc_pct != null
                ? `SOC ${status.devices['battery-0'].soc_pct!.toFixed(0)}%`
                : nd.key === 'ev' && status?.evse_stations?.[0]?.soc_pct != null
                  ? `SOC ${status.evse_stations[0].soc_pct!.toFixed(0)}%`
                  : nd.key === 'grid'
                    ? n.grid > 10 ? 'importing' : n.grid < -10 ? 'exporting' : 'balanced'
                    : nd.key === 'battery'
                      ? n.battery > 10 ? 'discharging' : n.battery < -10 ? 'charging' : 'idle'
                      : '';
            return (
              <g key={nd.key}>
                <rect x={nd.x} y={nd.y} width={NODE_W} height={NODE_H} rx={10} fill={token('--card')} stroke={lineToken} />
                <rect x={nd.x} y={nd.y + 12} width={4} height={NODE_H - 24} rx={2} fill={nd.color} />
                <text x={nd.x + 18} y={nd.y + 24} className="ops-node-name">{nd.name}</text>
                {sub && (
                  <text x={nd.x + NODE_W - 14} y={nd.y + 24} textAnchor="end" className="ops-node-sub">{sub}</text>
                )}
                <text x={nd.x + 18} y={nd.y + 48} className="ops-node-val">{formatWatts(nd.key === 'ev' || nd.key === 'solar' || nd.key === 'home' ? Math.abs(v) : v)}</text>
                <polyline
                  points={sparkPoints(hist[nd.key], nd.x + 16, nd.y + 54, NODE_W - 32, 16)}
                  fill="none"
                  stroke={nd.color}
                  strokeOpacity={0.85}
                  strokeWidth={1.4}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              </g>
            );
          })}
        </svg>
      )}
    </div>
  );
}
