// Hero strip (DESIGN_BRIEF.md §4.1): Without LEXA (gray) / With LEXA (green,
// sage fill) / Saved $ + % (hero, bolt underline). Uses the FOCUS tariff's
// numbers; caption names the plan. Quiet provenance line underneath.

import { formatDollars, formatPercent } from '../../lib/format';
import { ConfidenceBadge } from './badges';
import type { WhatifResponse, Tariff } from './types';
import { runFor, savingsFor } from './types';

export function HeroStrip({
  response,
  focusTariffId,
  tariffs,
}: {
  response: WhatifResponse;
  focusTariffId: string;
  tariffs: Tariff[];
}) {
  const baseline = runFor(response.runs, focusTariffId, 'baseline');
  const lexa = runFor(response.runs, focusTariffId, 'der_lexa');
  const saved = savingsFor(response.savings, focusTariffId, 'der_lexa');
  const tariff = tariffs.find((t) => t.id === focusTariffId);
  const monthLabel = new Date(response.scenario.period.start + 'T00:00').toLocaleDateString(
    'en-US',
    { month: 'long' }
  );

  if (!baseline || !lexa || !saved) {
    return null;
  }

  return (
    <div>
      <div className="st-hero">
        <div className="st-tile">
          <div className="st-tile-label">Without LEXA</div>
          <div className="st-tile-num gray">{formatDollars(baseline.bill.total_usd)}</div>
          <div className="st-tile-sub">Baseline — no solar, battery or smart charging</div>
        </div>
        <div className="st-tile lexa">
          <div className="st-tile-label">With LEXA</div>
          <div className="st-tile-num green">{formatDollars(lexa.bill.total_usd)}</div>
          <div className="st-tile-sub">LEXA policy model — TOU-aware dispatch</div>
        </div>
        <div className="st-tile saved">
          <div className="st-tile-label">Saved this {monthLabel}</div>
          <div className="st-tile-num hero">{formatDollars(saved.usd)}</div>
          <div className="st-tile-sub">
            {formatPercent(saved.pct)} lower bill
            {tariff ? ` · ${tariff.short_name || tariff.name}` : ''}
          </div>
        </div>
      </div>

      <div className="st-provline" style={{ marginTop: 12 }}>
        <span>{response.scenario.weather.source} weather</span>
        <span className="sep">·</span>
        <span>
          {response.scenario.location.city}, {response.scenario.location.state}
        </span>
        {tariff ? (
          <>
            <span className="sep">·</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {tariff.short_name} rate confidence
              <ConfidenceBadge
                confidence={tariff.provenance.confidence}
                sourceUrl={tariff.provenance.source_url}
                retrieved={tariff.provenance.retrieved}
              />
            </span>
          </>
        ) : null}
      </div>
    </div>
  );
}
