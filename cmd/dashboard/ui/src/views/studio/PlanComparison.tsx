// Plan comparison (DESIGN_BRIEF.md §4.6): shown only when >1 tariff. Rows =
// tariffs, cols = policies, cells = total_usd. The best (lowest) LEXA cell is
// sage-soft highlighted; confidence badge per row; NEM carryover noted.

import { formatDollars } from '../../lib/format';
import { ConfidenceBadge } from './badges';
import type { WhatifResponse, Tariff } from './types';
import { runFor, POLICY_ORDER, POLICY_LABEL } from './types';

export function PlanComparison({
  response,
  tariffs,
}: {
  response: WhatifResponse;
  tariffs: Tariff[];
}) {
  if (tariffs.length < 2) return null;

  // Lowest With-LEXA total across plans = the best plan to be on.
  let bestId = '';
  let bestVal = Infinity;
  for (const t of tariffs) {
    const lexa = runFor(response.runs, t.id, 'der_lexa');
    if (lexa && lexa.bill.total_usd < bestVal) {
      bestVal = lexa.bill.total_usd;
      bestId = t.id;
    }
  }

  return (
    <div className="st-card">
      <div className="st-card-head">
        <h2 className="card-title">Plan comparison</h2>
        <div className="st-head-meta">monthly bill per plan · lowest With-LEXA highlighted</div>
      </div>
      <div className="st-table-wrap">
        <table className="st-table">
          <thead>
            <tr>
              <th>Plan</th>
              {POLICY_ORDER.map((p) => (
                <th key={p}>{POLICY_LABEL[p]}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {tariffs.map((t) => {
              const lexa = runFor(response.runs, t.id, 'der_lexa');
              const carry = lexa?.bill.credit_carryover_usd ?? 0;
              return (
                <tr key={t.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                      <ConfidenceBadge
                        confidence={t.provenance.confidence}
                        sourceUrl={t.provenance.source_url}
                        retrieved={t.provenance.retrieved}
                      />
                      <div>
                        <div style={{ fontWeight: 600, color: 'var(--ink)' }}>
                          {t.short_name || t.name}
                        </div>
                        {carry > 0 ? (
                          <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>
                            + {formatDollars(carry)} credits banked
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </td>
                  {POLICY_ORDER.map((p) => {
                    const run = runFor(response.runs, t.id, p);
                    const isBest = p === 'der_lexa' && t.id === bestId;
                    return (
                      <td key={p} className={isBest ? 'st-cell-best' : 'muted'}>
                        {run ? formatDollars(run.bill.total_usd) : '—'}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
