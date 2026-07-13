// Assumptions & provenance (DESIGN_BRIEF.md §4): the credibility anchor —
// complete and quiet. Weather source + url + retrieved, the load-model sentence,
// per-tariff provenance (utility, confidence, source link, notes), engine line.

import { ConfidenceBadge } from './badges';
import type { WhatifResponse, Tariff } from './types';

export function ProvenanceCard({
  response,
  tariffs,
}: {
  response: WhatifResponse;
  tariffs: Tariff[];
}) {
  const prov = response.provenance;
  const utilityById = new Map(tariffs.map((t) => [t.id, t.utility]));
  const weatherUrl = response.scenario.weather.source_url;

  return (
    <div className="st-card">
      <div className="st-card-head">
        <h2 className="card-title">Assumptions & provenance</h2>
      </div>
      <div className="st-prov">
        <div className="st-prov-row">
          <div className="st-prov-k">Weather</div>
          <div className="st-prov-v">
            {prov.weather}
            {weatherUrl ? (
              <>
                {' '}
                <a href={weatherUrl} target="_blank" rel="noreferrer">
                  source
                </a>
              </>
            ) : null}
          </div>
        </div>

        <div className="st-prov-row">
          <div className="st-prov-k">Load model</div>
          <div className="st-prov-v">{prov.load_model}</div>
        </div>

        <div className="st-prov-row">
          <div className="st-prov-k">Tariffs</div>
          <div className="st-prov-v">
            {prov.tariffs.map((t) => (
              <div key={t.tariff_id} className="st-prov-tariff">
                <div className="st-prov-tariff-head">
                  <ConfidenceBadge
                    confidence={t.confidence}
                    sourceUrl={t.source_url}
                    retrieved={t.retrieved}
                  />
                  <span className="st-prov-tariff-name">{t.name}</span>
                </div>
                <div style={{ fontSize: 11.5 }}>
                  {utilityById.get(t.tariff_id) ? (
                    <span style={{ color: 'var(--ink-2)' }}>
                      {utilityById.get(t.tariff_id)} ·{' '}
                    </span>
                  ) : null}
                  <span style={{ textTransform: 'capitalize', color: 'var(--ink-2)' }}>
                    {t.confidence}
                  </span>
                  {t.source_url ? (
                    <>
                      {' · '}
                      <a href={t.source_url} target="_blank" rel="noreferrer">
                        rate sheet
                      </a>
                      {' · retrieved '}
                      {t.retrieved}
                    </>
                  ) : null}
                </div>
                {t.notes ? <div className="st-prov-notes">{t.notes}</div> : null}
              </div>
            ))}
          </div>
        </div>

        <div className="st-prov-row">
          <div className="st-prov-k">Engine</div>
          <div className="st-prov-v">{prov.engine}</div>
        </div>
      </div>
    </div>
  );
}
