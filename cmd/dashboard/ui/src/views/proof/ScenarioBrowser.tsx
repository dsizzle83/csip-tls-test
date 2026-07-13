// Scenario browser (brief §4.2): filterable table of the 69 curated scenarios
// with checkbox selection + presets. Selection state is lifted to Proof.tsx so
// the run panel can start exactly what's checked.

import { Fragment, useMemo, useState } from 'react';
import type { ScenarioInfo } from './types';
import { Chip } from './chips';
import { QUICK_SWEEP_IDS } from './verdict';

export function ScenarioBrowser({
  scenarios,
  selected,
  onSelectedChange,
}: {
  scenarios: ScenarioInfo[];
  selected: Set<string>;
  onSelectedChange: (next: Set<string>) => void;
}) {
  const [category, setCategory] = useState('');
  const [source, setSource] = useState('');
  const [query, setQuery] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const categories = useMemo(
    () => Array.from(new Set(scenarios.map((s) => s.category))).sort(),
    [scenarios]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return scenarios.filter((s) => {
      if (category && s.category !== category) return false;
      if (source && (s.source || 'go') !== source) return false;
      if (q && !`${s.id} ${s.name} ${s.hypothesis}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [scenarios, category, source, query]);

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onSelectedChange(next);
  };
  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  };

  // Presets operate on the FULL catalogue, not the current filter.
  const preset = (kind: 'quick' | 'curated' | 'extended') => {
    if (kind === 'quick') {
      const avail = new Set(scenarios.map((s) => s.id));
      onSelectedChange(new Set(QUICK_SWEEP_IDS.filter((id) => avail.has(id))));
    } else if (kind === 'curated') {
      onSelectedChange(new Set(scenarios.filter((s) => !s.extended).map((s) => s.id)));
    } else {
      onSelectedChange(new Set(scenarios.map((s) => s.id)));
    }
  };

  const selectFiltered = () => {
    const next = new Set(selected);
    for (const s of filtered) next.add(s.id);
    onSelectedChange(next);
  };
  const clearAll = () => onSelectedChange(new Set());

  const extCount = scenarios.filter((s) => s.extended).length;
  const curatedCount = scenarios.length - extCount;

  return (
    <div className="pf-card">
      <div className="pf-card-head">
        <h2 className="card-title">Scenario library</h2>
        <span className="pf-head-meta">
          {scenarios.length} scenarios · {curatedCount} curated · {extCount} extended
        </span>
      </div>

      <div className="pf-preset-row">
        <span style={{ fontSize: 11, color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Presets
        </span>
        <button type="button" className="pf-btn" onClick={() => preset('quick')} title="7 fast, well-known scenarios">
          Quick sweep · 7
        </button>
        <button type="button" className="pf-btn" onClick={() => preset('curated')} title="All non-extended scenarios">
          Full curated · {curatedCount}
        </button>
        <button type="button" className="pf-btn" onClick={() => preset('extended')} title="Every scenario incl. long-running dither (include_extended)">
          + Extended · {scenarios.length}
        </button>
        <span style={{ flex: 1 }} />
        <button type="button" className="pf-btn" onClick={selectFiltered} disabled={filtered.length === 0}>
          Select filtered
        </button>
        <button type="button" className="pf-btn" onClick={clearAll} disabled={selected.size === 0}>
          Clear
        </button>
        <span className="pf-count-note">{selected.size} selected</span>
      </div>

      <div className="pf-filter-row">
        <select className="pf-select" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories ({categories.length})</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select className="pf-select" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">All sources</option>
          <option value="go">go</option>
          <option value="spec">spec</option>
        </select>
        <input
          className="pf-input mono"
          type="text"
          placeholder="search id / name / hypothesis…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <span className="pf-count-note">{filtered.length} shown</span>
      </div>

      <div className="pf-table-wrap">
        <table className="pf-table">
          <thead>
            <tr>
              <th style={{ width: 28 }} />
              <th>Scenario</th>
              <th className="pf-cat-cell">Category</th>
              <th style={{ width: 64 }}>Source</th>
              <th style={{ width: 72 }} />
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => {
              const open = expanded.has(s.id);
              const checked = selected.has(s.id);
              return (
                <Fragment key={s.id}>
                  <tr className="pf-row-main" onClick={() => toggleExpand(s.id)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={checked} onChange={() => toggle(s.id)} aria-label={`select ${s.id}`} />
                    </td>
                    <td>
                      <div className="pf-scn-name">{s.name}</div>
                      <div className="pf-scn-id">{s.id}</div>
                    </td>
                    <td className="pf-cat-cell">
                      <Chip tone="neutral" title={s.category}>
                        <span className="pf-cat-chip">{s.category}</span>
                      </Chip>
                    </td>
                    <td>
                      <Chip tone={s.source === 'spec' ? 'sage' : 'mono'}>{s.source || 'go'}</Chip>
                    </td>
                    <td>
                      {s.extended && (
                        <span className="pf-chip pf-badge-ext" title="Long-running dither (excluded from default runs)">
                          extended
                        </span>
                      )}
                    </td>
                  </tr>
                  {open && (
                    <tr>
                      <td />
                      <td colSpan={4} className="pf-expand">
                        <div style={{ padding: '2px 0 6px' }}>
                          <b>Hypothesis:</b> {s.hypothesis}
                        </div>
                        <div>
                          <b>Expected:</b> {s.expected}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="pf-empty">
                  No scenarios match the filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
