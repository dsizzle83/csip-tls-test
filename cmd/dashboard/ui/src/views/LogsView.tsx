import { useEffect, useMemo, useRef, useState } from 'react';
import { useSSE } from '../lib/useSSE';
import { LogList } from './logs/LogList';
import type { LogLine } from './logs/types';
import { LOG_SOURCES } from './logs/sources';
import { countBySource, filterLines, regexError } from './logs/filter';
import { exportLogsAsTxt } from './logs/export';

const MAX_BUFFER = 10000;

// /logs — merged SSE stream. See DESIGN_BRIEF.md §4 (per-source color chips,
// level detection, regex/text filter, pause/resume, virtualized 10k ring,
// mono 12px). Backed by GET /api/logs/all (SSE, shape {src,line,at}) via
// src/lib/useSSE.ts (CONTRACTS.md §6).
//
// Named LogsView (not Logs) to avoid clashing with the DOM Console `Log`
// naming and any future `Logs` data type import.
export default function LogsView() {
  const { items: rawItems, connected, clear } = useSSE<LogLine>('/api/logs/all', {
    maxBufferSize: MAX_BUFFER,
  });

  const [enabledSources, setEnabledSources] = useState<Set<string>>(
    () => new Set(LOG_SOURCES.map((s) => s.id))
  );
  const [query, setQuery] = useState('');
  const [regexMode, setRegexMode] = useState(false);
  const [autoscroll, setAutoscroll] = useState(true);

  // Pausing freezes what's on screen without touching the live connection —
  // the buffer keeps growing underneath (brief §4: "buffer continues, show
  // '+N while paused'"). totalSeenRef counts every message the hook has ever
  // delivered (one items-array identity change == one message), which stays
  // accurate even once the ring buffer starts trimming and items.length caps out.
  const [paused, setPaused] = useState(false);
  const [pausedSnapshot, setPausedSnapshot] = useState<LogLine[]>([]);
  const [pausedAtCount, setPausedAtCount] = useState(0);
  const totalSeenRef = useRef(0);

  useEffect(() => {
    totalSeenRef.current += 1;
  }, [rawItems]);

  const sourceCounts = useMemo(() => countBySource(rawItems), [rawItems]);

  const baseItems = paused ? pausedSnapshot : rawItems;
  const filtered = useMemo(
    () => filterLines(baseItems, enabledSources, query, regexMode),
    [baseItems, enabledSources, query, regexMode]
  );
  const patternError = regexError(query, regexMode);
  const newWhilePaused = paused ? totalSeenRef.current - pausedAtCount : 0;

  const toggleSource = (id: string) => {
    setEnabledSources((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const togglePause = () => {
    if (paused) {
      setPaused(false);
    } else {
      setPausedSnapshot(rawItems);
      setPausedAtCount(totalSeenRef.current);
      setPaused(true);
    }
  };

  const handleClear = () => {
    clear();
    setPausedSnapshot([]);
    setPausedAtCount(totalSeenRef.current);
  };

  return (
    <div className="view-stack">
      <h1 className="page-title">Logs</h1>

      {!connected && (
        <div style={{ color: 'var(--s-warn)', fontSize: 12 }}>Reconnecting to log stream…</div>
      )}

      <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
          {LOG_SOURCES.map((s) => {
            const on = enabledSources.has(s.id);
            const count = sourceCounts[s.id] ?? 0;
            return (
              <button
                key={s.id}
                type="button"
                title={s.proto}
                aria-pressed={on}
                onClick={() => toggleSource(s.id)}
                style={{
                  fontSize: 11,
                  padding: '3px 9px',
                  borderRadius: 10,
                  cursor: 'pointer',
                  border: `1px solid ${on ? s.color : 'var(--line)'}`,
                  background: on ? 'var(--sage-soft)' : 'transparent',
                  color: on ? s.color : 'var(--ink-3)',
                  fontWeight: 600,
                }}
              >
                {s.label} · {count}
              </button>
            );
          })}
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={regexMode ? 'regex, e.g. timeout|refused' : 'filter text…'}
            className="mono"
            style={{
              flex: '1 1 220px',
              minWidth: 160,
              fontSize: 12,
              padding: '6px 8px',
              border: `1px solid ${patternError ? 'var(--s-critical)' : 'var(--line)'}`,
              borderRadius: 6,
              background: 'var(--card)',
              color: 'var(--ink)',
            }}
          />
          <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--ink-2)' }}>
            <input type="checkbox" checked={regexMode} onChange={(e) => setRegexMode(e.target.checked)} />
            regex
          </label>
          {patternError && (
            <span style={{ fontSize: 11, color: 'var(--s-critical)' }}>invalid pattern</span>
          )}

          <span style={{ flex: 1 }} />

          <button type="button" onClick={togglePause}>
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          {paused && newWhilePaused > 0 && (
            <span style={{ fontSize: 11, color: 'var(--s-warn)' }}>+{newWhilePaused} while paused</span>
          )}
          {!autoscroll && !paused && (
            <button type="button" onClick={() => setAutoscroll(true)}>
              ↓ Resume autoscroll
            </button>
          )}
          {autoscroll && (
            <button type="button" onClick={() => setAutoscroll(false)} title="Stop pinning to the newest line">
              Autoscroll on
            </button>
          )}
          <button type="button" onClick={handleClear}>
            Clear
          </button>
          <button type="button" onClick={() => exportLogsAsTxt(filtered)}>
            Export .txt
          </button>
        </div>

        <div style={{ fontSize: 11, color: 'var(--ink-3)' }}>
          {filtered.length} shown / {rawItems.length} buffered (max {MAX_BUFFER.toLocaleString()})
        </div>
      </div>

      <div className="card" style={{ height: '65vh', minHeight: 380, overflow: 'hidden' }}>
        <LogList
          items={filtered}
          autoscroll={autoscroll && !paused}
          onAutoscrollChange={setAutoscroll}
          style={{ height: '100%' }}
        />
      </div>
    </div>
  );
}
