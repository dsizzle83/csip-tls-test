import { useEffect, useRef, useState } from 'react';
import type { UIEvent } from 'react';
import type { LogLine } from './types';
import { sourceMeta } from './sources';
import { detectLevel, levelColor } from './level';
import { formatClock } from '../../lib/format';

export const ROW_HEIGHT = 22;
const OVERSCAN = 8;
// Distance (px) from the bottom that still counts as "at the bottom" —
// beyond this, a manual scroll-up switches autoscroll off (brief §4).
const BOTTOM_SLACK = 28;

export interface LogListProps {
  items: LogLine[];
  /** Pin to bottom on new rows; turns itself off when the user scrolls up. */
  autoscroll: boolean;
  onAutoscrollChange: (next: boolean) => void;
  style?: React.CSSProperties;
}

/**
 * Simple windowed renderer: fixed 22px rows, absolute-positioned inside a
 * spacer div sized to the full (filtered) list, sliced from scrollTop math
 * plus a fixed overscan. No virtualization library — per the brief, this
 * view gets no new deps.
 */
export function LogList({ items, autoscroll, onAutoscrollChange, style }: LogListProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const programmaticScrollRef = useRef(false);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(0);

  // Track viewport height (card can resize with the window/collapse of the nav).
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewportHeight(el.clientHeight));
    ro.observe(el);
    setViewportHeight(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  // Pin to bottom whenever the row count grows (or autoscroll is (re)enabled),
  // as long as autoscroll is on.
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !autoscroll) return;
    programmaticScrollRef.current = true;
    el.scrollTop = el.scrollHeight - el.clientHeight;
    setScrollTop(el.scrollTop);
    // Cleared on the next real scroll event (see handleScroll) rather than a
    // timer, so it can't race a slow layout pass.
  }, [items.length, autoscroll]);

  const handleScroll = (e: UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    setScrollTop(el.scrollTop);
    if (programmaticScrollRef.current) {
      programmaticScrollRef.current = false;
      return;
    }
    const distanceFromBottom = el.scrollHeight - el.clientHeight - el.scrollTop;
    if (autoscroll && distanceFromBottom > BOTTOM_SLACK) {
      onAutoscrollChange(false);
    }
  };

  const total = items.length;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN * 2;
  const endIndex = Math.min(total, startIndex + Math.max(visibleCount, 0));
  const visible = items.slice(startIndex, endIndex);

  return (
    <div
      ref={containerRef}
      onScroll={handleScroll}
      className="mono"
      style={{
        position: 'relative',
        overflow: 'auto',
        height: '100%',
        fontSize: 12,
        lineHeight: `${ROW_HEIGHT}px`,
        background: 'var(--card)',
        ...style,
      }}
    >
      <div style={{ position: 'relative', height: total * ROW_HEIGHT, minHeight: '100%' }}>
        {total === 0 && (
          <div className="empty-state" style={{ position: 'absolute', top: 0, left: 0, right: 0 }}>
            No log lines match the current filters.
          </div>
        )}
        {visible.map((item, i) => {
          const idx = startIndex + i;
          const meta = sourceMeta(item.src);
          const level = detectLevel(item.line);
          return (
            <div
              key={`${idx}-${item.at}`}
              title={item.line}
              style={{
                position: 'absolute',
                top: idx * ROW_HEIGHT,
                left: 0,
                right: 0,
                height: ROW_HEIGHT,
                padding: '0 10px',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                borderBottom: '1px solid var(--line)',
              }}
            >
              <span style={{ color: 'var(--ink-3)' }}>{formatClock(item.at)}</span>{' '}
              <span style={{ color: meta.color, fontWeight: 600 }}>[{meta.label}]</span>{' '}
              <span style={{ color: levelColor(level) }}>{item.line}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
