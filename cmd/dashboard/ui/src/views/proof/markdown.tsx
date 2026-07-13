// Minimal, dependency-free markdown → React renderer for the saved QA reports
// (writeReport in mayhem.go). Handles exactly what those reports use: ATX
// headings, unordered lists, fenced/inline code, **bold**, _italic_. Output is
// React nodes, so text is escaped by React itself — no dangerouslySetInnerHTML,
// no HTML injection surface (task: escape HTML).

import type { ReactNode } from 'react';

/** Parsed roll-up from a report's summary line (writeReport format). */
export interface ReportSummary {
  startedAt: string | null; // RFC3339 as written, or null if unparseable
  pass: number;
  degraded: number;
  fail: number;
  blind: number;
  inconclusive: number;
}

// "Run started <RFC3339>. N pass · N degraded · **N fail** · **N blind** · N inconclusive."
const SUMMARY_RE =
  /(\d+)\s+pass\s+·\s+(\d+)\s+degraded\s+·\s+\*\*(\d+)\s+fail\*\*\s+·\s+\*\*(\d+)\s+blind\*\*\s+·\s+(\d+)\s+inconclusive/;
const STARTED_RE = /Run started\s+(\S+?)\.?\s/;

/**
 * Parse the verdict counts from a report's markdown. Returns null when the
 * summary line isn't present/parseable — callers must treat that as "no
 * trend data", never fabricate counts (task: don't fake it).
 */
export function parseReportSummary(md: string): ReportSummary | null {
  const m = SUMMARY_RE.exec(md);
  if (!m) return null;
  const started = STARTED_RE.exec(md);
  return {
    startedAt: started ? started[1] : null,
    pass: Number(m[1]),
    degraded: Number(m[2]),
    fail: Number(m[3]),
    blind: Number(m[4]),
    inconclusive: Number(m[5]),
  };
}

// ── inline formatting ────────────────────────────────────────────────────────

// Split on **bold**, _italic_, `code`; keep delimiters via capture groups.
const INLINE_RE = /(\*\*[^*]+\*\*|_[^_]+_|`[^`]+`)/g;

function renderInline(text: string, keyBase: string): ReactNode[] {
  const parts = text.split(INLINE_RE);
  return parts.map((p, i) => {
    const key = `${keyBase}-${i}`;
    if (p.startsWith('**') && p.endsWith('**')) {
      return (
        <strong key={key} style={{ color: 'var(--ink)' }}>
          {p.slice(2, -2)}
        </strong>
      );
    }
    if (p.startsWith('_') && p.endsWith('_') && p.length > 1) {
      return (
        <em key={key} style={{ color: 'var(--ink-2)' }}>
          {p.slice(1, -1)}
        </em>
      );
    }
    if (p.startsWith('`') && p.endsWith('`') && p.length > 1) {
      return (
        <code key={key} className="mono md-code-inline">
          {p.slice(1, -1)}
        </code>
      );
    }
    return <span key={key}>{p}</span>;
  });
}

// ── block renderer ───────────────────────────────────────────────────────────

/** Render report markdown to a flat list of React block nodes. */
export function renderMarkdown(md: string): ReactNode[] {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  let list: string[] = [];
  let code: string[] = [];
  let inCode = false;
  let key = 0;

  const flushList = () => {
    if (list.length === 0) return;
    const items = list.slice();
    blocks.push(
      <ul key={`ul-${key++}`} className="md-list">
        {items.map((li, i) => (
          <li key={i}>{renderInline(li, `li-${key}-${i}`)}</li>
        ))}
      </ul>
    );
    list = [];
  };
  const flushCode = () => {
    const body = code.join('\n');
    blocks.push(
      <pre key={`pre-${key++}`} className="mono md-code-block">
        {body}
      </pre>
    );
    code = [];
  };

  for (const raw of lines) {
    if (raw.trim().startsWith('```')) {
      if (inCode) {
        flushCode();
        inCode = false;
      } else {
        flushList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      code.push(raw);
      continue;
    }
    const line = raw.trimEnd();
    if (line.startsWith('### ')) {
      flushList();
      blocks.push(
        <h4 key={`h-${key++}`} className="md-h4">
          {renderInline(line.slice(4), `h4-${key}`)}
        </h4>
      );
    } else if (line.startsWith('## ')) {
      flushList();
      blocks.push(
        <h3 key={`h-${key++}`} className="md-h3">
          {renderInline(line.slice(3), `h3-${key}`)}
        </h3>
      );
    } else if (line.startsWith('# ')) {
      flushList();
      blocks.push(
        <h2 key={`h-${key++}`} className="md-h2">
          {renderInline(line.slice(2), `h2-${key}`)}
        </h2>
      );
    } else if (/^\s*-\s+/.test(line)) {
      list.push(line.replace(/^\s*-\s+/, ''));
    } else if (line.trim() === '') {
      flushList();
    } else {
      flushList();
      blocks.push(
        <p key={`p-${key++}`} className="md-p">
          {renderInline(line, `p-${key}`)}
        </p>
      );
    }
  }
  flushList();
  if (inCode) flushCode();
  return blocks;
}
