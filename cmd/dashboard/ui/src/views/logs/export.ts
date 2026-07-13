import type { LogLine } from './types';
import { formatClock } from '../../lib/format';
import { sourceMeta } from './sources';

/** Export visible (already-filtered) rows as a flat .txt download. */
export function exportLogsAsTxt(items: LogLine[]): void {
  const text = items
    .map((e) => `${formatClock(e.at)} [${sourceMeta(e.src).label}] ${e.line}`)
    .join('\n');
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `lexa-logs-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}
