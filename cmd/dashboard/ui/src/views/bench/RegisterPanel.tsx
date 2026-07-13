import { usePoll } from '../../lib/usePoll';
import { getJSON } from '../../lib/api';
import { RegisterTable } from './RegisterTable';
import type { RegisterMap } from './types';
import type { RegAnnotation } from './registerAnnotations';

export interface RegisterPanelProps {
  sim: 'solar' | 'battery';
  annotations: Record<number, RegAnnotation>;
  ranges: Record<string, readonly [number, number]>;
}

/**
 * Only mounted while its card's "Registers" expander is open — usePoll's own
 * effect cleanup stops the 3 s poll the moment this unmounts, so collapsing
 * the expander is what turns the poll off (brief §4: "3s poll while expanded").
 */
export function RegisterPanel({ sim, annotations, ranges }: RegisterPanelProps) {
  const { data, error, loading } = usePoll(() => getJSON<RegisterMap>(`/api/${sim}/registers`), 3000);

  if (error && !data) {
    return <div className="empty-state">Registers unreachable.</div>;
  }
  if (loading && !data) {
    return <div className="empty-state">Loading registers…</div>;
  }
  return <RegisterTable registers={data ?? {}} annotations={annotations} ranges={ranges} />;
}
