// Reads color tokens from the CSS custom properties defined in theme.css so
// JS/ECharts stays in sync with the stylesheet. Hex fallbacks match
// DESIGN_BRIEF.md §1 verbatim in case this runs before the stylesheet is
// attached (e.g. in a unit test with no DOM styles loaded).

const FALLBACK: Record<string, string> = {
  '--bolt': '#82E28B',
  '--sage': '#B2CCB3',
  '--sage-soft': '#EAF2EB',
  '--ink': '#0B0F0C',
  '--ink-2': '#4B5563',
  '--ink-3': '#9CA3AF',
  '--surface': '#FCFCFB',
  '--card': '#FFFFFF',
  '--line': '#E5E9E6',
  '--green-ink': '#1F7A34',

  '--c-green': '#2E9E44',
  '--c-blue': '#2A78D6',
  '--c-amber': '#C88500',
  '--c-teal': '#0E9268',
  '--c-indigo': '#4A3AA7',
  '--c-red': '#E34948',
  '--c-pink': '#D6408F',

  '--s-good': '#15803D',
  '--s-warn': '#B45309',
  '--s-serious': '#C2410C',
  '--s-critical': '#B91C1C',
  '--s-neutral': '#64748B',

  '--seq-1': '#FFF4DC',
  '--seq-2': '#F3C874',
  '--seq-3': '#DD9A2B',
  '--seq-4': '#A96A08',
  '--seq-5': '#6F4402',
};

let cache: Map<string, string> | null = null;

function readTokens(): Map<string, string> {
  if (cache) return cache;
  const map = new Map<string, string>();
  const styles =
    typeof window !== 'undefined' && typeof getComputedStyle === 'function'
      ? getComputedStyle(document.documentElement)
      : null;
  for (const key of Object.keys(FALLBACK)) {
    const value = styles?.getPropertyValue(key)?.trim();
    map.set(key, value || FALLBACK[key]);
  }
  cache = map;
  return map;
}

/** Look up a single token (e.g. token('--c-green')). Falls back to the brief's hex if unset. */
export function token(name: string): string {
  return readTokens().get(name) ?? FALLBACK[name] ?? '#000000';
}

/** Fixed entity -> color maps (DESIGN_BRIEF.md §1). Assign by entity, never by rank. */
export const POWER_COLORS = {
  get solar() {
    return token('--c-amber');
  },
  get battery() {
    return token('--c-pink');
  },
  get grid() {
    return token('--c-blue');
  },
  get home() {
    return token('--c-indigo');
  },
  get ev() {
    return token('--c-teal');
  },
};

export const POLICY_COLORS = {
  get baseline() {
    return token('--ink-2');
  },
  get derNoLexa() {
    return token('--c-blue');
  },
  get derLexa() {
    return token('--c-green');
  },
};

/** Status colors — always pair with an icon + label, never color alone. */
export const STATUS_COLORS = {
  get pass() {
    return token('--s-good');
  },
  get degraded() {
    return token('--s-warn');
  },
  get blind() {
    return token('--s-serious');
  },
  get fail() {
    return token('--s-critical');
  },
  get inconclusive() {
    return token('--s-neutral');
  },
};

/** Sequential warm ramp (TOU price heatmaps), light -> dark = cheap -> expensive. */
export const SEQUENTIAL_RAMP = [
  '--seq-1',
  '--seq-2',
  '--seq-3',
  '--seq-4',
  '--seq-5',
].map(token);

/** Diverging scale for import(+)/export(-) around zero. */
export const DIVERGING = {
  get import() {
    return token('--c-blue');
  },
  get neutral() {
    return '#E5E7EB';
  },
  get export() {
    return token('--c-green');
  },
};

/** Call once after the stylesheet loads/changes if tokens were read too early (rare; readTokens caches). */
export function invalidateColorCache(): void {
  cache = null;
}
