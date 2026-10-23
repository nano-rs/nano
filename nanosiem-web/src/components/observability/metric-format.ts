// SPDX-License-Identifier: AGPL-3.0-or-later

export function fmtMetric(v: number, unit?: string): string {
  const a = Math.abs(v);
  let n: string;
  if (a >= 1_000_000) n = (v / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
  else if (a >= 1_000) n = (v / 1_000).toFixed(1).replace(/\.0$/, '') + 'k';
  else if (a >= 100 || a === 0) n = String(Math.round(v));
  else if (a >= 1) n = v.toFixed(1).replace(/\.0$/, '');
  else n = v.toPrecision(2);
  if (!unit) return n;
  return unit.startsWith('%') ? `${n}${unit}` : `${n} ${unit}`;
}
