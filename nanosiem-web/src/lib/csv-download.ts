// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Client-side CSV export: build, name and download (NAN-5699).
 *
 * One convention for every Search export — the events/stats table, the
 * timechart and the top/rare view: spreadsheet-safe cells via {@link csvCell},
 * a header row, `\n` line endings, and a `nano-export[-<view>]-<UTC time>.csv`
 * file name.
 */
import { csvCell } from './csv-safe';

/** A header row plus data rows, each cell made spreadsheet-safe. */
export function csvFromRows(header: readonly string[], rows: readonly (readonly unknown[])[]): string {
  return [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\n');
}

/** `nano-export-2026-11-19T12-30-00.csv`, or `nano-export-timechart-…` for a view. */
export function csvExportFilename(view?: string, now: Date = new Date()): string {
  const stamp = now.toISOString().slice(0, 19).replace(/:/g, '-');
  return view ? `nano-export-${view}-${stamp}.csv` : `nano-export-${stamp}.csv`;
}

/** Hand `csv` to the browser as a download named `filename`. */
export function downloadCsv(csv: string, filename: string): void {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
