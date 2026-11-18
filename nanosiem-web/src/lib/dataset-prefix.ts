// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5612: a leading `dataset=<name>` token in nPL text selects the dataset
 * the query runs on (`dataset=signals | timechart span=1h count by severity`).
 * Surfaces that store only query text (dashboard panels, saved searches,
 * drilldown links) use it; the search service resolves it the same way
 * (`resolve_dataset_selector`): only the FIRST token, `dataset=` with no
 * spaces or quotes, and only a known dataset name.
 */
import { parseSearchDataset, type SearchDataset } from '@/lib/api/types';

const PREFIX = /^\s*dataset=([A-Za-z]+)(?=\s|\||$)/i;

const KNOWN: Record<string, SearchDataset> = {
  logs: 'logs',
  log: 'logs',
  spans: 'spans',
  span: 'spans',
  traces: 'spans',
  trace: 'spans',
  metrics: 'metrics',
  metric: 'metrics',
  risk: 'risk',
  signals: 'signals',
  signal: 'signals',
};

/** The dataset a leading token selects, and the query without it. */
export function splitDatasetPrefix(query: string): { dataset: SearchDataset | null; query: string } {
  const m = PREFIX.exec(query);
  const dataset = m ? KNOWN[m[1].toLowerCase()] : undefined;
  if (!m || !dataset) return { dataset: null, query };
  const rest = query.slice(m[0].length).trim();
  return { dataset, query: rest };
}

/** `query` targeted at `dataset`: sets, replaces or (for logs) removes the token. */
export function withDatasetPrefix(query: string, dataset: SearchDataset): string {
  const { query: rest } = splitDatasetPrefix(query);
  if (dataset === 'logs') return rest;
  if (!rest) return `dataset=${dataset}`;
  return `dataset=${dataset} ${rest}`;
}

/** The dataset a stored query runs on (logs when it names none). */
export function datasetOfQuery(query: string): SearchDataset {
  return splitDatasetPrefix(query).dataset ?? parseSearchDataset(null);
}
