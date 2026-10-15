// SPDX-License-Identifier: AGPL-3.0-or-later

export interface AsyncSearchPage {
  append: boolean;
  offset: number;
  page: number;
  pageSize: number;
}

export interface ResultRow {
  id: string;
  fields: Record<string, unknown>;
}

export interface AsyncSearchPageState<T> {
  results: T[];
  totalCount: number;
  currentPage: number;
  complete: boolean;
}

/**
 * Stable identity for a result row. Offset-derived `result-N` ids are
 * positional, so they cannot be compared across requests (a live-tail prepend
 * or a re-run shifts every one of them); the event's own `metadata.uid` can.
 */
export function rowKey(row: ResultRow): string {
  const metadata = row.fields.metadata;
  const uid = row.fields['metadata.uid']
    ?? (metadata && typeof metadata === 'object' ? (metadata as Record<string, unknown>).uid : undefined);
  return typeof uid === 'string' && uid.length > 0 ? `uid:${uid}` : `id:${row.id}`;
}

export function mergeAsyncSearchPage<T extends ResultRow>(
  previous: AsyncSearchPageState<T>,
  incoming: T[],
  totalCount: number,
  context: AsyncSearchPage,
): AsyncSearchPageState<T> {
  if (!context.append) {
    return { results: incoming, totalCount, currentPage: context.page, complete: false };
  }
  const seen = new Set(previous.results.map(rowKey));
  const added = incoming.filter(row => {
    const key = rowKey(row);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return {
    results: [...previous.results, ...added],
    totalCount: previous.totalCount,
    currentPage: context.page,
    complete: incoming.length < context.pageSize || added.length === 0,
  };
}

// Reserve synchronously, before submission/React updates, so repeated observer
// callbacks cannot submit the same offset while admission or polling is pending.
export function reserveAsyncSearchOffset(
  lastOffset: { current: number | null },
  context: AsyncSearchPage,
  complete: boolean,
): boolean {
  if (context.append && (complete || lastOffset.current === context.offset)) return false;
  lastOffset.current = context.offset;
  return true;
}

export function captureInitialSearchPage(
  context: AsyncSearchPage | undefined,
  capture: () => void,
): void {
  if (!context?.append) capture();
}
