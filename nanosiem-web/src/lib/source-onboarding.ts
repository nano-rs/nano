// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PlannedSource } from './api/source-onboarding';
export type Filter = 'all' | 'attention' | 'unlinked' | 'ready';
export function visibleSources(rows: PlannedSource[], showCompleted: boolean, filter: Filter, query: string) {
 const q = query.trim().toLowerCase();
 return rows.filter(r => (!r.completed || r.progress.issue || showCompleted)
  && (filter !== 'attention' || r.progress.issue)
  && (filter !== 'unlinked' || !r.linkedLogSourceId)
  && (filter !== 'ready' || r.progress.ready)
  && (!q || [r.name, r.vendor, r.owner, r.notes, r.live?.source.name].join(' ').toLowerCase().includes(q)));
}
export function canComplete(row: PlannedSource, gate: boolean) { return row.completed || !gate || row.progress.ready; }
