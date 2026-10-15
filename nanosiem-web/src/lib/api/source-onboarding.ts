// SPDX-License-Identifier: AGPL-3.0-or-later
export interface Wave { id: string; name: string; target: string | null; order: number }
export interface Settings { groupBy: 'wave' | 'priority' | 'none'; completeGate: boolean; autoSuggest: boolean }
export interface PlanningFields { name: string; vendor: string; expectedType: string | null; waveId: string | null; priority: number; owner: string; target: string | null; notes: string }
export interface Candidate { id: string; name: string; sourceType: string }
export interface LiveSource { source: Candidate; labels: string[]; signals: { eps: number | null; lastEventAt: string | null; parseSuccessPct: number | null; refused24h: number | null; rulesUsing: number; status: string } }
export interface Suggestion { source: Candidate; confidence: number; overlappingTokens: string[]; typeMatch: boolean }
export interface Progress { c1: boolean; c2: boolean; c3: boolean; c4: boolean; c5: boolean; issue: boolean; ready: boolean; stage: string; late: boolean; parsingKnown: boolean }
export interface PlannedSource extends PlanningFields { id: string; linkedLogSourceId: string | null; completed: boolean; completedAt: string | null; completedBy: string | null; dismissedLogSourceIds: string[]; suggestion: Suggestion | null; live: LiveSource | null; progress: Progress; rulesNeeded: number; rules: { id: string; name: string; sources: string[] }[]; effectiveTarget: string | null }
export interface Plan { waves: Wave[]; sources: PlannedSource[]; settings: Settings; liveSources: LiveSource[] }
export interface PreviewRow extends PlanningFields { wave: string | null; newWave: boolean; duplicate: boolean; suggestion: Suggestion | null }
export type Action =
 | { action: 'createSource'; fields: PlanningFields }
 | { action: 'updateSource'; id: string; fields: PlanningFields }
 | { action: 'deleteSource' | 'deleteWave' | 'complete' | 'reopen' | 'unlink'; id: string }
 | { action: 'link' | 'dismiss'; id: string; sourceId: string }
 | { action: 'createWave'; name: string; target: string | null }
 | { action: 'updateWave'; id: string; name: string; target: string | null; order: number }
 | { action: 'settings'; settings: Settings }
 | { action: 'import'; csv: string }
 | { action: 'addUnplanned'; sourceIds: string[] };
export class SourceOnboardingApi {
 constructor(private request: <T>(path: string, options?: RequestInit) => Promise<T>, private raw: (path: string, options?: RequestInit) => Promise<Response>) {}
 read() { return this.request<Plan>('/api/source-onboarding'); }
 mutate(action: Action) { return this.request<{ ok: boolean }>('/api/source-onboarding/actions', { method: 'POST', body: JSON.stringify(action) }); }
 preview(csv: string) { return this.request<PreviewRow[]>('/api/source-onboarding/import-preview', { method: 'POST', body: JSON.stringify({ csv }) }); }
 async export() { return (await this.raw('/api/source-onboarding/export')).blob(); }
}
