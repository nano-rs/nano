// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for NotebooksApi. Notebooks back the Cases investigation surface — enterprise-only.

import type {
  Notebook,
  NotebookWithOwner,
  NotebookSummary,
  NotebookResponse,
  NotebookEntry,
  NotebookEntryWithCreator,
  NotebookShareWithNames,
  NotebookReference,
  NotebookTab,
  NotebookTabWithDetails,
  CreateNotebookRequest,
  UpdateNotebookRequest,
  AddEntryRequest,
  AddShareRequest,
  AddReferenceRequest,
  RelatedNotebook,
  GenerateQuerySuggestionsRequest,
  AnalyzeNoteRequest,
  MergeNotebooksResponse,
  ShareNotebookRequest,
  NotebookShareResult,
  MelodJobStartResponse,
  NotebookChatRequest,
  NotebookChatStreamCallbacks,
  GenerateInvestigationTimelineRequest,
} from '@/lib/api/types';

const ENTERPRISE_ONLY = (): Promise<never> =>
  Promise.reject(new Error('NotebooksApi is enterprise-only'));

export class NotebooksApi {
  constructor(
    _request: <T>(endpoint: string, options?: RequestInit) => Promise<T>,
    _getAccessToken?: () => string | null,
    _baseUrl?: string,
  ) {
    void _request;
    void _getAccessToken;
    void _baseUrl;
  }

  listNotebooks(_filter?: 'my' | 'shared' | 'all', _status?: string): Promise<NotebookSummary[]> {
    return ENTERPRISE_ONLY();
  }
  getNotebook(_id: string): Promise<NotebookResponse> {
    return ENTERPRISE_ONLY();
  }
  getActiveNotebook(): Promise<NotebookWithOwner | null> {
    return ENTERPRISE_ONLY();
  }
  createNotebook(_request: CreateNotebookRequest): Promise<Notebook> {
    return ENTERPRISE_ONLY();
  }
  updateNotebook(_id: string, _request: UpdateNotebookRequest): Promise<Notebook> {
    return ENTERPRISE_ONLY();
  }
  deleteNotebook(_id: string): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  getNotebookEntries(
    _notebookId: string,
    _limit?: number,
    _offset?: number,
  ): Promise<NotebookEntryWithCreator[]> {
    return ENTERPRISE_ONLY();
  }
  addNotebookEntry(_notebookId: string, _request: AddEntryRequest): Promise<NotebookEntry> {
    return ENTERPRISE_ONLY();
  }
  deleteNotebookEntry(_notebookId: string, _entryId: string): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  getNotebookShares(_notebookId: string): Promise<NotebookShareWithNames[]> {
    return ENTERPRISE_ONLY();
  }
  addNotebookShare(
    _notebookId: string,
    _request: AddShareRequest,
  ): Promise<NotebookShareWithNames> {
    return ENTERPRISE_ONLY();
  }
  deleteNotebookShare(_notebookId: string, _shareId: string): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  shareNotebook(
    _notebookId: string,
    _request: ShareNotebookRequest,
  ): Promise<NotebookShareResult> {
    return ENTERPRISE_ONLY();
  }
  getNotebookReferences(_notebookId: string): Promise<NotebookReference[]> {
    return ENTERPRISE_ONLY();
  }
  addNotebookReference(
    _notebookId: string,
    _request: AddReferenceRequest,
  ): Promise<NotebookReference> {
    return ENTERPRISE_ONLY();
  }
  deleteNotebookReference(
    _notebookId: string,
    _referenceId: string,
  ): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  findNotebooksByReference(
    _referenceType: string,
    _referenceId: string,
  ): Promise<NotebookSummary[]> {
    return ENTERPRISE_ONLY();
  }
  summarizeNotebook(
    _notebookId: string,
    _entries: Array<{
      entry_type: string;
      content: Record<string, unknown>;
      created_at: string;
    }>,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  getCaseNotebook(_caseId: string): Promise<NotebookWithOwner | null> {
    return ENTERPRISE_ONLY();
  }
  linkNotebookToCase(_caseId: string, _notebookId: string): Promise<Notebook> {
    return ENTERPRISE_ONLY();
  }
  unlinkNotebookFromCase(_caseId: string): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  getRelatedNotebooksForCase(_caseId: string): Promise<RelatedNotebook[]> {
    return ENTERPRISE_ONLY();
  }
  mergeNotebookIntoCase(
    _caseId: string,
    _sourceNotebookId: string,
  ): Promise<{ message: string; entries_merged: number }> {
    return ENTERPRISE_ONLY();
  }
  generateQuerySuggestions(
    _request: GenerateQuerySuggestionsRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  analyzeNoteForQueries(_request: AnalyzeNoteRequest): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  generateInvestigationTimeline(
    _request: GenerateInvestigationTimelineRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  listTabs(): Promise<NotebookTabWithDetails[]> {
    return ENTERPRISE_ONLY();
  }
  openTab(_notebookId: string): Promise<NotebookTab> {
    return ENTERPRISE_ONLY();
  }
  closeTab(_tabId: string): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  updateTab(
    _tabId: string,
    _request: import('@/lib/api/types').UpdateTabRequest,
  ): Promise<NotebookTab> {
    return ENTERPRISE_ONLY();
  }
  reorderTabs(_tabIds: string[]): Promise<{ success: boolean }> {
    return ENTERPRISE_ONLY();
  }
  setActiveTab(_notebookId: string): Promise<NotebookTab> {
    return ENTERPRISE_ONLY();
  }
  mergeNotebooks(
    _targetId: string,
    _sourceIds: string[],
  ): Promise<MergeNotebooksResponse> {
    return ENTERPRISE_ONLY();
  }
  unlinkFromCase(_notebookId: string): Promise<Notebook> {
    return ENTERPRISE_ONLY();
  }
  linkToCase(_caseId: string, _notebookId: string): Promise<Notebook> {
    return ENTERPRISE_ONLY();
  }
  notebookChat(
    _notebookId: string,
    _request: NotebookChatRequest,
  ): Promise<MelodJobStartResponse> {
    return ENTERPRISE_ONLY();
  }
  notebookChatStream(
    _notebookId: string,
    _request: NotebookChatRequest,
    callbacks: NotebookChatStreamCallbacks,
  ): AbortController {
    callbacks.onError?.('NotebooksApi is enterprise-only');
    return new AbortController();
  }
}
