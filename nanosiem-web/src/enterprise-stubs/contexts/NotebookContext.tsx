// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for NotebookContext. The investigation-notebook surface
// is enterprise-only; in open-edition Vite builds (`VITE_EDITION=open`) this
// file replaces the real implementation via the `@/enterprise` alias swap.
//
// Open consumers (`AlertDetail`, `Search`, `AppLayout`, plus pivt files until
// they're lifted in the PIVT phase) call `useNotebookOptional` /
// `useNotebookCapture` and already null-check for missing notebook state, so
// those return benign no-op values.
//
// `useNotebook` (non-optional) is reachable from `pivt/PivtCloseDialog.tsx`,
// which is mounted whenever the pivt shell renders — and the shell is still
// mounted unconditionally in `AppLayout` until the PIVT phase. Returning a
// permissive empty object lets that path execute harmlessly in open instead
// of crashing on Ctrl+. or other accidental pivt activation.

import { type ReactNode } from 'react';

const NOOP = () => {};
const NOOP_ASYNC = async () => {};

export interface InitialSearchData {
  query: string;
  queryMode: string;
  resultCount: number;
  executionTimeMs?: number;
  timeRangeStart?: string;
  timeRangeEnd?: string;
}

export function NotebookProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

// Empty-but-valid notebook value. Consumers that destructure
// activeNotebook/closeNotebook (today: PivtCloseDialog) get null + a no-op
// async fn; other field reads bottom out at undefined under
// `notebook?.foo`-style access. TS path priority resolves consumers to the
// real signature, so the call-site type contract is unchanged.
const STUB_NOTEBOOK_VALUE = {
  tabs: [],
  activeTab: null,
  activeNotebook: null,
  entries: [],
  isOpen: false,
  isMinimized: false,
  isPinned: false,
  isLoading: false,
  sidebarWidth: 0,
  lastSearch: null,
  isDetached: false,
  detachedLayout: { x: 0, y: 0, width: 0, height: 0 },
  detachedOpacity: 1,
  openTab: NOOP_ASYNC,
  closeTab: NOOP_ASYNC,
  switchTab: NOOP_ASYNC,
  pinTab: NOOP_ASYNC,
  unpinTab: NOOP_ASYNC,
  reorderTabs: NOOP_ASYNC,
  refreshTabs: NOOP_ASYNC,
  startNotebook: NOOP_ASYNC,
  quickStartNotebook: NOOP_ASYNC,
  openNotebook: NOOP_ASYNC,
  openCaseNotebook: NOOP_ASYNC,
  pauseNotebook: NOOP_ASYNC,
  resumeNotebook: NOOP_ASYNC,
  reopenNotebook: NOOP_ASYNC,
  closeNotebook: NOOP_ASYNC,
  addManualNote: NOOP_ASYNC,
  captureEvent: NOOP_ASYNC,
  addEntriesBulk: NOOP_ASYNC,
  deleteEntry: NOOP_ASYNC,
  analyzeNoteForSuggestions: NOOP_ASYNC,
  toggleDetached: NOOP,
  setDetachedLayout: NOOP,
  setDetachedOpacity: NOOP,
  toggleSidebar: NOOP,
  minimizeSidebar: NOOP,
  expandSidebar: NOOP,
  setSidebarWidth: NOOP,
  togglePinned: NOOP,
  setLastSearch: NOOP,
  refreshEntries: NOOP_ASYNC,
  mergeNotebooks: async () => ({ entries_merged: 0 }),
  unlinkFromCase: NOOP_ASYNC,
};

export function useNotebook() {
  return STUB_NOTEBOOK_VALUE;
}

export function useNotebookOptional(): undefined {
  return undefined;
}

export function useNotebookCapture() {
  return {
    isActive: false,
    captureSearch: NOOP,
    captureAlertView: NOOP,
    captureAlertAction: NOOP,
    captureDetectionView: NOOP,
    captureDetectionModified: NOOP,
    generateQuerySuggestions: NOOP_ASYNC,
    addEntityToNotebook: NOOP,
    addEntitiesToNotebook: NOOP_ASYNC,
    captureAiSummary: NOOP,
  };
}
