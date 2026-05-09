// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub for the pivt command router. Mirrors the real file's
// constant + type surface so any open code that listens for these events or
// references the types compiles cleanly. In open builds nothing dispatches
// the events, so listeners stay dormant. The audit's 17-decoupling list
// covers callers that should drop these listeners entirely (Task #15).

export interface PivtEntryEventDetail {
  kind: 'note' | 'pin' | 'handoff';
  text: string;
  notebookId?: string;
  origin?: string;
}

export interface PivtChatMessageDetail {
  text: string;
}

export interface PivtWizardEventDetail {
  /** Pre-fill prompt — when present, the wizard opens with it populated. */
  prompt?: string;
}

export interface PivtDispatchResult {
  handled: boolean;
  action: string;
}

export const PIVT_ENTRY_EVENT = 'pivt:create-entry' as const;
export const PIVT_CHAT_MESSAGE_EVENT = 'pivt:chat-message' as const;
export const PIVT_OPEN_DETECTION_WIZARD = 'pivt:open-detection-wizard' as const;
export const PIVT_OPEN_TUNING_WIZARD = 'pivt:open-tuning-wizard' as const;
export const PIVT_OPEN_DASHBOARD_WIZARD = 'pivt:open-dashboard-wizard' as const;
export const PIVT_SUMMARIZE_EVENT = 'pivt:summarize' as const;
