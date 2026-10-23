// SPDX-License-Identifier: AGPL-3.0-or-later

import { AlertTriangle, Play } from 'lucide-react';
import { PivtIcon } from '@/components/icons/PivtIcon';
import { useCapabilities } from '@/hooks/use-capabilities';

export type SidePanelTabId = 'ai' | 'test' | 'diag';

const ALL_TABS = [
  { id: 'ai', label: 'pivt', Icon: PivtIcon },
  { id: 'test', label: 'Test events', Icon: Play },
  { id: 'diag', label: 'Diagnostics', Icon: AlertTriangle },
] as const;

/**
 * NAN-4132: the parser side panel's pivt tab (LogSourceDetail VRL and
 * extension editors) exists only when AI does (`capabilities.melod`). Open
 * core has no AI, and an unknown capability is treated as none (fail closed),
 * so the tab is dropped and a stale `'ai'` selection falls back to Test events.
 */
export function useParserSidePanelTabs(selected: SidePanelTabId) {
  const aiAvailable = useCapabilities().capabilities.melod === true;
  const tabs = aiAvailable ? [...ALL_TABS] : ALL_TABS.filter((t) => t.id !== 'ai');
  const active: SidePanelTabId = !aiAvailable && selected === 'ai' ? 'test' : selected;
  return { aiAvailable, tabs, active };
}
