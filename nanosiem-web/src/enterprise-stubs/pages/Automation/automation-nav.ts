// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub: the Automation rail section is enterprise-only, so it is
// always empty and never renders.
import { Workflow } from 'lucide-react';
import type { NavItem } from '@/components/layout/AppLayout';

export const AUTOMATION_SECTION_ICON = Workflow;

export function useAutomationNav(): { items: NavItem[]; pendingApprovals: string | null } {
  return { items: [], pendingApprovals: null };
}
