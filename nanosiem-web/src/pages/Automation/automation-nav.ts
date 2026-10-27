// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540 — rail entries for the Automation section. Empty unless the SOAR
 * gate is enabled, so the section disappears (and reappears) the moment
 * Settings → SOAR writes the shared settings query.
 */
import { useMemo } from 'react';
import { Blocks, History, Stamp, Workflow } from 'lucide-react';
import type { NavItem } from '@/components/layout/AppLayout';
import { useSoarGate } from './soar-gate';
import { APPROVALS_PAGE, useApprovals } from './soar-queries';

export const AUTOMATION_SECTION_ICON = Workflow;

export function useAutomationNav(): { items: NavItem[]; pendingApprovals: string | null } {
  const gate = useSoarGate();
  const enabled = gate.state === 'enabled';
  const approvals = useApprovals(gate.tenant, 'pending', enabled && !gate.demo);
  const items = useMemo<NavItem[]>(() => {
    if (!enabled) return [];
    return [
      { name: 'Runs', href: '/automation/runs', icon: History },
      { name: 'Flows', href: '/automation/flows', icon: Workflow },
      ...(gate.demo ? [] : [{ name: 'Approvals', href: '/automation/approvals', icon: Stamp }]),
      { name: 'Capabilities', href: '/automation/capabilities', icon: Blocks },
    ];
  }, [enabled, gate.demo]);
  const n = approvals.data?.approvals.length ?? 0;
  const pendingApprovals = !enabled || n === 0 ? null : n >= APPROVALS_PAGE ? `${APPROVALS_PAGE - 1}+` : String(n);
  return { items, pendingApprovals };
}
