// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Generic settings page shell with eyebrow + title + underlined-tab subnav.
 *
 * Mirrors the visual contract of `AccessControl.tsx` (AccessHeader +
 * AccessSubnav) so any settings page with sub-tabs gets the same chrome:
 *
 *   ┌────────────────────────────────────────────────────────────┐
 *   │ WORKSPACE                                                  │  ← eyebrow
 *   │ Case Management · General                                  │  ← 18px title
 *   │ Configure case auto-grouping rules and …                   │  ← 12px desc
 *   ├────────────────────────────────────────────────────────────┤
 *   │  [General]   [Grouping Rules]   [SLA]                      │  ← subnav
 *   └────────────────────────────────────────────────────────────┘
 *   {children}
 *
 * The shell pulls eyebrow/title-prefix from the section registry by ID and
 * picks the active-tab title from the `tabs` prop. Tabs are filtered by
 * permission via `useAuth.hasAnyPermission`.
 *
 * Url state is owned by the page (`?tab=` driver). The shell calls back
 * through `onTabChange` so the page can `setSearchParams`.
 *
 * Accessibility:
 *   - Tablist uses ARIA `role="tablist"` + `role="tab"` + roving tabindex,
 *     matching the WAI-ARIA Authoring Practices tabs pattern.
 *   - Left/Right arrow keys cycle through visible tabs; Home/End jump to
 *     first/last. Activating a tab moves focus to the new tab button.
 *   - The body slot gets `role="tabpanel"` + `aria-labelledby` linking back
 *     to the active tab button.
 */

import { useCallback, useId, useRef, type KeyboardEvent } from 'react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/AuthContext';
import { GROUP_LABEL, SECTION_BY_ID } from '@/components/layout/settings/sections';

export interface SubsectionTab<TabId extends string = string> {
  id: TabId;
  label: string;
  icon?: LucideIcon;
  /** Optional mono count shown to the right of the label. */
  count?: number | string;
  /** ANY of these permissions reveals the tab. Empty = visible to everyone. */
  permissions?: string[];
  /** Per-tab description shown under the title when this tab is active. */
  desc?: string;
}

interface SettingsSubsectionShellProps<TabId extends string = string> {
  /** Section registry id (e.g. 'case-mgmt') — drives the eyebrow + title prefix. */
  sectionId: string;
  /** Tabs to render in the subnav. Order is preserved. */
  tabs: SubsectionTab<TabId>[];
  /** Currently-selected tab id. */
  activeTab: TabId;
  /** Called when the user clicks a different tab. The page wires this to URL state. */
  onTabChange: (id: TabId) => void;
  /** Override the default title sub (per-tab `desc` is preferred). */
  desc?: string;
  /** The tab's body. */
  children: React.ReactNode;
}

export function SettingsSubsectionShell<TabId extends string = string>({
  sectionId,
  tabs,
  activeTab,
  onTabChange,
  desc,
  children,
}: SettingsSubsectionShellProps<TabId>) {
  const { hasAnyPermission } = useAuth();
  const baseId = useId();
  const tabRefs = useRef<Map<TabId, HTMLButtonElement>>(new Map());

  const section = SECTION_BY_ID[sectionId];
  const groupLabel = section ? GROUP_LABEL[section.group] : null;
  const visibleTabs = tabs.filter(t => !t.permissions || hasAnyPermission(t.permissions));
  const active = visibleTabs.find(t => t.id === activeTab) || visibleTabs[0];
  const titleSub = desc ?? active?.desc ?? section?.desc;

  const tabBtnId = (id: TabId) => `${baseId}-tab-${id}`;
  const panelId = active ? `${baseId}-panel-${active.id}` : undefined;
  const labelledBy = active ? tabBtnId(active.id) : undefined;

  const focusTab = useCallback((id: TabId) => {
    tabRefs.current.get(id)?.focus();
  }, []);

  const handleKeyDown = (e: KeyboardEvent<HTMLButtonElement>, currentId: TabId) => {
    if (visibleTabs.length === 0) return;
    const idx = visibleTabs.findIndex(t => t.id === currentId);
    if (idx === -1) return;

    let nextIdx: number | null = null;
    switch (e.key) {
      case 'ArrowRight':
        nextIdx = (idx + 1) % visibleTabs.length;
        break;
      case 'ArrowLeft':
        nextIdx = (idx - 1 + visibleTabs.length) % visibleTabs.length;
        break;
      case 'Home':
        nextIdx = 0;
        break;
      case 'End':
        nextIdx = visibleTabs.length - 1;
        break;
      default:
        return;
    }
    if (nextIdx === null) return;
    e.preventDefault();
    const nextTab = visibleTabs[nextIdx];
    onTabChange(nextTab.id);
    // Defer focus so the new active button has its tabIndex updated first.
    requestAnimationFrame(() => focusTab(nextTab.id));
  };

  return (
    <div className="h-full flex flex-col min-h-0">
      {/* Eyebrow + title + sub */}
      <div className="px-5 pt-5 pb-2 shrink-0">
        {groupLabel && (
          <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
            {groupLabel}
          </div>
        )}
        <div className="text-[18px] font-semibold text-foreground tracking-tight leading-none">
          {section?.label ?? 'Settings'}
          {active ? <> · <span className="font-semibold">{active.label}</span></> : null}
        </div>
        {titleSub && (
          <div className="text-[12px] text-muted-foreground mt-1.5 max-w-[720px]">{titleSub}</div>
        )}
      </div>

      {/* Underlined-tab subnav */}
      <div
        role="tablist"
        aria-orientation="horizontal"
        aria-label={section?.label ? `${section.label} sections` : 'Settings sections'}
        className="flex items-center gap-1 border-b border-border px-5 shrink-0"
      >
        {visibleTabs.map(t => {
          const Icon = t.icon;
          const isActive = activeTab === t.id;
          return (
            <button
              key={t.id}
              ref={(el) => {
                if (el) tabRefs.current.set(t.id, el);
                else tabRefs.current.delete(t.id);
              }}
              role="tab"
              type="button"
              id={tabBtnId(t.id)}
              aria-selected={isActive}
              aria-controls={`${baseId}-panel-${t.id}`}
              tabIndex={isActive ? 0 : -1}
              onKeyDown={(e) => handleKeyDown(e, t.id)}
              onClick={() => onTabChange(t.id)}
              className={cn(
                'relative h-9 px-3 flex items-center gap-1.5 text-[12px] transition-colors',
                isActive ? 'text-foreground' : 'text-muted-foreground hover:text-foreground/80',
              )}
            >
              {Icon && (
                <Icon className={cn('w-[12px] h-[12px]', isActive ? 'text-primary' : 'text-muted-foreground')} />
              )}
              <span className="font-medium">{t.label}</span>
              {t.count !== undefined && (
                <span className={cn(
                  'font-mono text-[10px] tabular-nums',
                  isActive ? 'text-muted-foreground' : 'text-muted-foreground/70',
                )}>
                  {t.count}
                </span>
              )}
              {isActive && <span className="absolute -bottom-px left-0 right-0 h-[2px] bg-primary" />}
            </button>
          );
        })}
      </div>

      {/* Body */}
      <div
        role="tabpanel"
        id={panelId}
        aria-labelledby={labelledBy}
        tabIndex={0}
        className="flex-1 min-h-0 overflow-y-auto scrollbar-thin focus-visible:outline-none"
      >
        {children}
      </div>
    </div>
  );
}
