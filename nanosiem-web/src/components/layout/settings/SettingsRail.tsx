// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings rail — left navigation strip for the dedicated /settings shell.
 * Mirrors `design-ref/shadcn/settings-shell.jsx` `SettingsRail`.
 *
 * Sections are read from `sections.ts`. Permission-gated items are filtered
 * out before render.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ChevronDown, ChevronLeft, Search as SearchIcon, Settings as SettingsIcon, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useSystemConfig } from '@/hooks/use-api';
import {
  SETTINGS_GROUPS,
  SETTINGS_SECTIONS,
  type SettingsSection,
  type SettingsSectionChild,
  type SectionStatus,
  resolveActiveSection,
} from './sections';

const STATUS_DOT: Record<NonNullable<SectionStatus>, string> = {
  ok: '',
  attention: 'bg-primary',
  warn: 'bg-yellow-500',
  danger: 'bg-red-500',
};

function hasAny(perms: string | string[] | undefined, check: (p: string) => boolean): boolean {
  if (!perms) return true;
  if (Array.isArray(perms)) return perms.length === 0 || perms.some(check);
  return check(perms);
}

interface RailItemProps {
  section: SettingsSection;
  activeId: string | null;
  parentId: string | null;
  isOpen: boolean;
  onToggle: () => void;
  filteredChildren: SettingsSectionChild[];
}

function RailItem({ section, activeId, parentId, isOpen, onToggle, filteredChildren }: RailItemProps) {
  const navigate = useNavigate();
  const Icon = section.icon;
  const hasChildren = filteredChildren.length > 0;
  const isActive = activeId === section.id || parentId === section.id;
  const dotCls = section.status && section.status !== 'ok' ? STATUS_DOT[section.status] : '';

  const handleClick = () => {
    if (hasChildren) onToggle();
    navigate(section.href);
  };

  return (
    <div>
      <button
        onClick={handleClick}
        className={cn(
          'relative w-full h-7 px-2 rounded-md flex items-center gap-2 text-left transition-colors',
          isActive
            ? 'bg-primary/10 text-primary'
            : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
        )}
        title={section.desc}
      >
        {isActive && (
          <span className="absolute top-1.5 bottom-1.5 -left-[7px] w-[2px] rounded-r bg-primary" />
        )}
        <Icon className={cn('w-[13px] h-[13px] shrink-0', isActive ? 'text-primary' : 'text-muted-foreground')} />
        <span className="flex-1 text-[12px] font-medium tracking-[0.005em] truncate">{section.label}</span>
        {dotCls && <span className={cn('w-1.5 h-1.5 rounded-full', dotCls)} />}
        {hasChildren && (
          <ChevronDown className={cn('w-[12px] h-[12px] text-muted-foreground transition-transform', isOpen && 'rotate-180')} />
        )}
      </button>

      {hasChildren && isOpen && (
        <div className="pl-6 pt-0.5 pb-1 flex flex-col gap-0.5">
          {filteredChildren.map(c => {
            const cActive = activeId === c.id;
            const CIcon = c.icon;
            return (
              <Link
                key={c.id}
                to={c.href}
                className={cn(
                  'h-6 px-2 rounded-md flex items-center gap-2 text-[11.5px] transition-colors',
                  cActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
                )}
              >
                {CIcon ? (
                  <CIcon className={cn('w-[11px] h-[11px]', cActive ? 'text-primary' : 'text-muted-foreground/70')} />
                ) : (
                  <span className="w-1 h-1 rounded-full bg-muted-foreground/60" />
                )}
                <span className="flex-1 truncate">{c.label}</span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

interface SettingsRailProps {
  onBackToApp: () => void;
}

export function SettingsRail({ onBackToApp }: SettingsRailProps) {
  const location = useLocation();
  const { hasPermission, hasAnyPermission, isDemoUser, user } = useAuth();
  const { capabilities } = useCapabilities();
  const { data: systemConfig } = useSystemConfig();
  const isAirGap = systemConfig?.air_gap === true;
  const [query, setQuery] = useState('');
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({ access: true });
  const inputRef = useRef<HTMLInputElement>(null);

  const { sectionId: activeId, parentId } = useMemo(
    () => resolveActiveSection(location.pathname, location.search),
    [location.pathname, location.search],
  );

  // Auto-open the parent of the active child.
  useEffect(() => {
    if (parentId && !openGroups[parentId]) {
      setOpenGroups(prev => ({ ...prev, [parentId]: true }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [parentId]);

  const checkPerm = (p: string) => hasPermission(p);

  // Filter visible sections + their children.
  const visibleSections = useMemo(() => {
    return SETTINGS_SECTIONS
      .map((s): SettingsSection | null => {
        if (s.capability && !capabilities[s.capability]) return null;
        if (s.demoHidden && isDemoUser) return null;
        if (s.airgapOnly && !isAirGap) return null;
        const sectionVisible = !s.permissions
          || (Array.isArray(s.permissions) ? hasAnyPermission(s.permissions) : hasPermission(s.permissions));
        if (!sectionVisible) return null;
        const children = (s.children || []).filter(c => {
          if (c.capability && !capabilities[c.capability]) return false;
          return hasAny(c.permissions, checkPerm);
        });
        return { ...s, children };
      })
      .filter((s): s is SettingsSection => s !== null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasPermission, hasAnyPermission, isDemoUser, capabilities, isAirGap]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return visibleSections;
    return visibleSections
      .map((s): SettingsSection | null => {
        const selfMatch = s.label.toLowerCase().includes(q) || s.desc.toLowerCase().includes(q);
        const kids = (s.children || []).filter(c => c.label.toLowerCase().includes(q));
        if (selfMatch || kids.length) return { ...s, children: kids.length ? kids : s.children };
        return null;
      })
      .filter((s): s is SettingsSection => s !== null);
  }, [query, visibleSections]);

  const byGroup = useMemo(() => {
    const out: Record<string, SettingsSection[]> = {};
    for (const g of SETTINGS_GROUPS) out[g.id] = [];
    for (const s of filtered) out[s.group]?.push(s);
    return out;
  }, [filtered]);

  // ⌘K focuses search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        // Only steal ⌘K when the user is inside the settings shell. Other
        // pages (Search, etc.) might bind it themselves.
        if (location.pathname.startsWith('/settings')) {
          e.preventDefault();
          inputRef.current?.focus();
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [location.pathname]);

  const initials = useMemo(() => {
    const name = user?.name?.trim() || user?.email?.trim() || '';
    if (!name) return 'U';
    const parts = name.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return name.substring(0, 2).toUpperCase();
  }, [user]);

  return (
    <aside
      className="row-span-3 col-start-1 flex flex-col border-r border-border w-[232px] shrink-0"
      style={{ background: 'var(--background)' }}
    >
      {/* Header — back-to-app + title */}
      <div className="shrink-0 h-[42px] flex items-center px-3 gap-2 border-b border-border">
        <button
          onClick={onBackToApp}
          className="w-[22px] h-[22px] rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
          title="Back to app"
        >
          <ChevronLeft className="w-[14px] h-[14px]" />
        </button>
        <div className="flex items-center gap-2 text-foreground">
          <SettingsIcon className="w-[14px] h-[14px] text-muted-foreground" />
          <span className="text-[13px] font-medium tracking-[-0.005em]">Settings</span>
        </div>
      </div>

      {/* Search */}
      <div className="shrink-0 px-2.5 pt-2 pb-1">
        <div className="h-7 rounded-md border border-border bg-card flex items-center gap-1.5 px-2 focus-within:border-foreground/30">
          <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search settings…"
            className="flex-1 bg-transparent outline-none text-[12px] text-foreground placeholder:text-muted-foreground/70"
          />
          {query ? (
            <button onClick={() => setQuery('')} className="text-muted-foreground/60 hover:text-muted-foreground">
              <X className="w-[11px] h-[11px]" />
            </button>
          ) : (
            <span className="font-mono text-[10px] text-muted-foreground/60">⌘K</span>
          )}
        </div>
      </div>

      {/* Body — grouped sections */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden scrollbar-thin px-2 py-1.5">
        {SETTINGS_GROUPS.map(g => {
          const items = byGroup[g.id] || [];
          if (!items.length) return null;
          return (
            <div key={g.id} className="mb-2">
              <div className="px-2 pt-1 pb-1 text-[10px] uppercase tracking-[0.12em] text-muted-foreground/70 font-medium">
                {g.label}
              </div>
              <div className="flex flex-col gap-0.5">
                {items.map(s => (
                  <RailItem
                    key={s.id}
                    section={s}
                    activeId={activeId}
                    parentId={parentId}
                    isOpen={!!openGroups[s.id]}
                    onToggle={() => setOpenGroups(o => ({ ...o, [s.id]: !o[s.id] }))}
                    filteredChildren={s.children || []}
                  />
                ))}
              </div>
            </div>
          );
        })}

        {query && filtered.length === 0 && (
          <div className="px-3 py-6 text-center text-[11.5px] text-muted-foreground">
            No settings match "<span className="text-foreground">{query}</span>".
          </div>
        )}
      </div>

      {/* User footer */}
      <div className="shrink-0 border-t border-border px-2.5 py-2">
        <div className="w-full h-10 px-1.5 rounded-md flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-full bg-primary/15 text-primary flex items-center justify-center font-mono font-semibold text-[10.5px] shrink-0">
            {initials}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[12px] font-medium text-foreground truncate">{user?.name || user?.email || 'User'}</div>
            <div className="text-[10.5px] text-muted-foreground truncate">{user?.roles?.[0] || 'User'}</div>
          </div>
        </div>
      </div>
    </aside>
  );
}
