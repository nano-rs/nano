import { useEffect, useRef, useState } from 'react';

import {
  NavActivity,
  NavChart,
  NavGear,
  NavGrid,
  NavLayers,
  NavList,
  NavSearch,
} from '@/components/layout/nav-icons';

import { tabLabel, type Tab, type TabGroup } from '../state/tabs';

/**
 * The segmented dock: tabs live in a recessed well so the group reads as one
 * control rather than a row of floating chips, and the active tab is a raised
 * card — instant "where am I".
 *
 * pivt's tabs cluster inside a named, COLLAPSIBLE group, the way a browser groups
 * tabs. That matters more than it sounds: an investigation can open eight tabs, and
 * eight of anything in a titlebar squeezes every label down to "cl…". Collapsed,
 * the whole investigation is one chip you can park; expanded, its tabs are legible.
 *
 * Every tab has a MINIMUM width. Without one, flex happily shrinks them all to
 * three characters and an ellipsis, which is what the strip used to do.
 */
const MAX_VISIBLE = 5;
/** Past this many, a group's tail goes into its own overflow menu. */
const MAX_GROUP_VISIBLE = 4;

interface Props {
  tabs: Tab[];
  groups: TabGroup[];
  activeId: string;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
  onCloseGroup: (id: string) => void;
  onAdd: () => void;
}

export function TabStrip({
  tabs,
  groups,
  activeId,
  onSelect,
  onClose,
  onCloseGroup,
  onAdd,
}: Props) {
  const ungrouped = tabs.filter((tab) => !tab.groupId);

  const visible = ungrouped.slice(0, MAX_VISIBLE);
  let overflow = ungrouped.slice(MAX_VISIBLE);

  // The active tab must never hide in the overflow menu — swap it into view. The
  // tab it displaces goes INTO the overflow menu, in its place: dropping it
  // instead (as this once did) left a live, streaming tab rendered nowhere at
  // all — unreachable and uncloseable until the analyst happened to select a
  // lower-indexed tab.
  const activeIsHidden = overflow.some((tab) => tab.id === activeId);
  if (activeIsHidden) {
    const active = ungrouped.find((tab) => tab.id === activeId)!;
    const displaced = visible[MAX_VISIBLE - 1];
    visible[MAX_VISIBLE - 1] = active;
    overflow = overflow.map((tab) => (tab.id === activeId ? displaced : tab));
  }

  return (
    <div className="flex min-w-0 items-center gap-1 rounded-[10px] border border-line bg-inset p-1">
      {visible.map((tab) => (
        <TabButton
          key={tab.id}
          tab={tab}
          active={tab.id === activeId}
          onSelect={() => onSelect(tab.id)}
          onClose={() => onClose(tab.id)}
        />
      ))}

      {overflow.length > 0 && <OverflowMenu tabs={overflow} onSelect={onSelect} />}

      {groups.map((group) => (
        <GroupCluster
          key={group.id}
          group={group}
          tabs={tabs.filter((tab) => tab.groupId === group.id)}
          activeId={activeId}
          onSelect={onSelect}
          onClose={onClose}
          onCloseGroup={() => onCloseGroup(group.id)}
        />
      ))}

      <button
        onClick={onAdd}
        title="New tab (⌘T)"
        className="flex size-6 shrink-0 items-center justify-center rounded-[6px] text-[14px] text-t4 hover:bg-hover hover:text-t1"
      >
        +
      </button>
    </div>
  );
}

/**
 * One pivt investigation.
 *
 * Collapsed by default once it has more than a couple of tabs: the investigation
 * is a THING, and it should be possible to park it as one chip rather than have it
 * shove the analyst's own tabs off the strip.
 *
 * The name is a toggle, not a destructor. It used to close the entire group on
 * click — a destructive action on a control that reads as a label, which is about
 * the worst affordance you can give something. Closing is now its own ✕.
 */
function GroupCluster({
  group,
  tabs,
  activeId,
  onSelect,
  onClose,
  onCloseGroup,
}: {
  group: TabGroup;
  tabs: Tab[];
  activeId: string;
  onSelect: (id: string) => void;
  onClose: (id: string) => void;
  onCloseGroup: () => void;
}) {
  const holdsActive = tabs.some((tab) => tab.id === activeId);
  // Auto-collapse a big group, but never one the analyst is currently reading.
  const [collapsed, setCollapsed] = useState(tabs.length > MAX_GROUP_VISIBLE);
  const open = holdsActive || !collapsed;

  if (tabs.length === 0) return null;

  const running = tabs.some((tab) => tab.status === 'running');
  const visible = open ? tabs.slice(0, MAX_GROUP_VISIBLE) : [];
  const hidden = open ? tabs.slice(MAX_GROUP_VISIBLE) : tabs;

  return (
    <div
      className={`flex min-w-0 items-center gap-1 rounded-[8px] border px-1 py-0.5 ${
        open
          ? 'border-accent-line bg-accent-soft'
          : 'border-accent-line/60 bg-accent-soft/60 hover:bg-accent-soft'
      }`}
    >
      <button
        onClick={() => setCollapsed((current) => !current)}
        title={open ? `Collapse “${group.label}”` : `${group.label} — ${tabs.length} tabs`}
        className="flex min-w-0 shrink-0 items-center gap-1.5 rounded-[5px] px-1.5 py-0.5 text-[11px] font-semibold text-accent hover:bg-hover"
      >
        {running ? (
          <span className="size-1.5 shrink-0 rounded-full bg-accent pulse" />
        ) : (
          <span className="shrink-0 text-[10px]">✳</span>
        )}
        <span className="max-w-[140px] truncate">{group.label}</span>
        <span className="shrink-0 rounded-[20px] bg-accent/20 px-1.5 font-mono text-[10px]">
          {tabs.length}
        </span>
        <span className={`shrink-0 text-[8px] transition-transform ${open ? '' : '-rotate-90'}`}>
          ▾
        </span>
      </button>

      {visible.map((tab) => (
        <TabButton
          key={tab.id}
          tab={tab}
          active={tab.id === activeId}
          onSelect={() => onSelect(tab.id)}
          onClose={() => onClose(tab.id)}
        />
      ))}

      {hidden.length > 0 && open && <OverflowMenu tabs={hidden} onSelect={onSelect} />}

      {/* Past the tab cap pivt keeps working; the strip says so rather than
          pretending the investigation stopped there. */}
      {group.overflow > 0 && (
        <span
          title={`${group.overflow} further tool calls — see the pivt panel`}
          className="shrink-0 px-0.5 font-mono text-[10px] text-t4"
        >
          +{group.overflow}
        </span>
      )}

      <button
        onClick={onCloseGroup}
        title={`Close the investigation and its ${tabs.length} tabs`}
        className="ml-0.5 shrink-0 rounded-[5px] px-1 text-[11px] text-t4 hover:bg-hover hover:text-danger"
      >
        ✕
      </button>
    </div>
  );
}

function TabButton({
  tab,
  active,
  onSelect,
  onClose,
}: {
  tab: Tab;
  active: boolean;
  onSelect: () => void;
  onClose: () => void;
}) {
  return (
    <div
      onClick={onSelect}
      title={tabLabel(tab)}
      // A FLOOR on the width. `min-w-0` alone let flex crush eight tabs down to
      // "cl…" apiece, which is a strip of ellipses rather than a set of labels.
      className={`group flex w-[150px] max-w-[190px] min-w-[110px] shrink cursor-default items-center gap-1.5 rounded-[7px] px-2 py-1 text-[12.5px] ${
        active
          ? // Raised card: lifted off the well, not just tinted.
            'border border-line-strong bg-raised font-semibold text-t1 shadow-[0_1px_3px_rgba(0,0,0,0.45)]'
          : 'border border-transparent text-t3 hover:bg-hover hover:text-t2'
      }`}
    >
      <TabGlyph tab={tab} active={active} />

      <span className="min-w-0 flex-1 truncate font-mono">{tabLabel(tab)}</span>

      {/* A preview tab holds ten rows, not the result set. A dot says so without
          spending a quarter of the tab's width on the word "preview". */}
      {tab.preview && tab.kind === 'search' && (
        <span
          title="Preview — 10 rows, not the full result set"
          className="size-1 shrink-0 rounded-full bg-t4"
        />
      )}

      <button
        onClick={(event) => {
          event.stopPropagation();
          onClose();
        }}
        title="Close tab (⌘W)"
        className="shrink-0 text-t4 opacity-0 group-hover:opacity-100 hover:text-t1"
      >
        ✕
      </button>
    </div>
  );
}

/**
 * What KIND of thing this tab is, at a glance — the product's own icon set, not
 * unicode glyphs. The mock's ⌕/▦/◉ were explicit placeholders, and they render at
 * whatever size and weight the font feels like; these are the real 24×24 /
 * 1.5-stroke SVGs, shrunk to the strip's scale.
 */
const ICON: Record<string, (props: { className?: string }) => React.ReactElement> = {
  search: NavSearch,
  tool: NavActivity,
  bulk: NavLayers,
  dashboard: NavGrid,
  overview: NavChart,
  sessions: NavList,
  mcp: NavGear,
};

/** A running tab says so even while you're looking at another one. */
function TabGlyph({ tab, active }: { tab: Tab; active: boolean }) {
  if (tab.status === 'running') {
    return <span className="size-1.5 shrink-0 rounded-full bg-accent pulse" />;
  }
  const Icon = ICON[tab.kind] ?? NavSearch;
  return (
    <Icon className={`size-[13px] shrink-0 ${active ? 'text-accent' : 'text-t4'}`} />
  );
}

/** The tail, past what fits. */
function OverflowMenu({ tabs, onSelect }: { tabs: Tab[]; onSelect: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  if (tabs.length === 0) return null;

  return (
    <div ref={root} className="relative shrink-0">
      <button
        onClick={() => setOpen((current) => !current)}
        title={`${tabs.length} more`}
        className="flex h-6 items-center gap-1 rounded-[6px] px-1.5 text-[11px] text-t4 hover:bg-hover hover:text-t1"
      >
        ⌄<span className="font-mono">{tabs.length}</span>
      </button>

      {open && (
        <div className="absolute top-full left-0 z-50 mt-1.5 w-[300px] overflow-hidden rounded-[9px] border border-line-strong bg-[rgba(36,39,46,0.96)] p-1 shadow-[0_18px_44px_rgba(0,0,0,0.5)] backdrop-blur-[40px]">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                onSelect(tab.id);
                setOpen(false);
              }}
              className="flex w-full items-center gap-2 rounded-[6px] px-2 py-1.5 text-left text-[12px] text-t2 hover:bg-hover hover:text-t1"
            >
              <TabGlyph tab={tab} active={false} />
              <span className="truncate font-mono">{tabLabel(tab)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
