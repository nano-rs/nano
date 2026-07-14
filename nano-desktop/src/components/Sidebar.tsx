import { useEffect, useState } from 'react';

import {
  NavActivity,
  NavCollapse,
  NavChart,
  NavGrid,
  NavLayers,
  NavList,
  NavSearch,
  NavShield,
  NavSquares,
} from '@/components/layout/nav-icons';

import markWhite from '../assets/nano_mark_white.png';
import wordmarkWhite from '../assets/nano_white.png';

/**
 * The EXPLORE rail. Only Search is wired up in this build; the rest are rendered
 * inert (no hover, no pointer) rather than as buttons that do nothing.
 *
 * Collapses to an icon rail with hover flyouts — the labels don't disappear,
 * they move. An icon-only rail with no way to read it is a memory test.
 *
 * Icons are the product set (layout/nav-icons.tsx), not the mock's ⌕/▦/◉ unicode
 * glyphs — the handoff calls those explicit placeholders ("replace with the
 * product icon set"), and they render at whatever size the font feels like.
 * These are real 24×24 / 1.5-stroke SVGs, the house convention.
 */
const COLLAPSED_KEY = 'nano-desktop:rail-collapsed';

interface Props {
  /** Bulk IOC lookup (⌘B) — paste a report, see what's in your data. */
  onOpenBulk: () => void;
  /** Past pivt investigations, and the tools pivt can reach. */
  onOpenAgent: (kind: 'sessions' | 'mcp') => void;
  /** The platform's dashboards. */
  onOpenDashboard: () => void;
  /** The built-in SOC Overview. */
  onOpenOverview: () => void;
  /** A pulsing dot on Sessions while pivt is actually working. */
  agentRunning?: boolean;
}

/** Account, deployment and session actions live in the titlebar's user menu —
 *  the rail is navigation only, so the two don't duplicate each other. */
export function Sidebar({ onOpenBulk, onOpenAgent, onOpenDashboard, onOpenOverview, agentRunning }: Props) {
  const explore: NavEntry[] = [
    { Icon: NavSearch, label: 'Search', active: true },
    { Icon: NavGrid, label: 'Dashboards', active: true, onClick: onOpenDashboard },
    { Icon: NavChart, label: 'SOC Overview', active: true, onClick: onOpenOverview },
    { Icon: NavLayers, label: 'Bulk lookup', active: true, onClick: onOpenBulk },
    { Icon: NavShield, label: 'Detections', active: false },
    { Icon: NavList, label: 'Cases', active: false },
    { Icon: NavActivity, label: 'Sources', active: false },
  ];

  const agent: NavEntry[] = [
    {
      Icon: NavActivity,
      label: 'Sessions',
      active: true,
      onClick: () => onOpenAgent('sessions'),
      // The dot is the honest signal that something is running on the analyst's
      // behalf while they're looking at another screen.
      pulse: agentRunning,
    },
    { Icon: NavSquares, label: 'MCP tools', active: true, onClick: () => onOpenAgent('mcp') },
  ];

  return <Rail explore={explore} agent={agent} />;
}

type NavEntry = {
  Icon: (props: { className?: string }) => React.ReactElement;
  label: string;
  active: boolean;
  onClick?: () => void;
  pulse?: boolean;
};

function Rail({ explore, agent }: { explore: NavEntry[]; agent: NavEntry[] }) {
  // A layout preference, so it should survive a relaunch.
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(COLLAPSED_KEY) === '1'
  );

  useEffect(() => {
    localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
  }, [collapsed]);

  return (
    <div
      className={`flex shrink-0 flex-col gap-0.5 border-r border-line bg-sidebar p-2.5 pt-3.5 transition-[width] duration-150 ${
        collapsed ? 'w-[56px]' : 'w-[200px]'
      }`}
    >
      {/* The rail sits under the traffic lights, so it starts below them. */}
      <div data-tauri-drag-region className="h-7 shrink-0" />

      {/* The wordmark when there's room; the "n" mark (letter + brand dot, a
          complete mark on its own) when collapsed — never a squashed wordmark. */}
      <div
        data-tauri-drag-region
        className={`flex shrink-0 items-center pt-1 pb-3 ${collapsed ? 'justify-center' : 'px-2.5'}`}
      >
        <img
          src={collapsed ? markWhite : wordmarkWhite}
          alt="nano"
          className={collapsed ? 'h-[18px]' : 'h-[15px]'}
        />
      </div>

      {!collapsed && <SectionLabel>EXPLORE</SectionLabel>}

      {explore.map((item) => (
        <NavItem key={item.label} item={item} collapsed={collapsed} />
      ))}

      {/* The agent is a first-class part of the workspace, not a panel bolted to
          the side of it — so it gets its own section in the rail. */}
      <div className={collapsed ? 'my-2 h-px bg-line' : ''} />
      {!collapsed && <SectionLabel>AGENT</SectionLabel>}

      {agent.map((item) => (
        <NavItem key={item.label} item={item} collapsed={collapsed} />
      ))}

      <span className="flex-1" />

      <button
        onClick={() => setCollapsed((current) => !current)}
        title={collapsed ? 'Expand' : 'Collapse'}
        className={`mt-1.5 flex h-7 items-center rounded-[7px] px-2 text-[12px] text-t4 hover:bg-hover hover:text-t1 ${
          collapsed ? 'justify-center' : 'justify-end'
        }`}
      >
        <NavCollapse className={`size-[16px] ${collapsed ? 'rotate-180' : ''}`} />
      </button>
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-2.5 pt-1 pb-2 text-[10.5px] font-bold tracking-[0.08em] text-t4">
      {children}
    </div>
  );
}

function NavItem({ item, collapsed }: { item: NavEntry; collapsed: boolean }) {
  const { Icon } = item;
  const body = (
    <div
      onClick={item.onClick}
      className={`flex items-center gap-2.5 rounded-[7px] py-2 text-[13px] ${
        collapsed ? 'justify-center px-0' : 'px-2.5'
      } ${
        item.active
          ? // An item that DOES something is clickable; the destination that is
            // simply "where you already are" is highlighted but inert.
            item.onClick
            ? 'cursor-default text-t2 hover:bg-hover hover:text-t1'
            : 'bg-accent-soft font-semibold text-t1'
          : 'pointer-events-none text-t4 opacity-60'
      }`}
    >
      <Icon className={`shrink-0 ${collapsed ? 'size-[20px]' : 'size-[18px]'}`} />
      {!collapsed && item.label}
      {item.pulse && (
        <span className="ml-auto size-1.5 shrink-0 rounded-full bg-accent pulse" />
      )}
    </div>
  );

  // Collapsed, the label moves into a flyout rather than vanishing.
  return collapsed ? <Flyout label={item.label}>{body}</Flyout> : body;
}

/** Label on hover, for when the rail is collapsed. */
function Flyout({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="group/flyout relative">
      {children}
      <div className="pointer-events-none absolute top-1/2 left-full z-50 ml-2 -translate-y-1/2 rounded-[7px] border border-line-strong bg-[rgba(36,39,46,0.96)] px-2.5 py-1 text-[12px] whitespace-nowrap text-t1 opacity-0 shadow-[0_10px_30px_rgba(0,0,0,0.5)] backdrop-blur-[40px] transition-opacity group-hover/flyout:opacity-100">
        {label}
      </div>
    </div>
  );
}

