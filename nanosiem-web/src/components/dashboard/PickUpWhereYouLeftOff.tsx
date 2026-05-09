// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Recent Activity Component
 *
 * Shows recent user activity (searches, cases, notebooks, etc.) for quick access.
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Search, FileText, Briefcase, Bell, Shield, LayoutDashboard } from 'lucide-react';
import { useRecentActivity, UnifiedRecentItem } from '@/hooks/useRecentActivity';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

const TYPE_CONFIG: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  search: { icon: Search, color: 'text-blue-400', label: 'Search Query' },
  notebook: { icon: FileText, color: 'text-purple-400', label: 'Notebook' },
  case: { icon: Briefcase, color: 'text-cyan-400', label: 'Case' },
  alert: { icon: Bell, color: 'text-amber-400', label: 'Alert' },
  detection: { icon: Shield, color: 'text-green-400', label: 'Detection Rule' },
  dashboard: { icon: LayoutDashboard, color: 'text-pink-400', label: 'Dashboard' },
};

function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 py-2 px-3">
      <div className="w-4 h-4 rounded bg-muted animate-pulse" />
      <div className="h-4 flex-1 rounded bg-muted animate-pulse" />
      <div className="w-12 h-3 rounded bg-muted animate-pulse" />
    </div>
  );
}

function formatCompactTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return `${Math.floor(diffDays / 7)}w ago`;
}

function RecentItem({ item }: { item: UnifiedRecentItem }) {
  const config = TYPE_CONFIG[item.type] || TYPE_CONFIG.search;
  const Icon = config.icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Link
          to={item.url}
          className="group flex items-center gap-3 py-2 px-3 rounded-xl hover:bg-white/5 transition-colors"
        >
          <Icon className={cn('w-4 h-4 shrink-0', config.color)} />
          <span className="text-sm text-foreground/90 truncate flex-1 group-hover:text-primary transition-colors">
            {item.title}
          </span>
          <span className="text-xs text-muted-foreground shrink-0">
            {formatCompactTime(item.accessedAt)}
          </span>
        </Link>
      </TooltipTrigger>
      <TooltipContent side="top" className="text-xs">
        {config.label}
      </TooltipContent>
    </Tooltip>
  );
}

interface PickUpWhereYouLeftOffProps {
  /** Number of visible items before scrolling (default 8) */
  visibleCount?: number;
  /** Maximum items to load (default 15) */
  maxItems?: number;
}

export function PickUpWhereYouLeftOff({ visibleCount = 8, maxItems = 15 }: PickUpWhereYouLeftOffProps) {
  const { items, isLoading } = useRecentActivity({ limit: maxItems });
  const [showItems, setShowItems] = useState(false);
  const [minDelayPassed, setMinDelayPassed] = useState(false);

  // Minimum skeleton display time
  useEffect(() => {
    const timeout = setTimeout(() => setMinDelayPassed(true), 400);
    return () => clearTimeout(timeout);
  }, []);

  // Show items once data is loaded AND minimum delay has passed
  useEffect(() => {
    if (!isLoading && items.length > 0 && minDelayPassed) {
      setShowItems(true);
    }
  }, [isLoading, items.length, minDelayPassed]);

  // Don't show anything if no items and not loading
  if (!isLoading && items.length === 0) {
    return null;
  }

  // Calculate max height based on visible count (each item is ~40px)
  const maxHeight = visibleCount * 40;
  const showSkeleton = isLoading || !showItems;

  return (
    <TooltipProvider delayDuration={300}>
      <div className="w-full">
        <div className="bg-card/50 backdrop-blur-sm rounded-b-2xl border border-border border-t-0 px-2 py-2">
          {showSkeleton ? (
            <div className="space-y-0.5">
              {Array.from({ length: Math.min(visibleCount, 5) }).map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </div>
          ) : (
            <div
              className={cn(
                'space-y-0.5',
                items.length > visibleCount && 'overflow-y-auto scrollbar-hidden'
              )}
              style={{ maxHeight: items.length > visibleCount ? `${maxHeight}px` : undefined }}
            >
              {items.map((item) => (
                <RecentItem
                  key={`${item.type}-${item.id}`}
                  item={item}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </TooltipProvider>
  );
}
