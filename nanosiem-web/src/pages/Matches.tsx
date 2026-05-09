// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — redesigned per-rule Matches page at /rules/:id/matches.
//
// Port of design-ref/matches.html + shadcn/matches-*.jsx into the real app
// against the live detection-matches API. The old visuals lived at
// DetectionMatches.tsx (kept importable for the sunset PR).

import { useMemo, useState, useCallback } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { AlertTriangle, Loader2 } from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import {
  useAlerts,
  useDetection,
  useDetectionMatches,
  useDetectionStats,
  useTodayCounts,
  usePauseDetection,
  useResumeDetection,
  usePromoteDetection,
  useDemoteDetection,
} from '@/hooks/use-api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

import { MatchesHero } from '@/components/matches/MatchesHero';
import { MatchesList } from '@/components/matches/MatchesList';
import { MatchesDetail } from '@/components/matches/MatchesDetail';
import { LogicTab } from '@/components/matches/LogicTab';
import { buildMatchView, buildActivity28, type MatchView } from '@/components/matches/helpers';

type TabId = 'matches' | 'logic';

export function Matches() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('detections:edit');

  const { data: apiRule, loading: ruleLoading, error: ruleError, refetch: refetchRule } = useDetection(id);
  const { data: matchesData, loading: matchesLoading } = useDetectionMatches(id, { limit: 100 });
  const { data: apiAlerts } = useAlerts({ rule_id: id });
  const { data: statsData } = useDetectionStats(28);
  const { data: todayCounts } = useTodayCounts();
  const { mutate: pauseDetection } = usePauseDetection();
  const { mutate: resumeDetection } = useResumeDetection();
  const { mutate: promoteDetection } = usePromoteDetection();
  const { mutate: demoteDetection } = useDemoteDetection();

  useDocumentTitle(apiRule ? `${apiRule.name} Matches` : 'Matches', [apiRule?.id]);

  const [activeTab, setActiveTab] = useState<TabId>('matches');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'alerts'>('all');

  const views: MatchView[] = useMemo(() => {
    return (matchesData?.matches || []).map(buildMatchView);
  }, [matchesData]);

  // Set of match ids that generated alerts. The /api/alerts response doesn't
  // carry a `match_id` today, so we can't do an exact join — we correlate by
  // timestamp proximity (<60s between `alert.created_at` and `match.detected_at`).
  // Edge case: if a rule fires twice in the same minute, both matches can pick
  // up the badge. Acceptable for visual linking; fix properly when the backend
  // exposes match_id on alerts.
  const alertedMatchIds = useMemo(() => {
    const out = new Set<string>();
    if (!apiAlerts || apiAlerts.length === 0) return out;
    for (const v of views) {
      const near = apiAlerts.find((a) => {
        const at = new Date(a.created_at.endsWith('Z') ? a.created_at : a.created_at + 'Z').getTime();
        return Math.abs(at - v.detectedAt.getTime()) < 60_000;
      });
      if (near) out.add(v.id);
    }
    return out;
  }, [views, apiAlerts]);

  // Selected view defaults to the first one once loaded.
  const effectiveSelectedId = selectedId ?? views[0]?.id ?? null;
  const selected = useMemo(
    () => views.find((v) => v.id === effectiveSelectedId) || null,
    [views, effectiveSelectedId],
  );

  const linkedAlert = useMemo(() => {
    if (!selected || !apiAlerts) return undefined;
    return apiAlerts.find((a) => {
      const at = new Date(a.created_at.endsWith('Z') ? a.created_at : a.created_at + 'Z').getTime();
      return Math.abs(at - selected.detectedAt.getTime()) < 60_000;
    });
  }, [selected, apiAlerts]);

  const activity28d = useMemo(() => {
    if (!id) return Array(28).fill(0);
    const stats = statsData?.[id];
    const today = todayCounts?.[id] ?? 0;
    return buildActivity28(stats, today);
  }, [id, statsData, todayCounts]);

  const handleTogglePause = useCallback(async () => {
    if (!apiRule) return;
    try {
      if (apiRule.mode === 'paused') {
        await resumeDetection(apiRule.id);
        toast({ title: 'Rule resumed', description: 'Detection returned to live.' });
      } else {
        await pauseDetection(apiRule.id);
        toast({ title: 'Rule paused' });
      }
      refetchRule();
    } catch {
      toast({ title: 'Error', description: 'Failed to update rule.', variant: 'destructive' });
    }
  }, [apiRule, pauseDetection, resumeDetection, refetchRule, toast]);

  const handleToggleAlerting = useCallback(async () => {
    if (!apiRule) return;
    try {
      if (apiRule.mode === 'alerting') {
        await demoteDetection(apiRule.id);
        toast({ title: 'Alerting disabled', description: 'Rule demoted to live mode.' });
      } else {
        await promoteDetection(apiRule.id);
        toast({ title: 'Alerting enabled' });
      }
      refetchRule();
    } catch {
      toast({ title: 'Error', description: 'Failed to update rule mode.', variant: 'destructive' });
    }
  }, [apiRule, promoteDetection, demoteDetection, refetchRule, toast]);

  const handleOpenInSearch = useCallback((view: MatchView) => {
    if (!apiRule) return;
    const raw = (view.entity.raw || view.entity.label || '').trim();
    if (!raw) return;
    const escaped = raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    // Use only the source-filter stage of the rule's pipeline (everything
    // before the first `|`). Appending `| search "..."` after a stats step
    // breaks at compile time because `search` lowers to `WHERE message LIKE …`,
    // and `message` no longer exists post-aggregation. Drop the aggregation
    // entirely when pivoting to raw events — the analyst wants the underlying
    // activity for the entity, not a re-run of the rule's stats.
    const baseFilter = apiRule.query.split('|')[0].trim();
    let entityFilter: string;
    switch (view.entity.type) {
      case 'user':
      case 'role':
      case 'service':
        entityFilter = raw.startsWith('arn:')
          ? `user_identity.arn="${escaped}"`
          : `user="${escaped}"`;
        break;
      case 'host':
        entityFilter = `(src_host="${escaped}" OR dest_host="${escaped}" OR hostname="${escaped}")`;
        break;
      case 'ip':
        entityFilter = `(src_ip="${escaped}" OR dest_ip="${escaped}")`;
        break;
      default:
        entityFilter = `"${escaped}"`;
    }
    const q = baseFilter ? `${baseFilter} ${entityFilter}` : entityFilter;
    navigate(`/search?q=${encodeURIComponent(q)}`);
  }, [apiRule, navigate]);

  if (ruleLoading) {
    return (
      <div className="p-12 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (ruleError || !apiRule) {
    return (
      <div className="p-8 max-w-[520px] mx-auto">
        <div className="rounded-lg border border-destructive/30 bg-destructive/[0.05] p-5 flex flex-col gap-2">
          <div className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="w-4 h-4" strokeWidth={2} />
            <span className="text-[13px] font-medium">Detection rule not found</span>
          </div>
          <p className="text-[11.5px] text-muted-foreground">
            {ruleError?.message || 'This rule may have been deleted or the id is invalid.'}
          </p>
          <div>
            <Link
              to="/rules"
              className="h-7 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 inline-flex items-center gap-1.5"
            >
              Back to rules
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const tabs: Array<{ id: TabId; label: string; count?: number }> = [
    { id: 'matches', label: 'Matches', count: views.length },
    { id: 'logic',   label: 'Rule logic' },
  ];

  return (
    <div
      className="flex flex-col min-h-0"
      style={{ containerType: 'inline-size' }}
    >
      <div className="pt-3 pb-4 shrink-0">
        <MatchesHero
          rule={apiRule}
          views={views}
          totalMatches={matchesData?.total ?? views.length}
          alertsGenerated={apiAlerts?.length ?? 0}
          activity28d={activity28d}
          onTogglePause={handleTogglePause}
          onToggleAlerting={handleToggleAlerting}
          canEdit={canEdit}
        />
      </div>

      {/* Tab bar — sticky. The scroll container has p-3, which leaves a
          12px region above where sticky `top-0` pins. Other panes (the
          MatchesDetail right column has no sticky of its own) would scroll
          content through that region. Pin at `-top-3` and add matching `pt-3`
          so the bar's box extends up into and covers the padding. */}
      <div
        className="border-b border-border flex items-center gap-0 shrink-0 sticky -top-3 z-20 backdrop-blur pt-3"
        style={{ background: 'color-mix(in srgb, var(--background) 88%, transparent)' }}
      >
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setActiveTab(t.id)}
            className={cn(
              'h-9 px-3 text-[12px] flex items-center gap-1.5 border-b-2 -mb-px transition-colors',
              activeTab === t.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {t.label}
            {t.count !== undefined && (
              <span
                className={cn(
                  'font-mono text-[10px] tabular-nums rounded px-[5px] py-[1px]',
                  activeTab === t.id
                    ? 'bg-primary/15 text-primary'
                    : 'text-muted-foreground/70',
                )}
              >
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 min-h-0">
        {activeTab === 'matches' ? (
          <div className="grid grid-cols-[380px_1fr] @max-[900px]:grid-cols-1 min-h-[560px]">
            <MatchesList
              views={views}
              selectedId={effectiveSelectedId}
              onSelect={setSelectedId}
              filter={filter}
              onFilterChange={setFilter}
              alertedMatchIds={alertedMatchIds}
              loading={matchesLoading}
            />
            <MatchesDetail
              view={selected}
              alertGenerated={selected ? alertedMatchIds.has(selected.id) : false}
              linkedAlertId={linkedAlert?.id}
              linkedAlertTitle={linkedAlert?.rule_name}
              onOpenInSearch={handleOpenInSearch}
              ruleId={apiRule?.id}
            />
          </div>
        ) : (
          <LogicTab rule={apiRule} />
        )}
      </div>
    </div>
  );
}

export default Matches;
