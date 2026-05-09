// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, type ComponentType } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import {
  Database,
  Calendar,
  Loader2,
  Zap,
  Archive,
  Gauge,
  Trash2,
  Activity,
} from 'lucide-react';
import { api, StorageOverview, ClickHouseStorageStats, DiskPressureStatus } from '@/lib/api';
import { formatUTC } from '@/lib/date-utils';
import { useToast } from '@/hooks/use-toast';
import { SettingsSubsectionShell, type SubsectionTab } from '@/components/settings/SettingsSubsectionShell';

type StorageTabId = 'clickhouse' | 'postgres';
const TAB_IDS: StorageTabId[] = ['clickhouse', 'postgres'];

function isStorageTab(value: string | null): value is StorageTabId {
  return value !== null && (TAB_IDS as string[]).includes(value);
}

const TABS: SubsectionTab<StorageTabId>[] = [
  {
    id: 'clickhouse',
    label: 'ClickHouse · Logs',
    icon: Zap,
    desc: 'Time-series log storage. Daily partitions; TTL retention managed via deployment config.',
  },
  {
    id: 'postgres',
    label: 'PostgreSQL · Metadata',
    icon: Database,
    desc: 'Detection rules, alerts, dashboards, saved searches, parser configurations, AI settings.',
  },
];

export function RetentionSettings() {
  useDocumentTitle('Storage & Retention');

  const { toast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const [overview, setOverview] = useState<StorageOverview | null>(null);
  const [loading, setLoading] = useState(true);

  const requested = searchParams.get('tab');
  const activeTab: StorageTabId = isStorageTab(requested) ? requested : 'clickhouse';

  // Canonicalize URL on mount so the rail child highlights when arriving at bare /settings/storage
  useEffect(() => {
    if (!isStorageTab(searchParams.get('tab'))) {
      setSearchParams({ tab: 'clickhouse' }, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const overviewRes = await api.getStorageOverview();
        setOverview(overviewRes);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to load settings';
        toast({ title: 'Error', description: message, variant: 'destructive' });
      } finally {
        setLoading(false);
      }
    };
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleTabChange = (id: StorageTabId) => {
    setSearchParams({ tab: id });
  };

  return (
    <SettingsSubsectionShell
      sectionId="storage"
      tabs={TABS}
      activeTab={activeTab}
      onTabChange={handleTabChange}
    >
      {loading && !overview ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="px-6 py-5 space-y-5">
          {/* ClickHouse */}
          <div style={{ display: activeTab === 'clickhouse' ? 'block' : 'none' }} className="space-y-5">
            {overview?.disk_pressure && <DiskPressurePanel status={overview.disk_pressure} />}

            {overview?.clickhouse ? (
              <>
                <ClickHouseStats stats={overview.clickhouse} />
                <HelperNote
                  icon={Archive}
                  iconColor="text-cyan-400"
                  title="Data retention"
                  body="ClickHouse TTL retention and storage tiering are managed via deployment configuration. Data is automatically partitioned by day; expired partitions are dropped on the configured schedule."
                />
              </>
            ) : overview?.clickhouse_enabled ? (
              <HelperNote
                icon={Database}
                iconColor="text-yellow-400"
                title="No log data yet"
                body="ClickHouse is enabled but no log data has been ingested yet. Start sending logs to see storage statistics here."
              />
            ) : (
              <HelperNote
                icon={Database}
                iconColor="text-muted-foreground"
                title="ClickHouse not configured"
                body="ClickHouse is not enabled for this deployment. Log storage is using PostgreSQL."
              />
            )}
          </div>

          {/* PostgreSQL */}
          <div style={{ display: activeTab === 'postgres' ? 'block' : 'none' }} className="space-y-5">
            {overview?.postgres && <PostgresStats stats={overview.postgres} />}
            <HelperNote
              icon={Database}
              iconColor="text-primary"
              title="Metadata storage"
              body="PostgreSQL stores metadata: detection rules, alerts, dashboards, saved searches, parser configurations, and AI settings. Log telemetry lives in ClickHouse for query performance."
            />
          </div>
        </div>
      )}
    </SettingsSubsectionShell>
  );
}

interface StatCell {
  label: string;
  value: string;
  sub?: string | null;
}

function StatGrid({ cells }: { cells: StatCell[] }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 border-l border-t border-border">
      {cells.map((c) => (
        <div key={c.label} className="px-4 py-3 border-r border-b border-border min-w-0">
          <p className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">
            {c.label}
          </p>
          <p className="font-mono text-[16px] font-semibold tabular-nums text-foreground leading-none mt-1.5 truncate">
            {c.value}
          </p>
          {c.sub && (
            <p className="font-mono text-[10.5px] text-muted-foreground mt-1 truncate">{c.sub}</p>
          )}
        </div>
      ))}
    </div>
  );
}

function HelperNote({
  icon: Icon,
  iconColor,
  title,
  body,
}: {
  icon: ComponentType<{ className?: string }>;
  iconColor: string;
  title: string;
  body: string;
}) {
  return (
    <div className="rounded-md border border-border bg-card/40 p-3 flex items-start gap-2.5">
      <Icon className={`w-4 h-4 ${iconColor} mt-0.5 shrink-0`} />
      <div className="min-w-0">
        <p className="text-[12.5px] font-medium text-foreground">{title}</p>
        <p className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed">{body}</p>
      </div>
    </div>
  );
}

function ClickHouseStats({ stats }: { stats: ClickHouseStorageStats }) {
  const hasDetailedStats = stats.total_size_bytes > 0 || stats.parts_count > 0;
  const cells: StatCell[] = [
    {
      label: 'Total size',
      value: stats.total_size_pretty,
      sub: hasDetailedStats ? `${stats.compression_ratio.toFixed(1)}× compression` : null,
    },
    {
      label: 'Total logs',
      value: stats.row_count.toLocaleString(),
    },
    {
      label: 'Partitions',
      value: hasDetailedStats ? String(stats.partition_count) : '—',
      sub: hasDetailedStats ? `${stats.parts_count} parts` : null,
    },
    {
      label: 'Date range',
      value: formatUTC(stats.oldest_log),
      sub: `to ${formatUTC(stats.newest_log)}`,
    },
  ];
  return <StatGrid cells={cells} />;
}

function PostgresStats({
  stats,
}: {
  stats: {
    total_size_pretty: string;
    log_count: number;
    chunk_count: number;
    compressed_chunks: number;
    oldest_log: string | null;
    newest_log: string | null;
  };
}) {
  const cells: StatCell[] = [
    { label: 'Database size', value: stats.total_size_pretty },
    { label: 'Records', value: stats.log_count.toLocaleString(), sub: 'alerts, rules, cases' },
    { label: 'Tables', value: String(stats.chunk_count) },
    {
      label: 'Alert range',
      value: formatUTC(stats.oldest_log),
      sub: `to ${formatUTC(stats.newest_log)}`,
    },
  ];
  return <StatGrid cells={cells} />;
}

function DiskPressurePanel({ status }: { status: DiskPressureStatus }) {
  const formatBytes = (bytes: number) => {
    if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`;
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
    return `${(bytes / 1e3).toFixed(1)} KB`;
  };

  const usagePct = (status.usage_fraction * 100).toFixed(1);

  const levelConfig: Record<string, { bg: string; text: string; border: string; bar: string; label: string }> = {
    normal:    { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/20', bar: 'bg-emerald-500', label: 'Normal' },
    elevated:  { bg: 'bg-yellow-500/10',  text: 'text-yellow-400',  border: 'border-yellow-500/20',  bar: 'bg-yellow-500',  label: 'Elevated' },
    critical:  { bg: 'bg-orange-500/10',  text: 'text-orange-400',  border: 'border-orange-500/20',  bar: 'bg-orange-500',  label: 'Critical' },
    emergency: { bg: 'bg-red-500/10',     text: 'text-red-400',     border: 'border-red-500/20',     bar: 'bg-red-500',     label: 'Emergency' },
  };
  const level = levelConfig[status.level] ?? levelConfig.normal;

  return (
    <section className="space-y-3 pb-4 border-b border-border/60">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5 min-w-0">
          <Gauge className={`w-4 h-4 ${level.text} shrink-0`} />
          <div className="min-w-0">
            <p className="text-[12.5px] font-medium text-foreground">Disk pressure</p>
            <p className="font-mono text-[10.5px] text-muted-foreground mt-0.5">
              {formatBytes(status.used_bytes)} of {formatBytes(status.total_bytes)} used ({usagePct}%)
            </p>
          </div>
        </div>
        <span
          className={`font-mono text-[10px] font-semibold uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border ${level.bg} ${level.text} ${level.border}`}
        >
          {level.label}
        </span>
      </div>

      {/* Usage bar with watermark ticks */}
      <div className="relative">
        <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${level.bar}`}
            style={{ width: `${Math.min(status.usage_fraction * 100, 100)}%` }}
          />
        </div>
        <div
          className="absolute top-0 h-2 w-px bg-yellow-400/60"
          style={{ left: `${status.high_watermark * 100}%` }}
        />
        <div
          className="absolute top-0 h-2 w-px bg-red-400/60"
          style={{ left: `${status.critical_threshold * 100}%` }}
        />
        <div className="flex justify-between mt-1">
          <span className="font-mono text-[10px] text-muted-foreground">
            {(status.low_watermark * 100).toFixed(0)}% low
          </span>
          <span className="font-mono text-[10px] text-muted-foreground">
            {(status.high_watermark * 100).toFixed(0)}% high
          </span>
          <span className="font-mono text-[10px] text-muted-foreground">
            {(status.critical_threshold * 100).toFixed(0)}% critical
          </span>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-3">
        {[
          {
            icon: Calendar,
            label: 'Est. retention',
            value:
              status.estimated_retention_days != null
                ? status.estimated_retention_days > 3650
                  ? '10+ years'
                  : status.estimated_retention_days > 365
                  ? `${(status.estimated_retention_days / 365).toFixed(1)} years`
                  : `${status.estimated_retention_days.toFixed(0)} days`
                : '—',
          },
          { icon: Trash2, label: 'Partitions dropped', value: String(status.partitions_dropped) },
          {
            icon: Activity,
            label: 'Ingestion',
            value: status.ingestion_paused ? 'Paused' : 'Active',
            valueColor: status.ingestion_paused ? 'text-red-400' : 'text-emerald-400',
          },
        ].map(({ icon: Icon, label, value, valueColor }) => (
          <div key={label} className="flex items-center gap-1.5 min-w-0">
            <Icon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
            <div className="min-w-0">
              <p className="font-mono text-[10px] text-muted-foreground uppercase tracking-[0.08em]">
                {label}
              </p>
              <p className={`font-mono text-[12.5px] font-medium mt-0.5 truncate ${valueColor || 'text-foreground'}`}>
                {value}
              </p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

