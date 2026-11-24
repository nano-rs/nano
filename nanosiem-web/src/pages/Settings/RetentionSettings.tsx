// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, type ComponentType } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import {
  Database,
  Calendar,
  Zap,
  Archive,
  Gauge,
  Trash2,
  Activity,
  PauseCircle,
  PlayCircle,
  Clock,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import {
  api,
  StorageOverview,
  ClickHouseStorageStats,
  DiskPressureStatus,
  IngestionPauseStatus,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { formatUTC } from '@/lib/date-utils';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { SettingsSubsectionShell, type SubsectionTab } from '@/components/settings/SettingsSubsectionShell';
import { DiskUsageNotice } from '@/components/DiskSpaceBanner';
import { StatGrid, type StatCell } from '@/components/settings/StatGrid';
import { StorageTieringPanel } from '@/enterprise/components/settings/StorageTieringPanel';
import { Term } from '@/components/ui/term';

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
    desc: 'Where events are stored, how long they are kept, and optional cold storage.',
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
  const { capabilities } = useCapabilities();
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
          <LoadingIcon className="w-5 h-5 text-muted-foreground" />
        </div>
      ) : (
        <div className="px-6 py-5 space-y-5">
          {/* NAN-5450: data disks at 80 % or more, with the forecast. */}
          <DiskUsageNotice />
          {/* ClickHouse */}
          <div style={{ display: activeTab === 'clickhouse' ? 'block' : 'none' }} className="space-y-5">
            {overview?.ingestion && (
              <IngestionPausePanel
                status={overview.ingestion}
                onChange={(ingestion) =>
                  setOverview((prev) =>
                    prev
                      ? {
                          ...prev,
                          ingestion,
                          disk_pressure: prev.disk_pressure
                            ? { ...prev.disk_pressure, ingestion_paused: ingestion.paused }
                            : prev.disk_pressure,
                        }
                      : prev,
                  )
                }
              />
            )}
            {overview?.disk_pressure && <DiskPressurePanel status={overview.disk_pressure} />}

            {overview?.clickhouse ? (
              <>
                <ClickHouseStats stats={overview.clickhouse} />
                <RetentionPanel
                  stats={overview.clickhouse}
                  diskDays={overview.disk_pressure?.estimated_retention_days ?? null}
                  onSaved={(days) =>
                    setOverview((prev) =>
                      prev?.clickhouse
                        ? { ...prev, clickhouse: { ...prev.clickhouse, ttl_days: days, retention_source: 'ui' } }
                        : prev,
                    )
                  }
                />
                {/* Enterprise + licensed only: the open stub renders nothing (NAN-2356 gate). */}
                {capabilities.storageTiering && <StorageTieringPanel />}
                <HelperNote
                  icon={Archive}
                  iconColor="text-cyan-400"
                  title="How retention works"
                  body="nano deletes each whole day of events once it is older than the retention, in the cold tier too. If the disk gets too full and there is no cold tier, the oldest days go first. A value set at install (NANO_RETENTION_DAYS or nano.retention.days) replaces this one on the next deploy."
                />
              </>
            ) : overview?.clickhouse_enabled ? (
              <HelperNote
                icon={Database}
                iconColor="text-yellow-400"
                title="No log data yet"
                body="No logs ingested yet."
              />
            ) : (
              <HelperNote
                icon={Database}
                iconColor="text-muted-foreground"
                title="ClickHouse not configured"
                body="Log storage is using PostgreSQL."
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
              body="Rules, alerts, dashboards, saved searches, parsers and AI settings. Logs live in ClickHouse."
            />
          </div>
        </div>
      )}
    </SettingsSubsectionShell>
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

const MIN_RETENTION_DAYS = 1;
const MAX_RETENTION_DAYS = 3650;
/** Below this, the installer refuses a disk (NAN-5449); the UI warns. */
const SHORT_RETENTION_DAYS = 7;

/** NAN-5449: the event retention (ClickHouse TTL) and the control that sets it. */
export function RetentionPanel({
  stats,
  diskDays,
  onSaved,
}: {
  stats: ClickHouseStorageStats;
  diskDays: number | null;
  onSaved: (days: number) => void;
}) {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('settings:retention');
  const current = stats.ttl_days;
  const [value, setValue] = useState(current != null ? String(current) : '');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setValue(current != null ? String(current) : '');
  }, [current]);

  const parsed = /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN;
  const valid = Number.isInteger(parsed) && parsed >= MIN_RETENTION_DAYS && parsed <= MAX_RETENTION_DAYS;
  const changed = valid && parsed !== current;
  // Unknown current TTL: the new value may be a reduction, so confirm too.
  const reducing = changed && (current == null || parsed < current);

  const save = async () => {
    setBusy(true);
    try {
      await api.updateClickHouseRetention(parsed);
      onSaved(parsed);
      toast({ title: 'Retention updated', description: `Events are kept for ${parsed} days.` });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Request failed';
      toast({ title: 'Error', description: message, variant: 'destructive' });
    } finally {
      setBusy(false);
      setConfirmOpen(false);
    }
  };

  const sourceLabel =
    stats.retention_source === 'deployment'
      ? `set by deployment (NANO_RETENTION_DAYS=${stats.deployment_retention_days ?? current})`
      : stats.retention_source === 'ui'
        ? 'set in Settings'
        : 'shipped default';

  return (
    <section className="space-y-2 pb-4 border-b border-border/60" aria-label="Event retention">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <Clock className="w-4 h-4 text-cyan-400 shrink-0" />
          <div className="min-w-0">
            <p className="text-[12.5px] font-medium text-foreground">
              <Term id="event-retention">Event retention</Term>{' '}
              <span className="font-mono" data-testid="retention-current">
                {current != null ? `${current} days` : 'unknown'}
              </span>
            </p>
            <p className="font-mono text-[10.5px] text-muted-foreground mt-0.5 truncate">
              {sourceLabel}
              {diskDays != null && current != null && diskDays < current
                ? ` · disk holds ~${Math.floor(diskDays)} days at the current rate`
                : ''}
            </p>
          </div>
        </div>
        {canEdit && (
          <form
            className="flex items-center gap-1.5 shrink-0"
            onSubmit={(e) => {
              e.preventDefault();
              if (!changed || busy) return;
              if (reducing) setConfirmOpen(true);
              else void save();
            }}
          >
            <Input
              aria-label="Retention in days"
              inputMode="numeric"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              className="h-7 w-20 font-mono text-[12px] tabular-nums"
            />
            <span className="text-[11.5px] text-muted-foreground">days</span>
            <Button type="submit" size="sm" variant="outline" className="h-7 text-[11.5px]" disabled={!changed || busy}>
              Save
            </Button>
          </form>
        )}
      </div>
      {value.trim() !== '' && !valid && (
        <p className="text-[11.5px] text-red-400">
          Enter a whole number of days, {MIN_RETENTION_DAYS}-{MAX_RETENTION_DAYS}.
        </p>
      )}
      {valid && parsed < SHORT_RETENTION_DAYS && (
        <p className="text-[11.5px] text-yellow-400">
          Under {SHORT_RETENTION_DAYS} days leaves little history for investigations and detection tuning.
        </p>
      )}
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => !open && setConfirmOpen(false)}
        title={`Reduce retention to ${valid ? parsed : ''} days?`}
        description={
          <>
            {current == null && 'The current retention could not be read, so this may shorten it. '}
            Events older than{' '}
            <span className="text-foreground font-medium font-mono">{valid ? parsed : ''} days</span> are deleted in
            the background, including the audit trail stored in the event table. This cannot be undone.
          </>
        }
        confirmLabel="Reduce retention"
        variant="danger"
        loading={busy}
        onConfirm={() => void save()}
      />
    </section>
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
            <p className="text-[12.5px] font-medium text-foreground"><Term id="disk-pressure">Disk pressure</Term></p>
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

/** NAN-5217: the cluster-wide ingestion pause, its provenance and the admin control. */
function IngestionPausePanel({
  status,
  onChange,
}: {
  status: IngestionPauseStatus;
  onChange: (status: IngestionPauseStatus) => void;
}) {
  const { toast } = useToast();
  const [confirm, setConfirm] = useState<'pause' | 'resume' | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async (action: 'pause' | 'resume') => {
    setBusy(true);
    try {
      const next =
        action === 'pause' ? await api.pauseIngestion(reason.trim()) : await api.resumeIngestion();
      onChange(next);
      setReason('');
      toast({ title: action === 'pause' ? 'Ingestion paused' : 'Ingestion resumed' });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Request failed';
      toast({ title: 'Error', description: message, variant: 'destructive' });
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  };

  const sourceLabel =
    status.source === 'manual'
      ? 'manual'
      : status.source === 'disk_pressure' || status.paused
        ? 'automatic · disk pressure'
        : null;
  const guardLabel: Record<IngestionPauseStatus['clickhouse_guard'], string> = {
    applied: 'ClickHouse refusing ingest writes',
    absent: status.paused ? 'ClickHouse guard pending' : 'ClickHouse accepting ingest writes',
    unknown: 'ClickHouse guard state unknown',
  };

  return (
    <section className="space-y-2 pb-4 border-b border-border/60">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <Activity className={`w-4 h-4 shrink-0 ${status.paused ? 'text-red-400' : 'text-emerald-400'}`} />
          <div className="min-w-0">
            <p className="text-[12.5px] font-medium text-foreground">
              Ingestion{' '}
              <span className={`font-mono ${status.paused ? 'text-red-400' : 'text-emerald-400'}`}>
                {status.paused ? 'Paused' : 'Active'}
              </span>
            </p>
            <p className="font-mono text-[10.5px] text-muted-foreground mt-0.5 truncate">
              {status.paused
                ? [
                    sourceLabel,
                    status.paused_at ? `since ${formatUTC(status.paused_at)}` : null,
                    guardLabel[status.clickhouse_guard],
                  ]
                    .filter(Boolean)
                    .join(' · ')
                : `auto-pause at emergency disk level: ${status.auto_pause_enabled ? 'on' : 'off'} · ${guardLabel[status.clickhouse_guard]}`}
            </p>
            {status.paused && status.reason && (
              <p className="text-[11.5px] text-muted-foreground mt-0.5 truncate">{status.reason}</p>
            )}
          </div>
        </div>
        {status.paused ? (
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-[11.5px] shrink-0"
            disabled={busy}
            onClick={() => setConfirm('resume')}
          >
            <PlayCircle className="w-3.5 h-3.5 mr-1" />
            Resume ingestion
          </Button>
        ) : (
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-[11.5px] shrink-0"
            disabled={busy}
            onClick={() => setConfirm('pause')}
          >
            <PauseCircle className="w-3.5 h-3.5 mr-1" />
            Pause ingestion
          </Button>
        )}
      </div>

      <ConfirmDialog
        open={confirm === 'pause'}
        onOpenChange={(open) => !open && setConfirm(null)}
        title="Pause ingestion?"
        description={
          <>
            nano stops taking in events within seconds. Senders are told to retry later and keep their data,
            and pull feeds stop pulling. Nothing is stored until you resume.
          </>
        }
        confirmLabel="Pause ingestion"
        variant="danger"
        loading={busy}
        onConfirm={() => run('pause')}
      >
        <Input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason (shown here and in the audit log)"
          maxLength={500}
          className="h-8 text-[12px]"
        />
      </ConfirmDialog>
      <ConfirmDialog
        open={confirm === 'resume'}
        onOpenChange={(open) => !open && setConfirm(null)}
        title="Resume ingestion?"
        description={
          status.source === 'manual'
            ? 'Senders resend the events they held back, and nano stores them.'
            : 'nano paused intake because the disk was almost full. If it is still that full, intake pauses again at the next check.'
        }
        confirmLabel="Resume ingestion"
        loading={busy}
        onConfirm={() => run('resume')}
      />
    </section>
  );
}
