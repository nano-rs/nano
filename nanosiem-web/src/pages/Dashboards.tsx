// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  Box,
  ChevronRight,
  Clock,
  Eye,
  Globe,
  Grid as GridIcon,
  LayoutDashboard,
  Layers,
  List,
  Loader2,
  Lock,
  MoreHorizontal,
  Plus,
  RefreshCw,
  Search,
  Sparkles,
  Trash2,
  Upload,
  User,
  Users,
  X,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import {
  useCreateDashboard,
  useDashboards,
  useDeleteDashboard,
  useImportDashboard,
} from '@/hooks/use-api';
import { useRecentlyViewedDashboards } from '@/hooks/useRecentlyViewedDashboards';
import { useViewPreference } from '@/hooks/use-view-preference';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { formatRelativeUTC } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import type {
  CreateDashboardRequest,
  DashboardSummary,
  DashboardVisibility,
  GeneratedDashboard,
} from '@/lib/api';

import { DashboardGenerationWizard } from '@/enterprise/components/dashboard/DashboardGenerationWizard';
import { WireframePreview, synthesizePreview } from '@/components/dashboard/WireframePreview';

type Density = 'gallery' | 'list';
type FilterTab = 'my' | 'all';

const RECENT_STRIP_HIDDEN_KEY = 'nanosiem:dashboards:recent-hidden';

function ownerInitials(name?: string): string {
  if (!name) return '·';
  const parts = name.trim().split(/\s+/).slice(0, 2);
  return parts.map(p => p[0]?.toUpperCase() ?? '').join('') || '·';
}

function VisibilityIcon({ visibility, className }: { visibility?: DashboardVisibility; className?: string }) {
  switch (visibility) {
    case 'public':
      return <Globe className={cn('text-emerald-500', className)} aria-label="Public" />;
    case 'group':
      return <Users className={cn('text-sky-500', className)} aria-label="Shared with groups" />;
    case 'private':
    default:
      return <Lock className={cn('text-muted-foreground/70', className)} aria-label="Private" />;
  }
}

interface DashCardProps {
  d: DashboardSummary;
  density: Density;
  onDelete?: () => void;
  canDelete: boolean;
}

function DashCardGallery({ d, onDelete, canDelete }: DashCardProps) {
  const preview = useMemo(() => synthesizePreview(d.id, d.panel_count), [d.id, d.panel_count]);
  return (
    <div className="group relative bg-card border border-border rounded-lg p-3.5 hover:border-primary/40 hover:shadow-[0_6px_20px_rgba(0,0,0,0.15)] transition-all flex flex-col gap-3">
      <Link to={`/dashboards/${d.id}`} className="flex items-start gap-2 min-w-0">
        <div className="w-7 h-7 rounded-md bg-primary/10 text-primary flex items-center justify-center shrink-0">
          <GridIcon className="w-[14px] h-[14px]" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold text-foreground flex items-center gap-1.5 min-w-0">
            <span className="truncate">{d.name}</span>
            <span className="shrink-0">
              <VisibilityIcon visibility={d.visibility} className="w-[11px] h-[11px]" />
            </span>
          </div>
          <div className="text-[10.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground/70 mt-0.5">
            {d.panel_count} {d.panel_count === 1 ? 'panel' : 'panels'}
          </div>
        </div>
      </Link>
      {canDelete && (
        <div className="absolute top-2.5 right-2.5 opacity-0 group-hover:opacity-100 transition-opacity">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="w-5 h-5 rounded hover:bg-foreground/5 flex items-center justify-center text-muted-foreground hover:text-foreground"
                aria-label="More actions"
              >
                <MoreHorizontal className="w-[12px] h-[12px]" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-popover border-border">
              <DropdownMenuItem
                onClick={onDelete}
                className="text-rose-400 focus:text-rose-400 focus:bg-rose-500/10"
              >
                <Trash2 className="w-3.5 h-3.5 mr-2" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )}
      <Link
        to={`/dashboards/${d.id}`}
        className="rounded-md bg-foreground/[0.03] border border-border p-2 block"
      >
        <WireframePreview spec={preview} height={84} />
      </Link>
      <div className="text-[11px] text-muted-foreground leading-[1.45] line-clamp-2 min-h-[32px]">
        {d.description || ' '}
      </div>
      <div className="flex items-center gap-3 font-mono text-[10px] text-muted-foreground uppercase tracking-[0.08em] pt-1 border-t border-border">
        <span className="flex items-center gap-1">
          <Layers className="w-[11px] h-[11px] text-muted-foreground/70" />
          <span className="tabular-nums">{d.panel_count}</span>
        </span>
        {d.owner_name && (
          <span className="flex items-center gap-1 min-w-0">
            <span className="w-4 h-4 rounded-full bg-primary/15 text-primary flex items-center justify-center text-[8px] font-semibold shrink-0">
              {ownerInitials(d.owner_name)}
            </span>
            <span className="truncate max-w-[80px] normal-case tracking-normal">{d.owner_name}</span>
          </span>
        )}
        <span className="flex items-center gap-1 ml-auto">
          <Clock className="w-[10px] h-[10px] text-muted-foreground/70" />
          <span className="normal-case tracking-normal">{formatRelativeUTC(new Date(d.updated_at))}</span>
        </span>
      </div>
    </div>
  );
}

function DashCardList({ d, onDelete, canDelete }: DashCardProps) {
  return (
    <div className="group relative">
      <Link
        to={`/dashboards/${d.id}`}
        className="w-full h-[52px] px-3 border-b border-border hover:bg-foreground/[0.03] transition-colors flex items-center gap-3"
      >
        <div className="w-7 h-7 rounded-md bg-primary/10 text-primary flex items-center justify-center shrink-0">
          <GridIcon className="w-[14px] h-[14px]" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold text-foreground flex items-center gap-2">
            <span className="truncate">{d.name}</span>
            <VisibilityIcon visibility={d.visibility} className="w-[11px] h-[11px]" />
          </div>
          {d.description && (
            <div className="text-[11px] text-muted-foreground truncate">{d.description}</div>
          )}
        </div>
        <div className="flex items-center gap-5 font-mono text-[10.5px] text-muted-foreground shrink-0">
          <span className="w-[68px] tabular-nums">{d.panel_count} panels</span>
          {d.owner_name && <span className="w-[110px] truncate">{d.owner_name}</span>}
          <span className="w-[110px]">{formatRelativeUTC(new Date(d.updated_at))}</span>
          <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/70" />
        </div>
      </Link>
      {canDelete && (
        <div className="absolute top-1/2 -translate-y-1/2 right-9 opacity-0 group-hover:opacity-100 transition-opacity">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="w-6 h-6 rounded hover:bg-foreground/5 flex items-center justify-center text-muted-foreground hover:text-foreground"
                aria-label="More actions"
              >
                <MoreHorizontal className="w-[12px] h-[12px]" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-popover border-border">
              <DropdownMenuItem
                onClick={onDelete}
                className="text-rose-400 focus:text-rose-400 focus:bg-rose-500/10"
              >
                <Trash2 className="w-3.5 h-3.5 mr-2" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )}
    </div>
  );
}

function NewDashboardCard({ density, onClick }: { density: Density; onClick: () => void }) {
  if (density === 'list') {
    return (
      <button
        type="button"
        onClick={onClick}
        className="w-full h-[52px] px-3 border-b border-dashed border-primary/40 hover:bg-primary/5 transition-colors flex items-center gap-3 text-left text-primary"
      >
        <div className="w-7 h-7 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
          <Plus className="w-[14px] h-[14px]" />
        </div>
        <span className="text-[13px] font-semibold">New dashboard</span>
        <span className="text-[11px] text-muted-foreground font-normal">
          Create a blank or AI-generated board
        </span>
      </button>
    );
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className="text-center bg-card border border-dashed border-primary/35 rounded-lg p-3.5 hover:border-primary hover:bg-primary/5 transition-colors flex flex-col items-center justify-center gap-2.5 min-h-[252px] group"
    >
      <div className="w-10 h-10 rounded-full bg-primary/10 text-primary flex items-center justify-center group-hover:bg-primary/20 transition-colors">
        <Plus className="w-[18px] h-[18px]" />
      </div>
      <div className="flex flex-col gap-0.5">
        <div className="text-[13px] font-semibold text-foreground">New Dashboard</div>
        <div className="text-[11px] text-muted-foreground">Blank board or AI-generate</div>
      </div>
      <div className="mt-1 text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 flex items-center gap-1.5">
        <Sparkles className="w-[11px] h-[11px] text-primary" />
        <span>AI · BLANK</span>
      </div>
    </button>
  );
}

interface RecentStripProps {
  recent: DashboardSummary[];
  onClose: () => void;
}

function RecentStrip({ recent, onClose }: RecentStripProps) {
  if (recent.length === 0) return null;
  return (
    <div className="rounded-lg border border-border bg-card p-3.5">
      <div className="flex items-center gap-2 mb-2.5">
        <Eye className="w-[12px] h-[12px] text-muted-foreground" />
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Recently viewed
        </span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={onClose}
          className="w-5 h-5 rounded hover:bg-foreground/5 flex items-center justify-center text-muted-foreground/70 hover:text-foreground"
          aria-label="Hide recently viewed"
          title="Hide"
        >
          <X className="w-3 h-3" />
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
        {recent.slice(0, 4).map(d => (
          <Link
            key={d.id}
            to={`/dashboards/${d.id}`}
            className="text-left p-2 rounded-md border border-border hover:border-primary/40 hover:bg-foreground/[0.03] flex items-center gap-2 transition-colors min-w-0"
          >
            <div className="w-6 h-6 rounded bg-primary/10 text-primary flex items-center justify-center shrink-0">
              <GridIcon className="w-[11px] h-[11px]" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[11.5px] font-semibold text-foreground truncate">{d.name}</div>
              <div className="text-[9.5px] font-mono text-muted-foreground/70">
                {d.panel_count} panels · {formatRelativeUTC(new Date(d.updated_at))}
              </div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

export function Dashboards() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { hasPermission } = useAuth();

  useDocumentTitle('Dashboards');

  const dashboardFilter = ((searchParams.get('filter') as FilterTab) || 'my');
  const setDashboardFilter = (filter: FilterTab) => {
    const params = new URLSearchParams(searchParams);
    params.set('filter', filter);
    setSearchParams(params);
  };

  // NAN-833: fetch both lists so the tab counts are independent.
  // useDashboards is server-filtered; if we only fetched the visible tab's
  // list, both counts would always read the same number (the visible one).
  const myQuery = useDashboards('my');
  const allQuery = useDashboards('all');
  const activeQuery = dashboardFilter === 'my' ? myQuery : allQuery;
  const dashboards = activeQuery.data;
  const loading = activeQuery.loading;
  const refetch = useCallback(() => {
    myQuery.refetch();
    allQuery.refetch();
  }, [myQuery, allQuery]);
  const { mutate: createDashboard, loading: creating } = useCreateDashboard();
  const { mutate: deleteDashboard } = useDeleteDashboard();
  const { mutate: importDashboard, loading: importing } = useImportDashboard();
  const { recentDashboardIds, removeRecentDashboard } = useRecentlyViewedDashboards();

  const canCreate = hasPermission('dashboards:create');
  const canDelete = hasPermission('dashboards:delete');

  const [searchQuery, setSearchQuery] = useState('');
  const [density, setDensity] = useViewPreference<Density>('dashboards', 'gallery');
  const [showRecent, setShowRecent] = useState(() => {
    try {
      return localStorage.getItem(RECENT_STRIP_HIDDEN_KEY) !== '1';
    } catch {
      return true;
    }
  });
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [dashboardToDelete, setDashboardToDelete] = useState<DashboardSummary | null>(null);
  const [builderInitialMode, setBuilderInitialMode] = useState<'blank' | 'generate'>('blank');

  // PIVT bridge — `@dashboard <prompt>` opens the builder pre-seeded to AI mode.
  useEffect(() => {
    const handler = () => {
      setBuilderInitialMode('generate');
      setCreateDialogOpen(true);
    };
    window.addEventListener('pivt:open-dashboard-wizard', handler);
    return () => window.removeEventListener('pivt:open-dashboard-wizard', handler);
  }, []);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const filteredDashboards = useMemo(() => {
    if (!dashboards) return [];
    const q = searchQuery.trim().toLowerCase();
    if (!q) return dashboards;
    return dashboards.filter(
      d =>
        d.name.toLowerCase().includes(q) ||
        (d.description?.toLowerCase().includes(q) ?? false),
    );
  }, [dashboards, searchQuery]);

  const recentlyViewedDashboards = useMemo(() => {
    if (!dashboards) return [];
    return recentDashboardIds
      .map(id => dashboards.find(x => x.id === id))
      .filter((x): x is DashboardSummary => x !== undefined)
      .slice(0, 4);
  }, [dashboards, recentDashboardIds]);

  const handleHideRecent = () => {
    setShowRecent(false);
    try {
      localStorage.setItem(RECENT_STRIP_HIDDEN_KEY, '1');
    } catch {
      // ignore
    }
  };

  const openBuilder = (mode: 'blank' | 'generate') => {
    setBuilderInitialMode(mode);
    setCreateDialogOpen(true);
  };

  const handleCreateDashboard = async (data: { name: string; description: string; visibility: DashboardVisibility }) => {
    try {
      const newDashboard: CreateDashboardRequest = {
        name: data.name,
        description: data.description || undefined,
        layout: { columns: 12, rowHeight: 100, items: [] },
        panels: [],
        visibility: data.visibility,
      };
      const created = await createDashboard(newDashboard);
      toast({ title: 'Dashboard created', description: `Dashboard "${data.name}" has been created.` });
      setCreateDialogOpen(false);
      refetch();
      navigate(`/dashboards/${created.id}`);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to create dashboard',
        variant: 'destructive',
      });
      throw err;
    }
  };

  const handleDeleteDashboard = async () => {
    if (!dashboardToDelete) return;
    try {
      await deleteDashboard(dashboardToDelete.id);
      removeRecentDashboard(dashboardToDelete.id);
      toast({ title: 'Dashboard deleted', description: `Dashboard "${dashboardToDelete.name}" has been deleted.` });
      setDeleteDialogOpen(false);
      setDashboardToDelete(null);
      refetch();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete dashboard',
        variant: 'destructive',
      });
    }
  };

  const confirmDelete = (dashboard: DashboardSummary) => {
    setDashboardToDelete(dashboard);
    setDeleteDialogOpen(true);
  };

  const handleGeneratedDashboardComplete = async (
    generatedDashboard: GeneratedDashboard,
    _sessionId: string,
  ) => {
    try {
      const newDashboard: CreateDashboardRequest = {
        name: generatedDashboard.name,
        description: generatedDashboard.description || undefined,
        layout: {
          columns: generatedDashboard.layout.columns,
          rowHeight: generatedDashboard.layout.row_height,
          items: generatedDashboard.layout.items.map(item => ({
            i: item.panel_id,
            x: item.x,
            y: item.y,
            w: item.w,
            h: item.h,
          })),
          variables: generatedDashboard.variables.map(v => ({
            name: v.name,
            label: v.label,
            type: v.variable_type,
            defaultValue: v.default_value || '',
            options: v.options,
            query: v.query,
            queryField: v.query_field,
            multi: v.multi,
          })),
        },
        panels: generatedDashboard.panels.map(panel => ({
          id: panel.id,
          title: panel.title,
          query: panel.query,
          queryMode: panel.query_mode,
          visualizationType: panel.visualization_type as
            | 'bar'
            | 'line'
            | 'area'
            | 'pie'
            | 'table'
            | 'single_value'
            | 'timeline',
          visualizationConfig: panel.visualization_config,
          timeRangeMode: 'dashboard' as const,
          drilldownEnabled: false,
        })),
        visibility: 'private',
        refresh_interval: generatedDashboard.refresh_interval || undefined,
      };

      const created = await createDashboard(newDashboard);
      toast({
        title: 'Dashboard created',
        description: `AI-generated dashboard "${generatedDashboard.name}" has been created.`,
      });
      refetch();
      navigate(`/dashboards/${created.id}?edit=true`);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to create dashboard',
        variant: 'destructive',
      });
    }
  };

  const handleImportClick = () => fileInputRef.current?.click();

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    event.target.value = '';

    if (!file.name.endsWith('.json')) {
      toast({ title: 'Invalid file type', description: 'Please select a JSON file', variant: 'destructive' });
      return;
    }

    try {
      const text = await file.text();
      try {
        const parsed = JSON.parse(text);
        if (!parsed.version || !parsed.dashboard) {
          throw new Error('Invalid dashboard export format');
        }
      } catch (parseErr) {
        toast({
          title: 'Invalid JSON',
          description: parseErr instanceof Error ? parseErr.message : 'Failed to parse JSON file',
          variant: 'destructive',
        });
        return;
      }

      const imported = await importDashboard({ json: text });
      toast({
        title: 'Dashboard imported',
        description: `Dashboard "${imported.name}" has been imported successfully`,
      });
      refetch();
      navigate(`/dashboards/${imported.id}`);
    } catch (err) {
      toast({
        title: 'Import failed',
        description: err instanceof Error ? err.message : 'Failed to import dashboard',
        variant: 'destructive',
      });
    }
  };

  const counts = useMemo(() => ({
    my: myQuery.data?.length ?? 0,
    all: allQuery.data?.length ?? 0,
  }), [myQuery.data, allQuery.data]);

  return (
    <div className="flex-1 overflow-auto p-4 flex flex-col gap-4">
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileSelect}
        accept=".json"
        className="hidden"
      />

      {/* Eyebrow + title row */}
      <div className="flex items-start gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <LayoutDashboard className="w-[12px] h-[12px] text-primary" />
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
              Dashboard Index
            </span>
          </div>
          <div className="text-[22px] font-semibold text-foreground tracking-[-0.01em]">Dashboards</div>
          <div className="text-[12.5px] text-muted-foreground mt-1">
            Browse, open, and create monitoring dashboards across your stack.
          </div>
        </div>
        <div className="flex items-center gap-2 pt-1">
          <Button variant="outline" size="sm" className="h-[30px]" onClick={() => refetch()}>
            <RefreshCw className="w-[12px] h-[12px]" />
            Refresh
          </Button>
          {canCreate && (
            <Button
              variant="outline"
              size="sm"
              className="h-[30px]"
              onClick={handleImportClick}
              disabled={importing}
            >
              {importing ? <Loader2 className="w-[12px] h-[12px] animate-spin" /> : <Upload className="w-[12px] h-[12px]" />}
              Import
            </Button>
          )}
          {canCreate && (
            <Button size="sm" className="h-[30px]" onClick={() => openBuilder('blank')}>
              <Plus className="w-[12px] h-[12px]" />
              New Dashboard
            </Button>
          )}
        </div>
      </div>

      {/* Tabs + search + density */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="inline-flex items-center p-0.5 rounded-md border border-border bg-foreground/[0.03]">
          {([
            { id: 'my' as const, label: 'My dashboards', icon: User, count: counts.my },
            { id: 'all' as const, label: 'All', icon: Globe, count: counts.all },
          ]).map(t => {
            const active = dashboardFilter === t.id;
            const I = t.icon;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setDashboardFilter(t.id)}
                className={cn(
                  'h-[26px] px-2.5 rounded-[4px] flex items-center gap-1.5 text-[12px] font-medium transition-colors',
                  active
                    ? 'bg-card text-foreground shadow-[0_1px_3px_rgba(0,0,0,0.1)]'
                    : 'text-muted-foreground hover:text-foreground',
                )}
              >
                <I className={cn('w-[12px] h-[12px]', active && 'text-primary')} />
                <span>{t.label}</span>
                <span
                  className={cn(
                    'font-mono text-[10px] tabular-nums ml-0.5',
                    active ? 'text-muted-foreground' : 'text-muted-foreground/70',
                  )}
                >
                  {t.count}
                </span>
              </button>
            );
          })}
        </div>

        <div className="flex-1 relative max-w-[380px]">
          <Search className="w-[13px] h-[13px] absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search dashboards, descriptions…"
            className="h-[30px] pl-8 text-[12px]"
          />
        </div>

        <div className="flex-1" />

        <div className="inline-flex items-center p-0.5 rounded-md border border-border bg-foreground/[0.03]">
          <button
            type="button"
            onClick={() => setDensity('gallery')}
            className={cn(
              'h-[24px] w-[26px] rounded-[3px] flex items-center justify-center',
              density === 'gallery'
                ? 'bg-card text-primary shadow-[0_1px_3px_rgba(0,0,0,0.1)]'
                : 'text-muted-foreground hover:text-foreground',
            )}
            aria-label="Gallery view"
          >
            <GridIcon className="w-[12px] h-[12px]" />
          </button>
          <button
            type="button"
            onClick={() => setDensity('list')}
            className={cn(
              'h-[24px] w-[26px] rounded-[3px] flex items-center justify-center',
              density === 'list'
                ? 'bg-card text-primary shadow-[0_1px_3px_rgba(0,0,0,0.1)]'
                : 'text-muted-foreground hover:text-foreground',
            )}
            aria-label="List view"
          >
            <List className="w-[12px] h-[12px]" />
          </button>
        </div>
      </div>

      {/* Recently viewed */}
      {showRecent && !searchQuery && recentlyViewedDashboards.length > 0 && (
        <RecentStrip recent={recentlyViewedDashboards} onClose={handleHideRecent} />
      )}

      {/* Body */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="w-6 h-6 animate-spin text-primary" />
        </div>
      ) : filteredDashboards.length === 0 ? (
        <EmptyState
          searching={!!searchQuery}
          canCreate={canCreate}
          onNew={() => openBuilder('blank')}
          onAi={() => openBuilder('generate')}
        />
      ) : density === 'gallery' ? (
        <div className="flex flex-col gap-2">
          <SectionHeader label="All dashboards" count={filteredDashboards.length} />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {canCreate && <NewDashboardCard density="gallery" onClick={() => openBuilder('blank')} />}
            {filteredDashboards.map(d => (
              <DashCardGallery
                key={d.id}
                d={d}
                density="gallery"
                onDelete={() => confirmDelete(d)}
                canDelete={canDelete}
              />
            ))}
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          <SectionHeader label="All dashboards" count={filteredDashboards.length} />
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            {canCreate && <NewDashboardCard density="list" onClick={() => openBuilder('blank')} />}
            {filteredDashboards.map(d => (
              <DashCardList
                key={d.id}
                d={d}
                density="list"
                onDelete={() => confirmDelete(d)}
                canDelete={canDelete}
              />
            ))}
          </div>
        </div>
      )}

      {/* Delete confirmation */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent className="bg-card border-border max-w-md">
          <DialogHeader>
            <DialogTitle>Delete dashboard</DialogTitle>
            <DialogDescription className="text-muted-foreground">
              Are you sure you want to delete &ldquo;{dashboardToDelete?.name}&rdquo;? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleDeleteDashboard} className="bg-rose-600 hover:bg-rose-700">
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <DashboardGenerationWizard
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onComplete={handleGeneratedDashboardComplete}
        onCreateBlank={handleCreateDashboard}
        creatingBlank={creating}
        initialMode={builderInitialMode}
      />
    </div>
  );
}

function SectionHeader({ label, count }: { label: string; count: number }) {
  return (
    <div className="flex items-center gap-2 px-0.5">
      <Box className="w-[12px] h-[12px] text-muted-foreground" />
      <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
        {label}
      </span>
      <span className="font-mono text-[10px] text-muted-foreground/70">·</span>
      <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{count}</span>
      <div className="flex-1 h-px bg-border ml-2" />
    </div>
  );
}

function EmptyState({
  searching,
  canCreate,
  onNew,
  onAi,
}: {
  searching: boolean;
  canCreate: boolean;
  onNew: () => void;
  onAi: () => void;
}) {
  if (searching) {
    return (
      <div className="text-center py-16">
        <Search className="w-10 h-10 mx-auto text-muted-foreground/40 mb-3" />
        <div className="text-[13px] text-foreground font-medium">No matching dashboards</div>
        <div className="text-[11.5px] text-muted-foreground mt-1">Try a different search term.</div>
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center gap-5 py-10">
      <div className="text-center">
        <LayoutDashboard className="w-10 h-10 mx-auto text-muted-foreground/40 mb-3" />
        <div className="text-[13px] text-foreground font-medium">No dashboards yet</div>
        <div className="text-[11.5px] text-muted-foreground mt-1">
          Create a dashboard to visualize your security data.
        </div>
      </div>
      {canCreate && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-[520px] w-full">
          <button
            type="button"
            onClick={onNew}
            className="bg-card border border-dashed border-primary/35 rounded-lg p-4 hover:border-primary hover:bg-primary/5 transition-colors flex flex-col items-center gap-2 group"
          >
            <div className="w-9 h-9 rounded-full bg-primary/10 text-primary flex items-center justify-center group-hover:bg-primary/20 transition-colors">
              <Plus className="w-[16px] h-[16px]" />
            </div>
            <div className="text-[13px] font-semibold text-foreground">Blank canvas</div>
            <div className="text-[11px] text-muted-foreground text-center">
              Start with an empty dashboard and add panels manually.
            </div>
          </button>
          <button
            type="button"
            onClick={onAi}
            className="bg-card border border-dashed border-primary/35 rounded-lg p-4 hover:border-primary hover:bg-primary/5 transition-colors flex flex-col items-center gap-2 group"
          >
            <div className="w-9 h-9 rounded-full bg-primary/10 text-primary flex items-center justify-center group-hover:bg-primary/20 transition-colors">
              <Sparkles className="w-[16px] h-[16px]" />
            </div>
            <div className="text-[13px] font-semibold text-foreground">Generate with AI</div>
            <div className="text-[11px] text-muted-foreground text-center">
              Describe what you need; nano builds the panels for you.
            </div>
          </button>
        </div>
      )}
    </div>
  );
}

