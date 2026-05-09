// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * AddToDashboardDialog Component
 * 
 * Dialog for adding search queries to dashboards.
 * Supports adding to existing dashboards or creating new ones.
 * 
 * Requirements: 7.2, 7.3
 */

import { useState, useCallback, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  ChartColumn,
  LineChart,
  PieChart,
  Table,
  Activity,
  Hash,
  Plus,
  LayoutDashboard,
  Loader2,
  CircleCheck,
  CircleAlert,
} from 'lucide-react';
import { 
  useDashboards, 
  useCreateDashboard, 
  useUpdateDashboard,
} from '@/hooks/use-api';
import type { TimeRangeValue } from '@/hooks/use-api';
import type { 
  VisualizationType, 
  PanelConfig,
  DashboardLayout,
  LayoutItem,
} from '@/lib/api';
import { api } from '@/lib/api';

export interface AddToDashboardDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  query: string;
  queryMode: 'piped' | 'sql';
  timeRange: TimeRangeValue;
}

const VISUALIZATION_TYPES: { value: VisualizationType; label: string; icon: React.ReactNode }[] = [
  { value: 'bar', label: 'Bar Chart', icon: <ChartColumn className="w-4 h-4" /> },
  { value: 'line', label: 'Line Chart', icon: <LineChart className="w-4 h-4" /> },
  { value: 'area', label: 'Area Chart', icon: <Activity className="w-4 h-4" /> },
  { value: 'pie', label: 'Pie Chart', icon: <PieChart className="w-4 h-4" /> },
  { value: 'table', label: 'Table', icon: <Table className="w-4 h-4" /> },
  { value: 'single_value', label: 'Single Value', icon: <Hash className="w-4 h-4" /> },
  { value: 'timeline', label: 'Timeline', icon: <Activity className="w-4 h-4" /> },
];

function generatePanelId(): string {
  return `panel-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function AddToDashboardDialog({
  open,
  onOpenChange,
  query,
  queryMode,
}: AddToDashboardDialogProps) {
  const navigate = useNavigate();
  const { data: dashboards, loading: loadingDashboards } = useDashboards();
  const { mutate: createDashboard, loading: creating } = useCreateDashboard();
  const { mutate: updateDashboard, loading: updating } = useUpdateDashboard();

  const [mode, setMode] = useState<'existing' | 'new'>('existing');
  const [selectedDashboardId, setSelectedDashboardId] = useState<string>('');
  const [newDashboardName, setNewDashboardName] = useState('');
  const [panelTitle, setPanelTitle] = useState('');
  const [visualizationType, setVisualizationType] = useState<VisualizationType>('bar');
  const [status, setStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string>('');

  // Reset state when dialog opens
  useEffect(() => {
    if (open) {
      setMode(dashboards && dashboards.length > 0 ? 'existing' : 'new');
      setSelectedDashboardId(dashboards?.[0]?.id || '');
      setNewDashboardName('');
      setPanelTitle('');
      setVisualizationType('bar');
      setStatus('idle');
      setErrorMessage('');
    }
  }, [open, dashboards]);

  // Auto-select first dashboard when dashboards load
  useEffect(() => {
    if (dashboards && dashboards.length > 0 && !selectedDashboardId) {
      setSelectedDashboardId(dashboards[0].id);
    }
  }, [dashboards, selectedDashboardId]);

  const isValid = useMemo(() => {
    if (!panelTitle.trim()) return false;
    if (mode === 'existing' && !selectedDashboardId) return false;
    if (mode === 'new' && !newDashboardName.trim()) return false;
    return true;
  }, [mode, selectedDashboardId, newDashboardName, panelTitle]);

  const createPanelConfig = useCallback((): PanelConfig => {
    return {
      id: generatePanelId(),
      title: panelTitle.trim(),
      query: query,
      queryMode: queryMode,
      visualizationType: visualizationType,
      visualizationConfig: {},
      timeRangeMode: 'dashboard',
      drilldownEnabled: true,
    };
  }, [panelTitle, query, queryMode, visualizationType]);

  const handleAddToExistingDashboard = useCallback(async () => {
    if (!selectedDashboardId) return;

    setStatus('saving');
    setErrorMessage('');

    try {
      // Fetch the full dashboard to get existing panels and layout
      const fullDashboard = await api.getDashboard(selectedDashboardId);
      
      // Create the new panel
      const newPanel = createPanelConfig();
      
      // Get existing panels (ensure it's an array)
      const existingPanels: PanelConfig[] = Array.isArray(fullDashboard.panels) 
        ? fullDashboard.panels 
        : [];
      
      // Get existing layout items
      const existingLayout = fullDashboard.layout || { columns: 12, rowHeight: 80, items: [] };
      const existingItems: LayoutItem[] = Array.isArray(existingLayout.items) 
        ? existingLayout.items 
        : [];
      
      // Calculate position for new panel (place at bottom)
      // Find the maximum y + h to place the new panel below all existing panels
      let maxY = 0;
      for (const item of existingItems) {
        const itemBottom = (item.y || 0) + (item.h || 4);
        if (itemBottom > maxY) {
          maxY = itemBottom;
        }
      }
      
      // Create layout item for the new panel
      const newLayoutItem: LayoutItem = {
        i: newPanel.id,
        x: 0,
        y: maxY,
        w: 6,
        h: 4,
        minW: 2,
        minH: 2,
      };
      
      // Merge panels and layout items
      const updatedPanels = [...existingPanels, newPanel];
      const updatedLayout: DashboardLayout = {
        columns: existingLayout.columns || 12,
        rowHeight: existingLayout.rowHeight || 80,
        items: [...existingItems, newLayoutItem],
      };

      // Update the dashboard with merged panels and layout
      await updateDashboard({
        id: selectedDashboardId,
        data: {
          panels: updatedPanels,
          layout: updatedLayout,
        },
      });

      setStatus('success');
      
      // Navigate to the dashboard after a brief delay
      setTimeout(() => {
        onOpenChange(false);
        navigate(`/dashboards/${selectedDashboardId}`);
      }, 1000);
    } catch (err) {
      setStatus('error');
      setErrorMessage(err instanceof Error ? err.message : 'Failed to add panel to dashboard');
    }
  }, [selectedDashboardId, createPanelConfig, updateDashboard, navigate, onOpenChange]);

  const handleCreateNewDashboard = useCallback(async () => {
    if (!newDashboardName.trim()) return;

    setStatus('saving');
    setErrorMessage('');

    try {
      const newPanel = createPanelConfig();
      
      const layout: DashboardLayout = {
        columns: 12,
        rowHeight: 80,
        items: [{
          i: newPanel.id,
          x: 0,
          y: 0,
          w: 6,
          h: 4,
          minW: 2,
          minH: 2,
        }],
      };

      const dashboard = await createDashboard({
        name: newDashboardName.trim(),
        description: `Created from search query`,
        layout,
        panels: [newPanel],
      });

      setStatus('success');
      
      // Navigate to the new dashboard after a brief delay
      setTimeout(() => {
        onOpenChange(false);
        navigate(`/dashboards/${dashboard.id}`);
      }, 1000);
    } catch (err) {
      setStatus('error');
      setErrorMessage(err instanceof Error ? err.message : 'Failed to create dashboard');
    }
  }, [newDashboardName, createPanelConfig, createDashboard, navigate, onOpenChange]);

  const handleSave = useCallback(() => {
    if (mode === 'existing') {
      handleAddToExistingDashboard();
    } else {
      handleCreateNewDashboard();
    }
  }, [mode, handleAddToExistingDashboard, handleCreateNewDashboard]);

  const isLoading = creating || updating || status === 'saving';

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[560px] max-w-[min(560px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
      >
        <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2 shrink-0">
          <LayoutDashboard className="w-[13px] h-[13px] text-primary" />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
              Add to Dashboard
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              Save this search as a dashboard panel.
            </div>
          </div>
        </div>
        <SheetHeader className="hidden">
          <SheetTitle>Add to Dashboard</SheetTitle>
          <SheetDescription>Save this search query as a dashboard panel.</SheetDescription>
        </SheetHeader>

        <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-3.5">
          <div className="flex flex-col gap-1.5">
            <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Panel title
            </Label>
            <Input
              value={panelTitle}
              onChange={e => setPanelTitle(e.target.value)}
              placeholder="Enter a title for this panel"
              className="h-[30px] text-[12.5px]"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Visualization type
            </Label>
            <Select value={visualizationType} onValueChange={v => setVisualizationType(v as VisualizationType)}>
              <SelectTrigger className="h-[30px] text-[12.5px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {VISUALIZATION_TYPES.map(type => (
                  <SelectItem key={type.value} value={type.value} className="text-[12px]">
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">{type.icon}</span>
                      <span>{type.label}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Destination
            </Label>
            <RadioGroup value={mode} onValueChange={v => setMode(v as 'existing' | 'new')} className="flex flex-col gap-1.5">
              <div
                className={`flex items-center gap-2 px-3 py-2 rounded-md border transition-colors ${
                  mode === 'existing' ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/40'
                } ${(!dashboards || dashboards.length === 0) ? 'opacity-50' : 'cursor-pointer'}`}
                onClick={() => {
                  if (dashboards && dashboards.length > 0) setMode('existing');
                }}
              >
                <RadioGroupItem
                  value="existing"
                  id="existing"
                  disabled={!dashboards || dashboards.length === 0}
                  className="border-border"
                />
                <Label htmlFor="existing" className="text-[12.5px] font-semibold text-foreground cursor-pointer">
                  Add to existing dashboard
                </Label>
              </div>
              <div
                className={`flex items-center gap-2 px-3 py-2 rounded-md border cursor-pointer transition-colors ${
                  mode === 'new' ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/40'
                }`}
                onClick={() => setMode('new')}
              >
                <RadioGroupItem value="new" id="new" className="border-border" />
                <Label htmlFor="new" className="text-[12.5px] font-semibold text-foreground cursor-pointer">
                  Create new dashboard
                </Label>
              </div>
            </RadioGroup>
          </div>

          {mode === 'existing' && (
            <div className="flex flex-col gap-1.5">
              <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                Select dashboard
              </Label>
              {loadingDashboards ? (
                <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
                  <Loader2 className="w-[12px] h-[12px] animate-spin" />
                  Loading dashboards…
                </div>
              ) : dashboards && dashboards.length > 0 ? (
                <Select value={selectedDashboardId} onValueChange={setSelectedDashboardId}>
                  <SelectTrigger className="h-[30px] text-[12.5px]">
                    <SelectValue placeholder="Select a dashboard" />
                  </SelectTrigger>
                  <SelectContent>
                    {dashboards.map(dashboard => (
                      <SelectItem key={dashboard.id} value={dashboard.id} className="text-[12px]">
                        <div className="flex items-center gap-2">
                          <LayoutDashboard className="w-[12px] h-[12px] text-muted-foreground" />
                          <span>{dashboard.name}</span>
                          <span className="font-mono text-[10.5px] text-muted-foreground/70">
                            ({dashboard.panel_count} panels)
                          </span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <p className="text-[11.5px] text-muted-foreground">
                  No dashboards available. Create a new one.
                </p>
              )}
            </div>
          )}

          {mode === 'new' && (
            <div className="flex flex-col gap-1.5">
              <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                Dashboard name
              </Label>
              <Input
                value={newDashboardName}
                onChange={e => setNewDashboardName(e.target.value)}
                placeholder="Enter dashboard name"
                className="h-[30px] text-[12.5px]"
              />
            </div>
          )}

          <div className="flex flex-col gap-1.5">
            <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Query
            </Label>
            <div className="rounded-md border border-border bg-foreground/[0.03] px-3 py-2">
              <code className="font-mono text-[11px] text-emerald-400 break-all leading-[1.5]">
                {query.length > 200 ? `${query.substring(0, 200)}…` : query}
              </code>
            </div>
          </div>

          {status === 'success' && (
            <div className="flex items-center gap-2 text-[11.5px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-3 py-2 rounded-md">
              <CircleCheck className="w-[13px] h-[13px]" />
              <span>Panel added. Redirecting…</span>
            </div>
          )}
          {status === 'error' && errorMessage && (
            <div className="flex items-center gap-2 text-[11.5px] text-rose-400 bg-rose-500/10 border border-rose-500/30 px-3 py-2 rounded-md">
              <CircleAlert className="w-[13px] h-[13px]" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>

        <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
          <Button
            variant="ghost"
            size="sm"
            className="h-[28px]"
            onClick={() => onOpenChange(false)}
            disabled={isLoading}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-[28px] gap-1.5"
            onClick={handleSave}
            disabled={!isValid || isLoading || status === 'success'}
          >
            {isLoading ? (
              <>
                <Loader2 className="w-[12px] h-[12px] animate-spin" />
                {mode === 'new' ? 'Creating…' : 'Adding…'}
              </>
            ) : (
              <>
                <Plus className="w-[12px] h-[12px]" />
                {mode === 'new' ? 'Create dashboard' : 'Add panel'}
              </>
            )}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

export default AddToDashboardDialog;
