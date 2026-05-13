// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * DashboardEditor Component
 * 
 * Provides the editing interface for dashboards with name/description inputs,
 * view/edit mode toggle, and save/cancel buttons.
 * 
 * Requirements: 1.2, 1.4
 */

import { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Save,
  X,
  Plus,
  Eye,
  Pencil,
  LayoutDashboard,
  CircleAlert,
  Loader2,
  Variable,
  LayoutGrid,
  Shield,
  Lock,
  Users,
  Globe,
} from 'lucide-react';
import { toast } from 'sonner';
import { GridLayout, compactLayout } from './GridLayout';
import { Panel, type PanelDataState } from './Panel';
import { VisualizationRenderer } from './VisualizationRenderer';
import { PanelEditor } from './PanelEditor';
import { VariableEditor } from './VariableEditor';
import { DashboardShareDialog } from './DashboardShareDialog';
import { useUpdateDashboard, useCreateDashboard, usePanelQuery, toApiTimeRange, type TimeRangeValue } from '@/hooks/use-api';
import type { Dashboard, PanelConfig, LayoutItem, DashboardLayout, DashboardVariable, CreateDashboardRequest, DashboardVisibility, DashboardShareResult } from '@/lib/api';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import {
  hydrateDashboardTimeRange,
  serializeDashboardTimeRange,
} from '@/lib/dashboard-time-range';

export interface DashboardEditorProps {
  /** Existing dashboard to edit (undefined for new dashboard) */
  dashboard?: Dashboard;
  /** Callback when save is successful */
  onSave?: (dashboard: Dashboard) => void;
  /** Callback when cancel is clicked */
  onCancel?: () => void;
  /** Whether to start in edit mode */
  initialEditMode?: boolean;
}

// Default layout configuration
const DEFAULT_LAYOUT: DashboardLayout = {
  columns: 12,
  rowHeight: 80,
  items: [],
};

// Visibility icon helper
function VisibilityIcon({ visibility, className = '' }: { visibility?: DashboardVisibility; className?: string }) {
  switch (visibility) {
    case 'public':
      return <span title="Public - visible to all users"><Globe className={`${className} text-green-500`} /></span>;
    case 'group':
      return <span title="Group - shared with specific groups"><Users className={`${className} text-blue-500`} /></span>;
    case 'private':
    default:
      return <span title="Private - only visible to you"><Lock className={`${className} text-muted-foreground`} /></span>;
  }
}

// Generate a unique panel ID
function generatePanelId(): string {
  return `panel-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Find the next available position for a new panel
function findNextPosition(items: LayoutItem[], columns: number = 12): { x: number; y: number } {
  if (items.length === 0) {
    return { x: 0, y: 0 };
  }

  // Find the maximum y position
  let maxY = 0;
  let maxYItems: LayoutItem[] = [];

  items.forEach(item => {
    const itemBottom = item.y + item.h;
    if (itemBottom > maxY) {
      maxY = itemBottom;
      maxYItems = [item];
    } else if (itemBottom === maxY) {
      maxYItems.push(item);
    }
  });

  // Try to find space in the last row
  const lastRowItems = items.filter(item => item.y + item.h === maxY);
  const occupiedX = new Set<number>();
  lastRowItems.forEach(item => {
    for (let x = item.x; x < item.x + item.w; x++) {
      occupiedX.add(x);
    }
  });

  // Find first available x position in last row
  for (let x = 0; x <= columns - 4; x++) {
    let hasSpace = true;
    for (let dx = 0; dx < 4; dx++) {
      if (occupiedX.has(x + dx)) {
        hasSpace = false;
        break;
      }
    }
    if (hasSpace) {
      return { x, y: maxY - 3 }; // Place at same row level
    }
  }

  // No space in last row, add to new row
  return { x: 0, y: maxY };
}

export function DashboardEditor({
  dashboard,
  onSave,
  onCancel,
  initialEditMode = true,
}: DashboardEditorProps) {
  const navigate = useNavigate();
  const { mutate: updateDashboard, loading: updating } = useUpdateDashboard();
  const { mutate: createDashboard, loading: creating } = useCreateDashboard();
  const { mutate: executePanelQuery } = usePanelQuery();

  // Editor state
  const [isEditing, setIsEditing] = useState(initialEditMode);
  const [name, setName] = useState(dashboard?.name || '');
  const [description, setDescription] = useState(dashboard?.description || '');
  const [panels, setPanels] = useState<PanelConfig[]>(dashboard?.panels || []);
  const [layout, setLayout] = useState<DashboardLayout>(dashboard?.layout || DEFAULT_LAYOUT);
  // Variables are stored inside layout for persistence
  const variables = layout.variables || [];
  const setVariables = (newVars: DashboardVariable[]) => {
    setLayout(prev => ({ ...prev, variables: newVars }));
  };
  const [isDirty, setIsDirty] = useState(false);

  // Panel editor state
  const [editingPanel, setEditingPanel] = useState<PanelConfig | null>(null);
  const [showPanelEditor, setShowPanelEditor] = useState(false);
  const [showVariableEditor, setShowVariableEditor] = useState(false);

  // Confirmation dialogs
  const [showDiscardConfirm, setShowDiscardConfirm] = useState(false);

  // Share dialog state
  const [showShareDialog, setShowShareDialog] = useState(false);

  // Key to force GridLayout re-mount when snapping to grid
  const [layoutKey, setLayoutKey] = useState(0);

  // Panel data state
  const [panelData, setPanelData] = useState<Map<string, PanelDataState>>(new Map());
  const [timeRange, setTimeRange] = useState<TimeRangeValue>(() =>
    hydrateDashboardTimeRange(dashboard?.layout?.defaultTimeRange),
  );
  // Skip the first effect tick — we don't want opening a legacy dashboard to
  // silently mark it dirty just by hydrating the implicit default range.
  const timeRangeMountedRef = useRef(false);

  // While editing, the chosen range becomes the saved default for new viewers.
  // Stash it back into layout so dirty tracking + handleSave persist it.
  useEffect(() => {
    if (!timeRangeMountedRef.current) {
      timeRangeMountedRef.current = true;
      return;
    }
    setLayout(prev => {
      const next = serializeDashboardTimeRange(timeRange);
      if (JSON.stringify(prev.defaultTimeRange) === JSON.stringify(next)) {
        return prev;
      }
      return { ...prev, defaultTimeRange: next };
    });
  }, [timeRange]);

  // Track changes (variables are now stored in layout)
  useEffect(() => {
    if (dashboard) {
      const hasChanges =
        name !== dashboard.name ||
        description !== (dashboard.description || '') ||
        JSON.stringify(panels) !== JSON.stringify(dashboard.panels) ||
        JSON.stringify(layout) !== JSON.stringify(dashboard.layout);
      setIsDirty(hasChanges);
    } else {
      setIsDirty(name.length > 0 || panels.length > 0 || variables.length > 0);
    }
  }, [name, description, panels, layout, variables, dashboard]);

  // Substitute variables in query string
  // If a variable has no value, remove the entire "field=$var" clause to avoid type errors
  const substituteVariables = useCallback((query: string): string => {
    // Build variable map from defined variables
    const varMap: Record<string, string> = {};
    for (const variable of variables) {
      varMap[variable.name] = variable.defaultValue || '';
    }

    // First, remove entire "field=$var" or "field = $var" clauses where variable is empty
    // This handles cases like "duration=$duration" where duration is numeric
    let result = query.replace(/\b(\w+)\s*=\s*\$([a-zA-Z_][a-zA-Z0-9_]*)\b/g, (_match, field, varName) => {
      const value = varMap[varName];
      if (!value) {
        // Remove the entire clause
        return '';
      }
      return `${field}=${value}`;
    });

    // Clean up any remaining $var patterns (not in field=$var format)
    result = result.replace(/\$([a-zA-Z_][a-zA-Z0-9_]*)/g, (_, varName) => {
      return varMap[varName] || '*';
    });

    // Clean up multiple spaces and trim
    result = result.replace(/\s+/g, ' ').trim();

    return result;
  }, [variables]);

  // Build complete variable map with fallback values for any undefined variables
  const getCompleteVariables = useCallback(() => {
    if (!variables || variables.length === 0) return undefined;

    const completeVars: Record<string, string> = {};
    for (const variable of variables) {
      // Use default value or '*' as fallback for preview
      completeVars[variable.name] = variable.defaultValue || '*';
    }
    return completeVars;
  }, [variables]);

  // Fetch panel data
  const fetchPanelData = useCallback(async (panel: PanelConfig) => {
    setPanelData(prev => {
      const newMap = new Map(prev);
      newMap.set(panel.id, { status: 'loading' });
      return newMap;
    });

    try {
      const effectiveTimeRange = panel.timeRangeMode === 'custom' && panel.customTimeRange
        ? panel.customTimeRange
        : toApiTimeRange(timeRange);

      // Substitute variables client-side to handle undefined vars with '*' fallback
      const substitutedQuery = substituteVariables(panel.query);

      const response = await executePanelQuery({
        query: substitutedQuery,
        query_mode: panel.queryMode,
        time_range: effectiveTimeRange,
      });

      setPanelData(prev => {
        const newMap = new Map(prev);
        newMap.set(panel.id, {
          status: response.results.length > 0 ? 'success' : 'empty',
          data: response.results,
          lastRefresh: new Date(),
        });
        return newMap;
      });
    } catch (err) {
      setPanelData(prev => {
        const newMap = new Map(prev);
        newMap.set(panel.id, {
          status: 'error',
          error: err instanceof Error ? err.message : 'Failed to fetch data',
          lastRefresh: new Date(),
        });
        return newMap;
      });
    }
  }, [executePanelQuery, timeRange, substituteVariables]);

  // Fetch data for all panels (re-fetches when variables change)
  useEffect(() => {
    panels.forEach(panel => {
      fetchPanelData(panel);
    });
    // Re-fetch when panels change or when substituteVariables changes (due to variable changes)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [panels, substituteVariables]);

  // Handle layout changes
  const handleLayoutChange = useCallback((newItems: LayoutItem[]) => {
    setLayout(prev => ({
      ...prev,
      items: newItems,
    }));
    setIsDirty(true);
  }, []);

  // Add new panel
  const handleAddPanel = useCallback(() => {
    setEditingPanel(null);
    setShowPanelEditor(true);
  }, []);

  // Edit existing panel
  const handleEditPanel = useCallback((panel: PanelConfig) => {
    setEditingPanel(panel);
    setShowPanelEditor(true);
  }, []);

  // Save panel from editor
  const handleSavePanel = useCallback((panelConfig: PanelConfig) => {
    if (editingPanel) {
      // Update existing panel
      setPanels(prev => prev.map(p => p.id === panelConfig.id ? panelConfig : p));
    } else {
      // Add new panel
      const newPanel = {
        ...panelConfig,
        id: generatePanelId(),
      };
      setPanels(prev => [...prev, newPanel]);
      
      // Add layout item for new panel
      const position = findNextPosition(layout.items, layout.columns);
      setLayout(prev => ({
        ...prev,
        items: [
          ...prev.items,
          {
            i: newPanel.id,
            x: position.x,
            y: position.y,
            w: 4,
            h: 3,
            minW: 2,
            minH: 2,
          },
        ],
      }));

      // Fetch data for new panel
      fetchPanelData(newPanel);
    }
    
    setShowPanelEditor(false);
    setEditingPanel(null);
    setIsDirty(true);
  }, [editingPanel, layout, fetchPanelData]);

  // Duplicate panel
  const handleDuplicatePanel = useCallback((panel: PanelConfig) => {
    const newPanel: PanelConfig = {
      ...panel,
      id: generatePanelId(),
      title: `${panel.title} (Copy)`,
    };
    
    setPanels(prev => [...prev, newPanel]);
    
    // Find the original panel's layout item
    const originalItem = layout.items.find(item => item.i === panel.id);
    if (originalItem) {
      // Place duplicate adjacent to original
      const newX = originalItem.x + originalItem.w;
      const newItem: LayoutItem = {
        i: newPanel.id,
        x: newX >= layout.columns ? 0 : newX,
        y: newX >= layout.columns ? originalItem.y + originalItem.h : originalItem.y,
        w: originalItem.w,
        h: originalItem.h,
        minW: originalItem.minW,
        minH: originalItem.minH,
      };
      
      setLayout(prev => ({
        ...prev,
        items: [...prev.items, newItem],
      }));
    }

    // Copy panel data
    const originalData = panelData.get(panel.id);
    if (originalData) {
      setPanelData(prev => {
        const newMap = new Map(prev);
        newMap.set(newPanel.id, { ...originalData });
        return newMap;
      });
    }

    setIsDirty(true);
    toast.success('Panel duplicated');
  }, [layout, panelData]);

  // Delete panel
  const handleDeletePanel = useCallback((panelId: string) => {
    setPanels(prev => prev.filter(p => p.id !== panelId));
    setLayout(prev => ({
      ...prev,
      items: prev.items.filter(item => item.i !== panelId),
    }));
    setPanelData(prev => {
      const newMap = new Map(prev);
      newMap.delete(panelId);
      return newMap;
    });
    setIsDirty(true);
    toast.success('Panel deleted');
  }, []);

  // Snap panels to grid - reorganize and resize panels based on visualization type
  const handleSnapToGrid = useCallback(() => {
    const compactedItems = compactLayout(layout.items, layout.columns, panels);
    setLayout(prev => ({
      ...prev,
      items: compactedItems,
    }));
    // Force GridLayout to re-mount with new positions
    setLayoutKey(prev => prev + 1);
    setIsDirty(true);
    toast.success('Panels aligned to grid');
  }, [layout, panels]);

  // Save dashboard (variables are stored in layout)
  const handleSave = useCallback(async () => {
    if (!name.trim()) {
      toast.error('Dashboard name is required');
      return;
    }

    try {
      const dashboardData: CreateDashboardRequest = {
        name: name.trim(),
        description: description.trim() || undefined,
        layout, // variables are embedded in layout
        panels,
      };

      let savedDashboard: Dashboard;
      
      if (dashboard?.id) {
        savedDashboard = await updateDashboard({ id: dashboard.id, data: dashboardData });
        toast.success('Dashboard saved');
      } else {
        savedDashboard = await createDashboard(dashboardData);
        toast.success('Dashboard created');
      }

      setIsDirty(false);
      onSave?.(savedDashboard);
      
      if (!dashboard?.id) {
        // Navigate to the new dashboard
        navigate(`/dashboards/${savedDashboard.id}`);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save dashboard');
    }
  }, [name, description, layout, panels, variables, dashboard, updateDashboard, createDashboard, onSave, navigate]);

  // Cancel editing
  const handleCancel = useCallback(() => {
    if (isDirty) {
      setShowDiscardConfirm(true);
    } else {
      onCancel?.();
      if (dashboard?.id) {
        setIsEditing(false);
      } else {
        navigate('/dashboards');
      }
    }
  }, [isDirty, onCancel, dashboard, navigate]);

  // Confirm discard changes
  const handleConfirmDiscard = useCallback(() => {
    setShowDiscardConfirm(false);
    setIsDirty(false);
    onCancel?.();
    if (dashboard?.id) {
      // Reset to original values (variables are in layout)
      setName(dashboard.name);
      setDescription(dashboard.description || '');
      setPanels(dashboard.panels);
      setLayout(dashboard.layout);
      setIsEditing(false);
    } else {
      navigate('/dashboards');
    }
  }, [dashboard, onCancel, navigate]);

  // Toggle edit mode
  const handleToggleEditMode = useCallback(() => {
    if (isEditing && isDirty) {
      setShowDiscardConfirm(true);
    } else {
      setIsEditing(!isEditing);
    }
  }, [isEditing, isDirty]);

  // Render panel content
  const renderPanel = useCallback((panel: PanelConfig) => {
    const data = panelData.get(panel.id);
    
    return (
      <Panel
        config={panel}
        data={data}
        timeRange={timeRange}
        isEditing={isEditing}
        onEdit={() => handleEditPanel(panel)}
        onDuplicate={() => handleDuplicatePanel(panel)}
        onDelete={() => handleDeletePanel(panel.id)}
        onRefresh={() => fetchPanelData(panel)}
        hasRunOnce
      >
        {data?.status === 'success' && data.data && (
          <VisualizationRenderer
            type={panel.visualizationType}
            config={panel.visualizationConfig}
            data={data.data}
          />
        )}
      </Panel>
    );
  }, [panelData, timeRange, isEditing, handleEditPanel, handleDuplicatePanel, fetchPanelData]);

  const isSaving = updating || creating;

  return (
    <div className="flex flex-col gap-3">
      {/* Editor header — single 46px toolbar matching the NOC view */}
      <div className="flex items-center gap-3 h-[46px] border-b border-border">
        <LayoutDashboard className="w-[14px] h-[14px] text-primary shrink-0" />
        {isEditing ? (
          <div className="flex items-center gap-2 min-w-0">
            <Input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Dashboard name"
              className="h-[28px] w-[260px] text-[13px] font-semibold"
            />
            <Input
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Description (optional)"
              className="h-[28px] w-[280px] text-[12px]"
            />
          </div>
        ) : (
          <div className="flex items-baseline gap-2 min-w-0">
            <span className="text-[13.5px] font-semibold text-foreground truncate max-w-[400px]">
              {name || 'Untitled Dashboard'}
            </span>
            {dashboard && <VisibilityIcon visibility={dashboard.visibility} className="w-[12px] h-[12px]" />}
            {description && (
              <>
                <span className="text-[10.5px] font-mono text-muted-foreground/60">·</span>
                <span className="text-[11.5px] text-muted-foreground truncate max-w-[400px]">{description}</span>
              </>
            )}
          </div>
        )}

        <span className="flex-1" />

        {dashboard?.id && !isEditing && dashboard.is_owner && (
          <Button
            variant="outline"
            size="sm"
            className="h-[28px] gap-1.5"
            onClick={() => setShowShareDialog(true)}
          >
            <Shield className="w-[12px] h-[12px]" />
            Permissions
          </Button>
        )}

        {dashboard?.id && (
          <Button
            variant="outline"
            size="sm"
            className="h-[28px] gap-1.5"
            onClick={handleToggleEditMode}
          >
            {isEditing ? (
              <>
                <Eye className="w-[12px] h-[12px]" />
                View Mode
              </>
            ) : (
              <>
                <Pencil className="w-[12px] h-[12px]" />
                Edit Mode
              </>
            )}
          </Button>
        )}

        {isEditing && (
          <>
            <div
              className="flex items-center gap-2 [&_button]:h-[28px] [&_button]:text-[12px]"
              title="Default time range applied when this dashboard is opened"
            >
              <DateTimeRangePicker value={timeRange} onChange={setTimeRange} />
              <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground/70 whitespace-nowrap">
                saves as dashboard default
              </span>
            </div>

            <Button size="sm" className="h-[28px] gap-1.5" onClick={handleAddPanel}>
              <Plus className="w-[12px] h-[12px]" />
              Add Panel
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={() => setShowVariableEditor(true)}
            >
              <Variable className="w-[12px] h-[12px]" />
              Variables
              {variables.length > 0 && (
                <span className="font-mono text-[10px] tabular-nums px-1 rounded bg-primary/20 text-primary">
                  {variables.length}
                </span>
              )}
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={handleSnapToGrid}
              title="Reorganize panels into a clean grid layout"
            >
              <LayoutGrid className="w-[12px] h-[12px]" />
              Snap to Grid
            </Button>

            <Button
              variant="outline"
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={handleCancel}
            >
              <X className="w-[12px] h-[12px]" />
              Cancel
            </Button>

            <Button
              size="sm"
              className="h-[28px] gap-1.5"
              onClick={handleSave}
              disabled={isSaving || !name.trim()}
            >
              {isSaving ? (
                <Loader2 className="w-[12px] h-[12px] animate-spin" />
              ) : (
                <Save className="w-[12px] h-[12px]" />
              )}
              Save
            </Button>
          </>
        )}
      </div>

      {/* Status strip */}
      <div className="flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground">
        <span className="tabular-nums">
          {panels.length} {panels.length === 1 ? 'panel' : 'panels'}
        </span>
        {isEditing && (
          <span className="inline-flex items-center gap-1 h-5 px-1.5 rounded-[3px] border border-primary/30 text-primary text-[9.5px] uppercase tracking-[0.1em] font-semibold">
            <Pencil className="w-[10px] h-[10px]" />
            Editing
          </span>
        )}
        {isDirty && (
          <span className="inline-flex items-center gap-1 h-5 px-1.5 rounded-[3px] border border-amber-500/40 text-amber-400 text-[9.5px] uppercase tracking-[0.1em] font-semibold">
            <CircleAlert className="w-[10px] h-[10px]" />
            Unsaved changes
          </span>
        )}
      </div>

      {/* Panels Grid */}
      {panels.length === 0 ? (
        <div className="rounded-md border border-border bg-card flex flex-col items-center gap-2 py-12 px-6 text-center">
          <LayoutDashboard className="w-10 h-10 text-muted-foreground/40" />
          <p className="text-[13px] font-medium text-foreground">No panels yet</p>
          <p className="text-[11.5px] text-muted-foreground">
            {isEditing
              ? 'Click "Add Panel" to create your first panel.'
              : 'Edit this dashboard to add panels.'}
          </p>
          {isEditing && (
            <Button size="sm" className="h-[28px] gap-1.5 mt-1" onClick={handleAddPanel}>
              <Plus className="w-[12px] h-[12px]" />
              Add Panel
            </Button>
          )}
        </div>
      ) : (
        <GridLayout
          key={layoutKey}
          panels={panels}
          layoutItems={layout.items}
          isEditing={isEditing}
          onLayoutChange={handleLayoutChange}
          renderPanel={renderPanel}
          columns={layout.columns}
          rowHeight={layout.rowHeight}
        />
      )}

      {/* Panel Editor Dialog */}
      {showPanelEditor && (
        <PanelEditor
          panel={editingPanel || undefined}
          onSave={handleSavePanel}
          onCancel={() => {
            setShowPanelEditor(false);
            setEditingPanel(null);
          }}
          variables={getCompleteVariables()}
        />
      )}

      {/* Variable Editor Dialog */}
      <VariableEditor
        open={showVariableEditor}
        onOpenChange={setShowVariableEditor}
        variables={variables}
        onSave={(newVariables) => {
          setVariables(newVariables);
          setIsDirty(true);
        }}
      />

      {/* Discard Changes Confirmation */}
      <AlertDialog open={showDiscardConfirm} onOpenChange={setShowDiscardConfirm}>
        <AlertDialogContent className="bg-card border-border max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle>Discard changes?</AlertDialogTitle>
            <AlertDialogDescription className="text-[12px] text-muted-foreground">
              You have unsaved changes. Are you sure you want to discard them?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="h-[28px] text-[12px]">
              Keep editing
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirmDiscard}
              className="h-[28px] text-[12px] bg-rose-600 hover:bg-rose-700"
            >
              Discard changes
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Share Dialog */}
      {dashboard && (
        <DashboardShareDialog
          open={showShareDialog}
          onOpenChange={setShowShareDialog}
          dashboardId={dashboard.id}
          dashboardName={dashboard.name}
          currentVisibility={dashboard.visibility || 'public'}
          currentSharedGroups={dashboard.shared_groups || []}
          isOwner={dashboard.is_owner ?? true}
          onShare={(_result: DashboardShareResult) => {
            // Update the dashboard with new visibility
            toast.success('Permissions updated');
          }}
        />
      )}

    </div>
  );
}

export default DashboardEditor;
