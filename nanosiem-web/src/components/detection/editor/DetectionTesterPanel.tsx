// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useRef, useCallback, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Play,
  X,
  Minus,
  Maximize2,
  Minimize2,
  GripHorizontal,
  RefreshCw,
  ArrowUpToLine,
  Loader2,
  Search,
  AlertTriangle,
} from 'lucide-react';
import { Slider } from '@/components/ui/slider';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { QueryEditor } from '@/components/editor';
import { useSearch, toApiTimeRange } from '@/hooks/use-api';
import { DetectionTestResults } from './DetectionTestResults';
import { toast } from 'sonner';

// ============================================================================
// localStorage persistence
// ============================================================================

const STORAGE_KEY = 'nanosiem-detection-tester-panel';

interface PanelLayout {
  x: number;
  y: number;
  width: number;
  height: number;
}

function loadLayout(): PanelLayout {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        x: Math.max(0, Number(parsed.x) || 100),
        y: Math.max(0, Number(parsed.y) || 80),
        width: Math.max(480, Number(parsed.width) || 960),
        height: Math.max(320, Number(parsed.height) || 680),
      };
    }
  } catch {}
  return { x: 100, y: 60, width: 960, height: 680 };
}

function saveLayout(layout: PanelLayout) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
  } catch {}
}

// ============================================================================
// Component
// ============================================================================

interface DetectionTesterPanelProps {
  query: string;
  alertMode?: 'grouped' | 'per_event';
  lookbackMinutes?: number | null;
  state: import('./tester-state').TesterState;
  onClose: () => void;
  onDock?: () => void;
  onApplyQuery: (query: string) => void;
}

export function DetectionTesterPanel({
  query: ruleQuery,
  alertMode,
  lookbackMinutes,
  state,
  onClose,
  onDock,
  onApplyQuery,
}: DetectionTesterPanelProps) {
  // Panel layout
  const [layout, setLayout] = useState<PanelLayout>(loadLayout);
  const [minimized, setMinimized] = useState(false);
  const [panelOpacity, setPanelOpacity] = useState(1);
  const [isHovering, setIsHovering] = useState(false);

  // Use shared state
  const { panelQuery, setPanelQuery, timeRange, setTimeRange, searchResponse, setSearchResponse, hasSearched, setHasSearched, searchError, setSearchError } = state;
  const { mutate: search, loading: isSearching } = useSearch();

  // Drag state
  const dragRef = useRef<{ startX: number; startY: number; startLayoutX: number; startLayoutY: number } | null>(null);
  // Resize state
  const resizeRef = useRef<{ startX: number; startY: number; startW: number; startH: number } | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  const isDragging = dragRef.current !== null;
  const isResizing = resizeRef.current !== null;
  const effectiveOpacity = isHovering || isDragging || isResizing ? 1 : panelOpacity;
  const queryDiverged = panelQuery !== ruleQuery;
  const prevRuleQueryRef = useRef(ruleQuery);

  // Persist layout on change
  useEffect(() => {
    saveLayout(layout);
  }, [layout]);

  // Sync panelQuery when ruleQuery changes and user hasn't manually edited
  useEffect(() => {
    const prevRuleQuery = prevRuleQueryRef.current;
    prevRuleQueryRef.current = ruleQuery;
    // Only sync if panelQuery still matches the previous rule query (user hasn't diverged)
    setPanelQuery(prev => prev === prevRuleQuery ? ruleQuery : prev);
  }, [ruleQuery]);

  // ---- Drag handlers ----
  const onDragStart = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    dragRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      startLayoutX: layout.x,
      startLayoutY: layout.y,
    };
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, [layout.x, layout.y]);

  const onDragMove = useCallback((e: React.PointerEvent) => {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.startX;
    const dy = e.clientY - dragRef.current.startY;
    const maxX = window.innerWidth - 200;
    const maxY = window.innerHeight - 40;
    setLayout(prev => ({
      ...prev,
      x: Math.max(0, Math.min(maxX, dragRef.current!.startLayoutX + dx)),
      y: Math.max(0, Math.min(maxY, dragRef.current!.startLayoutY + dy)),
    }));
  }, []);

  const onDragEnd = useCallback(() => {
    dragRef.current = null;
  }, []);

  // ---- Resize handlers ----
  const onResizeStart = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    e.stopPropagation();
    resizeRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      startW: layout.width,
      startH: layout.height,
    };
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  }, [layout.width, layout.height]);

  const onResizeMove = useCallback((e: React.PointerEvent) => {
    if (!resizeRef.current) return;
    const dx = e.clientX - resizeRef.current.startX;
    const dy = e.clientY - resizeRef.current.startY;
    setLayout(prev => ({
      ...prev,
      width: Math.max(480, Math.min(window.innerWidth - prev.x, resizeRef.current!.startW + dx)),
      height: Math.max(320, Math.min(window.innerHeight - prev.y, resizeRef.current!.startH + dy)),
    }));
  }, []);

  const onResizeEnd = useCallback(() => {
    resizeRef.current = null;
  }, []);

  // ---- Search execution ----
  const handleRunTest = useCallback(async () => {
    const trimmed = panelQuery.trim();
    if (!trimmed) {
      toast.error('Query is empty');
      return;
    }

    setSearchError(null);
    setHasSearched(true);

    const apiTimeRange = toApiTimeRange(timeRange);

    try {
      const result = await search({
        query: trimmed,
        time_range: apiTimeRange,
        limit: 500,
        table_view: true,
        priority: 'interactive',
        skip_field_stats: true,
        // NAN-705: the rule tester doesn't render a histogram, and reruns
        // of the same rule are common — skipping the histogram subquery
        // and enabling CH server-side query cache cuts CH load by ~3×
        // per "Run Test" click.
        skip_histogram: true,
        use_cache: true,
      });

      setSearchResponse(result);
    } catch (err: unknown) {
      const msg = (err as Error).message || 'Search failed';
      setSearchError(msg);
      setSearchResponse(null);
    }
  }, [panelQuery, timeRange, search]);

  // (Cmd+Enter handled by QueryEditor's onSubmit)

  return (
    <div
      ref={panelRef}
      className={`fixed z-40 flex flex-col bg-card border rounded-lg overflow-hidden transition-shadow transition-opacity duration-150 ${minimized ? 'border-primary/60 shadow-lg shadow-primary/20' : 'border-border shadow-2xl'}`}
      style={{
        left: layout.x,
        top: layout.y,
        width: minimized ? 320 : layout.width,
        height: minimized ? 'auto' : layout.height,
        opacity: effectiveOpacity,
      }}
      onMouseEnter={() => setIsHovering(true)}
      onMouseLeave={() => setIsHovering(false)}
    >
      {/* Header / Drag Handle */}
      <div
        className={`flex items-center gap-2 px-3 py-2 border-b cursor-grab active:cursor-grabbing select-none flex-shrink-0 ${minimized ? 'bg-primary/10 border-primary/30' : 'bg-muted/80 border-border'}`}
        onPointerDown={onDragStart}
        onPointerMove={onDragMove}
        onPointerUp={onDragEnd}
      >
        <GripHorizontal className="w-4 h-4 text-muted-foreground flex-shrink-0" />
        <Search className="w-4 h-4 text-primary flex-shrink-0" />
        <span className="text-sm font-medium text-foreground truncate">Detection Tester</span>

        {queryDiverged && (
          <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-500/30 flex-shrink-0">
            modified
          </Badge>
        )}

        <div className="ml-auto flex items-center gap-1 flex-shrink-0">
          {onDock && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
              onClick={onDock}
              title="Dock back to bottom panel"
            >
              <Minimize2 className="w-3.5 h-3.5" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
            onClick={() => setMinimized(!minimized)}
            title={minimized ? 'Expand' : 'Minimize'}
          >
            {minimized ? <Maximize2 className="w-3.5 h-3.5" /> : <Minus className="w-3.5 h-3.5" />}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
            onClick={onClose}
            title="Close"
          >
            <X className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* Opacity slider */}
      {!minimized && (
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border bg-muted/30 flex-shrink-0">
          <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider shrink-0">Opacity</span>
          <Slider
            value={[panelOpacity * 100]}
            onValueChange={([v]) => setPanelOpacity(v / 100)}
            min={30}
            max={100}
            step={5}
            className="flex-1"
          />
          <span className="text-[10px] text-muted-foreground tabular-nums w-7 text-right">{Math.round(panelOpacity * 100)}%</span>
        </div>
      )}

      {!minimized && (
        <>
          {/* Query editor with syntax highlighting */}
          <div className="border-b border-border/50 bg-muted/30 flex-shrink-0 flex flex-col">
            <div className="overflow-auto px-3 pt-2">
              <QueryEditor
                value={panelQuery}
                onChange={setPanelQuery}
                placeholder="Enter nPL query..."
                minHeight={60}
                maxHeight={300}
                onSubmit={handleRunTest}
              />
            </div>

            {/* Controls row */}
            <div className="flex items-center gap-2 flex-wrap px-3 py-2">
              <DateTimeRangePicker
                value={timeRange}
                onChange={setTimeRange}
                className="h-7 text-xs rounded-lg border"
                align="start"
                defaultMode="presets"
                maxRangeDays={14}
              />

              <Button
                size="sm"
                className="h-7 text-xs bg-primary hover:bg-primary/90"
                onClick={handleRunTest}
                disabled={isSearching || !panelQuery.trim()}
              >
                {isSearching
                  ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  : <Play className="w-3.5 h-3.5" />
                }
                Run
              </Button>

              <div className="ml-auto flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => {
                    setPanelQuery(ruleQuery);
                    toast.success('Query synced from rule');
                  }}
                  title="Sync query from rule editor"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Sync from Rule
                </Button>

                {queryDiverged && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs text-primary hover:text-primary/80"
                    onClick={() => {
                      onApplyQuery(panelQuery);
                      toast.success('Query applied to rule');
                    }}
                    title="Apply this query back to the rule editor"
                  >
                    <ArrowUpToLine className="w-3.5 h-3.5" />
                    Apply to Rule
                  </Button>
                )}
              </div>
            </div>
          </div>

          {/* Error display */}
          {searchError && (
            <div className="px-3 py-2 bg-red-500/10 border-b border-red-500/20 flex-shrink-0">
              <p className="text-xs text-red-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                {searchError}
              </p>
            </div>
          )}

          {/* Results */}
          <DetectionTestResults
            response={searchResponse}
            isSearching={isSearching}
            hasSearched={hasSearched}
            alertMode={alertMode}
            lookbackMinutes={lookbackMinutes}
          />

          {/* Resize grip (panel corner) */}
          <div
            className="absolute bottom-0 right-0 w-5 h-5 cursor-se-resize hover:opacity-100 opacity-60 transition-opacity"
            onPointerDown={onResizeStart}
            onPointerMove={onResizeMove}
            onPointerUp={onResizeEnd}
          >
            <svg className="w-5 h-5 text-muted-foreground" viewBox="0 0 16 16">
              <path d="M14 14L6 14L14 6Z" fill="currentColor" opacity="0.3" />
              <path d="M14 14L10 14L14 10Z" fill="currentColor" opacity="0.5" />
            </svg>
          </div>
        </>
      )}
    </div>
  );
}

export default DetectionTesterPanel;
