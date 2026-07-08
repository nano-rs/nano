// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * GridLayout Component
 * 
 * A responsive grid layout manager for dashboard panels using react-grid-layout.
 * Supports drag and drop, resizing, and responsive breakpoints.
 * 
 * Requirements: 2.1, 2.2, 2.3, 2.4, 2.6, 9.5
 */

import { useMemo, useCallback } from 'react';
import { GridLayout as RGL, useContainerWidth, getCompactor } from 'react-grid-layout';
import type { Layout } from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import type { PanelConfig, LayoutItem } from '@/lib/api';

// Grid configuration constants
const GRID_COLUMNS = 12;
const ROW_HEIGHT = 80;
const MIN_PANEL_WIDTH = 2;
const MIN_PANEL_HEIGHT = 2;
const GRID_MARGIN: [number, number] = [16, 16];
const CONTAINER_PADDING: [number, number] = [0, 0];

export interface GridLayoutProps {
  /** Panel configurations */
  panels: PanelConfig[];
  /** Layout items defining panel positions */
  layoutItems: LayoutItem[];
  /** Whether the grid is in edit mode (enables drag/drop and resize) */
  isEditing: boolean;
  /** Callback when layout changes */
  onLayoutChange: (layout: LayoutItem[]) => void;
  /** Render function for each panel */
  renderPanel: (panel: PanelConfig) => React.ReactNode;
  /** Number of columns (default: 12) */
  columns?: number;
  /** Row height in pixels (default: 80) */
  rowHeight?: number;
}

/**
 * Convert LayoutItem to react-grid-layout Layout format
 */
function toGridLayout(items: LayoutItem[]): Layout {
  return items.map(item => ({
    i: item.i,
    x: item.x,
    y: item.y,
    w: item.w,
    h: item.h,
    minW: item.minW ?? MIN_PANEL_WIDTH,
    minH: item.minH ?? MIN_PANEL_HEIGHT,
  }));
}

/**
 * Convert react-grid-layout Layout to LayoutItem format
 */
function fromGridLayout(layout: Layout): LayoutItem[] {
  return layout.map(item => ({
    i: item.i,
    x: item.x,
    y: item.y,
    w: item.w,
    h: item.h,
    minW: item.minW,
    minH: item.minH,
  }));
}

/**
 * Check if two layout items overlap
 */
export function checkOverlap(a: LayoutItem, b: LayoutItem): boolean {
  // Two rectangles don't overlap if one is to the left, right, above, or below the other
  const noOverlap = 
    a.x + a.w <= b.x || // a is to the left of b
    b.x + b.w <= a.x || // b is to the left of a
    a.y + a.h <= b.y || // a is above b
    b.y + b.h <= a.y;   // b is above a
  
  return !noOverlap;
}

/**
 * Validate that no panels overlap in the layout
 */
export function validateNoOverlap(items: LayoutItem[]): boolean {
  for (let i = 0; i < items.length; i++) {
    for (let j = i + 1; j < items.length; j++) {
      if (checkOverlap(items[i], items[j])) {
        return false;
      }
    }
  }
  return true;
}

/**
 * Validate that all panels meet minimum size requirements
 */
export function validateMinimumSize(items: LayoutItem[]): boolean {
  return items.every(item =>
    item.w >= MIN_PANEL_WIDTH && item.h >= MIN_PANEL_HEIGHT
  );
}

/**
 * Get ideal size for a panel based on visualization type
 */
function getIdealSize(vizType: string): { w: number; h: number } {
  switch (vizType) {
    case 'single_value':
      return { w: 3, h: 2 }; // Small KPI card
    case 'pie':
      return { w: 4, h: 3 }; // Square-ish for pie
    case 'bar':
    case 'ranked_bar':
      return { w: 6, h: 3 }; // Wide for bar charts
    case 'line':
    case 'area':
    case 'timeline':
      return { w: 6, h: 3 }; // Wide for time series
    case 'table':
      return { w: 6, h: 4 }; // Large for tables
    case 'tree':
    case 'flow':
    case 'transaction':
      return { w: 6, h: 4 }; // Large for complex visualizations
    default:
      return { w: 4, h: 3 }; // Medium default
  }
}

/**
 * Reflow layout with smart resizing based on visualization type
 * Resizes panels to ideal sizes and packs them tightly
 */
export function compactLayout(
  items: LayoutItem[],
  columns: number = GRID_COLUMNS,
  panels?: PanelConfig[]
): LayoutItem[] {
  if (items.length === 0) return [];

  // Create panel lookup map
  const panelMap = new Map<string, PanelConfig>();
  if (panels) {
    panels.forEach(p => panelMap.set(p.id, p));
  }

  // Resize items based on visualization type if panels provided
  const resizedItems = items.map(item => {
    const panel = panelMap.get(item.i);
    if (panel) {
      const idealSize = getIdealSize(panel.visualizationType);
      return { ...item, w: idealSize.w, h: idealSize.h };
    }
    return item;
  });

  // Sort by area (largest first) for better packing
  const sortedItems = [...resizedItems].sort((a, b) => {
    const areaA = a.w * a.h;
    const areaB = b.w * b.h;
    if (areaA !== areaB) return areaB - areaA;
    return b.w - a.w;
  });

  // Track occupied cells in the grid
  const occupied: boolean[][] = [];

  const isOccupied = (x: number, y: number, w: number, h: number): boolean => {
    for (let row = y; row < y + h; row++) {
      for (let col = x; col < x + w; col++) {
        if (occupied[row]?.[col]) return true;
      }
    }
    return false;
  };

  const markOccupied = (x: number, y: number, w: number, h: number): void => {
    for (let row = y; row < y + h; row++) {
      if (!occupied[row]) occupied[row] = [];
      for (let col = x; col < x + w; col++) {
        occupied[row][col] = true;
      }
    }
  };

  // Place each item at first available position
  const newItems: LayoutItem[] = [];
  for (const item of sortedItems) {
    let placed = false;
    // Search for first available position, row by row
    for (let y = 0; !placed && y < 100; y++) {
      for (let x = 0; x <= columns - item.w; x++) {
        if (!isOccupied(x, y, item.w, item.h)) {
          newItems.push({ ...item, x, y });
          markOccupied(x, y, item.w, item.h);
          placed = true;
          break;
        }
      }
    }
  }

  return newItems;
}

export function GridLayout({
  panels,
  layoutItems,
  isEditing,
  onLayoutChange,
  renderPanel,
  columns = GRID_COLUMNS,
  rowHeight = ROW_HEIGHT,
}: GridLayoutProps) {
  // Use the container width hook for responsive sizing
  const { width, containerRef, mounted } = useContainerWidth({ 
    measureBeforeMount: true,
    initialWidth: 1200 
  });

  // DSH43: defensively de-duplicate layout items by id. Backend import now
  // rejects duplicate panel ids, but a hand-edited / older-tool dashboard could
  // still carry them; keeping the FIRST item per id avoids rendering the same
  // panel in two slots and colliding React / react-grid-layout keys.
  const dedupedLayoutItems = useMemo(() => {
    const seen = new Set<string>();
    return layoutItems.filter(item => {
      if (seen.has(item.i)) return false;
      seen.add(item.i);
      return true;
    });
  }, [layoutItems]);

  // Convert layout items to react-grid-layout format
  const gridLayout = useMemo(() => toGridLayout(dedupedLayoutItems), [dedupedLayoutItems]);

  // Handle layout change from react-grid-layout
  const handleLayoutChange = useCallback((newLayout: Layout) => {
    const convertedLayout = fromGridLayout(newLayout);
    onLayoutChange(convertedLayout);
  }, [onLayoutChange]);

  // Create a map of panel ID to panel for quick lookup.
  // DSH43: keep the FIRST panel for a given id (deterministic) rather than the
  // JS-default last-write-wins, so a duplicate id can't silently swap in the
  // wrong panel.
  const panelMap = useMemo(() => {
    const map = new Map<string, PanelConfig>();
    panels.forEach(panel => {
      if (!map.has(panel.id)) map.set(panel.id, panel);
    });
    return map;
  }, [panels]);

  // Grid configuration using the new API
  const gridConfig = useMemo(() => ({
    cols: columns,
    rowHeight: rowHeight,
    margin: GRID_MARGIN,
    containerPadding: CONTAINER_PADDING,
  }), [columns, rowHeight]);

  // Drag configuration
  const dragConfig = useMemo(() => ({
    enabled: isEditing,
    handle: isEditing ? undefined : '.panel-drag-handle',
  }), [isEditing]);

  // Resize configuration
  const resizeConfig = useMemo(() => ({
    enabled: isEditing,
    handles: isEditing ? ['se', 'sw', 'ne', 'nw', 'e', 'w', 'n', 's'] as const : [],
  }), [isEditing]);

  // Use vertical compactor - allows items to swap/push but compacts vertically
  const compactor = getCompactor('vertical', false, false);

  return (
    <div 
      ref={containerRef as React.RefObject<HTMLDivElement>}
      className={`grid-layout-container ${isEditing ? 'show-grid' : ''}`}
    >
      {mounted && (
        <RGL
          className="dashboard-grid"
          layout={gridLayout}
          width={width}
          gridConfig={gridConfig}
          dragConfig={dragConfig}
          resizeConfig={resizeConfig}
          compactor={compactor}
          onLayoutChange={handleLayoutChange}
        >
          {dedupedLayoutItems.map(item => {
            const panel = panelMap.get(item.i);
            if (!panel) return null;

            return (
              <div 
                key={item.i} 
                className={`grid-panel ${isEditing ? 'editing' : ''}`}
              >
                {renderPanel(panel)}
              </div>
            );
          })}
        </RGL>
      )}

      {/* Custom styles for the grid - consistent with dark theme */}
      <style>{`
        .grid-layout-container {
          width: 100%;
        }

        .dashboard-grid {
          min-height: 200px;
        }

        .grid-panel {
          transition: box-shadow 0.2s ease;
          height: 100%;
        }

        .grid-panel > * {
          height: 100%;
        }

        .grid-panel.editing {
          cursor: move;
        }

        .grid-panel.editing:hover {
          box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.5); /* blue-500 with opacity */
          border-radius: 1rem; /* rounded-2xl */
        }

        /* Drag placeholder styling - uses blue-500 accent color */
        .react-grid-placeholder {
          background: rgba(59, 130, 246, 0.2) !important;
          border: 2px dashed rgba(59, 130, 246, 0.5) !important;
          border-radius: 1rem !important; /* rounded-2xl */
          opacity: 1 !important;
        }

        /* Resize handle styling - subtle until hovered */
        .react-resizable-handle {
          opacity: 0;
          transition: opacity 0.2s ease;
        }

        .grid-panel.editing:hover .react-resizable-handle,
        .react-grid-item.resizing .react-resizable-handle {
          opacity: 1;
        }

        .react-resizable-handle::after {
          border-color: rgba(255, 255, 255, 0.3) !important; /* white/30 */
        }

        .react-resizable-handle:hover::after {
          border-color: rgba(59, 130, 246, 0.8) !important; /* blue-500 with opacity */
        }

        /* Drop zone indicator during drag - elevated with shadow */
        .react-grid-item.react-draggable-dragging {
          z-index: 100;
          box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5); /* shadow-lg equivalent */
          border-radius: 1rem; /* rounded-2xl */
          transition: none !important; /* Prevent bouncing during drag */
        }

        /* Smooth transitions for non-dragging items - eased for natural feel */
        .react-grid-item:not(.react-draggable-dragging):not(.resizing) {
          transition: transform 0.2s cubic-bezier(0.25, 0.1, 0.25, 1);
        }

        /* Grid lines for edit mode - subtle white/5 opacity */
        .grid-layout-container.show-grid {
          background-image: 
            linear-gradient(to right, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
          background-size: calc(100% / 12) ${rowHeight}px;
        }
      `}</style>
    </div>
  );
}

/**
 * Responsive GridLayout props
 */
export interface ResponsiveGridLayoutProps extends Omit<GridLayoutProps, 'columns'> {
  /** Custom breakpoints (optional) */
  breakpoints?: Record<string, number>;
  /** Columns per breakpoint (optional) */
  cols?: Record<string, number>;
}

/**
 * Responsive GridLayout that adapts to different screen sizes
 * Uses the standard GridLayout internally but with responsive column counts
 */
export function ResponsiveDashboardGrid({
  panels,
  layoutItems,
  isEditing,
  onLayoutChange,
  renderPanel,
  rowHeight = ROW_HEIGHT,
}: ResponsiveGridLayoutProps) {
  // For now, use the standard GridLayout with 12 columns
  // The useContainerWidth hook handles width responsiveness
  return (
    <GridLayout
      panels={panels}
      layoutItems={layoutItems}
      isEditing={isEditing}
      onLayoutChange={onLayoutChange}
      renderPanel={renderPanel}
      columns={GRID_COLUMNS}
      rowHeight={rowHeight}
    />
  );
}

export default GridLayout;
