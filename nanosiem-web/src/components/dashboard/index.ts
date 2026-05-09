// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Dashboard Components
 * 
 * Export all dashboard-related components for easy importing.
 */

export { Panel, type PanelProps, type PanelDataState, type DrilldownFilter } from './Panel';
export { VisualizationRenderer, type VisualizationRendererProps } from './VisualizationRenderer';
export { 
  GridLayout, 
  ResponsiveDashboardGrid,
  checkOverlap,
  validateNoOverlap,
  validateMinimumSize,
  type GridLayoutProps,
  type ResponsiveGridLayoutProps,
} from './GridLayout';
export { DashboardEditor, type DashboardEditorProps } from './DashboardEditor';
export { DashboardShareDialog } from './DashboardShareDialog';
export { PanelEditor, type PanelEditorProps } from './PanelEditor';
export { QueryTestModal } from './QueryTestModal';
export { AddToDashboardDialog, type AddToDashboardDialogProps } from './AddToDashboardDialog';
export { VariableControls, type VariableControlsProps } from './VariableControls';
export { VariableEditor, type VariableEditorProps } from './VariableEditor';

// Drilldown utilities
export {
  extractGroupingFields,
  buildDrilldownContext,
  escapeFilterValue,
  constructFilterQuery,
  buildSearchUrlParams,
  buildSearchUrl,
  type DrilldownContext,
} from './drilldown';

// Home dashboard components
export { AnimatedCounter } from './AnimatedCounter';
export { QuickEntitySearch } from './QuickEntitySearch';
export { QuickActions } from './QuickActions';
export { MiniStats } from './MiniStats';
export { TopFiringRules } from './TopFiringRules';
// RiskLeaderboard lifted to @/enterprise/components/dashboard/RiskLeaderboard (NAN-745).
export { CyberNewsFeed } from './CyberNewsFeed';
// MyCases lifted to @/enterprise/components/dashboard/MyCases (NAN-745).
export { AlertSummary } from './AlertSummary';
// RecentCases lifted to @/enterprise/components/dashboard/RecentCases (NAN-745).
export { UnassignedAlerts } from './UnassignedAlerts';
// UnassignedCases lifted to @/enterprise/components/dashboard/UnassignedCases (NAN-745).
export { PickUpWhereYouLeftOff } from './PickUpWhereYouLeftOff';
