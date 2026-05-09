// SPDX-License-Identifier: AGPL-3.0-or-later

import { Loader2 } from 'lucide-react';

/**
 * Generic page loading spinner
 */
export function PageLoadingFallback() {
  return (
    <div className="min-h-[400px] flex items-center justify-center">
      <Loader2 className="w-8 h-8 text-muted-foreground animate-spin" />
    </div>
  );
}

/**
 * Loading skeleton for code editor pages (RuleEditor, CustomEnrichmentWizard)
 */
export function EditorLoadingFallback() {
  return (
    <div className="h-full flex flex-col">
      {/* Header skeleton */}
      <div className="flex items-center justify-between p-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="h-8 w-48 bg-muted/50 rounded animate-pulse" />
          <div className="h-6 w-20 bg-muted/50 rounded animate-pulse" />
        </div>
        <div className="flex items-center gap-2">
          <div className="h-8 w-24 bg-muted/50 rounded animate-pulse" />
          <div className="h-8 w-24 bg-muted/50 rounded animate-pulse" />
        </div>
      </div>
      {/* Editor area skeleton */}
      <div className="flex-1 flex">
        <div className="flex-1 p-4">
          <div className="h-full bg-muted/30 rounded-lg border border-border flex items-center justify-center">
            <Loader2 className="w-6 h-6 text-muted-foreground animate-spin" />
          </div>
        </div>
        {/* Side panel skeleton */}
        <div className="w-80 border-l border-border p-4 space-y-3">
          <div className="h-6 w-32 bg-muted/50 rounded animate-pulse" />
          <div className="h-10 w-full bg-muted/50 rounded animate-pulse" />
          <div className="h-10 w-full bg-muted/50 rounded animate-pulse" />
          <div className="h-10 w-full bg-muted/50 rounded animate-pulse" />
        </div>
      </div>
    </div>
  );
}

/**
 * Loading skeleton for chart/dashboard pages
 */
export function ChartPageLoadingFallback() {
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="h-8 w-48 bg-muted/50 rounded animate-pulse" />
        <div className="flex items-center gap-2">
          <div className="h-8 w-32 bg-muted/50 rounded animate-pulse" />
          <div className="h-8 w-24 bg-muted/50 rounded animate-pulse" />
        </div>
      </div>
      {/* Stats row */}
      <div className="grid grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-24 bg-muted/30 rounded-lg border border-border animate-pulse" />
        ))}
      </div>
      {/* Chart area */}
      <div className="h-80 bg-muted/30 rounded-lg border border-border flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-muted-foreground animate-spin" />
      </div>
      {/* Table skeleton */}
      <div className="space-y-2">
        <div className="h-10 bg-muted/50 rounded animate-pulse" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 bg-muted/30 rounded animate-pulse" />
        ))}
      </div>
    </div>
  );
}

/**
 * Loading skeleton for list/table pages
 */
export function ListPageLoadingFallback() {
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="h-8 w-48 bg-muted/50 rounded animate-pulse" />
        <div className="flex items-center gap-2">
          <div className="h-10 w-64 bg-muted/50 rounded animate-pulse" />
          <div className="h-10 w-32 bg-muted/50 rounded animate-pulse" />
        </div>
      </div>
      {/* Filters */}
      <div className="flex items-center gap-2">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-8 w-24 bg-muted/50 rounded animate-pulse" />
        ))}
      </div>
      {/* Table */}
      <div className="border border-border rounded-lg overflow-hidden">
        <div className="h-12 bg-muted/50 border-b border-border animate-pulse" />
        {[...Array(10)].map((_, i) => (
          <div key={i} className="h-14 border-b border-border last:border-b-0 animate-pulse" style={{ animationDelay: `${i * 50}ms` }} />
        ))}
      </div>
    </div>
  );
}

/**
 * Loading skeleton for settings/form pages
 */
export function SettingsLoadingFallback() {
  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="space-y-2">
        <div className="h-8 w-48 bg-muted/50 rounded animate-pulse" />
        <div className="h-4 w-96 bg-muted/30 rounded animate-pulse" />
      </div>
      {/* Form sections */}
      {[...Array(3)].map((_, i) => (
        <div key={i} className="space-y-4 p-6 border border-border rounded-lg">
          <div className="h-6 w-32 bg-muted/50 rounded animate-pulse" />
          <div className="space-y-3">
            <div className="h-10 w-full bg-muted/30 rounded animate-pulse" />
            <div className="h-10 w-full bg-muted/30 rounded animate-pulse" />
          </div>
        </div>
      ))}
      {/* Action buttons */}
      <div className="flex items-center gap-3">
        <div className="h-10 w-24 bg-muted/50 rounded animate-pulse" />
        <div className="h-10 w-24 bg-muted/30 rounded animate-pulse" />
      </div>
    </div>
  );
}

/**
 * Loading skeleton for detail pages (case detail, alert detail, etc.)
 */
export function DetailPageLoadingFallback() {
  return (
    <div className="p-6 space-y-6">
      {/* Header with back button */}
      <div className="flex items-center gap-4">
        <div className="h-8 w-8 bg-muted/50 rounded animate-pulse" />
        <div className="space-y-1">
          <div className="h-7 w-64 bg-muted/50 rounded animate-pulse" />
          <div className="h-4 w-48 bg-muted/30 rounded animate-pulse" />
        </div>
      </div>
      {/* Status bar */}
      <div className="flex items-center gap-3">
        <div className="h-6 w-20 bg-muted/50 rounded-full animate-pulse" />
        <div className="h-6 w-24 bg-muted/50 rounded-full animate-pulse" />
        <div className="h-6 w-32 bg-muted/50 rounded-full animate-pulse" />
      </div>
      {/* Content sections */}
      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 space-y-4">
          <div className="h-48 bg-muted/30 rounded-lg border border-border animate-pulse" />
          <div className="h-64 bg-muted/30 rounded-lg border border-border animate-pulse" />
        </div>
        <div className="space-y-4">
          <div className="h-40 bg-muted/30 rounded-lg border border-border animate-pulse" />
          <div className="h-32 bg-muted/30 rounded-lg border border-border animate-pulse" />
        </div>
      </div>
    </div>
  );
}

/**
 * Loading skeleton for wizard pages (multi-step forms)
 */
export function WizardLoadingFallback() {
  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      {/* Progress steps */}
      <div className="flex items-center justify-between">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="flex items-center">
            <div className="h-8 w-8 bg-muted/50 rounded-full animate-pulse" />
            {i < 3 && <div className="h-1 w-24 bg-muted/30 mx-2 animate-pulse" />}
          </div>
        ))}
      </div>
      {/* Form content */}
      <div className="p-6 border border-border rounded-lg space-y-4">
        <div className="h-7 w-48 bg-muted/50 rounded animate-pulse" />
        <div className="h-4 w-full bg-muted/30 rounded animate-pulse" />
        <div className="space-y-3 pt-4">
          <div className="h-10 w-full bg-muted/30 rounded animate-pulse" />
          <div className="h-10 w-full bg-muted/30 rounded animate-pulse" />
          <div className="h-24 w-full bg-muted/30 rounded animate-pulse" />
        </div>
      </div>
      {/* Navigation buttons */}
      <div className="flex items-center justify-between">
        <div className="h-10 w-24 bg-muted/30 rounded animate-pulse" />
        <div className="h-10 w-24 bg-muted/50 rounded animate-pulse" />
      </div>
    </div>
  );
}

