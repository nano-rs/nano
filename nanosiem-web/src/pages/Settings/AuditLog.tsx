// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Audit Log Page
 *
 * Requirements: 11.6
 * - Query audit logs with filters
 * - Export functionality
 *
 * Density pass (NAN-543): redesign density — 10-11px mono row meta,
 * 24-28px rows, no shadows, no rounded-2xl, no Card wrappers where plain
 * bordered divs suffice.
 */

import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { auditFiltersFromSearch, auditFiltersToSearch, sameAuditUrlFilters } from '@/lib/audit-filters';
import { auditActorLabel } from '@/lib/audit-feed';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
// Badge not used in redesign pass
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DetailSheet } from '@/components/ui/detail-sheet';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import {
  FileText,
  Search,
  Download,
  Filter,
  ChevronLeft,
  ChevronRight,
  CircleCheck,
  XCircle,
  User,
  Globe,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useToast } from '@/hooks/use-toast';
import { api, AuditLogEntry, AuditLogQuery } from '@/lib/api';
import { formatUTC } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import { auditCsv } from '@/lib/audit-csv';

// Radix Select refuses an empty-string item value (it throws and blanks the
// page), so "all" is a sentinel that maps to an absent filter.
const ALL_FILTER = '__all__';

// Common audit actions for filtering (underscore convention)
const AUDIT_ACTIONS = [
  { value: ALL_FILTER, label: 'All Actions' },
  { value: 'login_success', label: 'Login Success' },
  { value: 'login_failed', label: 'Login Failed' },
  { value: 'logout', label: 'Logout' },
  { value: 'auth_denied', label: 'Authorization Denied' },
  { value: 'sso_sign_in_denied', label: 'SSO Sign-in Denied' },
  { value: 'sso_group_grants_synchronized', label: 'SSO Group Grants Synchronized' },
  { value: 'token_refresh', label: 'Session Refreshed' },
  { value: 'user_created', label: 'User Created' },
  { value: 'user_updated', label: 'User Updated' },
  { value: 'user_deleted', label: 'User Deleted' },
  { value: 'rule_created', label: 'Rule Created' },
  { value: 'rule_updated', label: 'Rule Updated' },
  { value: 'rule_deleted', label: 'Rule Deleted' },
  { value: 'dashboard_created', label: 'Dashboard Created' },
  { value: 'dashboard_updated', label: 'Dashboard Updated' },
  { value: 'dashboard_deleted', label: 'Dashboard Deleted' },
  { value: 'alert_acknowledged', label: 'Alert Acknowledged' },
  { value: 'alert_closed', label: 'Alert Closed' },
  { value: 'apikey_created', label: 'API Key Created' },
  { value: 'apikey_updated', label: 'API Key Updated' },
  { value: 'apikey_enabled', label: 'API Key Enabled' },
  { value: 'apikey_disabled', label: 'API Key Disabled' },
  { value: 'apikey_deleted', label: 'API Key Deleted' },
  { value: 'session_terminated', label: 'Session Terminated' },
  { value: 'oidc_provider_created', label: 'OIDC Provider Created' },
];

// Audit source subsystems for filtering
const AUDIT_SOURCES = [
  { value: ALL_FILTER, label: 'All Sources' },
  { value: 'search', label: 'Search' },
  { value: 'auth', label: 'Authentication' },
  { value: 'detection', label: 'Detection' },
  { value: 'user', label: 'User Management' },
  { value: 'case', label: 'Cases' },
  { value: 'dashboard', label: 'Dashboards' },
  { value: 'notebook', label: 'Notebooks' },
  { value: 'alert', label: 'Alerts' },
  { value: 'apikey', label: 'API Keys' },
  { value: 'role', label: 'Roles' },
  { value: 'group', label: 'Groups' },
  { value: 'log_source', label: 'Log Sources' },
  { value: 'source_config', label: 'Source Configs' },
  { value: 'enrichment', label: 'Enrichment' },
  { value: 'custom_enrichment', label: 'Custom Enrichment' },
  { value: 'oidc', label: 'OIDC' },
  { value: 'parser_repo', label: 'Parser Repos' },
  { value: 'rule_repo', label: 'Rule Repos' },
  { value: 'playbook_repo', label: 'Playbook Repos' },
  { value: 'marketplace', label: 'Marketplace' },
  { value: 'session', label: 'Sessions' },
  { value: 'settings', label: 'System Settings' },
  { value: 'tuning', label: 'Auto-Tuning' },
  { value: 'credentials', label: 'Credentials' },
  { value: 'identity', label: 'Identity Providers' },
  { value: 'agent_enrichment', label: 'Agent Enrichment' },
  { value: 'query_library', label: 'Query Library' },
];

function getActionTone(action: string): string {
  if (action.includes('deleted') || action.includes('failed') || action.includes('removed')) {
    return 'bg-red-500/10 text-red-400 border-red-500/20';
  }
  if (action.includes('created') || action.includes('imported')) {
    return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  }
  if (action.includes('updated') || action.includes('terminated') || action.includes('toggled') || action.includes('disabled')) {
    return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
  }
  if (action.includes('deployed') || action.includes('enabled') || action.includes('synced')) {
    return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  }
  if (action.includes('login') || action.includes('logout')) {
    return 'bg-primary/10 text-primary border-primary/20';
  }
  if (action.includes('acknowledged') || action.includes('closed') || action.includes('assigned')) {
    return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
  }
  return 'bg-muted/40 text-muted-foreground border-border';
}

function formatAction(action: string): string {
  return action
    .replace(/[._]/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

// Content component for use in tabbed Access Control page
export function AuditLogContent() {
  const { toast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();

  // Data state
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [degradedReason, setDegradedReason] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [serverExporting, setServerExporting] = useState(false);

  // Filter state
  // NAN-4480: action / source / resource_type round-trip through the URL so a
  // filtered view is a shareable deep link (other params, e.g. `tab`, kept).
  const [filters, setFilters] = useState<AuditLogQuery>(() => auditFiltersFromSearch(searchParams));
  useEffect(() => {
    const next = auditFiltersFromSearch(searchParams);
    setFilters((current) => (sameAuditUrlFilters(current, next) ? current : { ...current, action: next.action, source: next.source, resource_type: next.resource_type, offset: 0 }));
  }, [searchParams]);
  useEffect(() => {
    if (sameAuditUrlFilters(filters, auditFiltersFromSearch(searchParams))) return;
    setSearchParams((current) => auditFiltersToSearch(current, filters), { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.action, filters.source, filters.resource_type]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterOpen, setFilterOpen] = useState(false);

  // Detail dialog state
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const response = await api.queryAuditLogs(filters);
      setLogs(response.logs);
      setTotal(response.total);
      setDegradedReason(response.degraded ? (response.degraded_reason ?? 'Audit store degraded') : null);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load audit logs',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [filters]);

  const filteredLogs = logs.filter(log => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      log.action?.toLowerCase().includes(query) ||
      log.user_name?.toLowerCase().includes(query) ||
      log.api_key_name?.toLowerCase().includes(query) ||
      log.source?.toLowerCase().includes(query) ||
      log.ip_address?.toLowerCase().includes(query) ||
      log.resource_type?.toLowerCase().includes(query) ||
      log.resource_name?.toLowerCase().includes(query) ||
      log.message?.toLowerCase().includes(query)
    );
  });
  const exportAllBlockedBySearch = searchQuery.trim().length > 0;
  const exportAllSearchReason = 'Clear the search to export all rows matching the filters';

  const handleFilterChange = (key: keyof AuditLogQuery, value: string) => {
    setFilters(prev => ({
      ...prev,
      [key]: value || undefined,
      offset: 0,
    }));
  };

  const handlePageChange = (direction: 'prev' | 'next') => {
    const limit = filters.limit || 50;
    const currentOffset = filters.offset || 0;
    if (direction === 'prev' && currentOffset > 0) {
      setFilters(prev => ({ ...prev, offset: Math.max(0, currentOffset - limit) }));
    } else if (direction === 'next' && currentOffset + limit < total) {
      setFilters(prev => ({ ...prev, offset: currentOffset + limit }));
    }
  };

  const handleExport = async () => {
    try {
      // Exactly the rows on screen (search box applied), formula-neutralized.
      const csv = auditCsv(filteredLogs);
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-log-${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: 'Export complete', description: 'Audit log has been exported to CSV.' });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to export audit log',
        variant: 'destructive',
      });
    }
  };

  const handleExportAll = async () => {
    if (exportAllBlockedBySearch) return;
    setServerExporting(true);
    try {
      const { offset: _offset, ...matchingFilters } = filters;
      const download = await api.exportAuditLogs({
        ...matchingFilters,
        limit: 100_000,
        format: 'csv',
      });
      const url = URL.createObjectURL(download.blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = download.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({
        title: 'Export complete',
        description: 'Downloaded up to 100,000 matching audit rows.',
      });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to export all audit logs',
        variant: 'destructive',
      });
    } finally {
      setServerExporting(false);
    }
  };

  const handleViewDetails = (log: AuditLogEntry) => {
    setSelectedLog(log);
    setDetailDialogOpen(true);
  };

  const limit = filters.limit || 50;
  const offset = filters.offset || 0;
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit);
  const hasActiveFilters = !!(filters.action || filters.source || filters.resource_type || filters.start_time || filters.end_time);

  if (loading && logs.length === 0) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingIcon className="w-6 h-6 text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search logs…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-7 pl-8 text-[12px] border-border bg-card"
          />
        </div>
        <Popover open={filterOpen} onOpenChange={setFilterOpen}>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" className={cn('h-7 text-[11.5px] px-2.5 gap-1.5 border-border', hasActiveFilters && 'border-primary text-primary')}>
              <Filter className="w-3 h-3" />
              Filters
              {hasActiveFilters && (
                <span className="font-mono text-[9px] bg-primary/15 text-primary px-1 rounded">Active</span>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-72 bg-card border-border p-4" align="end">
            <div className="space-y-3">
              <div className="space-y-1.5">
                <label className="text-[11px] text-muted-foreground">Action</label>
                <Select
                  value={filters.action || ALL_FILTER}
                  onValueChange={(value) => handleFilterChange('action', value === ALL_FILTER ? '' : value)}
                >
                  <SelectTrigger className="h-8 text-[12px] border-border">
                    <SelectValue placeholder="All Actions" />
                  </SelectTrigger>
                  <SelectContent>
                    {AUDIT_ACTIONS.map((action) => (
                      <SelectItem key={action.value} value={action.value} className="text-[12px]">
                        {action.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <label className="text-[11px] text-muted-foreground">Source</label>
                <Select
                  value={filters.source || ALL_FILTER}
                  onValueChange={(value) => handleFilterChange('source', value === ALL_FILTER ? '' : value)}
                >
                  <SelectTrigger className="h-8 text-[12px] border-border">
                    <SelectValue placeholder="All Sources" />
                  </SelectTrigger>
                  <SelectContent>
                    {AUDIT_SOURCES.map((source) => (
                      <SelectItem key={source.value} value={source.value} className="text-[12px]">
                        {source.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <label className="text-[11px] text-muted-foreground">Start Time</label>
                <Input
                  type="datetime-local"
                  value={filters.start_time || ''}
                  onChange={(e) => handleFilterChange('start_time', e.target.value)}
                  className="h-8 text-[12px] border-border"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-[11px] text-muted-foreground">End Time</label>
                <Input
                  type="datetime-local"
                  value={filters.end_time || ''}
                  onChange={(e) => handleFilterChange('end_time', e.target.value)}
                  className="h-8 text-[12px] border-border"
                />
              </div>
              <Button
                variant="outline"
                size="sm"
                className="w-full h-7 text-[11.5px] px-2.5 border-border"
                onClick={() => {
                  setFilters({ limit: 50, offset: 0 });
                  setFilterOpen(false);
                }}
              >
                Clear filters
              </Button>
            </div>
          </PopoverContent>
        </Popover>
        <Button
          onClick={handleExport}
          variant="outline"
          size="sm"
          className="h-7 text-[11.5px] px-2.5 gap-1.5 border-border ml-auto"
        >
          <Download className="w-3 h-3" />
          Export CSV
        </Button>
        <Button
          onClick={handleExportAll}
          disabled={serverExporting || exportAllBlockedBySearch}
          variant="outline"
          size="sm"
          className="h-7 text-[11.5px] px-2.5 gap-1.5 border-border"
          title={exportAllBlockedBySearch
            ? exportAllSearchReason
            : 'Export all matching audit rows (up to 100,000)'}
        >
          {serverExporting ? <LoadingIcon className="w-3 h-3" /> : <Download className="w-3 h-3" />}
          {serverExporting ? 'Exporting…' : 'Export all'}
        </Button>
        {exportAllBlockedBySearch && (
          <span
            data-testid="audit-export-all-search-reason"
            className="font-mono text-[10.5px] text-muted-foreground"
          >
            {exportAllSearchReason}
          </span>
        )}
        {serverExporting && (
          <span role="status" className="font-mono text-[10.5px] text-muted-foreground">
            Exporting up to 100,000 matching rows…
          </span>
        )}
      </div>

      {degradedReason && (
        <div role="status" className="rounded border border-warning/40 bg-warning/10 px-3 py-2 text-[12px] text-foreground">
          <span className="font-medium">Partial audit view.</span>{' '}
          ClickHouse is not answering, so only security-critical events (logins, MFA, API keys, credentials) from the PostgreSQL record are shown.
          <div className="mt-0.5 font-mono text-[10.5px] text-muted-foreground break-all">{degradedReason}</div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-card/50">
              <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-36">Timestamp</th>
              <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-28">Actor</th>
              <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-24">Source</th>
              <th className="text-left px-3 py-2 text-[11px] text-muted-foreground">Action</th>
              <th className="text-left px-3 py-2 text-[11px] text-muted-foreground">Resource</th>
              <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-28">IP Address</th>
              <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-12"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center text-[12px] text-muted-foreground py-10">
                  No audit logs found
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => (
                <tr
                  key={log.id}
                  className="hover:bg-foreground/[0.025] cursor-pointer transition-colors"
                  onClick={() => handleViewDetails(log)}
                >
                  <td className="px-3 py-1.5">
                    <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
                      {formatUTC(log.timestamp)}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="flex items-center gap-1.5">
                      <User className="w-3 h-3 text-muted-foreground shrink-0" />
                      <span className="font-mono text-[10.5px] text-foreground truncate max-w-[90px]" title={auditActorLabel(log)}>
                        {auditActorLabel(log)}
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-1.5">
                    {log.source && (
                      <span className="font-mono text-[10px] text-muted-foreground uppercase tracking-wide">
                        {log.source}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    {log.action && (
                      <span className={cn('font-mono text-[10px] font-semibold tracking-[0.08em] uppercase px-1.5 py-0.5 rounded border', getActionTone(log.action))}>
                        {formatAction(log.action)}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1.5 max-w-[200px]">
                    {log.resource_type && (
                      <span className="text-[11px] text-muted-foreground">
                        {log.resource_type}
                        {log.resource_name ? (
                          <span className="text-foreground ml-1 font-mono text-[10.5px]">{log.resource_name}</span>
                        ) : log.resource_id ? (
                          <span className="text-muted-foreground ml-1 font-mono text-[10px]">
                            ({log.resource_id.slice(0, 8)}…)
                          </span>
                        ) : null}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    {log.ip_address && (
                      <div className="flex items-center gap-1">
                        <Globe className="w-3 h-3 text-muted-foreground shrink-0" />
                        <span className="font-mono text-[10.5px] text-muted-foreground">{log.ip_address}</span>
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    {log.success ? (
                      <CircleCheck className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-red-400" />
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        {total > limit && (
          <div className="flex items-center justify-between px-3 py-2 border-t border-border bg-card/30">
            <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
              {offset + 1}–{Math.min(offset + limit, total)} of {total}
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => handlePageChange('prev')}
                disabled={offset === 0}
                className="h-7 w-7 p-0 border-border"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </Button>
              <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums px-2">
                {currentPage}/{totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handlePageChange('next')}
                disabled={offset + limit >= total}
                className="h-7 w-7 p-0 border-border"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Dialog */}
      <DetailSheet
        open={detailDialogOpen}
        onOpenChange={setDetailDialogOpen}
        size="md"
        breadcrumb={['Settings', 'Audit log']}
        icon={<FileText className="w-4 h-4 text-primary" strokeWidth={1.5} />}
        title="Audit Event"
        meta={
          selectedLog && (
            <>
              <span title="Event ID">{selectedLog.id}</span>
              <span title="Timestamp">{formatUTC(selectedLog.timestamp)}</span>
              <span title="Actor">{auditActorLabel(selectedLog)}</span>
            </>
          )
        }
      >
        {selectedLog && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-[11px] text-muted-foreground mb-0.5">Timestamp</p>
                <p className="font-mono text-[11px] text-foreground">{formatUTC(selectedLog.timestamp)}</p>
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-0.5">Status</p>
                <p className="flex items-center gap-1.5">
                  {selectedLog.success ? (
                    <>
                      <CircleCheck className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-[11px] text-emerald-400">Success</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3.5 h-3.5 text-red-400" />
                      <span className="text-[11px] text-red-400">Failed</span>
                    </>
                  )}
                </p>
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-0.5">Actor</p>
                <p className="font-mono text-[11px] text-foreground">{auditActorLabel(selectedLog)}</p>
              </div>
              {(selectedLog.api_key_name || selectedLog.api_key_id) && (
                <div>
                  <p className="text-[11px] text-muted-foreground mb-0.5">API key</p>
                  <p className="font-mono text-[11px] text-foreground">
                    {selectedLog.api_key_name || selectedLog.api_key_id}
                    {selectedLog.api_key_name && selectedLog.api_key_id && (
                      <span className="text-muted-foreground"> · {selectedLog.api_key_id}</span>
                    )}
                  </p>
                </div>
              )}
              {selectedLog.source && (
                <div>
                  <p className="text-[11px] text-muted-foreground mb-0.5">Source</p>
                  <p className="font-mono text-[11px] text-foreground uppercase">{selectedLog.source}</p>
                </div>
              )}
            </div>
            {selectedLog.action && (
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Action</p>
                <span className={cn('font-mono text-[10px] font-semibold tracking-[0.08em] uppercase px-1.5 py-0.5 rounded border', getActionTone(selectedLog.action))}>
                  {formatAction(selectedLog.action)}
                </span>
              </div>
            )}
            {selectedLog.resource_type && (
              <div>
                <p className="text-[11px] text-muted-foreground mb-0.5">Resource</p>
                <p className="text-[11px] text-foreground">
                  {selectedLog.resource_type}
                  {selectedLog.resource_name && (
                    <span className="font-mono ml-2">{selectedLog.resource_name}</span>
                  )}
                  {selectedLog.resource_id && (
                    <span className="font-mono text-[10px] text-muted-foreground ml-2">
                      {selectedLog.resource_id}
                    </span>
                  )}
                </p>
              </div>
            )}
            {selectedLog.ip_address && (
              <div>
                <p className="text-[11px] text-muted-foreground mb-0.5">IP Address</p>
                <p className="font-mono text-[11px] text-foreground">{selectedLog.ip_address}</p>
              </div>
            )}
            {selectedLog.message && (
              <div>
                <p className="text-[11px] text-muted-foreground mb-0.5">Message</p>
                <p className="text-[11.5px] text-foreground">{selectedLog.message}</p>
              </div>
            )}
            {selectedLog.details && Object.keys(selectedLog.details).length > 0 && (
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Details</p>
                <pre className="p-3 bg-muted/20 rounded-md border border-border font-mono text-[10.5px] text-foreground overflow-x-auto">
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </DetailSheet>
    </div>
  );
}


// Standalone page wrapper for backward compatibility
export function AuditLogPage() {
  return (
    <div className="px-6 py-5">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-[18px] font-semibold tracking-tight text-foreground">Audit Log</h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            Platform audit events — authentication, detection, configuration, management
          </p>
        </div>
      </div>
      <AuditLogContent />
    </div>
  );
}
