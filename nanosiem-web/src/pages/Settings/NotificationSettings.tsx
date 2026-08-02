// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Notification channels (NAN-1790)
 *
 * Unified surface for outbound alert notifications. Absorbs the legacy generic
 * webhooks page: every channel — Slack, Teams, PagerDuty, and generic signed
 * JSON — is a row on the same delivery spine (SSRF-pinned, retried, logged).
 * Density: 11-13px body, mono for IDs / URLs / severities / timestamps, 1px
 * borders, no shadows.
 */

import { useState, useEffect, useCallback } from 'react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
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
  Bell,
  Plus,
  Trash2,
  Send,
  Loader2,
  CircleCheck,
  XCircle,
  List,
  FileText,
  AlertTriangle,
  Link2,
  Pencil,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type {
  WebhookConfig,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  WebhookDeliveryLog,
  ChannelType,
  NotificationConfig,
} from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { formatUTC } from '@/lib/date-utils';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'informational'];

const EVENT_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: 'siem_alert', label: 'SIEM alerts' },
  { value: 'obs_alert', label: 'Observability alerts' },
  { value: 'case', label: 'Cases' },
  { value: 'report', label: 'Scheduled reports' },
  { value: 'system_health', label: 'System health' },
];
const EVENT_TYPE_LABEL: Record<string, string> = Object.fromEntries(
  EVENT_TYPE_OPTIONS.map(o => [o.value, o.label]),
);
const DEFAULT_EVENT_TYPES = ['siem_alert', 'obs_alert'];
const HEALTH_CATEGORY_OPTIONS = [
  'integration', 'enrichment', 'log_source', 'ingestion', 'parser',
  'storage', 'query', 'credential', 'service',
];

interface ChannelTypeMeta {
  value: ChannelType;
  label: string;
  blurb: string;
  disabled?: boolean;
}

const CHANNEL_TYPES: ChannelTypeMeta[] = [
  { value: 'slack', label: 'Slack', blurb: 'Incoming webhook · Block Kit' },
  { value: 'teams', label: 'Teams', blurb: 'Incoming webhook · Adaptive Card' },
  { value: 'pagerduty', label: 'PagerDuty', blurb: 'Events API v2 · routing key' },
  { value: 'generic', label: 'Generic', blurb: 'HMAC-signed JSON POST' },
  { value: 'email', label: 'Email', blurb: 'SMTP · coming soon', disabled: true },
];
const CHANNEL_LABEL: Record<ChannelType, string> = {
  slack: 'Slack',
  teams: 'Teams',
  pagerduty: 'PagerDuty',
  generic: 'Generic',
  email: 'Email',
};
const CHANNEL_BADGE: Record<ChannelType, string> = {
  slack: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  teams: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  pagerduty: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  generic: 'bg-muted/40 text-muted-foreground border-border',
  email: 'bg-muted/40 text-muted-foreground border-border',
};

interface HeaderRow {
  id: number;
  key: string;
  value: string;
}

let nextHeaderId = 0;

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  informational: 'bg-muted/40 text-muted-foreground border-border',
};

/** A readable, secret-safe destination label for the channel list.
 *  F-39: the full URL is never returned — render the non-secret `url_host`. */
function destinationLabel(w: WebhookConfig): string {
  if (w.channel_type === 'pagerduty') return 'PagerDuty Events API';
  if (w.url_host) return w.url_host;
  if (usesUrl(w.channel_type)) return w.has_url ? 'configured' : '—';
  return CHANNEL_LABEL[w.channel_type];
}

/** Whether the channel type collects a user-supplied destination URL. */
function usesUrl(t: ChannelType): boolean {
  return t === 'generic' || t === 'slack' || t === 'teams';
}

function urlLabel(t: ChannelType): string {
  switch (t) {
    case 'slack':
      return 'Slack incoming webhook URL';
    case 'teams':
      return 'Teams incoming webhook / workflow URL';
    default:
      return 'Endpoint URL';
  }
}

function urlPlaceholder(t: ChannelType): string {
  switch (t) {
    case 'slack':
      return 'https://hooks.slack.com/services/…';
    case 'teams':
      return 'https://…webhook.office.com/webhookb2/…';
    default:
      return 'https://example.com/hook';
  }
}

function NotificationSettings() {
  useDocumentTitle('Notifications - Settings');

  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [channels, setChannels] = useState<WebhookConfig[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<WebhookConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [deliveriesId, setDeliveriesId] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDeliveryLog[]>([]);
  const [loadingDeliveries, setLoadingDeliveries] = useState(false);

  // Deep-link base URL config
  const [config, setConfig] = useState<NotificationConfig | null>(null);
  const [editingBaseUrl, setEditingBaseUrl] = useState(false);
  const [baseUrlDraft, setBaseUrlDraft] = useState('');
  const [savingBaseUrl, setSavingBaseUrl] = useState(false);

  // Form state
  const [formType, setFormType] = useState<ChannelType>('slack');
  const [formName, setFormName] = useState('');
  const [formUrl, setFormUrl] = useState('');
  const [formHeaders, setFormHeaders] = useState<HeaderRow[]>([]);
  const [formSecret, setFormSecret] = useState('');
  const [formSeverityFilter, setFormSeverityFilter] = useState<string[]>([]);
  const [formEventTypes, setFormEventTypes] = useState<string[]>(DEFAULT_EVENT_TYPES);
  const [formRuleFilter, setFormRuleFilter] = useState('');
  const [formHealthCategories, setFormHealthCategories] = useState<string[]>([]);
  const [formHealthResources, setFormHealthResources] = useState('');
  const [formEnabled, setFormEnabled] = useState(true);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [data, cfg] = await Promise.all([
        api.webhooks.listWebhooks(),
        api.webhooks.getNotificationConfig().catch(() => null),
      ]);
      setChannels(data);
      setConfig(cfg);
    } catch {
      toast({ title: 'Error', description: 'Failed to load channels', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const openCreate = () => {
    setEditing(null);
    setFormType('slack');
    setFormName('');
    setFormUrl('');
    setFormHeaders([]);
    setFormSecret('');
    setFormSeverityFilter([]);
    setFormEventTypes(DEFAULT_EVENT_TYPES);
    setFormRuleFilter('');
    setFormHealthCategories([]);
    setFormHealthResources('');
    setFormEnabled(true);
    setDialogOpen(true);
  };

  const openEdit = (c: WebhookConfig) => {
    setEditing(c);
    setFormType(c.channel_type);
    setFormName(c.name);
    // F-39: the destination URL is write-only (never returned). Start blank like
    // the secret field; blank on save keeps the stored destination.
    setFormUrl('');
    setFormHeaders([]);
    setFormSecret('');
    setFormSeverityFilter(c.severity_filter || []);
    setFormEventTypes(c.event_types && c.event_types.length > 0 ? c.event_types : DEFAULT_EVENT_TYPES);
    setFormRuleFilter((c.rule_filter || []).join(', '));
    setFormHealthCategories(c.health_category_filter || []);
    setFormHealthResources((c.health_resource_filter || []).join(', '));
    setFormEnabled(c.enabled);
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!formName.trim()) {
      toast({ title: 'Validation Error', description: 'Name is required', variant: 'destructive' });
      return;
    }
    if (usesUrl(formType)) {
      // F-39: on edit the URL is write-only — blank means "keep the current
      // destination", so it's only required at create time. Validate format only
      // when the user actually typed a new value.
      if (!editing && !formUrl.trim()) {
        toast({ title: 'Validation Error', description: 'A destination URL is required', variant: 'destructive' });
        return;
      }
      if (formUrl.trim()) {
        try { new URL(formUrl); } catch {
          toast({ title: 'Validation Error', description: 'URL must be a valid HTTP or HTTPS URL', variant: 'destructive' });
          return;
        }
        if (!/^https?:\/\//i.test(formUrl)) {
          toast({ title: 'Validation Error', description: 'URL must start with http:// or https://', variant: 'destructive' });
          return;
        }
      }
    }
    if (formType === 'pagerduty' && !editing && !formSecret.trim()) {
      toast({ title: 'Validation Error', description: 'A PagerDuty routing key is required', variant: 'destructive' });
      return;
    }
    const incompleteHeaders = formHeaders.some(row =>
      (row.key.trim() && !row.value.trim()) || (!row.key.trim() && row.value.trim())
    );
    if (incompleteHeaders) {
      toast({ title: 'Validation Error', description: 'Header rows must have both a name and value', variant: 'destructive' });
      return;
    }

    const ruleFilter = formRuleFilter
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    const healthResources = formHealthResources
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(Boolean);

    setSaving(true);
    try {
      const headersMap: Record<string, string> = {};
      for (const row of formHeaders) {
        if (row.key.trim()) headersMap[row.key.trim()] = row.value;
      }

      if (editing) {
        const request: UpdateWebhookRequest = {
          name: formName,
          channel_type: formType,
          severity_filter: formSeverityFilter.length > 0 ? formSeverityFilter : undefined,
          event_types: formEventTypes,
          rule_filter: ruleFilter,
          health_category_filter: formHealthCategories,
          health_resource_filter: healthResources,
          enabled: formEnabled,
        };
        // F-39: only send the URL when the user typed a new one; blank keeps the
        // stored destination (like the secret field).
        if (usesUrl(formType) && formUrl.trim()) request.url = formUrl;
        if (formType === 'generic' && formHeaders.length > 0) request.headers = headersMap;
        if (formSecret) request.secret = formSecret;
        await api.webhooks.updateWebhook(editing.id, request);
        toast({ title: 'Channel updated' });
      } else {
        const request: CreateWebhookRequest = {
          name: formName,
          url: usesUrl(formType) ? formUrl : '',
          channel_type: formType,
          severity_filter: formSeverityFilter.length > 0 ? formSeverityFilter : undefined,
          event_types: formEventTypes,
          rule_filter: ruleFilter.length > 0 ? ruleFilter : undefined,
          health_category_filter: formHealthCategories.length > 0 ? formHealthCategories : undefined,
          health_resource_filter: healthResources.length > 0 ? healthResources : undefined,
          enabled: formEnabled,
        };
        if (formType === 'generic' && Object.keys(headersMap).length > 0) request.headers = headersMap;
        if (formSecret) request.secret = formSecret;
        await api.webhooks.createWebhook(request);
        toast({ title: 'Channel created' });
      }
      setDialogOpen(false);
      load();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save channel';
      toast({ title: 'Error', description: msg, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteId) return;
    try {
      await api.webhooks.deleteWebhook(deleteId);
      toast({ title: 'Channel deleted' });
      load();
    } catch {
      toast({ title: 'Error', description: 'Failed to delete channel', variant: 'destructive' });
    } finally {
      setDeleteId(null);
    }
  };

  const handleTest = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setTestingId(id);
    try {
      const result = await api.webhooks.testWebhook(id);
      if (result.success) {
        toast({ title: 'Test delivered', description: `Status ${result.status_code} in ${result.duration_ms}ms` });
      } else {
        toast({ title: 'Test failed', description: result.error || `Status ${result.status_code}`, variant: 'destructive' });
      }
    } catch {
      toast({ title: 'Error', description: 'Failed to send test', variant: 'destructive' });
    } finally {
      setTestingId(null);
    }
  };

  const handleToggle = async (c: WebhookConfig) => {
    try {
      await api.webhooks.updateWebhook(c.id, { enabled: !c.enabled });
      toast({ title: c.enabled ? 'Channel disabled' : 'Channel enabled' });
      load();
    } catch {
      toast({ title: 'Error', description: 'Failed to toggle channel', variant: 'destructive' });
    }
  };

  const openDeliveries = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeliveriesId(id);
    setLoadingDeliveries(true);
    try {
      const data = await api.webhooks.listDeliveries(id, 20);
      setDeliveries(data);
    } catch {
      setDeliveries([]);
    } finally {
      setLoadingDeliveries(false);
    }
  };

  const startEditBaseUrl = () => {
    setBaseUrlDraft(config?.base_url ?? '');
    setEditingBaseUrl(true);
  };

  const saveBaseUrl = async () => {
    setSavingBaseUrl(true);
    try {
      const updated = await api.webhooks.updateNotificationConfig({
        base_url: baseUrlDraft.trim() ? baseUrlDraft.trim() : null,
      });
      setConfig(updated);
      setEditingBaseUrl(false);
      toast({ title: 'Base URL updated' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to update base URL';
      toast({ title: 'Error', description: msg, variant: 'destructive' });
    } finally {
      setSavingBaseUrl(false);
    }
  };

  const addHeaderRow = () => setFormHeaders([...formHeaders, { id: ++nextHeaderId, key: '', value: '' }]);
  const removeHeaderRow = (index: number) => setFormHeaders(formHeaders.filter((_, i) => i !== index));
  const updateHeaderRow = (index: number, field: 'key' | 'value', val: string) => {
    const updated = [...formHeaders];
    updated[index] = { ...updated[index], [field]: val };
    setFormHeaders(updated);
  };
  const toggleSeverity = (severity: string) => {
    setFormSeverityFilter(prev => prev.includes(severity) ? prev.filter(s => s !== severity) : [...prev, severity]);
  };
  const toggleEventType = (eventType: string) => {
    setFormEventTypes(prev => {
      if (prev.includes(eventType)) {
        if (prev.length === 1) return prev; // backend rejects an empty set
        return prev.filter(t => t !== eventType);
      }
      return [...prev, eventType];
    });
  };
  const toggleHealthCategory = (category: string) => {
    setFormHealthCategories(prev => prev.includes(category)
      ? prev.filter(value => value !== category)
      : [...prev, category]);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const showUrlField = usesUrl(formType);
  const showSecretField = formType === 'generic' || formType === 'pagerduty';
  const secretLabel = formType === 'pagerduty' ? 'Routing key' : 'HMAC secret';
  const secretRequired = formType === 'pagerduty' && !editing;

  return (
    <div className="px-6 py-5 space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold tracking-tight text-foreground">Notifications</h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">Route alerts to Slack, Teams, PagerDuty, or a signed JSON endpoint</p>
        </div>
        <Button onClick={openCreate} size="sm" className="h-7 text-[11.5px] px-2.5 gap-1.5">
          <Plus className="w-3 h-3" />
          Add channel
        </Button>
      </div>

      {/* Deep-link base URL */}
      <div className="rounded-md border border-border bg-card/40 px-3 py-2.5">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <Link2 className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
            <div className="min-w-0">
              <div className="text-[11.5px] font-medium text-foreground">Deep link base URL</div>
              <div className="text-[10.5px] text-muted-foreground mt-0.5">
                Prepended to alert links in every notification.
              </div>
            </div>
          </div>
          {!editingBaseUrl && (
            <div className="flex items-center gap-2 shrink-0">
              <span className="font-mono text-[10.5px] text-muted-foreground truncate max-w-[280px]" title={config?.resolved_base_url ?? undefined}>
                {config?.resolved_base_url ?? 'not configured — links omitted'}
              </span>
              <Button variant="ghost" size="sm" onClick={startEditBaseUrl} className="h-6 text-[10.5px] px-1.5 gap-1">
                <Pencil className="w-3 h-3" />
                Edit
              </Button>
            </div>
          )}
        </div>
        {editingBaseUrl && (
          <div className="flex items-center gap-2 mt-2.5">
            <Input
              value={baseUrlDraft}
              onChange={e => setBaseUrlDraft(e.target.value)}
              placeholder="https://nano.example.com"
              className="h-7 text-[11.5px] font-mono flex-1"
            />
            <Button onClick={saveBaseUrl} disabled={savingBaseUrl} size="sm" className="h-7 text-[11px] px-2.5">
              {savingBaseUrl && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
              Save
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setEditingBaseUrl(false)} className="h-7 text-[11px] px-2.5">
              Cancel
            </Button>
          </div>
        )}
      </div>

      {/* Channel list */}
      {channels.length === 0 ? (
        <div className="rounded-md border border-border bg-card/40 px-4 py-10 text-center">
          <Bell className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" />
          <p className="text-[12.5px] text-foreground font-medium">No notification channels</p>
          <p className="text-[11.5px] text-muted-foreground mt-1">Add a channel to route alerts to Slack, Teams, PagerDuty, or a custom endpoint.</p>
          <Button onClick={openCreate} size="sm" className="h-7 text-[11.5px] px-2.5 mt-4 gap-1.5">
            <Plus className="w-3 h-3" />
            Add channel
          </Button>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-card/50">
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Name</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-24">Type</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Destination</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Severity</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Events</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-20">Status</th>
                <th className="text-right px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-32">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {channels.map(c => (
                <tr
                  key={c.id}
                  className="hover:bg-foreground/[0.025] cursor-pointer transition-colors group"
                  onClick={() => openEdit(c)}
                >
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      {!c.enabled && (
                        <AlertTriangle className="w-3 h-3 text-yellow-500 shrink-0" aria-label="Channel disabled" />
                      )}
                      <span className="text-[12.5px] font-medium text-foreground">{c.name}</span>
                      {c.rule_filter && c.rule_filter.length > 0 && (
                        <span className="font-mono text-[9.5px] text-muted-foreground border border-border rounded px-1 py-0.5" title={`Scoped to ${c.rule_filter.length} rule(s)`}>
                          {c.rule_filter.length} rule{c.rule_filter.length > 1 ? 's' : ''}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className={cn('font-mono text-[10px] font-semibold tracking-[0.08em] uppercase px-1.5 py-0.5 rounded border', CHANNEL_BADGE[c.channel_type])}>
                      {CHANNEL_LABEL[c.channel_type]}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-[10.5px] text-muted-foreground truncate max-w-[220px] block" title={destinationLabel(c)}>
                      {destinationLabel(c)}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    {c.severity_filter && c.severity_filter.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {c.severity_filter.map(s => (
                          <span key={s} className={cn('font-mono text-[10px] font-semibold tracking-[0.08em] uppercase px-1.5 py-0.5 rounded border', SEVERITY_COLOR[s] || SEVERITY_COLOR.informational)}>
                            {s}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-muted-foreground">All</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {c.event_types && c.event_types.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {c.event_types.map(t => (
                          <span key={t} className="text-[11px] text-muted-foreground border border-border rounded px-1.5 py-0.5">
                            {EVENT_TYPE_LABEL[t] || t}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={cn(
                        'font-mono text-[10px] font-semibold uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border w-fit inline-block',
                        c.enabled
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          : 'bg-muted/40 text-muted-foreground border-border',
                      )}
                    >
                      {c.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
                        onClick={(e) => handleTest(c.id, e)}
                        disabled={testingId === c.id}
                        title="Send test"
                      >
                        {testingId === c.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
                        onClick={(e) => openDeliveries(c.id, e)}
                        title="Delivery log"
                      >
                        <List className="w-3.5 h-3.5" />
                      </Button>
                      <Switch
                        checked={c.enabled}
                        onCheckedChange={() => handleToggle(c)}
                        className="h-4 w-7"
                        aria-label={c.enabled ? 'Disable channel' : 'Enable channel'}
                      />
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                        onClick={(e) => { e.stopPropagation(); setDeleteId(c.id); }}
                        title="Delete"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
      )}

      {/* Create/Edit Sheet */}
      <Sheet open={dialogOpen} onOpenChange={setDialogOpen}>
        <SheetContent className="w-[520px] overflow-y-auto border-l border-border bg-card px-0 sm:w-[560px]">
          <SheetHeader className="border-b border-border px-5 pb-3 pt-4 space-y-0">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
              Notification channel
            </div>
            <SheetTitle className="text-[14px] font-semibold text-foreground flex items-center gap-2">
              <Bell className="w-[14px] h-[14px] text-primary" />
              {editing ? 'Edit channel' : 'New channel'}
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              Provider-formatted delivery on the shared spine: SSRF-guarded, retried, and logged.
            </SheetDescription>
          </SheetHeader>

          <div className="px-5 py-4 flex flex-col gap-4">
            {/* Channel type */}
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Channel type</label>
              <div className="grid grid-cols-2 gap-1.5">
                {CHANNEL_TYPES.map(({ value, label, blurb, disabled }) => (
                  <button
                    key={value}
                    type="button"
                    disabled={disabled || (!!editing && editing.channel_type !== value)}
                    onClick={() => setFormType(value)}
                    className={cn(
                      'flex flex-col items-start gap-0.5 rounded-md border px-2.5 py-2 text-left transition-colors',
                      formType === value
                        ? 'border-primary bg-primary/10'
                        : 'border-border bg-card hover:bg-foreground/5',
                      (disabled || (!!editing && editing.channel_type !== value)) && 'opacity-40 cursor-not-allowed',
                    )}
                  >
                    <span className="text-[12px] font-medium text-foreground">{label}</span>
                    <span className="text-[10px] text-muted-foreground">{blurb}</span>
                  </button>
                ))}
              </div>
              {editing && (
                <p className="text-[10.5px] text-muted-foreground mt-1.5">
                  Channel type can't be changed after creation.
                </p>
              )}
            </div>

            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Name</label>
              <Input
                value={formName}
                onChange={e => setFormName(e.target.value)}
                placeholder="e.g. SOC on-call"
                className="h-8 text-[12px]"
              />
            </div>

            {showUrlField && (
              <div>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">{urlLabel(formType)}</label>
                <Input
                  value={formUrl}
                  onChange={e => setFormUrl(e.target.value)}
                  placeholder={editing ? '(configured — enter new to replace)' : urlPlaceholder(formType)}
                  className="h-8 text-[12px] font-mono"
                />
                {editing && (
                  <p className="text-[10.5px] text-muted-foreground mt-1">
                    Leave blank to keep the current destination{editing.url_host ? ` (${editing.url_host})` : ''}.
                  </p>
                )}
              </div>
            )}

            {formType === 'pagerduty' && (
              <p className="text-[10.5px] text-muted-foreground -mt-1">
                Events are enqueued to <span className="font-mono">events.pagerduty.com/v2/enqueue</span> with dedup key = alert id.
              </p>
            )}

            {formType === 'generic' && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-[11px] font-medium text-foreground/80">
                    Custom headers <span className="text-muted-foreground/70 font-normal ml-1">(optional)</span>
                  </label>
                  <Button variant="ghost" size="sm" onClick={addHeaderRow} className="h-6 text-[10.5px] px-2">
                    <Plus className="w-[11px] h-[11px] mr-0.5" />
                    Add
                  </Button>
                </div>
                {formHeaders.length > 0 && (
                  <div className="flex flex-col gap-1.5">
                    {formHeaders.map((row, i) => (
                      <div key={row.id} className="flex items-center gap-2">
                        <Input value={row.key} onChange={e => updateHeaderRow(i, 'key', e.target.value)} placeholder="Header" className="h-7 text-[11.5px] font-mono flex-1" />
                        <Input value={row.value} onChange={e => updateHeaderRow(i, 'value', e.target.value)} placeholder="Value" className="h-7 text-[11.5px] font-mono flex-1" />
                        <Button variant="ghost" size="icon" onClick={() => removeHeaderRow(i)} className="h-7 w-7 shrink-0">
                          <Trash2 className="w-[12px] h-[12px]" />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
                {editing?.has_headers && formHeaders.length === 0 && (
                  <p className="text-[10.5px] text-muted-foreground mt-1">Custom headers are configured. Add rows to replace them.</p>
                )}
              </div>
            )}

            {showSecretField && (
              <div>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                  {secretLabel} {secretRequired ? <span className="text-red-400 font-normal ml-1">(required)</span> : <span className="text-muted-foreground/70 font-normal ml-1">(optional)</span>}
                </label>
                <Input
                  type="password"
                  value={formSecret}
                  onChange={e => setFormSecret(e.target.value)}
                  placeholder={editing?.has_secret ? '(configured — enter new to replace)' : (formType === 'pagerduty' ? 'Integration routing key' : 'Signing secret')}
                  className="h-8 text-[12px] font-mono"
                />
                {formType === 'generic' && (
                  <p className="text-[10.5px] text-muted-foreground mt-1">
                    Signs the body with an <span className="font-mono">X-NanoSIEM-Signature</span> header.
                  </p>
                )}
              </div>
            )}

            {/* Routing */}
            <div className="pt-1 border-t border-border/60" />
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                Event types <span className="text-muted-foreground/70 font-normal ml-1">(at least one)</span>
              </label>
              <div className="flex flex-wrap gap-1.5">
                {EVENT_TYPE_OPTIONS.map(({ value, label }) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => toggleEventType(value)}
                    className={cn(
                      'h-6 rounded-sm border px-2 text-[11px] font-medium transition-colors',
                      formEventTypes.includes(value)
                        ? 'border-primary bg-primary/15 text-primary'
                        : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-foreground/5',
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {formEventTypes.includes('system_health') && (
              <div className="space-y-3 rounded-md border border-border bg-card/40 p-3">
                <div>
                  <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                    Health categories <span className="text-muted-foreground/70 font-normal ml-1">(empty = all)</span>
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    {HEALTH_CATEGORY_OPTIONS.map(category => (
                      <button
                        key={category}
                        type="button"
                        onClick={() => toggleHealthCategory(category)}
                        className={cn(
                          'h-6 rounded-sm border px-2 font-mono text-[10px] transition-colors',
                          formHealthCategories.includes(category)
                            ? 'border-primary bg-primary/15 text-primary'
                            : 'border-border bg-card text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
                        )}
                      >
                        {category}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                    Health resource types <span className="text-muted-foreground/70 font-normal ml-1">(optional)</span>
                  </label>
                  <Input
                    value={formHealthResources}
                    onChange={e => setFormHealthResources(e.target.value)}
                    placeholder="integration, enrichment, log_source"
                    className="h-8 text-[11.5px] font-mono"
                  />
                  <p className="text-[10.5px] text-muted-foreground mt-1">
                    Route only matching resource types. Leave empty to receive every selected health category.
                  </p>
                </div>
              </div>
            )}

            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                Severity filter <span className="text-muted-foreground/70 font-normal ml-1">(empty = all)</span>
              </label>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITY_OPTIONS.map(s => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => toggleSeverity(s)}
                    className={cn(
                      'h-6 rounded-sm border px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] transition-colors',
                      formSeverityFilter.includes(s)
                        ? SEVERITY_COLOR[s] || 'border-primary bg-primary/15 text-primary'
                        : 'border-border bg-card text-muted-foreground hover:text-foreground hover:bg-foreground/5',
                    )}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                Detection rule filter <span className="text-muted-foreground/70 font-normal ml-1">(optional)</span>
              </label>
              <Input
                value={formRuleFilter}
                onChange={e => setFormRuleFilter(e.target.value)}
                placeholder="rule_… ids, comma-separated (empty = all rules)"
                className="h-8 text-[11.5px] font-mono"
              />
              <p className="text-[10.5px] text-muted-foreground mt-1">
                Restrict this channel to alerts from specific detection rules.
              </p>
            </div>

            <div className="flex items-center justify-between gap-3 pt-1">
              <div>
                <label className="text-[11.5px] font-medium text-foreground">Enabled</label>
                <p className="text-[10.5px] text-muted-foreground mt-0.5">Disabled channels don't fire but their config is kept.</p>
              </div>
              <Switch checked={formEnabled} onCheckedChange={setFormEnabled} className="h-4 w-7" />
            </div>
          </div>

          <SheetFooter className="border-t border-border px-5 py-3 flex sm:justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setDialogOpen(false)} className="h-7 text-[11.5px] px-2.5">Cancel</Button>
            <Button onClick={handleSave} disabled={saving} size="sm" className="h-7 text-[11.5px] px-2.5">
              {saving && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
              {editing ? 'Save changes' : 'Create channel'}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      {/* Deliveries Sheet */}
      <Sheet open={!!deliveriesId} onOpenChange={() => setDeliveriesId(null)}>
        <SheetContent className="w-[520px] overflow-y-auto border-l border-border bg-card px-0 sm:w-[600px]">
          <SheetHeader className="border-b border-border px-5 pb-3 pt-4 space-y-0">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">Channel</div>
            <SheetTitle className="text-[14px] font-semibold text-foreground tracking-tight flex items-center gap-2">
              <FileText className="w-[14px] h-[14px] text-primary" />
              Delivery log
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">Last 20 outbound delivery attempts — newest first.</SheetDescription>
          </SheetHeader>
          {loadingDeliveries ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : deliveries.length === 0 ? (
            <div className="px-5 py-12 text-center">
              <FileText className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" />
              <p className="text-[12.5px] text-foreground font-medium">No deliveries yet</p>
              <p className="text-[11.5px] text-muted-foreground mt-1">The first attempt will appear here within seconds.</p>
            </div>
          ) : (
            <div className="flex flex-col">
              <div className="grid grid-cols-[20px_minmax(0,1fr)_60px_60px_minmax(120px,auto)] gap-2 px-5 py-1.5 border-b border-border bg-card/50 text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">
                <div></div>
                <div>Event</div>
                <div className="text-right">Status</div>
                <div className="text-right">Latency</div>
                <div className="text-right">Time</div>
              </div>
              {deliveries.map((d) => (
                <div key={d.id} className="grid grid-cols-[20px_minmax(0,1fr)_60px_60px_minmax(120px,auto)] gap-2 items-center px-5 py-2 border-b border-border/60 hover:bg-foreground/[0.025] transition-colors">
                  {d.success ? (
                    <CircleCheck className="w-3.5 h-3.5 text-emerald-400" aria-label="Delivered successfully" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5 text-red-400" aria-label="Delivery failed" />
                  )}
                  <div className="min-w-0">
                    <div className="font-mono text-[10.5px] text-foreground truncate">{d.event_type}</div>
                    {d.error_message && (
                      <div className="text-[10.5px] text-red-400 truncate mt-0.5" title={d.error_message}>{d.error_message}</div>
                    )}
                  </div>
                  <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums text-right">{d.status_code ?? '—'}</span>
                  <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums text-right">{d.duration_ms != null ? `${d.duration_ms}ms` : '—'}</span>
                  <span className="font-mono text-[10.5px] text-muted-foreground text-right">{formatUTC(d.delivered_at)}</span>
                </div>
              ))}
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <AlertDialogContent className="bg-card border-border gap-0 p-0 max-w-md">
          <AlertDialogHeader className="border-b border-border px-5 py-4">
            <AlertDialogTitle className="text-[14px] font-semibold text-foreground tracking-tight">Delete channel</AlertDialogTitle>
            <AlertDialogDescription className="text-[11.5px] text-muted-foreground mt-1">
              Are you sure you want to delete this channel? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="border-t border-border px-5 py-3">
            <AlertDialogCancel className="h-7 text-[11.5px] px-2.5 border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} className="h-7 text-[11.5px] px-2.5 bg-red-600 hover:bg-red-700">Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export { NotificationSettings };
export default NotificationSettings;
