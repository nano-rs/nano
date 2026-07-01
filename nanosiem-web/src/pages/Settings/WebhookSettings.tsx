// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Webhook Settings
 *
 * Density pass (NAN-543): list layout instead of card grid,
 * redesign density — no shadows, no rounded-2xl, 11-12px body.
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
  Webhook,
  Plus,
  Trash2,
  Send,
  Loader2,
  CircleCheck,
  XCircle,
  List,
  FileText,
  AlertTriangle,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type {
  WebhookConfig,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  WebhookDeliveryLog,
} from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { formatUTC } from '@/lib/date-utils';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'informational'];

const EVENT_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: 'siem_alert', label: 'SIEM alerts' },
  { value: 'obs_alert', label: 'Observability alerts' },
  { value: 'case', label: 'Cases' },
];
const EVENT_TYPE_LABEL: Record<string, string> = Object.fromEntries(
  EVENT_TYPE_OPTIONS.map(o => [o.value, o.label]),
);
const DEFAULT_EVENT_TYPES = ['siem_alert', 'obs_alert'];

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

function WebhookSettings() {
  useDocumentTitle('Webhooks - Settings');

  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<WebhookConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [deliveriesWebhookId, setDeliveriesWebhookId] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDeliveryLog[]>([]);
  const [loadingDeliveries, setLoadingDeliveries] = useState(false);

  // Form state
  const [formName, setFormName] = useState('');
  const [formUrl, setFormUrl] = useState('');
  const [formHeaders, setFormHeaders] = useState<HeaderRow[]>([]);
  const [formSecret, setFormSecret] = useState('');
  const [formSeverityFilter, setFormSeverityFilter] = useState<string[]>([]);
  const [formEventTypes, setFormEventTypes] = useState<string[]>(DEFAULT_EVENT_TYPES);
  const [formEnabled, setFormEnabled] = useState(true);

  const loadWebhooks = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.webhooks.listWebhooks();
      setWebhooks(data);
    } catch {
      toast({ title: 'Error', description: 'Failed to load webhooks', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { loadWebhooks(); }, [loadWebhooks]);

  const openCreateDialog = () => {
    setEditingWebhook(null);
    setFormName('');
    setFormUrl('');
    setFormHeaders([]);
    setFormSecret('');
    setFormSeverityFilter([]);
    setFormEventTypes(DEFAULT_EVENT_TYPES);
    setFormEnabled(true);
    setDialogOpen(true);
  };

  const openEditDialog = (webhook: WebhookConfig) => {
    setEditingWebhook(webhook);
    setFormName(webhook.name);
    setFormUrl(webhook.url);
    setFormHeaders([]);
    setFormSecret('');
    setFormSeverityFilter(webhook.severity_filter || []);
    setFormEventTypes(
      webhook.event_types && webhook.event_types.length > 0
        ? webhook.event_types
        : DEFAULT_EVENT_TYPES,
    );
    setFormEnabled(webhook.enabled);
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!formName.trim()) {
      toast({ title: 'Validation Error', description: 'Name is required', variant: 'destructive' });
      return;
    }
    if (!formUrl.trim()) {
      toast({ title: 'Validation Error', description: 'URL is required', variant: 'destructive' });
      return;
    }
    try { new URL(formUrl); } catch {
      toast({ title: 'Validation Error', description: 'URL must be a valid HTTP or HTTPS URL', variant: 'destructive' });
      return;
    }
    if (!/^https?:\/\//i.test(formUrl)) {
      toast({ title: 'Validation Error', description: 'URL must start with http:// or https://', variant: 'destructive' });
      return;
    }
    const incompleteHeaders = formHeaders.some(row =>
      (row.key.trim() && !row.value.trim()) || (!row.key.trim() && row.value.trim())
    );
    if (incompleteHeaders) {
      toast({ title: 'Validation Error', description: 'Header rows must have both a name and value', variant: 'destructive' });
      return;
    }

    setSaving(true);
    try {
      const headersMap: Record<string, string> = {};
      for (const row of formHeaders) {
        if (row.key.trim()) headersMap[row.key.trim()] = row.value;
      }

      if (editingWebhook) {
        const request: UpdateWebhookRequest = {
          name: formName,
          url: formUrl,
          severity_filter: formSeverityFilter.length > 0 ? formSeverityFilter : undefined,
          event_types: formEventTypes,
          enabled: formEnabled,
        };
        if (formHeaders.length > 0) request.headers = headersMap;
        if (formSecret) request.secret = formSecret;
        await api.webhooks.updateWebhook(editingWebhook.id, request);
        toast({ title: 'Webhook updated' });
      } else {
        const request: CreateWebhookRequest = {
          name: formName,
          url: formUrl,
          headers: Object.keys(headersMap).length > 0 ? headersMap : undefined,
          secret: formSecret || undefined,
          severity_filter: formSeverityFilter.length > 0 ? formSeverityFilter : undefined,
          event_types: formEventTypes,
          enabled: formEnabled,
        };
        await api.webhooks.createWebhook(request);
        toast({ title: 'Webhook created' });
      }
      setDialogOpen(false);
      loadWebhooks();
    } catch {
      toast({ title: 'Error', description: 'Failed to save webhook', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteId) return;
    try {
      await api.webhooks.deleteWebhook(deleteId);
      toast({ title: 'Webhook deleted' });
      loadWebhooks();
    } catch {
      toast({ title: 'Error', description: 'Failed to delete webhook', variant: 'destructive' });
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
        toast({ title: 'Test successful', description: `Status ${result.status_code} in ${result.duration_ms}ms` });
      } else {
        toast({ title: 'Test failed', description: result.error || `Status ${result.status_code}`, variant: 'destructive' });
      }
    } catch {
      toast({ title: 'Error', description: 'Failed to send test', variant: 'destructive' });
    } finally {
      setTestingId(null);
    }
  };

  const handleToggle = async (webhook: WebhookConfig) => {
    try {
      await api.webhooks.updateWebhook(webhook.id, { enabled: !webhook.enabled });
      toast({ title: webhook.enabled ? 'Webhook disabled' : 'Webhook enabled' });
      loadWebhooks();
    } catch {
      toast({ title: 'Error', description: 'Failed to toggle webhook', variant: 'destructive' });
    }
  };

  const openDeliveries = async (webhookId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeliveriesWebhookId(webhookId);
    setLoadingDeliveries(true);
    try {
      const data = await api.webhooks.listDeliveries(webhookId, 20);
      setDeliveries(data);
    } catch {
      setDeliveries([]);
    } finally {
      setLoadingDeliveries(false);
    }
  };

  const addHeaderRow = () => {
    setFormHeaders([...formHeaders, { id: ++nextHeaderId, key: '', value: '' }]);
  };
  const removeHeaderRow = (index: number) => {
    setFormHeaders(formHeaders.filter((_, i) => i !== index));
  };
  const updateHeaderRow = (index: number, field: 'key' | 'value', val: string) => {
    const updated = [...formHeaders];
    updated[index] = { ...updated[index], [field]: val };
    setFormHeaders(updated);
  };
  const toggleSeverity = (severity: string) => {
    setFormSeverityFilter(prev =>
      prev.includes(severity) ? prev.filter(s => s !== severity) : [...prev, severity]
    );
  };
  const toggleEventType = (eventType: string) => {
    setFormEventTypes(prev => {
      if (prev.includes(eventType)) {
        // At least one event stream must remain selected — backend rejects an empty set.
        if (prev.length === 1) return prev;
        return prev.filter(t => t !== eventType);
      }
      return [...prev, eventType];
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="px-6 py-5 space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold tracking-tight text-foreground">Webhooks</h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">Alert delivery endpoints — route events to external services</p>
        </div>
        <Button onClick={openCreateDialog} size="sm" className="h-7 text-[11.5px] px-2.5 gap-1.5">
          <Plus className="w-3 h-3" />
          Add webhook
        </Button>
      </div>

      {/* Webhook list */}
      {webhooks.length === 0 ? (
        <div className="rounded-md border border-border bg-card/40 px-4 py-10 text-center">
          <Webhook className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" />
          <p className="text-[12.5px] text-foreground font-medium">No webhooks configured</p>
          <p className="text-[11.5px] text-muted-foreground mt-1">Add a webhook to receive alert notifications at an external endpoint.</p>
          <Button onClick={openCreateDialog} size="sm" className="h-7 text-[11.5px] px-2.5 mt-4 gap-1.5">
            <Plus className="w-3 h-3" />
            Add webhook
          </Button>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-card/50">
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Name</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">URL</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Severity Filter</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Events</th>
                <th className="text-left px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-20">Status</th>
                <th className="text-right px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground w-32">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {webhooks.map(webhook => (
                <tr
                  key={webhook.id}
                  className="hover:bg-foreground/[0.025] cursor-pointer transition-colors group"
                  onClick={() => openEditDialog(webhook)}
                >
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      {!webhook.enabled && (
                        <AlertTriangle className="w-3 h-3 text-yellow-500 shrink-0" aria-label="Webhook disabled" />
                      )}
                      <span className="text-[12.5px] font-medium text-foreground">{webhook.name}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-[10.5px] text-muted-foreground truncate max-w-[220px] block" title={webhook.url}>
                      {webhook.url}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    {webhook.severity_filter && webhook.severity_filter.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {webhook.severity_filter.map(s => (
                          <span key={s} className={cn('font-mono text-[10px] font-semibold tracking-[0.08em] uppercase px-1.5 py-0.5 rounded border', SEVERITY_COLOR[s] || SEVERITY_COLOR.informational)}>
                            {s}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-muted-foreground">All severities</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {webhook.event_types && webhook.event_types.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {webhook.event_types.map(t => (
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
                        webhook.enabled
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          : 'bg-muted/40 text-muted-foreground border-border',
                      )}
                    >
                      {webhook.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
                        onClick={(e) => handleTest(webhook.id, e)}
                        disabled={testingId === webhook.id}
                        title="Send test"
                      >
                        {testingId === webhook.id ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Send className="w-3.5 h-3.5" />
                        )}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
                        onClick={(e) => openDeliveries(webhook.id, e)}
                        title="Delivery log"
                      >
                        <List className="w-3.5 h-3.5" />
                      </Button>
                      <Switch
                        checked={webhook.enabled}
                        onCheckedChange={() => handleToggle(webhook)}
                        className="h-4 w-7"
                        aria-label={webhook.enabled ? 'Disable webhook' : 'Enable webhook'}
                      />
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                        onClick={(e) => { e.stopPropagation(); setDeleteId(webhook.id); }}
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
      )}

      {/* Create/Edit Sheet — right-side flyout matching Access Control / Queues. */}
      <Sheet open={dialogOpen} onOpenChange={setDialogOpen}>
        <SheetContent className="w-[520px] overflow-y-auto border-l border-border bg-card px-0 sm:w-[560px]">
          <SheetHeader className="border-b border-border px-5 pb-3 pt-4 space-y-0">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
              Webhook
            </div>
            <SheetTitle className="text-[14px] font-semibold text-foreground flex items-center gap-2">
              <Webhook className="w-[14px] h-[14px] text-primary" />
              {editingWebhook ? 'Edit webhook' : 'New webhook'}
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              Outbound HTTP delivery for cases, alerts, and rule changes. Optional HMAC signing,
              custom headers, and per-severity filtering.
            </SheetDescription>
          </SheetHeader>

          <div className="px-5 py-4 flex flex-col gap-4">
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Name</label>
              <Input
                value={formName}
                onChange={e => setFormName(e.target.value)}
                placeholder="e.g. Slack alerts"
                className="h-8 text-[12px]"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Endpoint URL</label>
              <Input
                value={formUrl}
                onChange={e => setFormUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/…"
                className="h-8 text-[12px] font-mono"
              />
            </div>

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
                      <Input
                        value={row.key}
                        onChange={e => updateHeaderRow(i, 'key', e.target.value)}
                        placeholder="Header"
                        className="h-7 text-[11.5px] font-mono flex-1"
                      />
                      <Input
                        value={row.value}
                        onChange={e => updateHeaderRow(i, 'value', e.target.value)}
                        placeholder="Value"
                        className="h-7 text-[11.5px] font-mono flex-1"
                      />
                      <Button variant="ghost" size="icon" onClick={() => removeHeaderRow(i)} className="h-7 w-7 shrink-0">
                        <Trash2 className="w-[12px] h-[12px]" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
              {editingWebhook?.has_headers && formHeaders.length === 0 && (
                <p className="text-[10.5px] text-muted-foreground mt-1">
                  Custom headers are already configured. Add rows here to replace them.
                </p>
              )}
            </div>

            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                HMAC secret <span className="text-muted-foreground/70 font-normal ml-1">(optional)</span>
              </label>
              <Input
                type="password"
                value={formSecret}
                onChange={e => setFormSecret(e.target.value)}
                placeholder={editingWebhook?.has_secret ? '(configured — enter new to replace)' : 'Signing secret'}
                className="h-8 text-[12px] font-mono"
              />
              <p className="text-[10.5px] text-muted-foreground mt-1">
                Used to sign request bodies with an <span className="font-mono">X-Webhook-Signature</span> header.
              </p>
            </div>

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

            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                Severity filter <span className="text-muted-foreground/70 font-normal ml-1">(empty = fire for all)</span>
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

            <div className="flex items-center justify-between gap-3 pt-1">
              <div>
                <label className="text-[11.5px] font-medium text-foreground">Enabled</label>
                <p className="text-[10.5px] text-muted-foreground mt-0.5">
                  Disabled webhooks don't fire but their config is preserved.
                </p>
              </div>
              <Switch checked={formEnabled} onCheckedChange={setFormEnabled} className="h-4 w-7" />
            </div>
          </div>

          <SheetFooter className="border-t border-border px-5 py-3 flex sm:justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setDialogOpen(false)}
              className="h-7 text-[11.5px] px-2.5"
            >
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={saving} size="sm" className="h-7 text-[11.5px] px-2.5">
              {saving && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
              {editingWebhook ? 'Save changes' : 'Create webhook'}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      {/* Deliveries Sheet */}
      <Sheet open={!!deliveriesWebhookId} onOpenChange={() => setDeliveriesWebhookId(null)}>
        <SheetContent className="w-[520px] overflow-y-auto border-l border-border bg-card px-0 sm:w-[600px]">
          <SheetHeader className="border-b border-border px-5 pb-3 pt-4 space-y-0">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">
              Webhook
            </div>
            <SheetTitle className="text-[14px] font-semibold text-foreground tracking-tight flex items-center gap-2">
              <FileText className="w-[14px] h-[14px] text-primary" />
              Delivery log
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              Last 20 outbound delivery attempts — newest first.
            </SheetDescription>
          </SheetHeader>
          {loadingDeliveries ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : deliveries.length === 0 ? (
            <div className="px-5 py-12 text-center">
              <FileText className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" />
              <p className="text-[12.5px] text-foreground font-medium">No deliveries yet</p>
              <p className="text-[11.5px] text-muted-foreground mt-1">
                The first attempt will appear here within seconds.
              </p>
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
                <div
                  key={d.id}
                  className="grid grid-cols-[20px_minmax(0,1fr)_60px_60px_minmax(120px,auto)] gap-2 items-center px-5 py-2 border-b border-border/60 hover:bg-foreground/[0.025] transition-colors"
                >
                  {d.success ? (
                    <CircleCheck
                      className="w-3.5 h-3.5 text-emerald-400"
                      aria-label="Delivered successfully"
                    />
                  ) : (
                    <XCircle
                      className="w-3.5 h-3.5 text-red-400"
                      aria-label="Delivery failed"
                    />
                  )}
                  <div className="min-w-0">
                    <div className="font-mono text-[10.5px] text-foreground truncate">{d.event_type}</div>
                    {d.error_message && (
                      <div className="text-[10.5px] text-red-400 truncate mt-0.5" title={d.error_message}>
                        {d.error_message}
                      </div>
                    )}
                  </div>
                  <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums text-right">
                    {d.status_code ?? '—'}
                  </span>
                  <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums text-right">
                    {d.duration_ms != null ? `${d.duration_ms}ms` : '—'}
                  </span>
                  <span className="font-mono text-[10.5px] text-muted-foreground text-right">
                    {formatUTC(d.delivered_at)}
                  </span>
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
            <AlertDialogTitle className="text-[14px] font-semibold text-foreground tracking-tight">
              Delete webhook
            </AlertDialogTitle>
            <AlertDialogDescription className="text-[11.5px] text-muted-foreground mt-1">
              Are you sure you want to delete this webhook? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="border-t border-border px-5 py-3">
            <AlertDialogCancel className="h-7 text-[11.5px] px-2.5 border-border">Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="h-7 text-[11.5px] px-2.5 bg-red-600 hover:bg-red-700"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export { WebhookSettings };
export default WebhookSettings;
