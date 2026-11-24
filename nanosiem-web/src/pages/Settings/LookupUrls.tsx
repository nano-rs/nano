// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Lookup URLs (NAN-5443) — the hosts `inputlookup url=...` may fetch from.
 *
 * Two lists feed the effective allowlist:
 *   • deployment — INPUTLOOKUP_ALLOWED_DOMAINS, set by the operator; shown
 *     read-only here.
 *   • settings   — added on this page, stored in PostgreSQL.
 * By default they are merged. INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED=true makes the
 * deployment list an override and this page read-only. An empty effective list
 * means any public host (the SSRF guard still blocks internal addresses).
 *
 * Read needs `settings:view`; add/remove needs `settings:system`. Every change
 * and every fetch is audited (host only).
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Lock, Plus, Trash2 } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type { LookupAllowlistSettings } from '@/lib/api/lookup-url-allowlist';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Term } from '@/components/ui/term';

interface Row {
  host: string;
  source: 'deployment' | 'settings';
  /** A settings row that the locked deployment list overrides. */
  ignored: boolean;
}

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

export function LookupUrls() {
  useDocumentTitle('Lookup URLs');
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canManage = hasPermission('settings:system');

  const [settings, setSettings] = useState<LookupAllowlistSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const [pendingRemove, setPendingRemove] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSettings(await api.lookupUrlAllowlist.get());
      setLoadError(null);
    } catch (err) {
      setLoadError(errorMessage(err, 'Could not load the lookup URL allowlist'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = useCallback(
    async (domains: string[], done: string) => {
      setSaving(true);
      try {
        setSettings(await api.lookupUrlAllowlist.update(domains));
        toast({ title: done });
        return true;
      } catch (err) {
        toast({ title: 'Not saved', description: errorMessage(err, 'Save failed'), variant: 'destructive' });
        return false;
      } finally {
        setSaving(false);
      }
    },
    [toast],
  );

  const rows: Row[] = useMemo(() => {
    if (!settings) return [];
    const out: Row[] = settings.deployment_domains.map((host) => ({ host, source: 'deployment', ignored: false }));
    for (const host of settings.domains) {
      out.push({ host, source: 'settings', ignored: settings.locked });
    }
    return out.sort((a, b) => a.host.localeCompare(b.host) || a.source.localeCompare(b.source));
  }, [settings]);

  const editable = canManage && !!settings && !settings.locked;

  const onAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    const host = draft.trim();
    if (!settings || !host) return;
    if (await save([...settings.domains, host], `Added ${host}`)) setDraft('');
  };

  const onConfirmRemove = async () => {
    if (!settings || !pendingRemove) return;
    const host = pendingRemove;
    if (await save(settings.domains.filter((d) => d !== host), `Removed ${host}`)) setPendingRemove(null);
  };

  return (
    <div className="h-full flex flex-col min-h-0">
      {/* Title + meta row (breadcrumb comes from the global Settings TopBar) */}
      <div className="shrink-0 px-6 pt-5 pb-3 border-b border-border">
        <h1 className="text-[18px] font-semibold tracking-tight text-foreground"><Term id="lookup-url-allowlist">Lookup URLs</Term></h1>
        <p className="text-[11.5px] text-muted-foreground mt-0.5">
          Web hosts a search may download a lookup table from with{' '}
          <span className="font-mono">inputlookup url=…</span>. Each host also allows its subdomains.
        </p>
        {settings && (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-2 font-mono text-[10.5px] text-muted-foreground">
            <span data-testid="lookup-mode">
              {settings.mode === 'allowlist'
                ? `allowlist · ${settings.effective.length} host${settings.effective.length === 1 ? '' : 's'}`
                : 'any public host'}
            </span>
            <span>{settings.domains.length}/{settings.max_domains} from settings</span>
            <span>{settings.deployment_domains.length} from deployment</span>
            <span>applies within {settings.refresh_interval_secs}s</span>
            {settings.locked && (
              <span className="inline-flex items-center gap-1 text-amber-500">
                <Lock className="w-[11px] h-[11px]" /> locked by deployment
              </span>
            )}
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-6 py-4 space-y-3 max-w-[880px]">
        {settings?.mode === 'any_public_host' && (
          <div className="border border-border rounded-md px-3 py-2 text-[11.5px] text-muted-foreground">
            No hosts listed, so lookups may reach any public host. Internal and private addresses stay blocked.
            Add a host to allow only the hosts on the list.
          </div>
        )}
        {settings?.locked && (
          <div className="border border-amber-500/40 rounded-md px-3 py-2 text-[11.5px] text-muted-foreground">
            This list is read-only. The install settings lock it (
            <span className="font-mono">INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED</span>), so only the hosts set at install apply.
          </div>
        )}

        {editable && (
          <form onSubmit={onAdd} className="flex items-center gap-2">
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="feeds.example.com"
              aria-label="Host to allow"
              className="h-7 flex-1 max-w-[360px] rounded-md border border-border bg-card px-2 font-mono text-[12px] outline-none focus:border-primary"
            />
            <button
              type="submit"
              disabled={saving || !draft.trim()}
              className="h-7 px-2.5 rounded-md bg-primary text-primary-foreground text-[12px] inline-flex items-center gap-1 disabled:opacity-50"
            >
              <Plus className="w-[12px] h-[12px]" /> Add host
            </button>
          </form>
        )}

        <div className="border border-border rounded-md">
          <div className="grid grid-cols-[1fr_120px_40px] h-7 items-center px-3 border-b border-border text-[10.5px] uppercase tracking-wide text-muted-foreground">
            <span>Host</span>
            <span>Source</span>
            <span />
          </div>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingIcon className="w-4 h-4 text-muted-foreground" />
            </div>
          ) : loadError ? (
            <div className="px-3 py-4 text-[12px] text-destructive">{loadError}</div>
          ) : rows.length === 0 ? (
            <div className="px-3 py-4 text-[12px] text-muted-foreground">No hosts listed.</div>
          ) : (
            rows.map((row) => (
              <div
                key={`${row.source}:${row.host}`}
                className="grid grid-cols-[1fr_120px_40px] h-7 items-center px-3 border-b border-border/60 last:border-b-0"
              >
                <span className={`font-mono text-[12px] truncate ${row.ignored ? 'text-muted-foreground line-through' : 'text-foreground'}`}>
                  {row.host}
                </span>
                <span className="font-mono text-[10.5px] text-muted-foreground">
                  {row.source}
                  {row.ignored ? ' · ignored' : ''}
                </span>
                <span className="flex justify-end">
                  {editable && row.source === 'settings' && (
                    <button
                      type="button"
                      onClick={() => setPendingRemove(row.host)}
                      className="text-muted-foreground hover:text-destructive"
                      aria-label={`Remove ${row.host}`}
                    >
                      <Trash2 className="w-[12px] h-[12px]" />
                    </button>
                  )}
                </span>
              </div>
            ))
          )}
        </div>

        <p className="text-[11px] text-muted-foreground">
          Changes and fetches go to the{' '}
          <Link to="/settings/audit" className="text-primary hover:underline"><Term id="audit-log" nested>audit log</Term></Link>, host only.
        </p>
      </div>

      <ConfirmDialog
        open={pendingRemove !== null}
        onOpenChange={(open) => { if (!open) setPendingRemove(null); }}
        title="Remove host"
        description={
          <>
            Lookups to <span className="font-mono">{pendingRemove}</span> and its subdomains will be refused
            {settings && settings.effective.length === 1 ? ', and with no hosts left any public host is allowed again' : ''}.
          </>
        }
        confirmLabel="Remove"
        variant="danger"
        loading={saving}
        onConfirm={() => { void onConfirmRemove(); }}
      />
    </div>
  );
}

export default LookupUrls;
