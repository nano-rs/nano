// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * API Keys — Access Control deep-dive (master/detail with reveal-once create).
 *
 * Mirrors `design-ref/shadcn/settings-keys.jsx`:
 *   • Master: 320px filterable key list with status pill, mono prefix, mono "used N ago".
 *   • Detail: header with prefix + created/expires, Edit / Rotate / Revoke actions;
 *     4-up meta; 14-day call-volume sparkline (`CallVolumeChart`); scopes chip strip;
 *     danger-zone revoke card.
 *   • Create dialog has reveal-once secret screen with Copy and "I've stored it."
 *   • Edit dialog (`EditApiKeyDialog`) changes name / description / scopes in place.
 *
 * Mockup features parked until backend support lands:
 *   • IP allowlist — `ApiKeySummary` has no `ip_ranges` field.
 */

import { useEffect, useMemo, useState } from 'react';
import {
  Search as SearchIcon,
  Plus,
  KeyRound,
  Copy,
  RefreshCw,
  AlertCircle,
  Check,
  Loader2,
  ShieldOff,
  Pencil,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import {
  api,
  type ApiKeySummary,
  type ApiKeyCreatedResponse,
  type PermissionInfo,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
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
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { formatUTC, formatRelativeCompact } from '@/lib/date-utils';
import { CreateApiKeyDialog } from './CreateApiKeyDialog';
import { EditApiKeyDialog } from './EditApiKeyDialog';
import { CallVolumeChart } from './CallVolumeChart';

type DerivedStatus = 'active' | 'expiring' | 'unused' | 'revoked';

const STATUS_PILL: Record<DerivedStatus, { label: string; cls: string }> = {
  active: { label: 'Active', cls: 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30' },
  expiring: { label: 'Expiring', cls: 'bg-yellow-500/12 text-yellow-500 border-yellow-500/30' },
  unused: { label: 'Unused', cls: 'bg-foreground/10 text-muted-foreground border-border' },
  revoked: { label: 'Revoked', cls: 'bg-red-500/12 text-red-500 border-red-500/30' },
};

function deriveStatus(k: ApiKeySummary): DerivedStatus {
  if (!k.enabled) return 'revoked';
  if (k.expires_at) {
    const expiresMs = new Date(k.expires_at).getTime();
    const days = (expiresMs - Date.now()) / 86_400_000;
    if (days < 14) return 'expiring';
  }
  if (!k.last_used_at) return 'unused';
  return 'active';
}

function StatusPill({ status }: { status: DerivedStatus }) {
  const def = STATUS_PILL[status];
  return (
    <span className={cn('inline-flex items-center h-5 px-1.5 rounded-sm border text-[10.5px] font-medium', def.cls)}>
      {def.label}
    </span>
  );
}

function Labeled({ label, mono, children }: { label: string; mono?: boolean; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">{label}</div>
      <div className={cn('text-[12px] text-foreground', mono && 'font-mono')}>{children}</div>
    </div>
  );
}

interface ApiKeyListItemProps {
  apiKey: ApiKeySummary;
  selected: boolean;
  onSelect: (id: string) => void;
}

function ApiKeyListItem({ apiKey, selected, onSelect }: ApiKeyListItemProps) {
  const status = deriveStatus(apiKey);
  return (
    <button
      onClick={() => onSelect(apiKey.id)}
      className={cn(
        'w-full text-left px-3 py-2.5 border-b border-border/60 flex items-start gap-2.5 transition-colors',
        selected ? 'bg-foreground/[0.04]' : 'hover:bg-foreground/[0.025]',
      )}
    >
      <div className="w-6 h-6 rounded-md bg-card border border-border flex items-center justify-center shrink-0">
        <KeyRound className="w-[12px] h-[12px] text-muted-foreground" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <div className="text-[12.5px] text-foreground font-medium truncate leading-tight">{apiKey.name}</div>
          <span className={cn(
            'inline-flex items-center h-4 px-1 rounded-sm border text-[9.5px] font-medium shrink-0',
            STATUS_PILL[status].cls,
          )}>
            {STATUS_PILL[status].label}
          </span>
        </div>
        <div className="font-mono text-[10.5px] text-muted-foreground truncate mt-0.5">{apiKey.key_prefix}…</div>
        <div className="flex items-center gap-2 mt-1 text-[10.5px] text-muted-foreground">
          <span className="font-mono">used {apiKey.last_used_at ? formatRelativeCompact(apiKey.last_used_at) : 'never'}</span>
          {apiKey.expires_at && (
            <>
              <span>·</span>
              <span className="font-mono">expires {formatRelativeCompact(apiKey.expires_at)}</span>
            </>
          )}
        </div>
      </div>
    </button>
  );
}

interface ApiKeyDetailProps {
  apiKey: ApiKeySummary;
  permissions: PermissionInfo[];
  onEdit: () => void;
  onRotate: () => void;
  onRevoke: () => void;
  onEnable: () => void;
  onDelete: () => void;
}

function ApiKeyDetail({ apiKey, permissions, onEdit, onRotate, onRevoke, onEnable, onDelete }: ApiKeyDetailProps) {
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('apikeys:edit');
  const canDelete = hasPermission('apikeys:delete');
  const status = deriveStatus(apiKey);

  const permissionMap = useMemo(() => new Map(permissions.map(p => [p.id, p])), [permissions]);

  return (
    <div className="flex-1 overflow-y-auto scrollbar-thin">
      <div className="px-6 pt-5 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-card border border-border flex items-center justify-center">
            <KeyRound className="w-[15px] h-[15px] text-muted-foreground" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <div className="text-[17px] font-semibold text-foreground tracking-tight leading-none">{apiKey.name}</div>
              <StatusPill status={status} />
            </div>
            <div className="flex items-center gap-2 mt-1.5 font-mono text-[11px] text-muted-foreground">
              <span>{apiKey.key_prefix}…</span>
              <button
                className="text-muted-foreground hover:text-foreground"
                title="Copy prefix"
                onClick={() => navigator.clipboard?.writeText(apiKey.key_prefix)}
              >
                <Copy className="w-[11px] h-[11px]" />
              </button>
              <span>·</span>
              <span>created {formatUTC(apiKey.created_at)}</span>
              {apiKey.expires_at && (
                <>
                  <span>·</span>
                  <span>expires {formatUTC(apiKey.expires_at)}</span>
                </>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {canEdit && (
              <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={onEdit}>
                <Pencil className="w-[11px] h-[11px] mr-1" />
                Edit
              </Button>
            )}
            {canEdit && apiKey.enabled && (
              <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={onRotate}>
                <RefreshCw className="w-[11px] h-[11px] mr-1" />
                Rotate
              </Button>
            )}
            {canEdit && (apiKey.enabled ? (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-[11.5px] px-2.5 text-yellow-500 hover:text-yellow-500/90"
                onClick={onRevoke}
              >
                <ShieldOff className="w-[11px] h-[11px] mr-1" />
                Revoke
              </Button>
            ) : (
              <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={onEnable}>
                Enable
              </Button>
            ))}
          </div>
        </div>
        {apiKey.description && (
          <div className="text-[12px] text-muted-foreground mt-2 max-w-[640px]">{apiKey.description}</div>
        )}
      </div>

      <div className="px-6 py-5 flex flex-col gap-6">
        <div className="grid grid-cols-4 gap-6">
          <Labeled label="Last used" mono>
            {apiKey.last_used_at ? formatUTC(apiKey.last_used_at) : '—'}
          </Labeled>
          <Labeled label="Rate limit" mono>
            {apiKey.rate_limit ? `${apiKey.rate_limit}/min` : '—'}
          </Labeled>
          <Labeled label="Created" mono>{formatUTC(apiKey.created_at)}</Labeled>
          <Labeled label="Expires" mono>{apiKey.expires_at ? formatUTC(apiKey.expires_at) : 'Never'}</Labeled>
        </div>

        <CallVolumeChart apiKeyId={apiKey.id} />

        {/* Scopes */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Scopes</div>
            <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{apiKey.permissions.length}</span>
          </div>
          {apiKey.permissions.length === 0 ? (
            <div className="text-[11.5px] text-muted-foreground">No scopes — this key cannot call any APIs.</div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {apiKey.permissions.map(p => {
                const info = permissionMap.get(p);
                return (
                  <span
                    key={p}
                    className="inline-flex items-center h-6 px-2 rounded-sm border border-border bg-card text-[11px] text-foreground/80 font-mono"
                    title={info?.description}
                  >
                    {p}
                  </span>
                );
              })}
            </div>
          )}
        </div>

        {/* Unused warning */}
        {status === 'unused' && (
          <div className="rounded-md border border-yellow-500/25 bg-yellow-500/5 p-3 flex items-center gap-3">
            <AlertCircle className="w-[13px] h-[13px] text-yellow-500 shrink-0" />
            <div className="flex-1 text-[11.5px] text-foreground/80">
              This key has never been used. Consider revoking it to reduce attack surface.
            </div>
          </div>
        )}

        {/* Danger zone */}
        {canDelete && (
          <div className="rounded-md border border-red-500/25 bg-red-500/5 p-3 flex items-center gap-3">
            <AlertCircle className="w-[13px] h-[13px] text-red-500 shrink-0" />
            <div className="flex-1 text-[11.5px] text-foreground/80">
              Deleting a key removes it permanently. Active sessions using it will fail their next request.
            </div>
            <button onClick={onDelete} className="text-[11px] text-red-500 hover:underline shrink-0">
              Delete key
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

interface RevealOnceCardProps {
  secret: ApiKeyCreatedResponse;
  onDismiss: () => void;
}

function RevealOnceCard({ secret, onDismiss }: RevealOnceCardProps) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="m-5 rounded-md border border-yellow-500/40 bg-yellow-500/5 p-4">
      <div className="flex items-start gap-3">
        <AlertCircle className="w-[14px] h-[14px] text-yellow-500 shrink-0 mt-0.5" />
        <div className="flex-1">
          <div className="text-[13px] font-medium text-foreground">New API key — copy it now</div>
          <div className="text-[11.5px] text-muted-foreground mt-1">
            This is the only time you'll see the full key. Store it somewhere safe; we don't keep a copy.
          </div>
          <div className="mt-3 rounded-md border border-border bg-card p-2 flex items-center gap-2 font-mono text-[11.5px] text-foreground break-all">
            <span className="flex-1">{secret.key}</span>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(secret.key);
                setCopied(true);
                setTimeout(() => setCopied(false), 1800);
              }}
              className="shrink-0 inline-flex items-center gap-1 text-[10.5px] text-primary hover:text-primary/90"
            >
              {copied ? <Check className="w-[11px] h-[11px]" /> : <Copy className="w-[11px] h-[11px]" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <Button size="sm" className="h-7 text-[11.5px] px-2.5" onClick={onDismiss}>
              I've stored it. Dismiss.
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function ApiKeysView() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('apikeys:create');

  const [keys, setKeys] = useState<ApiKeySummary[]>([]);
  const [permissions, setPermissions] = useState<PermissionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  const [createdSecret, setCreatedSecret] = useState<ApiKeyCreatedResponse | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<ApiKeySummary | null>(null);
  const [pendingDelete, setPendingDelete] = useState<ApiKeySummary | null>(null);
  const [pendingRotate, setPendingRotate] = useState<ApiKeySummary | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [keysRes, permsRes] = await Promise.all([
        api.listApiKeys(),
        api.listPermissions().catch(() => []),
      ]);
      setKeys(keysRes.api_keys);
      setPermissions(permsRes);
      if (!selectedId && keysRes.api_keys.length > 0) {
        setSelectedId(keysRes.api_keys[0].id);
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load API keys',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return keys;
    return keys.filter(k =>
      k.name.toLowerCase().includes(q)
      || k.key_prefix.toLowerCase().includes(q)
      || (k.description?.toLowerCase().includes(q) ?? false),
    );
  }, [query, keys]);

  const selected = keys.find(k => k.id === selectedId) || filtered[0] || null;

  const handleRevoke = async () => {
    if (!pendingRevoke) return;
    setActionLoading(true);
    try {
      await api.disableApiKey(pendingRevoke.id);
      toast({ title: 'Key revoked', description: `${pendingRevoke.name} can no longer call the API.` });
      setPendingRevoke(null);
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to revoke key',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  const handleEnable = async (k: ApiKeySummary) => {
    try {
      await api.enableApiKey(k.id);
      toast({ title: 'Key enabled', description: `${k.name} is active again.` });
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to enable key',
        variant: 'destructive',
      });
    }
  };

  const handleDelete = async () => {
    if (!pendingDelete) return;
    setActionLoading(true);
    try {
      await api.deleteApiKey(pendingDelete.id);
      toast({ title: 'Key deleted', description: `${pendingDelete.name} has been deleted.` });
      const remaining = keys.filter(k => k.id !== pendingDelete.id);
      setSelectedId(remaining[0]?.id || null);
      setPendingDelete(null);
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete key',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  const handleRotate = async () => {
    if (!pendingRotate) return;
    setActionLoading(true);
    try {
      const res = await api.resetApiKey(pendingRotate.id);
      setCreatedSecret(res);
      toast({ title: 'Key rotated', description: `New secret issued for ${pendingRotate.name}.` });
      setPendingRotate(null);
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to rotate key',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      {createdSecret && (
        <RevealOnceCard secret={createdSecret} onDismiss={() => setCreatedSecret(null)} />
      )}

      <div className="flex-1 flex min-h-0">
        <div
          className="w-[320px] shrink-0 flex flex-col border-r border-border"
          style={{ background: 'var(--panel)' }}
        >
          <div className="shrink-0 px-3 py-3 flex items-center gap-2 border-b border-border">
            <div className="h-7 flex-1 rounded-md border border-border bg-card flex items-center gap-2 px-2">
              <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Filter keys…"
                className="flex-1 bg-transparent outline-none text-[11.5px] text-foreground placeholder:text-muted-foreground/70"
              />
            </div>
            {canCreate && (
              <button
                onClick={() => setShowCreate(true)}
                className="h-7 w-7 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 flex items-center justify-center"
                title="New API key"
              >
                <Plus className="w-[12px] h-[12px]" />
              </button>
            )}
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-thin">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
              </div>
            ) : filtered.length === 0 ? (
              <div className="px-4 py-8 text-center text-[11.5px] text-muted-foreground">
                {keys.length === 0 ? 'No API keys yet.' : 'No keys match.'}
              </div>
            ) : (
              filtered.map(k => (
                <ApiKeyListItem
                  key={k.id}
                  apiKey={k}
                  selected={selected?.id === k.id}
                  onSelect={setSelectedId}
                />
              ))
            )}
          </div>
          <div className="shrink-0 h-8 px-3 border-t border-border flex items-center font-mono text-[10.5px] text-muted-foreground">
            {keys.length} keys · {keys.filter(k => !k.enabled).length} revoked
          </div>
        </div>

        {selected ? (
          <ApiKeyDetail
            apiKey={selected}
            permissions={permissions}
            onEdit={() => setShowEdit(true)}
            onRotate={() => setPendingRotate(selected)}
            onRevoke={() => setPendingRevoke(selected)}
            onEnable={() => handleEnable(selected)}
            onDelete={() => setPendingDelete(selected)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-[12px] text-muted-foreground">
            {loading ? null : 'Select a key.'}
          </div>
        )}
      </div>

      <CreateApiKeyDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        permissions={permissions}
        onCreated={async (res) => {
          setShowCreate(false);
          setCreatedSecret(res);
          await fetchAll();
        }}
      />

      {selected && (
        <EditApiKeyDialog
          open={showEdit}
          apiKey={selected}
          permissions={permissions}
          onClose={() => setShowEdit(false)}
          onSaved={async () => {
            setShowEdit(false);
            await fetchAll();
          }}
        />
      )}

      <ConfirmDialog
        open={!!pendingRevoke}
        onOpenChange={(open) => !open && setPendingRevoke(null)}
        variant="danger"
        title="Revoke API key"
        description={
          <>
            Revoke <span className="text-foreground font-medium">{pendingRevoke?.name}</span>? This
            is reversible — you can re-enable the key from its detail panel.
          </>
        }
        confirmLabel="Revoke"
        loadingLabel="Revoking…"
        loading={actionLoading}
        onConfirm={handleRevoke}
      />

      <ConfirmDialog
        open={!!pendingDelete}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        variant="danger"
        title="Delete API key"
        description={
          <>
            Permanently delete{' '}
            <span className="text-foreground font-medium">{pendingDelete?.name}</span>? This cannot
            be undone.
          </>
        }
        confirmLabel="Delete"
        loadingLabel="Deleting…"
        loading={actionLoading}
        onConfirm={handleDelete}
      />

      <AlertDialog open={!!pendingRotate} onOpenChange={(open) => !open && setPendingRotate(null)}>
        <AlertDialogContent className="max-w-[440px] p-0 gap-0 overflow-hidden">
          <AlertDialogHeader className="px-5 py-3.5 border-b border-border flex flex-row items-center gap-3 space-y-0">
            <div className="w-8 h-8 rounded-md bg-primary/12 text-primary flex items-center justify-center shrink-0">
              <RefreshCw className="w-[14px] h-[14px]" />
            </div>
            <div className="flex-1 min-w-0 text-left">
              <AlertDialogTitle className="text-[14px] font-semibold leading-none">Rotate API key</AlertDialogTitle>
              <AlertDialogDescription className="text-[11px] text-muted-foreground mt-1">
                Issues a new secret for this key.
              </AlertDialogDescription>
            </div>
          </AlertDialogHeader>
          <div className="px-5 py-4 text-[11.5px] text-foreground/80 leading-relaxed">
            A new secret will be issued for{' '}
            <span className="text-foreground font-medium">{pendingRotate?.name}</span>.
            {' '}The old secret stops working immediately. You'll see the new secret once — copy it before dismissing.
          </div>
          <AlertDialogFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
            <AlertDialogCancel className="h-7 text-[11.5px] mt-0">Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleRotate} disabled={actionLoading} className="h-7 text-[11.5px]">
              {actionLoading && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
              Rotate
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
