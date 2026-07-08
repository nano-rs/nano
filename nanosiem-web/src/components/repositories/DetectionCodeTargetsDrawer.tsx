// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-1745 — Detection-as-Code push targets.
//
// A push target is the customer's OWN detection-as-code GitHub repo. When
// nano's AI tuning produces a rule change it opens a Pull Request in that repo
// for review instead of mutating the rule in nano's DB — Git stays the source
// of truth. This is push-only; it is NOT a rule source (pull-only rule repos
// live on the same page but are a separate system).
//
// Reuses the SideDrawer shell + Field helper + dense input/button styling from
// RepoDrawers.tsx.

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  CircleAlert,
  CircleCheck,
  Eye,
  EyeOff,
  ExternalLink,
  GitPullRequest,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import type {
  DetectionCodeTarget,
  TestConnectionResult,
} from '@/lib/api/detection-code-targets';
import { useToast } from '@/hooks/use-toast';
import { Switch } from '@/components/ui/switch';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { SideDrawer, Field } from './RepoDrawers';

const DEFAULT_BASE_BRANCH = 'main';
const DEFAULT_PATH_TEMPLATE = 'detections/{rule_name}.yaml';

const INPUT_CLS =
  'w-full h-[30px] px-2.5 rounded-md border border-border bg-card text-[12px] focus:outline-none focus:border-primary';
const MONO_INPUT_CLS = cn(INPUT_CLS, 'font-mono placeholder:text-muted-foreground');

interface Props {
  open: boolean;
  onClose: () => void;
  /** Write access (detection_code_targets:manage). When false the surface is read-only. */
  canManage: boolean;
}

export function DetectionCodeTargetsDrawer({ open, onClose, canManage }: Props) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['detection-code-targets'],
    queryFn: () => api.detectionCodeTargets.listTargets(),
    enabled: open,
  });
  const targets = useMemo(() => data?.targets ?? [], [data]);

  // Form state — `editingId === null` is add-new mode.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [baseBranch, setBaseBranch] = useState(DEFAULT_BASE_BRANCH);
  const [pathTemplate, setPathTemplate] = useState(DEFAULT_PATH_TEMPLATE);
  const [enabled, setEnabled] = useState(true);
  const [token, setToken] = useState('');
  const [showToken, setShowToken] = useState(false);

  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Map<string, TestConnectionResult>>(new Map());
  const [testingId, setTestingId] = useState<string | null>(null);

  const editingTarget = targets.find((t) => t.id === editingId) ?? null;

  const resetForm = () => {
    setEditingId(null);
    setName('');
    setRepoUrl('');
    setBaseBranch(DEFAULT_BASE_BRANCH);
    setPathTemplate(DEFAULT_PATH_TEMPLATE);
    setEnabled(true);
    setToken('');
    setShowToken(false);
  };

  // Reset the form on the closed→open transition so a stale edit doesn't leak in.
  useEffect(() => {
    if (open) resetForm();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const loadForEdit = (t: DetectionCodeTarget) => {
    setEditingId(t.id);
    setName(t.name);
    setRepoUrl(t.repo_url);
    setBaseBranch(t.base_branch || DEFAULT_BASE_BRANCH);
    setPathTemplate(t.path_template || DEFAULT_PATH_TEMPLATE);
    setEnabled(t.enabled);
    setToken('');
    setShowToken(false);
  };

  const saveMutation = useMutation({
    mutationFn: async (): Promise<DetectionCodeTarget> => {
      const trimmedToken = token.trim();
      if (editingId) {
        const updated = await api.detectionCodeTargets.updateTarget(editingId, {
          name: name.trim(),
          repo_url: repoUrl.trim(),
          base_branch: baseBranch.trim() || DEFAULT_BASE_BRANCH,
          path_template: pathTemplate.trim() || DEFAULT_PATH_TEMPLATE,
          enabled,
        });
        if (trimmedToken) {
          return api.detectionCodeTargets.setToken(editingId, trimmedToken);
        }
        return updated;
      }
      return api.detectionCodeTargets.createTarget({
        name: name.trim(),
        repo_url: repoUrl.trim(),
        base_branch: baseBranch.trim() || DEFAULT_BASE_BRANCH,
        path_template: pathTemplate.trim() || DEFAULT_PATH_TEMPLATE,
        enabled,
        token: trimmedToken || undefined,
      });
    },
    onSuccess: () => {
      const wasEditing = editingId !== null;
      queryClient.invalidateQueries({ queryKey: ['detection-code-targets'] });
      toast({ title: wasEditing ? 'Push target updated' : 'Push target added' });
      resetForm();
    },
    onError: (err: Error) => {
      toast({ title: 'Save failed', description: err.message, variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.detectionCodeTargets.deleteTarget(id),
    onSuccess: (_res, id) => {
      queryClient.invalidateQueries({ queryKey: ['detection-code-targets'] });
      if (editingId === id) resetForm();
      setDeleteTargetId(null);
      toast({ title: 'Push target removed' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to remove target', description: err.message, variant: 'destructive' });
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => api.detectionCodeTargets.testConnection(id),
    onMutate: (id: string) => {
      setTestingId(id);
    },
    onSuccess: (result, id) => {
      setTestResults((m) => new Map(m).set(id, result));
      setTestingId(null);
    },
    onError: (err: Error, id) => {
      setTestResults((m) =>
        new Map(m).set(id, {
          success: false,
          can_read: false,
          can_write: false,
          default_branch: null,
          message: err.message,
        }),
      );
      setTestingId(null);
    },
  });

  const valid = name.trim().length > 0 && repoUrl.trim().length > 0;
  const targetPendingDelete = targets.find((t) => t.id === deleteTargetId) ?? null;

  return (
    <>
      <SideDrawer
        open={open}
        onClose={onClose}
        title="Detection-as-Code push targets"
        subtitle="Open pull requests in your own repo instead of editing rules in nano"
        width={540}
        footer={
          canManage ? (
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={resetForm}
                className="h-[28px] px-3 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-[11.5px]"
              >
                {editingId ? 'Cancel edit' : 'Clear'}
              </button>
              <button
                type="button"
                onClick={() => saveMutation.mutate()}
                disabled={!valid || saveMutation.isPending}
                className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium flex items-center gap-1.5 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {saveMutation.isPending ? (
                  <Loader2 className="w-[11px] h-[11px] animate-spin" strokeWidth={1.5} />
                ) : editingId ? (
                  <Pencil className="w-[11px] h-[11px]" strokeWidth={1.5} />
                ) : (
                  <Plus className="w-[11px] h-[11px]" strokeWidth={2} />
                )}
                {editingId ? 'Save changes' : 'Add target'}
              </button>
            </div>
          ) : undefined
        }
      >
        <div className="p-4 space-y-4">
          {/* Push-vs-pull explainer */}
          <div className="rounded-md border border-border bg-card/30 px-3 py-2 flex items-start gap-2">
            <GitPullRequest className="w-[13px] h-[13px] text-muted-foreground mt-0.5 shrink-0" strokeWidth={1.5} />
            <div className="text-[10.5px] text-muted-foreground leading-relaxed">
              A <span className="text-foreground/80">push destination</span> for AI-tuned rules —
              not a rule source. When nano proposes a change it opens a pull request here for your
              review; Git stays the source of truth. After you merge, your own pipeline redeploys
              the rule to nano.
            </div>
          </div>

          {/* Existing targets */}
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
              Configured targets
            </div>
            {isLoading ? (
              <div className="flex items-center justify-center py-6 text-muted-foreground">
                <Loader2 className="w-4 h-4 animate-spin" strokeWidth={1.5} />
              </div>
            ) : targets.length === 0 ? (
              <div className="rounded-md border border-dashed border-border px-3 py-4 text-center text-[11px] text-muted-foreground">
                No push targets yet. Add one below to route AI-tuned rules to your repo as pull
                requests.
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                {targets.map((t) => (
                  <TargetCard
                    key={t.id}
                    target={t}
                    active={t.id === editingId}
                    canManage={canManage}
                    testing={testingId === t.id}
                    testResult={testResults.get(t.id)}
                    onEdit={() => loadForEdit(t)}
                    onDelete={() => setDeleteTargetId(t.id)}
                    onTest={() => testMutation.mutate(t.id)}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Create / edit form */}
          {canManage ? (
            <div className="border-t border-border pt-4 space-y-3">
              <div className="flex items-center gap-2">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  {editingId ? 'Edit target' : 'Add a push target'}
                </div>
                {editingId && (
                  <span className="font-mono text-[10px] text-muted-foreground/70 truncate">
                    {editingTarget?.name}
                  </span>
                )}
              </div>

              <Field label="Display name">
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="acme detections (prod)"
                  className={INPUT_CLS}
                />
              </Field>
              <Field label="Repository URL">
                <input
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/acme-corp/detections"
                  className={MONO_INPUT_CLS}
                />
              </Field>
              <div className="grid grid-cols-2 gap-2">
                <Field label="Base branch">
                  <input
                    value={baseBranch}
                    onChange={(e) => setBaseBranch(e.target.value)}
                    placeholder={DEFAULT_BASE_BRANCH}
                    className={MONO_INPUT_CLS}
                  />
                </Field>
                <Field label="Path template">
                  <input
                    value={pathTemplate}
                    onChange={(e) => setPathTemplate(e.target.value)}
                    placeholder={DEFAULT_PATH_TEMPLATE}
                    className={MONO_INPUT_CLS}
                  />
                </Field>
              </div>

              <Field label="Enabled">
                <div className="flex items-center gap-2 h-[30px]">
                  <Switch checked={enabled} onCheckedChange={setEnabled} className="h-4 w-7" />
                  <span className="text-[11px] text-muted-foreground">
                    {enabled
                      ? 'AI tuning may open pull requests here'
                      : 'Disabled — no pull requests will be opened'}
                  </span>
                </div>
              </Field>

              <Field label="Access token (PAT)">
                <div className="relative">
                  <input
                    type={showToken ? 'text' : 'password'}
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    autoComplete="off"
                    placeholder={
                      editingTarget?.has_token
                        ? '••••••••••••••••'
                        : 'ghp_… (needs write access to open PRs)'
                    }
                    className={cn(MONO_INPUT_CLS, 'pr-9')}
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken((v) => !v)}
                    className="absolute right-1 top-1/2 -translate-y-1/2 h-[24px] w-[24px] rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
                    aria-label={showToken ? 'Hide token' : 'Show token'}
                  >
                    {showToken ? (
                      <EyeOff className="w-[13px] h-[13px]" strokeWidth={1.5} />
                    ) : (
                      <Eye className="w-[13px] h-[13px]" strokeWidth={1.5} />
                    )}
                  </button>
                </div>
                {editingTarget?.has_token ? (
                  <p className="mt-1 text-[10.5px] text-emerald-500 flex items-center gap-1">
                    <CircleCheck className="w-3 h-3" strokeWidth={2} />
                    Token configured — enter a new one to replace it.
                  </p>
                ) : (
                  <p className="mt-1 text-[10.5px] text-muted-foreground">
                    Write-only — stored server-side and never shown again.
                    {editingId && ' Add a token, then use Test connection on the card above.'}
                  </p>
                )}
              </Field>
            </div>
          ) : (
            <div className="border-t border-border pt-4">
              <div className="rounded-md border border-border bg-card/30 px-3 py-2 text-[10.5px] text-muted-foreground leading-relaxed">
                You have read-only access to push targets. Managing targets requires the
                <span className="font-mono text-foreground/70"> detection_code_targets:manage </span>
                permission.
              </div>
            </div>
          )}
        </div>
      </SideDrawer>

      <ConfirmDialog
        open={!!deleteTargetId}
        onOpenChange={(o) => !o && setDeleteTargetId(null)}
        variant="danger"
        title="Remove push target"
        description={
          <>
            AI tuning will stop opening pull requests in{' '}
            <span className="text-foreground font-medium">{targetPendingDelete?.name}</span>. The
            stored token is deleted. This does not touch any pull requests already open in the repo.
          </>
        }
        confirmLabel="Remove"
        loading={deleteMutation.isPending}
        onConfirm={() => deleteTargetId && deleteMutation.mutate(deleteTargetId)}
      />
    </>
  );
}

// ------------------------------------------------------------------
// Target card — one configured push target with test/edit/delete.
// ------------------------------------------------------------------

function TargetCard({
  target,
  active,
  canManage,
  testing,
  testResult,
  onEdit,
  onDelete,
  onTest,
}: {
  target: DetectionCodeTarget;
  active: boolean;
  canManage: boolean;
  testing: boolean;
  testResult?: TestConnectionResult;
  onEdit: () => void;
  onDelete: () => void;
  onTest: () => void;
}) {
  return (
    <div
      className={cn(
        'rounded-md border bg-card',
        active ? 'border-primary/50' : 'border-border',
      )}
    >
      <div className="px-3 pt-2.5 pb-2">
        <div className="flex items-center gap-2">
          <span className="text-[12px] font-semibold text-foreground truncate">{target.name}</span>
          <span
            className={cn(
              'inline-flex items-center h-4 px-1.5 rounded-[3px] font-mono text-[9.5px] font-semibold uppercase tracking-wider shrink-0',
              target.enabled
                ? 'bg-emerald-500/15 text-emerald-500'
                : 'bg-foreground/10 text-muted-foreground',
            )}
          >
            {target.enabled ? 'Enabled' : 'Disabled'}
          </span>
          <span
            className={cn(
              'inline-flex items-center h-4 px-1.5 rounded-[3px] font-mono text-[9.5px] font-semibold uppercase tracking-wider shrink-0',
              target.has_token
                ? 'bg-primary/15 text-primary'
                : 'bg-amber-500/15 text-amber-500',
            )}
          >
            {target.has_token ? 'Token set' : 'No token'}
          </span>
        </div>
        <div className="mt-1 font-mono text-[10.5px] text-muted-foreground truncate">
          {target.repo_url}
        </div>
        <div className="mt-1 flex items-center gap-3 font-mono text-[10px] text-muted-foreground/80 flex-wrap">
          <span>branch {target.base_branch}</span>
          <span className="truncate">path {target.path_template}</span>
          {target.last_pr_url && (
            <a
              href={target.last_pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              <GitPullRequest className="w-[10px] h-[10px]" strokeWidth={1.5} />
              last PR
              <ExternalLink className="w-[9px] h-[9px]" strokeWidth={1.5} />
            </a>
          )}
        </div>
      </div>

      {/* Test-connection result strip */}
      {testResult && (
        <div
          className={cn(
            'mx-3 mb-2 rounded-md px-2 py-1.5 flex items-start gap-1.5 text-[10.5px]',
            testResult.success
              ? 'bg-emerald-500/10 text-emerald-500'
              : 'bg-amber-500/10 text-amber-500',
          )}
        >
          {testResult.success ? (
            <CircleCheck className="w-3 h-3 mt-px shrink-0" strokeWidth={2} />
          ) : (
            <CircleAlert className="w-3 h-3 mt-px shrink-0" strokeWidth={2} />
          )}
          <div className="min-w-0">
            <div className="leading-snug">{testResult.message}</div>
            <div className="mt-0.5 font-mono text-[9.5px] opacity-80 flex items-center gap-2 flex-wrap">
              <span>read {testResult.can_read ? '✓' : '✗'}</span>
              <span>write {testResult.can_write ? '✓' : '✗'}</span>
              {testResult.default_branch && <span>default {testResult.default_branch}</span>}
            </div>
          </div>
        </div>
      )}

      {canManage && (
        <div className="px-3 py-2 border-t border-border flex items-center gap-1.5">
          <button
            type="button"
            onClick={onTest}
            disabled={testing || !target.has_token}
            title={target.has_token ? undefined : 'Add a token first to test the connection'}
            className="h-[24px] px-2 rounded-md border border-border bg-card hover:bg-muted text-[10.5px] text-foreground/80 flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {testing ? (
              <Loader2 className="w-[11px] h-[11px] animate-spin" strokeWidth={1.5} />
            ) : (
              <RefreshCw className="w-[11px] h-[11px]" strokeWidth={1.5} />
            )}
            Test connection
          </button>
          <div className="flex-1" />
          <button
            type="button"
            onClick={onEdit}
            className="h-[24px] px-2 rounded-md text-[10.5px] text-foreground/80 hover:text-foreground hover:bg-foreground/5 flex items-center gap-1.5"
          >
            <Pencil className="w-[11px] h-[11px]" strokeWidth={1.5} />
            Edit
          </button>
          <button
            type="button"
            onClick={onDelete}
            className="h-[24px] px-2 rounded-md text-[10.5px] text-muted-foreground hover:text-destructive hover:bg-destructive/10 flex items-center gap-1.5"
          >
            <Trash2 className="w-[11px] h-[11px]" strokeWidth={1.5} />
            Remove
          </button>
        </div>
      )}
    </div>
  );
}

export default DetectionCodeTargetsDrawer;
