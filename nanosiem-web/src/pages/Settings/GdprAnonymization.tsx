// SPDX-License-Identifier: AGPL-3.0-or-later

import { useId, useState } from 'react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Loader2,
  ChevronLeft,
  ChevronRight,
  Play,
  Send,
  List,
  Eye,
  AlertTriangle,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useGdprRequests } from '@/hooks/use-api';
import { api } from '@/lib/api';
import type {
  GdprIdentifierType,
  GdprAnonymizationStatus,
  GdprAnonymizationPreview,
} from '@/lib/api';
import { formatUTC } from '@/lib/date-utils';

const IDENTIFIER_TYPES: { value: GdprIdentifierType; label: string }[] = [
  { value: 'username', label: 'Username' },
  { value: 'email', label: 'Email' },
  { value: 'ip', label: 'IP address' },
];

const STATUS_PILL: Record<GdprAnonymizationStatus, string> = {
  pending: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  running: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  completed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  failed: 'bg-red-500/10 text-red-400 border-red-500/20',
};

function StatusPill({ status }: { status: GdprAnonymizationStatus }) {
  return (
    <span
      className={`font-mono text-[10px] font-semibold uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border w-fit ${STATUS_PILL[status]}`}
    >
      {status}
    </span>
  );
}

export function GdprAnonymizationPage() {
  useDocumentTitle('GDPR & Compliance');
  useBreadcrumbTitle('GDPR & Compliance');
  const { toast } = useToast();
  const baseId = useId();

  // Form state
  const [identifierType, setIdentifierType] = useState<GdprIdentifierType>('username');
  const [identifierValue, setIdentifierValue] = useState('');
  const [justification, setJustification] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Preview dialog
  const [preview, setPreview] = useState<GdprAnonymizationPreview | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);

  // Execute confirmation dialog
  const [executeId, setExecuteId] = useState<string | null>(null);
  const [executeOpen, setExecuteOpen] = useState(false);
  const [executing, setExecuting] = useState(false);

  // Pagination
  const [offset, setOffset] = useState(0);
  const limit = 20;

  const { data, loading, refetch } = useGdprRequests(limit, offset);
  const requests = data?.requests ?? [];
  const total = data?.total ?? 0;
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const id = (suffix: string) => `${baseId}-${suffix}`;

  const handleSubmit = async () => {
    if (submitting) return;
    if (!identifierValue.trim()) {
      toast({
        title: 'Identifier required',
        description: 'Enter an identifier value to anonymize.',
        variant: 'destructive',
      });
      return;
    }
    setSubmitting(true);
    try {
      const result = await api.submitGdprRequest({
        identifier_type: identifierType,
        identifier_value: identifierValue.trim(),
        justification: justification.trim() || undefined,
      });
      setPreview(result);
      setPreviewOpen(true);
    } catch (err) {
      toast({
        title: 'Submission failed',
        description: err instanceof Error ? err.message : 'Failed to submit anonymization request',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handlePreviewConfirm = () => {
    setPreviewOpen(false);
    setPreview(null);
    setIdentifierValue('');
    setJustification('');
    toast({
      title: 'Request created',
      description: 'Anonymization request is pending. Click Execute when ready.',
    });
    refetch();
  };

  const handleExecute = async () => {
    if (!executeId || executing) return;
    setExecuting(true);
    try {
      await api.executeGdprRequest(executeId);
      toast({
        title: 'Execution started',
        description: 'Anonymization mutations have been submitted.',
      });
      refetch();
    } catch (err) {
      toast({
        title: 'Execution failed',
        description: err instanceof Error ? err.message : 'Failed to execute anonymization',
        variant: 'destructive',
      });
    } finally {
      setExecuting(false);
      setExecuteOpen(false);
      setExecuteId(null);
    }
  };

  const totalAffected = (r: typeof requests[0]) =>
    r.logs_affected +
    r.identity_observations_affected +
    r.cloud_activity_affected +
    r.user_registry_affected;

  const placeholderFor = (t: GdprIdentifierType) =>
    t === 'ip' ? '192.168.1.100' : t === 'email' ? 'user@example.com' : 'jdoe';

  return (
    <div className="px-6 py-5 space-y-7">
      <div>
        <h1 className="text-[18px] font-semibold tracking-tight text-foreground">
          GDPR &amp; Compliance
        </h1>
        <p className="text-[11.5px] text-muted-foreground mt-0.5">
          Submit and manage data-subject anonymization requests.
        </p>
      </div>

      {/* SUBMIT REQUEST */}
      <section>
        <div className="flex items-center gap-1.5 mb-1">
          <Send className="w-3 h-3 text-muted-foreground" />
          <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">
            Submit request
          </div>
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          Anonymize all PII matching an identifier across logs, identity observations, cloud
          activity, and the user registry. The original value is hashed immediately and never
          stored.
        </p>

        <div className="flex flex-col">
          <div className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
            <div className="min-w-0 flex-1">
              <label htmlFor={id('identifier-type')} className="text-[12.5px] font-medium text-foreground cursor-pointer">
                Identifier type
              </label>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                Determines which UDM columns and tables are scanned for matches.
              </div>
            </div>
            <Select
              value={identifierType}
              onValueChange={(v) => setIdentifierType(v as GdprIdentifierType)}
            >
              <SelectTrigger
                id={id('identifier-type')}
                className="h-8 w-[180px] text-[12px] shrink-0"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {IDENTIFIER_TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value} className="text-[12px]">
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
            <div className="min-w-0 flex-1">
              <label htmlFor={id('identifier-value')} className="text-[12.5px] font-medium text-foreground cursor-pointer">
                Identifier value
              </label>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                Hashed immediately; never stored in plain text.
              </div>
            </div>
            <Input
              id={id('identifier-value')}
              placeholder={placeholderFor(identifierType)}
              value={identifierValue}
              onChange={(e) => setIdentifierValue(e.target.value)}
              className="h-8 w-[280px] text-[12px] font-mono shrink-0"
            />
          </div>

          <div className="flex items-start justify-between gap-4 py-3 border-b border-border/60">
            <div className="min-w-0 flex-1">
              <label htmlFor={id('justification')} className="text-[12.5px] font-medium text-foreground cursor-pointer">
                Justification (optional)
              </label>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                Free-text reason — recorded on the audit trail. Useful for ticket references.
              </div>
            </div>
            <Textarea
              id={id('justification')}
              placeholder="GDPR erasure request ticket #..."
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              className="text-[12px] resize-none w-[280px] shrink-0"
              rows={2}
            />
          </div>

          <div className="flex justify-end pt-4">
            <Button
              onClick={handleSubmit}
              disabled={submitting}
              size="sm"
              className="h-7 text-[11.5px] px-2.5"
            >
              {submitting ? (
                <Loader2 className="w-3 h-3 mr-1 animate-spin" />
              ) : (
                <Send className="w-3 h-3 mr-1" />
              )}
              Submit request
            </Button>
          </div>
        </div>
      </section>

      {/* REQUESTS */}
      <section>
        <div className="flex items-center gap-1.5 mb-1">
          <List className="w-3 h-3 text-muted-foreground" />
          <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">
            Requests
          </div>
        </div>
        <p className="text-[11.5px] text-muted-foreground mb-3 max-w-[720px]">
          Submitted anonymization requests. Pending requests can be executed once you've confirmed
          the preview counts.
        </p>

        {loading && requests.length === 0 ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="border-y border-border">
            <div className="grid grid-cols-[100px_120px_100px_120px_minmax(140px,1fr)_minmax(160px,auto)] gap-3 px-3 py-1.5 bg-card/50 border-b border-border text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">
              <div>ID</div>
              <div>Type</div>
              <div>Status</div>
              <div>Affected rows</div>
              <div>Created</div>
              <div>Actions</div>
            </div>

            {requests.length === 0 ? (
              <div className="px-3 py-10 text-center text-[12px] text-muted-foreground">
                No anonymization requests yet.
              </div>
            ) : (
              requests.map((r) => (
                <div
                  key={r.id}
                  className="grid grid-cols-[100px_120px_100px_120px_minmax(140px,1fr)_minmax(160px,auto)] gap-3 items-center px-3 h-11 border-b border-border/60 hover:bg-foreground/[0.025] transition-colors"
                >
                  <span className="font-mono text-[10.5px] text-muted-foreground truncate">
                    {r.id.slice(0, 8)}…
                  </span>
                  <span className="text-[12px] text-foreground capitalize">
                    {r.identifier_type}
                  </span>
                  <StatusPill status={r.status} />
                  <span className="font-mono text-[11.5px] text-foreground tabular-nums">
                    {totalAffected(r).toLocaleString()}
                  </span>
                  <span className="font-mono text-[10.5px] text-muted-foreground truncate">
                    {formatUTC(r.created_at)}
                  </span>
                  <div className="flex items-center gap-2 min-w-0">
                    {r.status === 'pending' && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 text-[11.5px] px-2.5 border-border"
                        onClick={() => {
                          setExecuteId(r.id);
                          setExecuteOpen(true);
                        }}
                      >
                        <Play className="w-3 h-3 mr-1" />
                        Execute
                      </Button>
                    )}
                    {r.status === 'failed' && r.error_message && (
                      <span
                        className="font-mono text-[10.5px] text-red-400 truncate"
                        title={r.error_message}
                      >
                        {r.error_message}
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Pagination + count */}
        {(total > 0 || requests.length > 0) && (
          <div className="flex items-center justify-between pt-3">
            <span className="font-mono text-[10.5px] text-muted-foreground">
              {total === 0
                ? '0 requests'
                : `${offset + 1}–${Math.min(offset + limit, total)} of ${total}`}
            </span>
            {total > limit && (
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                  className="h-7 w-7 p-0 border-border"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </Button>
                <span className="font-mono text-[10.5px] text-muted-foreground">
                  Page {currentPage} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(offset + limit)}
                  disabled={offset + limit >= total}
                  className="h-7 w-7 p-0 border-border"
                  aria-label="Next page"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </Button>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Preview dialog (after submit) */}
      <AlertDialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <AlertDialogContent className="bg-card border-border gap-0 p-0 max-w-md">
          <AlertDialogHeader className="border-b border-border px-5 py-4">
            <div className="flex items-center gap-1.5 mb-1">
              <Eye className="w-3 h-3 text-muted-foreground" />
              <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">
                Preview
              </div>
            </div>
            <AlertDialogTitle className="text-[14px] font-semibold text-foreground tracking-tight">
              Anonymization request created
            </AlertDialogTitle>
            <p className="text-[11.5px] text-muted-foreground mt-1">
              The request is pending. Estimated affected rows by source:
            </p>
          </AlertDialogHeader>
          {preview && (
            <div className="px-5 py-4">
              <div className="flex flex-col">
                {[
                  { label: 'Logs', value: preview.estimated_logs },
                  { label: 'Identity observations', value: preview.estimated_identity_observations },
                  { label: 'Cloud activity', value: preview.estimated_cloud_activity },
                  { label: 'User registry', value: preview.estimated_user_registry },
                ].map(({ label, value }) => (
                  <div
                    key={label}
                    className="flex items-center justify-between gap-4 py-2 border-b border-border/60 last:border-b-0"
                  >
                    <span className="text-[11.5px] text-muted-foreground">{label}</span>
                    <span className="font-mono text-[12px] text-foreground tabular-nums">
                      {value.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
              {preview.limitations.length > 0 && (
                <div className="mt-3 rounded-md border border-yellow-500/20 bg-yellow-500/10 p-3">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <AlertTriangle className="w-3 h-3 text-yellow-400" />
                    <div className="text-[10px] uppercase tracking-[0.08em] text-yellow-400 font-medium">
                      Limitations
                    </div>
                  </div>
                  <ul className="text-[11px] text-muted-foreground space-y-0.5 leading-relaxed">
                    {preview.limitations.map((l, i) => (
                      <li key={i}>• {l}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
          <AlertDialogFooter className="border-t border-border px-5 py-3">
            <AlertDialogCancel className="h-7 text-[11.5px] px-2.5 border-border">
              Close
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handlePreviewConfirm}
              className="h-7 text-[11.5px] px-2.5"
            >
              OK
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Execute confirmation dialog */}
      <AlertDialog open={executeOpen} onOpenChange={setExecuteOpen}>
        <AlertDialogContent className="bg-card border-border gap-0 p-0 max-w-md">
          <AlertDialogHeader className="border-b border-border px-5 py-4">
            <div className="flex items-center gap-1.5 mb-1">
              <AlertTriangle className="w-3 h-3 text-red-400" />
              <div className="text-[10px] uppercase tracking-[0.12em] text-red-400 font-medium">
                Irreversible
              </div>
            </div>
            <AlertDialogTitle className="text-[14px] font-semibold text-foreground tracking-tight">
              Execute anonymization
            </AlertDialogTitle>
            <p className="text-[11.5px] text-muted-foreground mt-1">
              This will permanently anonymize all matching PII across logs, identity observations,
              cloud activity, and the user registry. The original values cannot be recovered.
            </p>
          </AlertDialogHeader>
          <AlertDialogFooter className="border-t border-border px-5 py-3">
            <AlertDialogCancel
              className="h-7 text-[11.5px] px-2.5 border-border"
              disabled={executing}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleExecute}
              className="h-7 text-[11.5px] px-2.5 bg-red-600 hover:bg-red-700"
              disabled={executing}
            >
              {executing && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
              Execute
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
