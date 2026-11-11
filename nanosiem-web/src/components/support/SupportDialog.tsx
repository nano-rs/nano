// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5253: Help > Report a bug / Get support.
 *
 * Collects what happened, what was expected, when, and the affected objects;
 * attaches non-sensitive browser context (version, edition, page route without
 * query secrets, browser, the last failed API calls with request IDs, recent
 * console errors); and points at `nano support-bundle`. Nothing leaves the
 * browser on its own: the user copies, downloads or emails the report. With
 * the air-gap toggle on (default on air-gapped installs) only copy and
 * download are offered.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Bug, Check, Copy, Download, ExternalLink, LifeBuoy, Mail } from 'lucide-react';
import { toast } from 'sonner';

import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { useCapabilitiesOptional } from '@/hooks/use-capabilities';
import { api } from '@/lib/api';
import { copyText } from '@/lib/clipboard';
import { cn } from '@/lib/utils';
import {
  OPEN_SUPPORT_EVENT,
  SUPPORT_BUNDLE_COMMANDS,
  SUPPORT_EMAIL,
  SUPPORT_SEVERITIES,
  buildSupportReport,
  collectSupportContext,
  feedbackUrl,
  localTimestamp,
  supportMailto,
  type SupportContext,
  type SupportKind,
  type SupportSeverity,
} from '@/lib/support-diagnostics';

const AIRGAP_PREF_KEY = 'nano-support-airgap';
const ICON = 'w-3.5 h-3.5';
const LABEL = 'text-[11px] font-medium text-muted-foreground';
const FIELD = 'text-[12px] min-h-0';

function readAirgapPref(): boolean | null {
  try {
    const v = localStorage.getItem(AIRGAP_PREF_KEY);
    return v === null ? null : v === 'true';
  } catch {
    return null;
  }
}

function writeAirgapPref(value: boolean): void {
  try {
    localStorage.setItem(AIRGAP_PREF_KEY, String(value));
  } catch {
    /* private mode: preference just isn't remembered */
  }
}

/** Mounted once at the app root; opens on `openSupportDialog(kind)` from any shell. */
export function SupportDialogHost() {
  const [kind, setKind] = useState<SupportKind | null>(null);
  useEffect(() => {
    const onOpen = (event: Event) => {
      const detail = (event as CustomEvent<SupportKind>).detail;
      setKind(detail === 'support' ? 'support' : 'bug');
    };
    window.addEventListener(OPEN_SUPPORT_EVENT, onOpen);
    return () => window.removeEventListener(OPEN_SUPPORT_EVENT, onOpen);
  }, []);
  if (!kind) return null;
  return <SupportDialog kind={kind} onKindChange={setKind} onClose={() => setKind(null)} />;
}

export function SupportDialog({
  kind,
  onKindChange,
  onClose,
}: {
  kind: SupportKind;
  onKindChange: (kind: SupportKind) => void;
  onClose: () => void;
}) {
  const caps = useCapabilitiesOptional();
  const enterprise = caps?.edition === 'enterprise';
  // Air-gap detection is best effort: the license status says so on licensed
  // installs. Open core and errors fall back to the remembered toggle.
  const { data: licence } = useQuery({
    queryKey: ['support-dialog', 'license-status'],
    queryFn: () => api.getLicenseStatus(),
    enabled: enterprise,
    retry: false,
    staleTime: 5 * 60 * 1000,
  });
  const detectedAirgap = licence?.airgap === true;
  const [airgapPref, setAirgapPref] = useState<boolean | null>(() => readAirgapPref());
  const airgap = airgapPref ?? detectedAirgap;

  // Snapshot once per open so the preview matches what gets copied.
  const [context] = useState<SupportContext>(() =>
    collectSupportContext({ appVersion: caps?.version, edition: caps?.edition }),
  );
  const fullContext: SupportContext = useMemo(
    () => ({
      ...context,
      installationId: licence?.installation_id || undefined,
      deploymentId: licence?.deployment_id || undefined,
    }),
    [context, licence?.installation_id, licence?.deployment_id],
  );

  const [whatHappened, setWhatHappened] = useState('');
  const [expected, setExpected] = useState('');
  const [when, setWhen] = useState(() => localTimestamp());
  const [affected, setAffected] = useState('');
  const [severity, setSeverity] = useState<SupportSeverity>('SEV3');
  const [copied, setCopied] = useState<string | null>(null);

  const reportInput = useMemo(
    () => ({ kind, severity, whatHappened, expected, when, affected, context: fullContext }),
    [kind, severity, whatHappened, expected, when, affected, fullContext],
  );
  const report = useMemo(() => buildSupportReport(reportInput), [reportInput]);
  const feedback = useMemo(() => feedbackUrl(reportInput), [reportInput]);

  const flash = useCallback((key: string) => {
    setCopied(key);
    window.setTimeout(() => setCopied((cur) => (cur === key ? null : cur)), 1500);
  }, []);

  const copyReport = async () => {
    if (await copyText(report)) {
      flash('report');
      toast.success('Report copied. Paste it into your ticket or email.');
    } else {
      toast.error('The browser blocked clipboard access. Use Download instead.');
    }
  };

  const downloadReport = () => {
    const blob = new Blob([report], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nano-${kind === 'bug' ? 'bug-report' : 'support-request'}-${context.collectedAt.replace(/[:.]/g, '-')}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  // Primary path: app.nano.rs's form, prefilled from the URL fragment (never
  // sent to a server). The user reviews and submits there, signed in.
  const openFeedbackForm = () => {
    window.open(feedback.url, '_blank', 'noopener,noreferrer');
  };

  const emailReport = async () => {
    // The full report goes to the clipboard first: a mailto body is length-limited.
    await copyText(report);
    window.location.href = supportMailto(report, kind, whatHappened);
  };

  const copyCommand = async (key: 'compose' | 'helm') => {
    if (await copyText(SUPPORT_BUNDLE_COMMANDS[key])) flash(key);
  };

  const canSend = whatHappened.trim().length > 0;

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="flex max-h-[90vh] w-[calc(100vw-32px)] max-w-[680px] flex-col gap-0 overflow-hidden p-0">
        <div className="border-b border-border px-4 py-3">
          <DialogTitle className="text-[13px] font-semibold">
            {kind === 'bug' ? 'Report a bug' : 'Get support'}
          </DialogTitle>
          <DialogDescription className="mt-0.5 text-[11.5px] text-muted-foreground">
            {airgap
              ? 'Nothing is sent automatically. Review the report, then copy or download it.'
              : 'Nothing is sent automatically. Review it here, then submit it on app.nano.rs (or copy, download or email it).'}
          </DialogDescription>
          <div className="mt-2 inline-flex rounded-md border border-border p-0.5" role="tablist" aria-label="Request type">
            {(['bug', 'support'] as const).map((k) => (
              <button
                key={k}
                role="tab"
                aria-selected={kind === k}
                onClick={() => onKindChange(k)}
                className={cn(
                  'flex h-6 items-center gap-1.5 rounded px-2 text-[11.5px]',
                  kind === k ? 'bg-accent text-foreground' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {k === 'bug' ? <Bug className={ICON} strokeWidth={1.5} /> : <LifeBuoy className={ICON} strokeWidth={1.5} />}
                {k === 'bug' ? 'Report a bug' : 'Get support'}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3">
          {kind === 'support' && (
            <div className="space-y-1">
              <span className={LABEL}>Severity</span>
              <div className="flex flex-wrap gap-1" role="radiogroup" aria-label="Severity">
                {SUPPORT_SEVERITIES.map((s) => (
                  <button
                    key={s.value}
                    role="radio"
                    aria-checked={severity === s.value}
                    onClick={() => setSeverity(s.value)}
                    className={cn(
                      'flex h-6 items-center gap-1.5 rounded-md border px-2 text-[11.5px]',
                      severity === s.value
                        ? 'border-foreground/30 bg-accent text-foreground'
                        : 'border-border text-muted-foreground hover:text-foreground',
                    )}
                  >
                    <span className="font-mono text-[10.5px]">{s.value}</span>
                    {s.label}
                  </button>
                ))}
              </div>
            </div>
          )}
          <label className="block space-y-1">
            <span className={LABEL}>What happened <span className="text-destructive">*</span></span>
            <Textarea
              autoFocus
              rows={3}
              className={FIELD}
              value={whatHappened}
              onChange={(e) => setWhatHappened(e.target.value)}
              placeholder={kind === 'bug'
                ? 'Steps, and the exact error or status code you saw'
                : 'What you are trying to do, and where you are stuck'}
            />
          </label>
          <label className="block space-y-1">
            <span className={LABEL}>{kind === 'bug' ? 'What did you expect' : 'What do you need'}</span>
            <Textarea rows={2} className={FIELD} value={expected} onChange={(e) => setExpected(e.target.value)} />
          </label>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="block space-y-1">
              <span className={LABEL}>When (with timezone; still happening?)</span>
              <Input className="h-7 font-mono text-[11.5px]" value={when} onChange={(e) => setWhen(e.target.value)} />
            </label>
            <label className="block space-y-1">
              <span className={LABEL}>Affected objects (exact names)</span>
              <Input
                className="h-7 font-mono text-[11.5px]"
                value={affected}
                onChange={(e) => setAffected(e.target.value)}
                placeholder="rule: …, log source: …, dashboard: …"
              />
            </label>
          </div>

          <details className="rounded-md border border-border">
            <summary className="cursor-pointer select-none px-2.5 py-1.5 text-[11.5px] text-muted-foreground">
              Attached context
              <span className="ml-2 font-mono text-[10.5px]">
                v{fullContext.appVersion} · {fullContext.edition} · {fullContext.failedCalls.length} failed calls ·{' '}
                {fullContext.consoleErrors.length} console errors
              </span>
            </summary>
            <div className="space-y-2 border-t border-border px-2.5 py-2">
              <dl className="grid grid-cols-[96px_1fr] gap-x-2 gap-y-0.5 font-mono text-[10.5px]">
                <dt className="text-muted-foreground">page</dt><dd className="break-all">{fullContext.route}</dd>
                <dt className="text-muted-foreground">browser</dt><dd className="break-all">{fullContext.userAgent}</dd>
                <dt className="text-muted-foreground">timezone</dt><dd>{fullContext.timezone}</dd>
                <dt className="text-muted-foreground">collected</dt><dd>{fullContext.collectedAt}</dd>
                {fullContext.installationId && (
                  <><dt className="text-muted-foreground">installation</dt><dd>{fullContext.installationId}</dd></>
                )}
              </dl>
              {fullContext.failedCalls.length > 0 && (
                <table className="w-full font-mono text-[10.5px]">
                  <thead className="text-left text-muted-foreground">
                    <tr><th className="pr-2 font-normal">time</th><th className="pr-2 font-normal">status</th>
                      <th className="pr-2 font-normal">endpoint</th><th className="font-normal">request id</th></tr>
                  </thead>
                  <tbody>
                    {fullContext.failedCalls.slice().reverse().map((f, i) => (
                      <tr key={`${f.at}-${i}`} className="h-5 align-top">
                        <td className="whitespace-nowrap pr-2">{f.at.slice(11, 19)}</td>
                        <td className={cn('pr-2', f.status >= 500 || f.status === 0 ? 'text-destructive' : '')}>
                          {f.status || 'net'}
                        </td>
                        <td className="break-all pr-2">{f.method} {f.path}</td>
                        <td className="break-all">{f.requestId ?? '–'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {fullContext.consoleErrors.length > 0 && (
                <ul className="space-y-0.5 font-mono text-[10.5px]">
                  {fullContext.consoleErrors.slice(-5).map((e, i) => (
                    <li key={`${e.at}-${i}`} className="break-all"><span className="text-muted-foreground">{e.at.slice(11, 19)}</span> {e.message}</li>
                  ))}
                </ul>
              )}
              <p className="text-[11px] text-muted-foreground">
                No request bodies, query strings, search results or event data are included.
              </p>
            </div>
          </details>

          <div className="space-y-1.5 rounded-md border border-border px-2.5 py-2">
            <p className="text-[11.5px]">
              Install, ingestion or performance problem? Run this on any host of the install and attach the
              archive it prints (redacted, no event data; review it before sending):
            </p>
            {(['compose', 'helm'] as const).map((key) => (
              <div key={key} className="flex items-center gap-2">
                <span className="w-[72px] shrink-0 text-[11px] text-muted-foreground">{key === 'compose' ? 'Compose' : 'Kubernetes'}</span>
                <code className="min-w-0 flex-1 truncate rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[10.5px]">
                  {SUPPORT_BUNDLE_COMMANDS[key]}
                </code>
                <Button variant="ghost" size="icon" className="h-6 w-6" aria-label={`Copy ${key} command`} onClick={() => void copyCommand(key)}>
                  {copied === key ? <Check className={ICON} strokeWidth={1.5} /> : <Copy className={ICON} strokeWidth={1.5} />}
                </Button>
              </div>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-border px-4 py-2.5">
          <label className="mr-auto flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
            <Checkbox
              className="h-3.5 w-3.5"
              checked={airgap}
              onCheckedChange={(v) => { const on = v === true; setAirgapPref(on); writeAirgapPref(on); }}
            />
            Air-gapped: copy or download only
          </label>
          <Button variant="outline" size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={downloadReport} disabled={!canSend}>
            <Download className={ICON} strokeWidth={1.5} /> Download
          </Button>
          <Button variant="outline" size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => void copyReport()} disabled={!canSend}>
            {copied === 'report' ? <Check className={ICON} strokeWidth={1.5} /> : <Copy className={ICON} strokeWidth={1.5} />} Copy report
          </Button>
          {!airgap && (
            <>
              <Button variant="outline" size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={() => void emailReport()} disabled={!canSend}
                title={`Opens your mail client addressed to ${SUPPORT_EMAIL}; the full report is also copied`}>
                <Mail className={ICON} strokeWidth={1.5} /> Email
              </Button>
              <Button size="sm" className="h-7 gap-1.5 text-[11.5px]" onClick={openFeedbackForm} disabled={!canSend}
                title={feedback.truncated
                  ? 'Opens the prefilled form on app.nano.rs. The report was shortened to fit a link: attach the downloaded report for the rest.'
                  : 'Opens the prefilled form on app.nano.rs; you review and submit it there.'}>
                <ExternalLink className={ICON} strokeWidth={1.5} />
                {kind === 'bug' ? 'Report on app.nano.rs' : 'Open support request'}
              </Button>
            </>
          )}
        </div>
        {!airgap && feedback.truncated && (
          <p className="border-t border-border px-4 py-1.5 text-[11px] text-muted-foreground">
            The app.nano.rs link carries a shortened report (older errors dropped to fit a URL). Download the full
            report and attach it there.
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}
