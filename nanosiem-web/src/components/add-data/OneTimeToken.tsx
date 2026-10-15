// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, KeyRound } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import type { IssuedCredential } from '@/lib/ingest-credential-issuance';
import { PROTOCOL_LABEL } from '@/lib/add-data-sources';
import { CopyButton } from './CopyButton';

/**
 * The plaintext token, shown once (NAN-2593). Copy is focused on mount and the
 * panel scrolls into view. The token stays until the user says it is saved;
 * dismissing a token that was never copied asks first, because it can never
 * be shown again (the NAN-2589 lesson).
 */
export function OneTimeToken({
  credential,
  copied,
  onCopied,
  onDismiss,
}: {
  credential: IssuedCredential;
  copied: boolean;
  onCopied: () => void;
  onDismiss: () => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const copyRef = useRef<HTMLButtonElement>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  useEffect(() => {
    panelRef.current?.scrollIntoView?.({ block: 'nearest' });
    copyRef.current?.focus();
  }, []);

  return (
    <div
      ref={panelRef}
      className="rounded-md border border-emerald-500/40 bg-emerald-500/[0.04]"
      data-testid="one-time-token"
      role="region"
      aria-label={`Ingest token for ${credential.label}`}
    >
      <div className="flex items-center gap-2 px-3 h-8 border-b border-emerald-500/25">
        <KeyRound className="w-3.5 h-3.5 text-emerald-500" strokeWidth={1.5} />
        <span className="text-[12px] font-medium text-foreground">Token issued</span>
        <span className="font-mono text-[10.5px] text-muted-foreground truncate">{credential.label}</span>
        <span className="font-mono text-[10.5px] text-muted-foreground">· {PROTOCOL_LABEL[credential.protocol] ?? credential.protocol}</span>
        {credential.sourceSlugs.map((s) => (
          <span key={s} className="font-mono text-[10.5px] px-1.5 h-4 inline-flex items-center rounded-sm border border-border text-foreground/80">
            {s}
          </span>
        ))}
        <span className="flex-1" />
        {credential.credentialId && (
          <span className="font-mono text-[10.5px] text-muted-foreground/70 truncate" title="credential id">
            {credential.credentialId}
          </span>
        )}
      </div>
      <div className="px-3 py-2.5 space-y-2">
        <div className="flex items-center gap-2">
          <input
            readOnly
            value={credential.token}
            aria-label="Ingest token"
            spellCheck={false}
            autoComplete="off"
            onFocus={(e) => e.currentTarget.select()}
            className="flex-1 min-w-0 h-7 rounded border border-border bg-background px-2 font-mono text-[12px] text-foreground"
          />
          <CopyButton ref={copyRef} text={credential.token} label="Copy token" onCopied={onCopied} className="h-7" />
        </div>
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3 h-3 text-amber-500 shrink-0" strokeWidth={1.5} />
          <span className="text-[11px] text-muted-foreground">
            Shown once. nano does not keep it; if you lose it, revoke the credential and issue another.
          </span>
          <span className="flex-1" />
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-[11.5px]"
            onClick={() => (copied ? onDismiss() : setConfirmOpen(true))}
          >
            I&apos;ve saved it
          </Button>
        </div>
      </div>
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Hide a token you haven't copied?"
        description="This token was never copied. Once hidden it can never be shown again; you would have to revoke the credential and issue a new one."
        confirmLabel="Hide token"
        cancelLabel="Keep it"
        variant="warning"
        onConfirm={onDismiss}
      />
    </div>
  );
}
