// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Air-gap bundle sync control (NAN-1226).
 *
 * Compact button + hidden file input that uploads a signed `.tar.gz` bundle to
 * an air-gap endpoint. The upload is SYNC-ONLY — it populates the repository
 * catalog so items appear *available to import* — so on success we just refetch
 * the repo/catalog query and surface a "synced" toast. The operator then uses
 * the page's existing select → import (→ deploy) flow.
 *
 * Deliberately NOT imported from `@/enterprise/*` (no open-core stub needed):
 * the endpoint is enterprise-gated server-side, but this is plain UI that posts
 * to it. Used in air-gap mode on the parser/rule/playbook repository pages in
 * place of the egress controls (connect-repo / sync-from-Git).
 */

import { useRef, useState } from 'react';
import { Upload, Loader2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface SyncResult {
  content_version: string;
  synced: number;
}

interface ImportBundleButtonProps {
  /** Uploads the bundle and resolves to the sync result. */
  onUpload: (file: File) => Promise<SyncResult>;
  /** What kind of items the bundle carries — used in copy ("12 parsers synced"). */
  noun: string;
  /** Called after a successful sync so the page can refetch its catalog query. */
  onSynced: () => void;
  className?: string;
}

export function ImportBundleButton({
  onUpload,
  noun,
  onSynced,
  className,
}: ImportBundleButtonProps) {
  const { toast } = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setUploading(true);
    try {
      const res = await onUpload(file);
      toast({
        title: 'Bundle synced',
        description: `${res.synced} ${noun} now available to import (v${res.content_version}).`,
      });
      onSynced();
    } catch (err) {
      toast({
        title: 'Bundle sync failed',
        description:
          err instanceof Error ? err.message : 'Could not sync the air-gap bundle.',
        variant: 'destructive',
      });
    } finally {
      setUploading(false);
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  return (
    <>
      <button
        type="button"
        disabled={uploading}
        onClick={() => inputRef.current?.click()}
        className={cn(
          'h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-60 text-[11.5px] font-medium inline-flex items-center gap-1.5',
          className,
        )}
      >
        {uploading ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" strokeWidth={1.5} />
        ) : (
          <Upload className="w-3.5 h-3.5" strokeWidth={1.5} />
        )}
        {uploading ? 'Syncing…' : 'Import bundle (.tar.gz)'}
      </button>
      <input
        ref={inputRef}
        type="file"
        accept=".tar.gz,.tgz,application/gzip"
        className="hidden"
        onChange={(e) => void handleFile(e.target.files?.[0])}
      />
    </>
  );
}
