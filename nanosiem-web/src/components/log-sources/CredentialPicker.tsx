// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Key, Plus, CircleAlert, Lock, RotateCcw, Settings2 } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import {
  AddCredentialSheet,
  CredentialInspectorSheet,
  useCredentialUsage,
} from '@/components/credentials/CredentialsManager';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';

export type CredentialPickerProvider = 'aws_s3' | 'gcp_pubsub' | 'kafka' | 'azure_event_hubs';

interface CredentialPickerProps {
  provider: CredentialPickerProvider;
  value: string | undefined;
  onChange: (credentialId: string | undefined) => void;
  disabled?: boolean;
}

/** The credential provider a source configuration type reads with, if it takes one. */
export function credentialProviderFor(configType: string): CredentialPickerProvider | null {
  switch (configType) {
    case 'aws_s3':
    case 'aws_sqs':
    case 'crowdstrike_fdr':
      return 'aws_s3';
    case 'gcp_pubsub':
      return 'gcp_pubsub';
    case 'azure_event_hubs':
      return 'azure_event_hubs';
    case 'kafka':
      return 'kafka';
    default:
      return null;
  }
}

const PROVIDER_LABELS: Record<string, string> = {
  aws_s3: 'AWS',
  gcp_pubsub: 'GCP',
  kafka: 'Kafka',
  azure_event_hubs: 'Azure Event Hubs',
};

// What "no credential selected" actually means depends on the provider:
// AWS/GCP fall back to ambient cloud identity (instance metadata / ADC), but
// Kafka with no credential means an anonymous PLAINTEXT consumer — common for
// local dev brokers like the NAN-884 test stand. Be explicit so the picker
// doesn't read as "set credentials = magic env" for the Kafka case.
const NONE_OPTION_LABEL: Record<string, string> = {
  aws_s3: 'None (use environment / IAM role)',
  gcp_pubsub: 'None (use Application Default Credentials)',
  kafka: 'None (unauthenticated — local / dev brokers)',
  azure_event_hubs: 'None (use managed identity)',
};

/**
 * Pick the stored credential a pull source reads with. NAN-4941: the secret
 * is entered ("Enter new"), rotated and managed (versions, rollback, usage,
 * delete) in place; it is only ever shown masked.
 */
export function CredentialPicker({ provider, value, onChange, disabled }: CredentialPickerProps) {
  const { hasPermission } = useAuth();
  const canView = hasPermission('credentials:view');
  const canCreate = hasPermission('credentials:create');
  const canRotate = hasPermission('credentials:rotate');
  const [adding, setAdding] = useState(false);
  const [managing, setManaging] = useState<'inspect' | 'rotate' | null>(null);
  const list = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.listCredentials().then((r) => r.credentials),
    enabled: canView,
  });
  const usage = useCredentialUsage();
  const credentials = (list.data ?? []).filter((c) => c.provider === provider);
  const selectedCredential = credentials.find((c) => c.id === value);

  return (
    <div className="space-y-1.5" data-testid="credential-picker">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <Key className="w-3 h-3 text-muted-foreground" />
          <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            {PROVIDER_LABELS[provider]} Credentials
          </Label>
        </div>
        {canCreate && !disabled && (
          <button
            type="button"
            onClick={() => setAdding(true)}
            className="flex items-center gap-1 text-[10.5px] text-primary hover:underline"
          >
            <Plus className="w-3 h-3" />
            Enter new
          </button>
        )}
      </div>

      {!canView ? (
        <p className="text-[10.5px] text-muted-foreground">
          {value ? <span className="font-mono">{value}</span> : 'No credential'} · you need credentials:view to change it.
        </p>
      ) : list.isLoading ? (
        <div className="flex items-center gap-2 px-2.5 py-1.5 bg-muted/30 rounded-md">
          <LoadingIcon className="w-3 h-3 text-muted-foreground" />
          <span className="text-[11px] text-muted-foreground">Loading credentials…</span>
        </div>
      ) : list.error ? (
        <div className="flex items-center gap-2 px-2.5 py-1.5 bg-red-500/10 rounded-md text-red-400">
          <CircleAlert className="w-3 h-3" />
          <span className="text-[11px]">{list.error instanceof Error ? list.error.message : 'Failed to load credentials'}</span>
        </div>
      ) : (
        <Select
          value={value ?? '_none'}
          onValueChange={(v) => onChange(v === '_none' ? undefined : v)}
          disabled={disabled}
        >
          <SelectTrigger className="h-8 text-[12px] bg-card" aria-label={`${PROVIDER_LABELS[provider]} credential`}>
            <SelectValue placeholder="Select credentials..." />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_none" className="text-[12px] text-muted-foreground">
              {NONE_OPTION_LABEL[provider]}
            </SelectItem>
            {credentials.map((cred) => (
              <SelectItem key={cred.id} value={cred.id} className="text-[12px]">
                <div className="flex items-center gap-2">
                  <span>{cred.name}</span>
                  {cred.region && (
                    <span className="text-[10.5px] text-muted-foreground">({cred.region})</span>
                  )}
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      {selectedCredential && (
        <div className="flex items-center gap-2 h-7 px-2 rounded-md border border-border bg-card" data-testid="credential-picker-selected">
          <Lock className="w-3 h-3 text-muted-foreground shrink-0" />
          <span className="font-mono text-[11px] text-muted-foreground truncate" aria-label="Secret hidden">
            {selectedCredential.external_id ? 'role assumption' : '••••••••••••'} · v{selectedCredential.active_version}
          </span>
          <span className="flex-1" />
          {canRotate && (
            <Button type="button" variant="ghost" size="sm" className="h-5 px-1.5 text-[10.5px] gap-1" onClick={() => setManaging('rotate')}>
              <RotateCcw className="w-3 h-3" /> Rotate
            </Button>
          )}
          <Button type="button" variant="ghost" size="sm" className="h-5 px-1.5 text-[10.5px] gap-1" onClick={() => setManaging('inspect')}>
            <Settings2 className="w-3 h-3" /> Manage
          </Button>
        </div>
      )}

      {canView && !list.isLoading && credentials.length === 0 && !list.error && (
        <p className="text-[10.5px] text-amber-600 dark:text-amber-400 leading-relaxed">
          No {PROVIDER_LABELS[provider]} credentials stored.{' '}
          {canCreate && (
            <button type="button" onClick={() => setAdding(true)} className="underline hover:text-amber-500 dark:hover:text-amber-300">
              Enter one
            </button>
          )}
          {provider === 'kafka'
            ? ' — or leave as None for an unauthenticated broker.'
            : ' or use environment variables/IAM roles.'}
        </p>
      )}

      {canCreate && (
        <AddCredentialSheet
          open={adding}
          onOpenChange={setAdding}
          initialProvider={provider}
          providers={[provider]}
          onCreated={(cred) => onChange(cred.id)}
        />
      )}
      <CredentialInspectorSheet
        cred={managing && selectedCredential ? selectedCredential : null}
        usage={selectedCredential ? usage.get(selectedCredential.id) ?? [] : []}
        rotateOnOpen={managing === 'rotate'}
        onClose={() => setManaging(null)}
      />
    </div>
  );
}
