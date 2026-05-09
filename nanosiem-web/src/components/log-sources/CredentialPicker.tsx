// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Key, Plus, Loader2, CircleAlert } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { api } from '@/lib/api';
import type { CloudCredential } from '@/lib/api/types';

interface CredentialPickerProps {
  provider: 'aws_s3' | 'gcp_pubsub' | 'kafka';
  value: string | undefined;
  onChange: (credentialId: string | undefined) => void;
  disabled?: boolean;
}

const PROVIDER_LABELS: Record<string, string> = {
  aws_s3: 'AWS',
  gcp_pubsub: 'GCP',
  kafka: 'Kafka',
};

export function CredentialPicker({ provider, value, onChange, disabled }: CredentialPickerProps) {
  const [credentials, setCredentials] = useState<CloudCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchCredentials() {
      setLoading(true);
      setError(null);
      try {
        const response = await api.listCredentials();
        // Filter by provider on the frontend
        const filtered = response.credentials.filter(c => c.provider === provider);
        setCredentials(filtered);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load credentials');
        setCredentials([]);
      } finally {
        setLoading(false);
      }
    }
    fetchCredentials();
  }, [provider]);

  const selectedCredential = credentials.find(c => c.id === value);

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <Key className="w-3 h-3 text-muted-foreground" />
          <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            {PROVIDER_LABELS[provider]} Credentials
          </Label>
        </div>
        <Link
          to={`/ingestion/credentials?add=${provider}`}
          className="flex items-center gap-1 text-[10.5px] text-primary hover:underline"
        >
          <Plus className="w-3 h-3" />
          Create new
        </Link>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 px-2.5 py-1.5 bg-muted/30 rounded-md">
          <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />
          <span className="text-[11px] text-muted-foreground">Loading credentials…</span>
        </div>
      ) : error ? (
        <div className="flex items-center gap-2 px-2.5 py-1.5 bg-red-500/10 rounded-md text-red-400">
          <CircleAlert className="w-3 h-3" />
          <span className="text-[11px]">{error}</span>
        </div>
      ) : (
        <Select
          value={value ?? '_none'}
          onValueChange={(v) => onChange(v === '_none' ? undefined : v)}
          disabled={disabled}
        >
          <SelectTrigger className="h-8 text-[12px] bg-card">
            <SelectValue placeholder="Select credentials..." />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_none" className="text-[12px] text-muted-foreground">
              None (use environment/IAM)
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
        <p className="text-[10.5px] text-muted-foreground leading-relaxed">
          {selectedCredential.description || `Using ${selectedCredential.name}`}
          {selectedCredential.region && ` in ${selectedCredential.region}`}
        </p>
      )}

      {!loading && credentials.length === 0 && !error && (
        <p className="text-[10.5px] text-amber-600 dark:text-amber-400 leading-relaxed">
          No {PROVIDER_LABELS[provider]} credentials configured.{' '}
          <Link
            to={`/ingestion/credentials?add=${provider}`}
            className="underline hover:text-amber-500 dark:hover:text-amber-300"
          >
            Add credentials
          </Link>{' '}
          or use environment variables/IAM roles.
        </p>
      )}
    </div>
  );
}
