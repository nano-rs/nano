// SPDX-License-Identifier: AGPL-3.0-or-later

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { connectorSecretFields } from './connector-credentials';

const FIELD_LABEL = 'text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground';

/** Provider-specific secret inputs of a connector credential (NAN-4914). */
export function ConnectorCredentialFields({
  provider,
  values,
  onChange,
}: {
  provider: string;
  values: Record<string, string>;
  onChange: (values: Record<string, string>) => void;
}) {
  const specs = useQuery({ queryKey: ['connectorSpecs'], queryFn: () => api.connectorFeeds.listSpecs() });
  const fields = connectorSecretFields(provider, specs.data ?? []);
  if (specs.isLoading) return <div className="text-[11px] text-muted-foreground">Loading connector fields…</div>;
  if (fields.length === 0) {
    return <div className="text-[11px] text-red-600">No connector uses the {provider} provider.</div>;
  }
  return (
    <div className="space-y-2.5">
      {fields.map((f) =>
        f === 'credentials_json' ? (
          <div key={f} className="space-y-1.5">
            <Label htmlFor={`conn-${f}`} className={FIELD_LABEL}>Service account key (JSON)</Label>
            <Textarea
              id={`conn-${f}`}
              className="min-h-[96px] text-[11px] font-mono"
              value={values[f] ?? ''}
              onChange={(e) => onChange({ ...values, [f]: e.target.value })}
            />
          </div>
        ) : (
          <div key={f} className="space-y-1.5">
            <Label htmlFor={`conn-${f}`} className={FIELD_LABEL}>{f}</Label>
            <Input
              id={`conn-${f}`}
              type="password"
              autoComplete="off"
              className="h-8 text-[12px] font-mono"
              value={values[f] ?? ''}
              onChange={(e) => onChange({ ...values, [f]: e.target.value })}
            />
          </div>
        ),
      )}
    </div>
  );
}
