// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';
import type { AddDataSource } from '@/lib/add-data-sources';
import { ADD_DATA_PATH } from '@/lib/add-data-sources';

export function AssignSourcePanel({ credentialId, initialLabel = '', sources, onAssigned }: {
  credentialId: string; initialLabel?: string; sources: AddDataSource[]; onAssigned?: () => void;
}) {
  const client = useQueryClient();
  const [slug, setSlug] = useState(sources.length === 1 ? sources[0].slug : '');
  const [label, setLabel] = useState(initialLabel);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const selected = sources.find((s) => s.slug === slug);
  if (done) return <div role="status" className="text-xs">Source assigned. Your sender keeps its current token. <Link className="text-primary hover:underline" to="/ingestion/log-sources">View Log sources</Link></div>;
  return <form className="space-y-3 text-xs" onSubmit={async (event) => {
    event.preventDefault(); setBusy(true); setError('');
    try {
      await api.assignIngestSource(credentialId, slug, label.trim());
      await client.invalidateQueries({ queryKey: ['log-sources'] });
      setDone(true); onAssigned?.();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not assign source'); }
    finally { setBusy(false); }
  }}>
    <p className="text-muted-foreground">Keep the same credential and token. New events use the selected source after routing refreshes (about 5 seconds). Historical events and batches already accepted keep their original source label and remain searchable.</p>
    <div className="space-y-1">
      <Label className="text-xs" htmlFor="assign-source-type">Source type</Label>
      <Select value={slug} onValueChange={setSlug}>
        <SelectTrigger id="assign-source-type" className="font-mono"><SelectValue placeholder="Choose a source type" /></SelectTrigger>
        <SelectContent>{sources.map((s) => <SelectItem key={s.slug} value={s.slug}>{s.logSource?.name ?? s.slug}{!s.enrolled ? ' (rolling out)' : ''}</SelectItem>)}</SelectContent>
      </Select>
    </div>
    <div className="space-y-1">
      <Label className="text-xs" htmlFor="assign-source-label">Credential name</Label>
      <Input id="assign-source-label" value={label} maxLength={120} onChange={(e) => setLabel(e.target.value)} required />
    </div>
    {selected && !selected.enrolled && <p role="status">Wait for this source’s parser rollout to finish, then assign it here.</p>}
    {error && <p role="alert" className="text-destructive">{error}</p>}
    <div className="flex items-center justify-between gap-2">
      <Button asChild variant="outline" size="sm"><Link to={`${ADD_DATA_PATH}?convert=${encodeURIComponent(credentialId)}`}>Create custom source</Link></Button>
      <Button type="submit" size="sm" disabled={busy || !selected?.enrolled || !label.trim()}>{busy ? 'Assigning…' : 'Assign source'}</Button>
    </div>
  </form>;
}
