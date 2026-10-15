// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
export function InventoryRepositoryEditor() {
  const { user } = useAuth();
  const client = useQueryClient();
  const key = ['marketplace-repositories', user?.id, user?.active_tenant?.id];
  const repos = useQuery({ queryKey: key, queryFn: () => api.marketplace.listRepos() });
  const [editing, setEditing] = useState<string>();
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [path, setPath] = useState('enrichments');
  const create = useMutation({ mutationFn: () => editing ? api.marketplace.updateRepo(editing, { name, branch, enrichments_path: path }) : api.marketplace.createRepo({ name, url, branch, enrichments_path: path }), onSuccess: () => { void client.invalidateQueries({ queryKey: key }); } });
  const sync = useMutation({ mutationFn: (id: string) => api.marketplace.syncRepo(id), onSuccess: () => { void client.invalidateQueries({ queryKey: key }); } });
  return <section aria-label="Git bundle connection" className="space-y-3 py-3">
    <p>Connect a tenant repository using the existing bundle importer. Credentials stay in the configured repository service.</p>
    <Label htmlFor="bundle-name">Name</Label><Input id="bundle-name" value={name} onChange={e => setName(e.target.value)} />
    <Label htmlFor="bundle-url">Repository URL (no embedded credentials)</Label><Input id="bundle-url" disabled={!!editing} value={url} onChange={e => setUrl(e.target.value)} />
    <Label htmlFor="bundle-branch">Branch</Label><Input id="bundle-branch" value={branch} onChange={e => setBranch(e.target.value)} />
    <Label htmlFor="bundle-path">Bundle path</Label><Input id="bundle-path" value={path} onChange={e => setPath(e.target.value)} />
    <Button disabled={create.isPending || !name || !url} onClick={() => create.mutate()}>{editing ? 'Save repository' : 'Connect repository'}</Button>
    {editing && <Button variant="outline" onClick={() => { setEditing(undefined); setName(''); setUrl(''); }}>New connection</Button>}
    {(create.isError || sync.isError || repos.isError) && <p role="alert">Repository operation failed.</p>}
    {repos.data?.map(repo => <div key={repo.id} className="border-t py-2">
      <p>{repo.name}</p><p className="font-mono text-[10.5px]">{repo.last_sync_commit ?? 'No imported commit'} · {repo.last_sync_status ?? 'Not synced'}</p>
      <Button variant="outline" onClick={() => { setEditing(repo.id); setName(repo.name); setUrl(repo.url); setBranch(repo.branch); setPath(repo.enrichments_path); }}>Edit repository</Button>
      <Button variant="outline" disabled={sync.isPending} onClick={() => sync.mutate(repo.id)}>Sync bundle</Button>
    </div>)}
  </section>;
}
