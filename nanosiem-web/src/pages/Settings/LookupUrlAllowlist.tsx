// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table';

export function LookupUrlAllowlist() {
  useDocumentTitle('Lookup URL allowlist');
  const { user } = useAuth();
  const shared = user?.deployment_mode === 'enterprise_shared';
  const client = useQueryClient();
  const [host, setHost] = useState('');
  const [note, setNote] = useState('');
  const queryKey = ['lookup-url-allowlist', browserTenantRuntime.current().key];
  const list = useQuery({
    queryKey,
    queryFn: () => api.lookupUrlAllowlist.get(),
    staleTime: 0,
    enabled: shared,
  });
  const refresh = () => client.invalidateQueries({ queryKey });
  const add = useMutation({
    mutationFn: () => api.lookupUrlAllowlist.add(host, note),
    onSuccess: () => {
      setHost('');
      setNote('');
      void refresh();
    },
  });
  const remove = useMutation({
    mutationFn: (value: string) => api.lookupUrlAllowlist.remove(value),
    onSuccess: refresh,
  });
  const error = add.error ?? remove.error ?? list.error;
  if (!shared)
    return (
      <p className="px-6 py-5 text-xs">
        Lookup URL allowlists are managed for shared tenants.
      </p>
    );
  return (
    <div className="px-6 py-5 space-y-5 text-xs">
      <div>
        <h1 className="text-[18px] font-semibold tracking-tight text-foreground">
          Lookup URL allowlist
        </h1>
        <p className="mt-0.5 font-mono text-[10.5px] text-muted-foreground">
          {list.data?.entries.length ?? 0} hosts · changes apply within 30
          seconds
        </p>
      </div>
      <p className="max-w-[720px] text-[11.5px] leading-relaxed text-muted-foreground">
        Hosts must serve public HTTPS on port 443. No hosts are allowed until an
        admin adds them. Use an exact host or{' '}
        <span className="font-mono">*.example.com</span> for subdomains.
      </p>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate();
        }}
      >
        <label className="block min-w-0 w-full sm:w-[240px] space-y-1 text-[11.5px] font-medium">
          Host
          <Input
            aria-label="Host"
            className="h-7 font-mono text-xs"
            placeholder="intel.example.com"
            value={host}
            onChange={(event) => setHost(event.target.value)}
            required
            maxLength={255}
          />
        </label>
        <label className="block min-w-0 flex-1 basis-[240px] space-y-1 text-[11.5px] font-medium">
          Note
          <Input
            aria-label="Note"
            className="h-7 text-xs"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            maxLength={1000}
          />
        </label>
        <Button
          size="sm"
          className="h-7 px-2.5 text-[11.5px] shadow-none"
          type="submit"
          disabled={add.isPending || remove.isPending || !host}
        >
          Add host
        </Button>
      </form>
      {error && (
        <p role="alert" className="text-destructive">
          {error instanceof Error
            ? error.message
            : 'Unable to update allowlist'}
        </p>
      )}
      <Table className="text-xs">
        <TableHeader>
          <TableRow className="border-border bg-card/50 hover:bg-card/50">
            {['Host', 'Note', 'Added by', 'Added at'].map((label) => (
              <TableHead
                key={label}
                className="h-7 px-3 text-[10px] uppercase tracking-[0.08em]"
              >
                {label}
              </TableHead>
            ))}
            <TableHead className="h-7 px-3">
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.isPending ? (
            <TableRow>
              <TableCell
                colSpan={5}
                className="px-3 py-6 text-center text-[11.5px] text-muted-foreground"
              >
                Loading allowlist…
              </TableCell>
            </TableRow>
          ) : list.data?.entries.length === 0 ? (
            <TableRow>
              <TableCell
                colSpan={5}
                className="px-3 py-6 text-center text-[11.5px] text-muted-foreground"
              >
                No hosts allowed.
              </TableCell>
            </TableRow>
          ) : (
            list.data?.entries.map((entry) => (
              <TableRow
                key={entry.host}
                className="h-7 border-border/60 hover:bg-foreground/[0.025]"
              >
                <TableCell className="px-3 py-0 font-mono whitespace-nowrap">
                  {entry.host}
                </TableCell>
                <TableCell className="min-w-[160px] max-w-[320px] px-3 py-0 break-words">
                  {entry.note}
                </TableCell>
                <TableCell className="px-3 py-0 font-mono text-[10.5px] text-muted-foreground whitespace-nowrap">
                  {entry.created_by === '00000000-0000-0000-0000-000000000000'
                    ? 'Unknown (migrated)'
                    : entry.created_by}
                </TableCell>
                <TableCell className="px-3 py-0 font-mono text-[10.5px] text-muted-foreground whitespace-nowrap">
                  {entry.created_at === '1970-01-01T00:00:00Z'
                    ? 'Unknown (migrated)'
                    : entry.created_at}
                </TableCell>
                <TableCell className="px-3 py-0 text-right">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-[11.5px]"
                    disabled={remove.isPending || add.isPending}
                    onClick={() => remove.mutate(entry.host)}
                    aria-label={`Remove ${entry.host}`}
                  >
                    Remove
                  </Button>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
