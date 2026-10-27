// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { formatDistanceToNowStrict } from 'date-fns';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { UserDetail } from '@/lib/api/types';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { SettingsSection } from '@/components/settings/SettingsSection';
import {
  checkLookupUrl,
  normalizeLookupHost,
  utf8Bytes,
} from '@/lib/lookup-url-policy';

function addedAt(raw: string): string {
  const date = new Date(raw);
  return date.getTime() === 0 || !Number.isFinite(date.getTime())
    ? 'Unknown (migrated)'
    : formatDistanceToNowStrict(date, { addSuffix: true });
}

const NIL_USER_ID = '00000000-0000-0000-0000-000000000000';

function AddedBy({
  id,
  createdAt,
  user,
}: {
  id: string;
  createdAt: string;
  user?: Pick<UserDetail, 'name' | 'email'>;
}) {
  const migrated = id === NIL_USER_ID;
  const name = migrated ? '' : user?.name.trim() || user?.email.trim() || '';
  const words = name.split(/\s+/);
  const initials =
    words.length > 1
      ? words
          .slice(0, 2)
          .map((word) => Array.from(word)[0])
          .join('')
      : Array.from(name.split('@')[0]).slice(0, 2).join('');
  const label = migrated ? 'Unknown (migrated)' : name || 'unknown user';
  return (
    <TooltipProvider>
      {name && (
        <Avatar
          aria-hidden="true"
          className="size-[18px] rounded-sm font-mono text-[9px]"
        >
          <AvatarFallback className="rounded-sm bg-muted text-muted-foreground">
            {initials.toUpperCase()}
          </AvatarFallback>
        </Avatar>
      )}
      <div className="min-w-0 leading-3">
        <Tooltip>
          <TooltipTrigger asChild>
            <span
              tabIndex={0}
              className="block truncate font-mono text-[10.5px]"
            >
              {label}
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-[320px] space-y-1 break-all rounded-md shadow-none">
            <p className="font-mono text-[10.5px]">{label}</p>
            {name && user?.email && (
              <p className="font-mono text-[10.5px]">{user.email}</p>
            )}
            <p className="font-mono text-[10.5px]">{id}</p>
          </TooltipContent>
        </Tooltip>
        <time
          title={createdAt}
          dateTime={createdAt}
          className="font-mono text-[10.5px]"
        >
          {addedAt(createdAt)}
        </time>
      </div>
    </TooltipProvider>
  );
}

export function LookupUrlAllowlist() {
  useDocumentTitle('Lookup URL allowlist');
  const { user, hasPermission } = useAuth();
  const shared = user?.deployment_mode === 'enterprise_shared';
  const canEdit = hasPermission('settings:system');
  const canViewUsers = hasPermission('users:view');
  const client = useQueryClient();
  const [host, setHost] = useState('');
  const [note, setNote] = useState('');
  const [filter, setFilter] = useState('');
  const [pendingRemove, setPendingRemove] = useState<string | null>(null);
  const [testUrl, setTestUrl] = useState('');
  const tenant = browserTenantRuntime.current().key;
  const queryKey = ['lookup-url-allowlist', tenant];
  const list = useQuery({
    queryKey,
    queryFn: () => api.lookupUrlAllowlist.get(),
    staleTime: 0,
    enabled: shared,
  });
  const refresh = () => client.invalidateQueries({ queryKey });
  const add = useMutation({
    mutationFn: (entry: { host: string; note: string }) =>
      api.lookupUrlAllowlist.add(entry.host, entry.note),
    onSuccess: () => {
      setHost('');
      setNote('');
      void refresh();
    },
    onError: (error) => {
      if ((error as { status?: number })?.status === 409) void refresh();
    },
  });
  const remove = useMutation({
    mutationFn: (value: string) => api.lookupUrlAllowlist.remove(value),
    onSuccess: () => {
      setPendingRemove(null);
      void refresh();
    },
    onError: (error) => {
      if ((error as { status?: number })?.status === 404) {
        setPendingRemove(null);
        void refresh();
      }
    },
  });
  const entries = list.data?.entries ?? [];
  const users = useQuery({
    queryKey: ['users', tenant],
    queryFn: () => api.listUsers(),
    enabled:
      shared &&
      canViewUsers &&
      entries.some((entry) => entry.created_by !== NIL_USER_ID),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  // Disabled queries can still expose cached data; gate rendering as well as IO.
  const usersById = new Map(
    (canViewUsers && !users.isError ? (users.data?.users ?? []) : []).map(
      (user) => [user.id, user],
    ),
  );
  const normalized = normalizeLookupHost(host);
  const hint = !host
    ? null
    : (normalized.error ??
      (entries.some((entry) => entry.host === normalized.value)
        ? 'host already in allowlist'
        : null));
  const noteError =
    utf8Bytes(note) > 1000 ? 'note must be at most 1000 bytes' : null;
  const busy = add.isPending || remove.isPending || list.isFetching;
  const error = add.error ?? remove.error ?? list.error;
  const shown = entries.filter((entry) =>
    (entry.host + ' ' + entry.note)
      .toLowerCase()
      .includes(filter.trim().toLowerCase()),
  );
  const checked =
    testUrl && list.data
      ? checkLookupUrl(
          testUrl,
          entries.map((entry) => entry.host),
        )
      : null;
  if (!shared)
    return (
      <p className="px-6 py-5 text-xs text-muted-foreground">
        Lookup URL allowlists are managed for shared tenants.
      </p>
    );

  return (
    <div className="max-w-[1160px] space-y-6 px-6 py-5 text-xs">
      <header className="space-y-2">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-[18px] font-semibold tracking-tight text-foreground">
              Lookup URL allowlist
            </h1>
            <p className="mt-1 text-[11.5px] leading-relaxed text-muted-foreground">
              Hosts this tenant can fetch lookup files from. Nothing is allowed
              until an admin adds it.
            </p>
          </div>
          {hasPermission('audit:view') && (
            <Button
              asChild
              variant="link"
              size="sm"
              className="h-7 px-0 text-[11.5px] shadow-none"
            >
              <Link to="/settings/audit?action=inputlookup_allowlist_updated">
                View audit history
              </Link>
            </Button>
          )}
        </div>
        <p className="font-mono text-[10.5px] text-muted-foreground">
          {list.data
            ? entries.length + ' hosts · changes apply within 30 seconds'
            : 'Loading allowlist…'}
        </p>
      </header>

      <div className="space-y-5">
        <SettingsSection
          title="Allowed hosts"
          description={
            <ul className="space-y-2">
              <li>
                Public HTTPS on port <span className="font-mono">443</span>{' '}
                only.
              </li>
              <li>
                Exact host: <span className="font-mono">intel.example.com</span>
                .
              </li>
              <li>
                Subdomains: <span className="font-mono">*.example.com</span>,
                excluding the parent itself.
              </li>
              <li>
                No scheme, path, port or IP. Use ASCII or punycode and a
                registrable domain.
              </li>
            </ul>
          }
        >
          {canEdit && (
            <form
              className="space-y-2 border-b border-border p-3"
              onSubmit={(event) => {
                event.preventDefault();
                if (
                  normalized.value &&
                  !hint &&
                  !noteError &&
                  !busy &&
                  list.data
                )
                  add.mutate({ host: normalized.value, note });
              }}
            >
              <div className="grid gap-2 sm:grid-cols-[minmax(130px,1fr)_minmax(100px,1fr)_auto]">
                <Input
                  aria-label="Host"
                  aria-describedby="lookup-host-hint"
                  aria-invalid={!!hint}
                  className="h-7 min-w-0 font-mono text-[11.5px] shadow-none"
                  placeholder="intel.example.com"
                  value={host}
                  onChange={(event) => {
                    setHost(event.target.value);
                    add.reset();
                  }}
                  disabled={add.isPending || remove.isPending}
                  required
                  maxLength={255}
                />
                <Input
                  aria-label="Note"
                  aria-describedby="lookup-host-hint"
                  className="h-7 min-w-0 text-[11.5px] shadow-none"
                  placeholder="Who needs it, and why"
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  disabled={add.isPending || remove.isPending}
                  maxLength={1000}
                />
                <Button
                  size="sm"
                  className="h-7 px-2.5 text-[11.5px] shadow-none"
                  type="submit"
                  disabled={
                    busy ||
                    !list.data ||
                    !normalized.value ||
                    !!hint ||
                    !!noteError
                  }
                >
                  Add host
                </Button>
              </div>
              <p
                id="lookup-host-hint"
                className={
                  'text-[10.5px] ' +
                  (hint || noteError
                    ? 'text-destructive'
                    : 'text-muted-foreground')
                }
              >
                {hint ||
                  noteError ||
                  (normalized.value
                    ? normalized.value.startsWith('*.')
                      ? 'Allows subdomains of ' + normalized.value.slice(2)
                      : 'Allows https://' + normalized.value + ' only'
                    : 'Enter a hostname. Press Enter to add.')}
              </p>
            </form>
          )}
          {!canEdit && (
            <p className="border-b border-border px-4 py-3 text-[11px] text-muted-foreground">
              Read-only. A tenant admin manages allowed hosts.
            </p>
          )}
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-2">
            <span className="font-mono text-[10.5px] text-muted-foreground">
              {list.data
                ? (filter ? shown.length + ' of ' : '') +
                  entries.length +
                  (entries.length === 1 ? ' host' : ' hosts')
                : 'Loading…'}
            </span>
            <Input
              aria-label="Filter hosts"
              placeholder="Filter hosts or notes"
              className="h-7 w-full text-[11.5px] shadow-none sm:w-[180px]"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
            />
          </div>
          {error && (
            <div
              role="alert"
              className="space-y-2 border-b border-border px-4 py-3 text-destructive"
            >
              <p>
                {error instanceof Error
                  ? error.message
                  : 'Unable to update allowlist'}
              </p>
              {list.isError && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 text-[11.5px] shadow-none"
                  onClick={() => void refresh()}
                >
                  Retry
                </Button>
              )}
            </div>
          )}
          {list.isPending ? (
            <p className="px-4 py-5 text-muted-foreground">
              Loading allowlist…
            </p>
          ) : list.data && shown.length === 0 ? (
            <div className="px-4 py-5 text-[11.5px] text-muted-foreground">
              <p className="font-medium text-foreground">
                {entries.length ? 'No matching hosts' : 'No hosts allowed yet'}
              </p>
              <p className="mt-1">
                {entries.length
                  ? 'Try a different host or note.'
                  : 'All lookup URL fetches are blocked until an admin adds a host.'}
              </p>
            </div>
          ) : (
            shown.map((entry) => (
              <div
                key={entry.host}
                className="grid min-h-7 grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 border-b border-border px-3 last:border-b-0 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)_minmax(0,1fr)_auto]"
              >
                <div className="flex min-h-7 min-w-0 items-center gap-2">
                  <span
                    className="min-w-0 truncate font-mono text-[11.5px]"
                    title={entry.host}
                  >
                    {entry.host}
                  </span>
                  <Badge
                    variant="secondary"
                    className="shrink-0 rounded-sm font-mono text-[10.5px] font-normal"
                  >
                    {entry.host.startsWith('*.') ? 'SUBDOMAINS' : 'EXACT'}
                  </Badge>
                </div>
                <span
                  className="col-start-1 min-w-0 truncate text-[11px] text-muted-foreground xl:col-start-auto"
                  title={entry.note}
                >
                  {entry.note || 'No note'}
                </span>
                <div className="col-start-2 row-start-1 row-span-3 flex items-center justify-end gap-1 xl:col-start-4 xl:row-span-1">
                  {canEdit &&
                    (pendingRemove === entry.host ? (
                      <div
                        className="flex items-center gap-1"
                        role="group"
                        aria-label={'Remove ' + entry.host + '?'}
                      >
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-1.5 text-[11px] shadow-none"
                          disabled={remove.isPending}
                          onClick={() => {
                            setPendingRemove(null);
                            remove.reset();
                          }}
                        >
                          Keep
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          className="h-7 px-2 text-[11px] shadow-none"
                          disabled={busy}
                          onClick={() => remove.mutate(entry.host)}
                        >
                          Remove
                        </Button>
                      </div>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-1.5 text-[11px] text-muted-foreground hover:text-destructive shadow-none"
                        disabled={busy}
                        aria-label={'Remove ' + entry.host}
                        onClick={() => {
                          remove.reset();
                          setPendingRemove(entry.host);
                        }}
                      >
                        Remove
                      </Button>
                    ))}
                </div>
                <div className="col-start-1 flex min-h-7 min-w-0 items-center gap-1.5 whitespace-nowrap text-muted-foreground xl:col-start-3 xl:row-start-1">
                  <AddedBy
                    id={entry.created_by}
                    createdAt={entry.created_at}
                    user={usersById.get(entry.created_by)}
                  />
                </div>
              </div>
            ))
          )}
        </SettingsSection>

        <SettingsSection
          title="Check a URL"
          description="Check the URL and host against this allowlist without fetching it. DNS and the server’s egress checks still run when a lookup is fetched."
        >
          <div className="p-3">
            <Input
              aria-label="URL to check"
              type="text"
              value={testUrl}
              onChange={(event) => setTestUrl(event.target.value)}
              placeholder="https://intel.example.com/feeds/ioc.csv"
              className="h-7 min-w-0 font-mono text-[11.5px] shadow-none"
              aria-describedby="lookup-url-result"
            />
          </div>
          {testUrl && (
            <div
              id="lookup-url-result"
              role="status"
              className="flex items-start gap-2 border-t border-border bg-muted/20 px-4 py-3 text-[11.5px]"
            >
              <span
                aria-hidden="true"
                className={
                  'mt-1 size-1.5 shrink-0 rounded-full ' +
                  (checked?.value ? 'bg-primary' : 'bg-muted-foreground')
                }
              />
              <p>
                {!list.data ? (
                  'Load the allowlist before checking a URL.'
                ) : checked?.value ? (
                  <>
                    Allowed by{' '}
                    <span className="font-mono">{checked.value.entry}</span>.
                  </>
                ) : (
                  checked?.error
                )}
              </p>
            </div>
          )}
        </SettingsSection>
      </div>
    </div>
  );
}
