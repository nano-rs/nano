// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4941: the retired ingestion pages redirect into Log Sources, keeping the
 * item a link named.
 *
 * - /ingestion/source-configurations      → Cloud pull
 * - /ingestion/source-configurations/:id  → /ingestion/log-sources/inputs/:id
 * - /ingestion/credentials[?add=|?cred=]  → Cloud pull, or Pull feeds for a
 *   connector credential, with the add form or the credential opened
 * - /ingestion/credentials/:id            → same, by the credential's provider; a
 *   failed lookup stays here with a retry, a 404 says the credential is gone
 * - /ingestion/credentials/new            → Cloud pull with the add form
 * - /ingestion/pull-feeds, /ingestion/connector-feeds → Pull feeds
 */

import { useQuery } from '@tanstack/react-query';
import { Link, Navigate, useLocation, useParams } from 'react-router-dom';

import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Button } from '@/components/ui/button';
import { api, ApiClientError } from '@/lib/api';
import { CLOUD_PULL_PATH, PULL_FEEDS_PATH, credentialTarget, sourceConfigPath } from '@/lib/ingestion-paths';

export function LegacySourceConfigRedirect() {
  const { id } = useParams<{ id?: string }>();
  return <Navigate replace to={id ? sourceConfigPath(id) : CLOUD_PULL_PATH} />;
}

export function LegacyPullFeedsRedirect() {
  const { search } = useLocation();
  return <Navigate replace to={PULL_FEEDS_PATH + search} />;
}

export function LegacyCredentialRedirect({ adding = false }: { adding?: boolean }) {
  const { id: pathId } = useParams<{ id?: string }>();
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  const add = adding ? params.get('add') ?? 'aws_s3' : params.get('add');
  const id = pathId ?? params.get('cred');
  const cred = useQuery({
    queryKey: ['credential', id],
    queryFn: () => api.getCredential(id as string),
    enabled: !!id,
    retry: false,
  });
  if (!id) return <Navigate replace to={credentialTarget(add, { add })} />;
  if (cred.isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <LoadingIcon className="w-5 h-5 text-muted-foreground" />
      </div>
    );
  }
  // The destination depends on the provider (cloud → Cloud pull, connector →
  // Pull feeds), and the destination consumes the id. So it is only chosen
  // after a successful lookup: a transient failure keeps this URL and the id
  // and offers a retry (NAN-4941 review), and a confirmed 404 says so.
  if (cred.isError || !cred.data) {
    const notFound = cred.error instanceof ApiClientError && cred.error.status === 404;
    return (
      <div className="px-5 py-8 max-w-[640px] space-y-2" data-testid={notFound ? 'legacy-credential-not-found' : 'legacy-credential-error'} role="alert">
        <div className="text-[13px] font-semibold text-foreground">
          {notFound ? 'Credential not found' : 'Could not look up this credential'}
        </div>
        <div className="text-[11.5px] text-muted-foreground leading-relaxed">
          <span className="font-mono text-foreground/80">{id}</span>{' '}
          {notFound
            ? 'does not exist (it may have been deleted). Credentials now live under Log Sources.'
            : `could not be loaded${cred.error instanceof Error ? `: ${cred.error.message}` : ''}. Retry to open it where it now lives.`}
        </div>
        <div className="flex items-center gap-2 pt-1">
          {!notFound && (
            <Button size="sm" className="h-7 text-[11.5px]" onClick={() => void cred.refetch()} disabled={cred.isFetching}>
              Retry
            </Button>
          )}
          <Button asChild size="sm" variant="outline" className="h-7 text-[11.5px]">
            <Link to={CLOUD_PULL_PATH}>Cloud pull</Link>
          </Button>
          <Button asChild size="sm" variant="outline" className="h-7 text-[11.5px]">
            <Link to={PULL_FEEDS_PATH}>Pull feeds</Link>
          </Button>
        </div>
      </div>
    );
  }
  return <Navigate replace to={credentialTarget(cred.data.provider, { add, cred: id })} />;
}

/** `/ingestion/credentials/new`: the add form, AWS unless `?add=` names another provider. */
export function LegacyCredentialNewRedirect() {
  return <LegacyCredentialRedirect adding />;
}

export default LegacyCredentialRedirect;
