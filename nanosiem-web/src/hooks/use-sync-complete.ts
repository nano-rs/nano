// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef } from 'react';
import { RepositorySyncTracker, type SyncRow } from './repository-sync-state';

/** Poll-driven completion, including syncs that finish before the first GET. */
export function useSyncCompleteEffect<R extends SyncRow>(
  repos: readonly R[], activeId: string | null, onComplete: (repo: R) => void,
) {
  const tracker = useRef(new RepositorySyncTracker());
  const callback = useRef(onComplete);
  callback.current = onComplete;
  useEffect(() => {
    for (const repo of repos) {
      if (tracker.current.observe(repo) && repo.id === activeId) callback.current(repo);
    }
  }, [repos, activeId]);
  return (id: string, startedAt?: string) => tracker.current.start(id, startedAt);
}
