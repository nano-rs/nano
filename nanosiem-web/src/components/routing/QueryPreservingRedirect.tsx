// SPDX-License-Identifier: AGPL-3.0-or-later

import { Navigate, useLocation } from 'react-router-dom';
import { redirectTarget, type RedirectQuery } from './redirects';

/**
 * `<Navigate replace>` that keeps the query string (and hash) unless told to
 * drop it. The name ends in "Redirect" so scripts/release/check-e2e-coverage.py
 * classifies the routes that render it as redirects.
 */
export function QueryPreservingRedirect({ to, query = 'keep' }: { to: string; query?: RedirectQuery }) {
  const { search, hash } = useLocation();
  return <Navigate replace to={redirectTarget(to, search, hash, query)} />;
}
