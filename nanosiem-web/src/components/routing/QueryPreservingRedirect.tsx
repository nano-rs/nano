// SPDX-License-Identifier: AGPL-3.0-or-later

import { Navigate, useLocation, useParams } from 'react-router-dom';
import { fillParams, redirectTarget, type RedirectQuery } from './redirects';

/**
 * `<Navigate replace>` that keeps the query string (and hash) unless told to
 * drop it. The name ends in "Redirect" so scripts/release/check-e2e-coverage.py
 * classifies the routes that render it as redirects. `:name` segments in `to`
 * are filled from the matched route's params (NAN-5859).
 */
export function QueryPreservingRedirect({ to, query = 'keep' }: { to: string; query?: RedirectQuery }) {
  const { search, hash } = useLocation();
  const params = useParams();
  return <Navigate replace to={redirectTarget(fillParams(to, params), search, hash, query)} />;
}
