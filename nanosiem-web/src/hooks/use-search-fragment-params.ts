// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useEffect, useMemo } from 'react';
import { createSearchParams, useLocation, useNavigate, type NavigateOptions, type URLSearchParamsInit } from 'react-router-dom';

import { readSearchFragment } from '@/lib/search-fragment';
export { readSearchFragment } from '@/lib/search-fragment';

export function useSearchFragmentParams(): [URLSearchParams, (next: URLSearchParamsInit, options?: NavigateOptions) => void] {
  const location = useLocation();
  const navigate = useNavigate();
  const params = useMemo(() => readSearchFragment(location.search, location.hash), [location.search, location.hash]);
  const setParams = useCallback((next: URLSearchParamsInit, options?: NavigateOptions) => {
    const hash = createSearchParams(next).toString();
    navigate({ pathname: location.pathname, search: '', hash: hash ? `#${hash}` : '' }, options);
  }, [navigate, location.pathname]);

  // Router replace uses history.replaceState in the browser, preserving Back.
  // Legacy links must reach the SPA before this compatibility migration can run.
  useEffect(() => {
    if (location.search) setParams(params, { replace: true, state: location.state });
  }, [location.search, location.state, params, setParams]);
  return [params, setParams];
}
