// SPDX-License-Identifier: AGPL-3.0-or-later

// Self-hosted Geist fonts (air-gap: no Google Fonts CDN). Family names
// 'Geist' / 'Geist Mono' match --font-sans / --font-mono in index.css.
import '@fontsource/geist/400.css';
import '@fontsource/geist/500.css';
import '@fontsource/geist/600.css';
import '@fontsource/geist/700.css';
import '@fontsource/geist-mono/400.css';
import '@fontsource/geist-mono/500.css';
import '@fontsource/geist-mono/600.css';
import '@fontsource/geist-mono/700.css';

import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import { toast } from 'sonner';
import { watchForNewBuild } from './lib/build-update';
import { initTenantPathAlias } from './lib/tenant-auth-shell';
import { resolveTenantlessDeepLink } from './lib/tenant-deep-link';

if (import.meta.env.PROD) {
  watchForNewBuild(() => {
    toast('A new version of nano is available.', {
      id: 'build-update',
      duration: Infinity,
      description: 'Save your work, then reload to update.',
      action: { label: 'Reload', onClick: () => window.location.reload() },
    });
  });
}

// NAN-4800: a tenant-less product deep link (`/ingestion/...` on a pooled
// host) cannot authenticate: the refresh has no tenant selector and answers
// `tenant_required`, which used to dump the user at login. When this browser
// has an enterprise-shared tenant on record, go to `/t/<tenant>/<path>` before
// anything boots, but only after verifying the hint against the live session.
// Dedicated deployments are checked against the server-owned deployment mode.
void resolveTenantlessDeepLink(window.location).then((tenantlessRedirect) => {
  if (tenantlessRedirect !== undefined) window.location.replace(tenantlessRedirect);
  else bootApp();
});

function bootApp(): void {
  // NAN-4152: resolve a `/t/<alias>` web path alias BEFORE the first render, so
  // every tenant selector the app derives from the path is the canonical slug.
  // Off a /t/ path this is a no-op; any failure leaves no alias (the segment is
  // treated as a slug, as before).
  void initTenantPathAlias(window.location.pathname)
    .catch(() => undefined)
    .finally(() => {
      createRoot(document.getElementById('root')!).render(
        <App />
      );
    });
}
