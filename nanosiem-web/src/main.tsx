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
