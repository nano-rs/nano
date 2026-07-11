// SPDX-License-Identifier: AGPL-3.0-or-later

import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('..', import.meta.url));
const server = await createServer({
  root,
  configFile: false,
  appType: 'custom',
  logLevel: 'error',
  optimizeDeps: { noDiscovery: true },
  server: { middlewareMode: true },
});

try {
  // Vite is already a direct dependency and provides the Node 20-compatible
  // TypeScript transform used by the production build.
  await server.ssrLoadModule('/tests/mitre-coverage-contract.test.mjs');
} finally {
  await server.close();
}
