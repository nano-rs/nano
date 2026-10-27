import path from 'path';
import { createHash } from 'node:crypto';
import { readFileSync } from 'fs';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, Plugin } from 'vite';
import { applyCsp, assertInlineScriptsAllowed } from './csp';

// Stamp the package.json version into the bundle as `__APP_VERSION__` so
// pre-auth surfaces (Login terminal banner) can display a real release
// without an extra fetch. Single source of truth: `nanosiem-web/package.json`.
const pkgVersion = JSON.parse(
  readFileSync(path.resolve(__dirname, 'package.json'), 'utf-8'),
).version as string;

// Edition flag for the open-core split. `@/enterprise` resolves to the real
// implementations under `src/enterprise/` by default (matches existing prod
// + dev expectations); `VITE_EDITION=open` opts into the no-op stubs under
// `src/enterprise-stubs/` for open-core releases.
// See ~/.claude/plans/buzzing-brewing-crown.md.
function resolveEdition(env: Record<string, string>): 'open' | 'enterprise' {
  return env.VITE_EDITION === 'enterprise' ? 'enterprise' : 'open';
}

// CSP for index.html. Production hashes are derived from the inline scripts at
// build time (see csp.ts); the build re-checks the emitted HTML and fails if an
// inline script is not covered, so the policy can't drift from the script.
function cspPlugin(): Plugin {
  return {
    name: 'csp',
    transformIndexHtml: {
      order: 'pre',
      handler(html, ctx) {
        return applyCsp(html, !!ctx.server);
      },
    },
  };
}

function cspVerifyPlugin(): Plugin {
  return {
    name: 'csp-verify',
    apply: 'build',
    enforce: 'post',
    writeBundle(_options, bundle) {
      for (const asset of Object.values(bundle)) {
        if (asset.type !== 'asset' || !asset.fileName.endsWith('.html')) continue;
        const html = typeof asset.source === 'string'
          ? asset.source
          : new TextDecoder().decode(asset.source);
        assertInlineScriptsAllowed(html);
      }
    },
  };
}

const VENDOR_CHUNKS: Record<string, string[]> = {
  'vendor-react': ['react', 'react-dom', 'react-router-dom'],
  'vendor-query': ['@tanstack/react-query'],
  'vendor-recharts': ['recharts'],
  'vendor-codemirror': [
    '@codemirror/autocomplete',
    '@codemirror/commands',
    '@codemirror/lang-javascript',
    '@codemirror/language',
    '@codemirror/lint',
    '@codemirror/state',
    '@codemirror/view',
    '@lezer/highlight',
    'codemirror',
  ],
  'vendor-radix': [
    '@radix-ui/react-accordion',
    '@radix-ui/react-alert-dialog',
    '@radix-ui/react-avatar',
    '@radix-ui/react-checkbox',
    '@radix-ui/react-collapsible',
    '@radix-ui/react-context-menu',
    '@radix-ui/react-dialog',
    '@radix-ui/react-dropdown-menu',
    '@radix-ui/react-hover-card',
    '@radix-ui/react-label',
    '@radix-ui/react-menubar',
    '@radix-ui/react-navigation-menu',
    '@radix-ui/react-popover',
    '@radix-ui/react-progress',
    '@radix-ui/react-radio-group',
    '@radix-ui/react-scroll-area',
    '@radix-ui/react-select',
    '@radix-ui/react-separator',
    '@radix-ui/react-slider',
    '@radix-ui/react-slot',
    '@radix-ui/react-switch',
    '@radix-ui/react-tabs',
    '@radix-ui/react-toast',
    '@radix-ui/react-toggle',
    '@radix-ui/react-toggle-group',
    '@radix-ui/react-tooltip',
  ],
  'vendor-date': ['date-fns', 'date-fns-tz'],
};

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const edition = resolveEdition(env);
  const enterpriseTarget = path.resolve(
    __dirname,
    edition === 'enterprise' ? './src/enterprise' : './src/enterprise-stubs',
  );

  return {
  plugins: [cspPlugin(), tailwindcss(), react(), {
    name: 'build-id',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler(html) {
        // Final HTML includes content-hashed entry/preload URLs, unlike package version.
        const id = createHash('sha256').update(html).digest('hex');
        return [{ tag: 'meta', attrs: { name: 'nano-build-id', content: id }, injectTo: 'head' }];
      },
    },
  }, cspVerifyPlugin()],
  define: {
    __APP_VERSION__: JSON.stringify(pkgVersion),
    __EDITION__: JSON.stringify(edition),
  },
  resolve: {
    // Order matters: '@/enterprise' must come before '@' so the more
    // specific prefix wins.
    alias: [
      { find: /^@\/enterprise(\/|$)/, replacement: `${enterpriseTarget}$1` },
      { find: '@', replacement: path.resolve(__dirname, './src') },
    ],
  },
  optimizeDeps: {
    exclude: ['lucide-react'],
  },
  server: {
    allowedHosts: true, // Allow all hosts (nginx handles external access)
    proxy: {
      // Mirrors nginx routing: search-specific paths → search service (3002),
      // everything else → main API (3000). This makes all requests same-origin
      // so cookie auth (Set-Cookie from login) works for Swagger UI etc.
      '/api/search/history': 'http://localhost:3000',
      '/api/search/share': 'http://localhost:3000',
      '/api/search/shared': 'http://localhost:3000',
      '/api/search/explanation': 'http://localhost:3000',
      '/api/search': 'http://localhost:3002',
      '/api': 'http://localhost:3000',
      '/swagger-ui': 'http://localhost:3000',
      '/api-docs': 'http://localhost:3000',
      '/health': 'http://localhost:3000',
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Vite 8 ships rolldown, whose manualChunks only accepts a function
        // (the rollup object-literal shorthand is gone). This preserves the
        // same vendor split.
        manualChunks(id) {
          if (!id.includes('node_modules/')) return undefined;
          for (const [chunk, pkgs] of Object.entries(VENDOR_CHUNKS)) {
            for (const pkg of pkgs) {
              if (id.includes(`/node_modules/${pkg}/`)) return chunk;
            }
          }
          return undefined;
        },
      },
    },
  },
  };
});
