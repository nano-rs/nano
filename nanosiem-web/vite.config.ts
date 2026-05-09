import path from 'path';
import { readFileSync } from 'fs';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, Plugin } from 'vite';

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

// SHA-256 hash of the inline theme initialization script in index.html.
// If that script changes, regenerate with:
//   node -e "const c=require('crypto');const fs=require('fs');const html=fs.readFileSync('index.html','utf8');const m=html.match(/<script>\n([\s\S]*?)<\/script>/);console.log('sha256-'+c.createHash('sha256').update(m[0].replace('<script>','').replace('</script>','')).digest('base64'))"
const THEME_SCRIPT_HASH = 'sha256-xDrT8IFmjIpMzTvgu+zkap91EejskcGBkCScJ4QjSMc=';

function cspPlugin(): Plugin {
  return {
    name: 'csp',
    transformIndexHtml: {
      order: 'pre',
      handler(html, ctx) {
        const isDev = !!ctx.server;

        // Dev needs 'unsafe-inline' for Vite HMR + React Refresh injected scripts.
        // Prod uses a hash allowlist for the single inline theme script.
        const scriptSrc = isDev
          ? "'self' 'unsafe-inline'"
          : `'self' '${THEME_SCRIPT_HASH}'`;

        // Dev: allow direct localhost API access (bypass Vite proxy) for testing.
        // Prod: 'self' covers all requests (nginx proxies everything same-origin).
        // CSP3: 'self' on https pages also matches wss:// same-origin.
        const connectSrc = isDev
          ? "'self' http://localhost:3000 http://localhost:3001 http://localhost:3002 ws://localhost:*"
          : "'self'";

        const csp = [
          "default-src 'self'",
          `script-src ${scriptSrc}`,
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
          "img-src 'self' data: blob:",
          "font-src 'self' data: https://fonts.gstatic.com",
          `connect-src ${connectSrc}`,
          "base-uri 'self'",
          "form-action 'self'",
        ].join('; ');

        return html.replace('__CSP__', csp);
      },
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
  plugins: [cspPlugin(), tailwindcss(), react()],
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
