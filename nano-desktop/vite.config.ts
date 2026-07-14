import { fileURLToPath, URL } from 'node:url';

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

/**
 * `@/*` resolves into nanosiem-web/src on purpose. The desktop app reuses the
 * web app's event-flattening rules (event-flatten.ts + the three small modules
 * it leans on) rather than keeping a second copy: those rules encode which
 * fields are ClickHouse defaults, which are internal accelerators, how the OCSF
 * `event`/`unmapped` objects expand into dotted leaves, and how fields bucket
 * into categories. A drifting copy would render the same event differently in
 * the two apps.
 */
const webSrc = fileURLToPath(new URL('../nanosiem-web/src', import.meta.url));
const ownModule = (name: string) =>
  fileURLToPath(new URL(`./node_modules/${name}`, import.meta.url));

/**
 * Packages that MUST be a single instance. The desktop QueryBar and the reused
 * nanosiem-web nPL editor modules both pull CodeMirror; CodeMirror keeps its
 * Facet/Extension identity in @codemirror/state (and its Tree identity in
 * @lezer/common). Two copies of @codemirror/state → an extension built by one is
 * unrecognizable to the EditorView of the other → "Unrecognized extension value
 * in extension set", thrown as the query bar mounts, blanking the Search screen.
 *
 * `resolve.dedupe` and directory aliases don't fix it: the second copy comes in
 * through node_modules-internal imports (e.g. nanosiem-web's @codemirror/lint
 * importing @codemirror/state), which those mechanisms don't reach. A `pre`
 * resolveId hook pins EVERY importer to the desktop's one copy. Vite's dev server
 * (esbuild) deduped these for free, so it only broke in the production build.
 */
const SINGLETON = [
  '@codemirror/state',
  '@codemirror/view',
  '@codemirror/language',
  '@codemirror/autocomplete',
  '@codemirror/commands',
  '@lezer/common',
  '@lezer/highlight',
  '@lezer/lr',
];

const singletonPaths: Record<string, string> = Object.fromEntries(
  // `import.meta.resolve` returns the package's ESM entry (its `import`
  // condition), resolved from this config's location — i.e. the desktop's copy.
  SINGLETON.map((name) => [name, fileURLToPath(import.meta.resolve(name))])
);

const forceSingletonCodemirror = {
  name: 'force-singleton-codemirror',
  enforce: 'pre' as const,
  resolveId(source: string) {
    return singletonPaths[source] ?? null;
  },
};

export default defineConfig({
  plugins: [forceSingletonCodemirror, react(), tailwindcss()],
  clearScreen: false,
  resolve: {
    // Shared modules live under nanosiem-web/src, so their bare `react` import
    // resolves against nanosiem-web/node_modules — a SECOND copy of React. Any
    // shared component that calls a hook then dies with "invalid hook call"
    // (two Reacts, two dispatchers). Force one copy.
    dedupe: ['react', 'react-dom'],
    alias: {
      '@': webSrc,
      // The shared modules import these; bare specifiers would otherwise resolve
      // against nanosiem-web/node_modules, which a desktop-only checkout lacks.
      clsx: ownModule('clsx'),
      'tailwind-merge': ownModule('tailwind-merge'),
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    // Vite's dev server refuses to serve files outside the project root by default.
    fs: { allow: ['..'] },
    // design-ref holds the handoff mocks; editing them must not reload the app.
    watch: { ignored: ['**/src-tauri/**', '**/design-ref/**'] },
  },
});
