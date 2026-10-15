// SPDX-License-Identifier: AGPL-3.0-or-later
import { registerHooks } from 'node:module';
// @ts-expect-error jsdom is an existing test dependency without bundled declarations.
import { JSDOM } from 'jsdom';
const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost', pretendToBeVisual: true });
for (const key of ['window', 'document', 'HTMLElement', 'Element', 'Node', 'MutationObserver', 'CustomEvent', 'Event', 'MouseEvent', 'DocumentFragment', 'HTMLInputElement', 'NodeFilter', 'HTMLSelectElement', 'HTMLTextAreaElement', 'requestAnimationFrame', 'cancelAnimationFrame']) {
  Object.defineProperty(globalThis, key, { configurable: true, value: dom.window[key] });
}
// jsdom lacks ResizeObserver; Radix Checkbox (stream picker) measures itself with it.
if (!('ResizeObserver' in globalThis)) {
  Object.defineProperty(globalThis, 'ResizeObserver', { configurable: true, value: class { observe() {} unobserve() {} disconnect() {} } });
}
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: dom.window.navigator });
Object.defineProperty(globalThis, 'getComputedStyle', { configurable: true, value: dom.window.getComputedStyle });
// jsdom lacks matchMedia; DetailSheet (NAN-3209) reads it via useIsMobile. Desktop by default.
if (!dom.window.matchMedia) {
  dom.window.matchMedia = (query: string) => ({
    matches: false, media: query, onchange: null,
    addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false,
  });
}
export const context = { mode: 'dedicated', permissions: true, coverage: false, permission: undefined as undefined | ((permission: string) => boolean) };
export const moduleMocks: Record<string, Record<string, unknown>> = {};
Object.assign(globalThis, { __marketplaceTestContext: context, __marketplaceModuleMocks: moduleMocks });
registerHooks({
  load(url, options, next) {
    const stub = Object.keys(moduleMocks).find(suffix => url.endsWith(suffix));
    if (stub) return { format: 'module', shortCircuit: true, source: Object.keys(moduleMocks[stub]).map(name => `export const ${name} = globalThis.__marketplaceModuleMocks[${JSON.stringify(stub)}][${JSON.stringify(name)}];`).join('\n') };
    if (url.endsWith('/contexts/AuthContext.tsx')) return { format: 'module', shortCircuit: true, source: `
      export function useAuth() { const c = globalThis.__marketplaceTestContext; return {
        user: { id: 'fixture-user', active_tenant: { id: 'fixture-tenant' }, deployment_mode: c.mode },
        hasPermission: p => c.permission ? c.permission(p) : c.permissions,
        hasAllPermissions: p => c.permissions && (!p.includes('search:execute') || c.coverage)
      }; }` };
    if (url.endsWith('/hooks/use-capabilities.ts')) return { format: 'module', shortCircuit: true, source: "import { createContext } from 'react'; export const CapabilitiesContext = createContext(null); export function useCapabilities() { return { capabilities: { customEnrichment: false } }; }" };
    if (url.endsWith('/lib/api/index.ts')) return { format: 'module', shortCircuit: true, source: `
      export const collectorManifest = () => null; export const streamNeedsAttention = () => false;
      export const api = { marketplace: {}, integrations: {}, pullSources: {} };
      export class ApiClientError extends Error { constructor(message, code, details, status) { super(message); this.code = code; this.details = details; this.status = status; } }
    ` };
    return next(url, options);
  },
});
