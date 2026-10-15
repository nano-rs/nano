// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import { swaggerUiPath } from './tenant-auth-shell';

describe('API documentation link', () => {
  it('keeps dedicated URLs', () => {
    expect(swaggerUiPath('/search')).toBe('/swagger-ui/');
  });
  it('carries the current tenant on every SPA surface', () => {
    for (const slug of ['globex', 'other-soc']) {
      for (const page of ['', '/search', '/settings/api-keys']) {
        expect(swaggerUiPath(`/t/${slug}${page}`)).toBe(`/t/${slug}/swagger-ui/`);
      }
    }
  });
  it('refuses malformed selectors instead of dropping tenant context', () => {
    for (const path of ['/t/ACME/search', '/t/%61cme/search', '/t//search']) {
      expect(() => swaggerUiPath(path)).toThrow();
    }
  });
});


it('Swagger sends only tenant-local explicit credentials', () => {
  let config: any;
  const bundle = Object.assign((value: any) => { config = value; return {}; }, { presets: { apis: {} } });
  const browser: any = { location: { pathname: '/t/globex/swagger-ui/', origin: 'https://app.example.com' } };
  runInNewContext(readFileSync(new URL('../../../nanosiem-api/src/tenant_swagger.js', import.meta.url), 'utf8'), {
    window: browser, SwaggerUIBundle: bundle, SwaggerUIStandalonePreset: {}, URL,
  });
  browser.onload();
  expect(config.url).toBe('/t/globex/api-docs/openapi.json');
  expect(config.validatorUrl).toBeNull();
  expect(config.persistAuthorization).toBe(false);
  const request = config.requestInterceptor({ url: 'https://app.example.com/t/globex/api/search',
    headers: { 'X-API-Key': 'test-only-key', Authorization: 'discard', Cookie: 'discard' } });
  expect(request.credentials).toBe('omit');
  expect(request.headers).toEqual({ 'X-API-Key': 'test-only-key' });
  for (const url of ['/api/search', '/t/other-soc/api/search', 'https://example.com/t/globex/api/search',
    '/t/globex/api/../../other-soc/api/search']) {
    expect(() => config.requestInterceptor({ url })).toThrow(/within this tenant/);
  }
});
