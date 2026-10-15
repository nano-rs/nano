// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2593: sender snippets filled in the browser from the NAN-2592 templates. */
import { describe, expect, it } from 'vitest';
import type { SenderTemplate, SenderTemplateCatalog } from '@/lib/api/types';
import {
  buildConnectionSummary,
  identifierLabel,
  renderSenderTemplate,
  senderValuesFromEndpoint,
  templatesForCredential,
} from './sender-config';
import { declaredSources } from './collector-sources';
// The server's exact catalog, kept in lockstep by the Rust test
// `ingest_sender_templates::tests::web_fixture_matches_the_catalog`.
import serverCatalog from './sender-templates.fixture.json';

const BASE = 'https://acme.ingest.nano.rs';
const endpoint = {
  hostname: BASE.slice('https://'.length),
  base_url: `${BASE}/`,
  hec_url: `${BASE}/services/collector/event`,
  nano_https_url: `${BASE}/ingest`,
  otlp_logs_url: `${BASE}/v1/logs`,
};

function template(partial: Partial<SenderTemplate>): SenderTemplate {
  return {
    id: 'x', sender: 'curl', sender_name: 'curl', protocol: 'hec', credential_kinds: ['source'],
    format: 'shell', title: 't', description: 'd', body: '', ...partial,
  };
}

// The server's curl-hec and vector-hec bodies (nanosiem-core/src/ingest_sender_templates.rs).
const CURL_HEC = template({
  id: 'curl-hec',
  body: 'curl -sS "{{hec_url}}" \\\n  -H "Authorization: Splunk {{token}}" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"event": {"message": "hello from curl"}}\'\n',
});
const VECTOR_HEC = template({
  id: 'vector-hec', sender: 'vector', sender_name: 'Vector', format: 'toml',
  body: '[sinks.nano_{{label}}]\ntype = "splunk_hec_logs"\nendpoint = "{{base_url}}"\ndefault_token = "{{token}}"\n',
});

describe('sender config (NAN-2593)', () => {
  it('fills the endpoint and the token into the curl HEC template', () => {
    const values = senderValuesFromEndpoint(endpoint, { token: 'TOKEN-abc_123', label: 'fw' });
    expect(values.base_url).toBe(BASE);
    const out = renderSenderTemplate(CURL_HEC, values);
    expect(out).toContain(`curl -sS "${BASE}/services/collector/event"`);
    expect(out).toContain('Authorization: Splunk TOKEN-abc_123');
    expect(out).not.toMatch(/\{\{/);
  });

  it('turns the label into an identifier like the server does', () => {
    expect(identifierLabel('Prod firewall #1')).toBe('prod_firewall__1');
    expect(identifierLabel('   ')).toBe('ingest');
    expect(identifierLabel('x'.repeat(60))).toHaveLength(48);
    const out = renderSenderTemplate(VECTOR_HEC, senderValuesFromEndpoint(endpoint, { token: 't', label: 'Prod firewall #1' }));
    expect(out).toContain('[sinks.nano_prod_firewall__1]');
    expect(out).toContain(`endpoint = "${BASE}"`);
  });

  it('never re-expands a marker that appears inside a value', () => {
    const out = renderSenderTemplate(template({ body: '{{label}} {{token}}' }), senderValuesFromEndpoint(endpoint, { token: '{{hec_url}}', label: 'a' }));
    expect(out).toBe('a {{hec_url}}');
  });

  it('keeps unknown markers visible instead of blanking them', () => {
    const out = renderSenderTemplate(template({ body: '{{future_marker}}' }), senderValuesFromEndpoint(endpoint, { token: 't', label: 'a' }));
    expect(out).toBe('{{future_marker}}');
  });

  it('offers only templates for the credential protocol and kind', () => {
    const catalog: SenderTemplateCatalog = {
      version: 1,
      placeholders: [],
      templates: [
        CURL_HEC,
        VECTOR_HEC,
        template({ id: 'curl-nano-https', protocol: 'nano_https' }),
        template({ id: 'cribl-collector', protocol: 'hec', credential_kinds: ['collector'] }),
      ],
    };
    expect(templatesForCredential(catalog, 'hec').map((t) => t.id)).toEqual(['curl-hec', 'vector-hec']);
    expect(templatesForCredential(catalog, 'nano_https').map((t) => t.id)).toEqual(['curl-nano-https']);
    expect(templatesForCredential(catalog, 'hec', 'collector').map((t) => t.id)).toEqual(['cribl-collector']);
    expect(templatesForCredential(undefined, 'hec')).toEqual([]);
  });

  it('renders every server template completely, and collectors declare their allowlist (NAN-2597)', () => {
    const catalog = serverCatalog as SenderTemplateCatalog;
    const aliases = { 'pan:traffic': 'palo_alto_traffic', 'OktaIM2:log': 'okta' };
    const values = senderValuesFromEndpoint(endpoint, {
      token: 'TOKEN-SAMPLE', label: 'Cribl prod',
      sources: declaredSources(['palo_alto_traffic', 'okta'], aliases), exampleSource: 'palo_alto_traffic',
    });
    const collectors = catalog.templates.filter((t) => t.credential_kinds.includes('collector'));
    expect(collectors.map((t) => t.sender).sort()).toEqual(
      expect.arrayContaining(['cribl', 'curl', 'fluent_bit', 'otel_collector', 'vector']),
    );
    for (const t of catalog.templates) {
      const out = renderSenderTemplate(t, values);
      expect(out, t.id).not.toMatch(/\{\{[a-z_]+\}\}/);
      expect(out, t.id).toContain('TOKEN-SAMPLE');
    }
    for (const t of collectors) {
      const out = renderSenderTemplate(t, values);
      expect(out, t.id).toContain('palo_alto_traffic, okta, OktaIM2:log, pan:traffic');
      expect(out, t.id).toMatch(/unknown/);
    }
    // Every protocol has collector templates, and source templates never declare a source.
    for (const protocol of ['hec', 'nano_https', 'otlp_http']) {
      expect(templatesForCredential(catalog, protocol, 'collector').length, protocol).toBeGreaterThan(0);
      for (const t of templatesForCredential(catalog, protocol, 'source')) {
        expect(t.body.toLowerCase(), t.id).not.toMatch(/sourcetype|x-nano-source|source_type|nano\.source/);
      }
    }

    const cribl = renderSenderTemplate(catalog.templates.find((t) => t.id === 'cribl-hec-collector')!, values);
    expect(cribl).toContain(`HEC endpoint:        ${BASE}/services/collector/event`);
    expect(cribl).toContain('HEC auth token:      TOKEN-SAMPLE');
    expect(cribl).toContain("sourcetype = 'palo_alto_traffic'");
    // Vector's own `{{ field }}` template syntax is not a marker and survives.
    const vector = renderSenderTemplate(catalog.templates.find((t) => t.id === 'vector-hec-collector')!, values);
    expect(vector).toContain('sourcetype = "{{ nano_source }}"');
    expect(vector).toContain('.nano_source = "palo_alto_traffic"');
    expect(vector).toContain('[sinks.nano_cribl_prod]');
    const otel = renderSenderTemplate(catalog.templates.find((t) => t.id === 'otel-collector-otlphttp-collector')!, values);
    expect(otel).toContain('key: nano.source');
    expect(otel).toContain(`logs_endpoint: ${BASE}/v1/logs`);
  });

  it('keeps the dedicated connection summary unchanged', () => {
    const http = buildConnectionSummary({ config_type: 'http', connection_config: { port: 9443, path: '/ingest' } });
    expect(http.full).toBe('https://{your-ingest-host}:9443/ingest');
    expect(http.auth).toBe('Bearer ${NANO_INGEST_TOKEN}');
    expect(http.usesPlaceholderHost).toBe(true);
    expect(http.snippet?.split('\n')[0]).toBe('curl -X POST https://{your-ingest-host}:9443/ingest \\');
    const hec = buildConnectionSummary({ config_type: 'splunk_hec', connection_config: {} });
    expect(hec.full).toBe('https://{your-ingest-host}:8088/services/collector/event');
    expect(hec.display).toBe('HEC :8088');
    expect(hec.auth).toBe('HEC token (rotate via credentials)');
    const kafka = buildConnectionSummary({ config_type: 'kafka', connection_config: { bootstrap_servers: 'b:9092', topics: ['a', 'b'] }, credential_id: 'cred_1' });
    expect(kafka.full).toBe('bootstrap=b:9092  topics=a, b');
    expect(kafka.auth).toBe('credential cred_1');
    // NAN-3764
    const hub = buildConnectionSummary({
      config_type: 'azure_event_hubs',
      connection_config: { namespace: 'acme-logs', event_hub_name: 'insights' },
    });
    expect(hub.full).toBe('namespace=acme-logs  hub=insights  group=$Default');
    expect(hub.auth).toBe('managed identity');
  });
});
