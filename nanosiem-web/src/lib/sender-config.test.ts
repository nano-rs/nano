// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4922: sender snippets target this deployment's Vector listeners and never declare a source type. */
import { describe, expect, it } from 'vitest';
import type { IngestEndpoint } from '@/lib/api/types';
import { SENDER_TEMPLATES, identifierLabel, renderSenderTemplate, senderValuesFromEndpoint, templatesForProtocol } from './sender-config';

const endpoint: IngestEndpoint = {
  base_url: 'https://siem.example', hostname: 'siem.example', scheme: 'https', hec_url: 'http://siem.example:8088',
  hec_event_url: 'http://siem.example:8088/services/collector/event', hec_health_url: 'http://siem.example:8088/services/collector/health',
  nano_https_url: 'https://siem.example/ingest', otlp_logs_url: 'https://siem.example/otlp/v1/logs',
  otlp_traces_url: 'https://siem.example/otlp/v1/traces', otlp_metrics_url: 'https://siem.example/otlp/v1/metrics', configured: true,
};

describe('sender templates', () => {
  it('fills every marker in one pass and keeps sender syntax with spaces', () => {
    const body = renderSenderTemplate({ body: 'a={{token}} b={{label}} c={{ field }} d={{unknown}}' },
      senderValuesFromEndpoint(endpoint, { token: 'nit_{{label}}', label: 'Okta prod' }));
    expect(body).toBe('a=nit_{{label}} b=okta_prod c={{ field }} d={{unknown}}');
  });

  it('renders HEC curl with the Splunk scheme at the event URL, HTTP JSON and OTLP with Bearer', () => {
    const values = senderValuesFromEndpoint(endpoint, { token: 'nit_abc', label: 'okta-hec' });
    const hec = renderSenderTemplate(templatesForProtocol('hec')[0], values);
    expect(hec).toContain('"http://siem.example:8088/services/collector/event"');
    expect(hec).toContain('Authorization: Splunk nit_abc');
    expect(hec).toContain('X-Splunk-Request-Channel:');
    const http = renderSenderTemplate(templatesForProtocol('nano_https')[0], values);
    expect(http).toContain('Authorization: Bearer nit_abc');
    expect(http).toContain('"https://siem.example/ingest"');
    const otlp = templatesForProtocol('otlp_http').map((t) => renderSenderTemplate(t, values)).join('\n');
    expect(otlp).toContain('logs_endpoint: https://siem.example/otlp/v1/logs');
  });

  it('has no curl OTLP template: the edge forwards to an OTLP receiver that takes protobuf only', () => {
    expect(templatesForProtocol('otlp_http').map((t) => t.sender)).not.toContain('curl');
  });

  it('never points a sender at raw Vector HTTP/OTLP ports, and fills Fluent Bit edge settings', () => {
    const values = senderValuesFromEndpoint(endpoint, { token: 't', label: 'l' });
    for (const t of SENDER_TEMPLATES) {
      const body = renderSenderTemplate(t, values);
      expect(body).not.toMatch(/:8080|:4318/);
      expect(body).not.toMatch(/\{\{[a-z_]+\}\}/);
    }
    const fb = renderSenderTemplate(SENDER_TEMPLATES.find((t) => t.id === 'fluent-bit-http')!, values);
    expect(fb).toMatch(/Port\s+443/);
    expect(fb).toMatch(/URI\s+\/ingest/);
    expect(fb).toMatch(/TLS\s+On/);
    const fbHec = renderSenderTemplate(SENDER_TEMPLATES.find((t) => t.id === 'fluent-bit-hec')!, values);
    expect(fbHec).toMatch(/Port\s+8088/);
  });

  it('never declares a source type (the token decides the source)', () => {
    for (const t of SENDER_TEMPLATES) {
      expect(t.body).not.toMatch(/sourcetype|X-Source-Type|source_type/i);
      expect(t.body).toContain('{{token}}');
    }
  });

  it('makes every curl snippet fail loudly (NAN-4945): a 401/404 is never a silent exit 0', () => {
    const curls = SENDER_TEMPLATES.filter((t) => t.sender === 'curl');
    expect(curls.length).toBeGreaterThan(0);
    for (const t of curls) expect(t.body).toMatch(/^curl -sS --fail-with-body /);
  });

  it('reduces labels to identifiers', () => {
    expect(identifierLabel('  ')).toBe('ingest');
    expect(identifierLabel('A-b.c')).toBe('a_b_c');
  });
});
