// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-4945: the endpoint card warns when its origin is a dev server that cannot receive events. */
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { IngestEndpoint } from '@/lib/api/types';
import { IngestEndpointCard } from './IngestEndpointCard';

function endpoint(base: string, configured: boolean): IngestEndpoint {
  const host = new URL(base).hostname;
  return {
    base_url: base, hostname: host, scheme: 'http', configured,
    nano_https_url: `${base}/ingest`, otlp_logs_url: `${base}/otlp/v1/logs`,
    otlp_traces_url: `${base}/otlp/v1/traces`, otlp_metrics_url: `${base}/otlp/v1/metrics`,
    hec_url: `http://${host}:8088`, hec_event_url: `http://${host}:8088/services/collector/event`,
    hec_health_url: `http://${host}:8088/services/collector/health`,
  } as IngestEndpoint;
}

afterEach(cleanup);

it('warns on an inferred Vite origin and names NANO_INGEST_PUBLIC_BASE_URL', () => {
  render(<IngestEndpointCard endpoint={endpoint('http://localhost:5173', false)} protocol="nano_https" />);
  expect(screen.getByTestId('ingest-endpoint-state').textContent).toBe('dev server');
  const warning = screen.getByTestId('ingest-endpoint-dev-server');
  expect(warning.textContent).toContain('NANO_INGEST_PUBLIC_BASE_URL');
  expect(warning.textContent).toContain('/ingest');
});

it('warns even when BASE_URL configured the dev server as the origin', () => {
  render(<IngestEndpointCard endpoint={endpoint('http://localhost:5173', true)} />);
  expect(screen.getByTestId('ingest-endpoint-state').textContent).toBe('dev server');
  expect(screen.getByTestId('ingest-endpoint-dev-server')).toBeTruthy();
});

it('shows configured / inferred for real edge origins without a warning', () => {
  render(<IngestEndpointCard endpoint={endpoint('http://localhost:18090', true)} />);
  expect(screen.getByTestId('ingest-endpoint-state').textContent).toBe('configured');
  expect(screen.queryByTestId('ingest-endpoint-dev-server')).toBeNull();
  cleanup();
  render(<IngestEndpointCard endpoint={endpoint('https://siem.example', false)} />);
  expect(screen.getByTestId('ingest-endpoint-state').textContent).toBe('inferred');
  expect(screen.getByTestId('ingest-endpoint-state').getAttribute('title')).toContain('NANO_INGEST_PUBLIC_BASE_URL');
  expect(screen.queryByTestId('ingest-endpoint-dev-server')).toBeNull();
});
