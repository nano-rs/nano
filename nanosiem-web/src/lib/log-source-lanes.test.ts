// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4922: lanes on the ClickHouse product come from the connect status, not lake slugs. */
import { expect, it } from 'vitest';
import { logSourceSlugLabel, receivingWithoutParser } from './log-source-lanes';

it('reads "receiving, not parsed" from the connect state', () => {
  expect(receivingWithoutParser({ deployed: false }, { state: 'receiving_unparsed', events_24h: 4 })).toBe(true);
  expect(receivingWithoutParser({ deployed: false }, { state: 'awaiting_data', events_24h: 0 })).toBe(false);
  expect(receivingWithoutParser({ deployed: true }, { state: 'receiving', events_24h: 4 })).toBe(false);
  expect(receivingWithoutParser({ deployed: false }, null)).toBe(false);
});

it('labels a row with its route key, else its match values, else the transport', () => {
  expect(logSourceSlugLabel({ source_type: 'routed', match_values: ['a', 'b'] }, { route_key: 'a' })).toBe('a');
  expect(logSourceSlugLabel({ source_type: 'routed', match_values: ['a', 'b'] })).toBe('a, b');
  expect(logSourceSlugLabel({ source_type: 'splunk_hec', match_values: [] })).toBe('splunk_hec');
});
