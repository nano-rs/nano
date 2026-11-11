// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { isGeoEnrichmentField, isIocField } from './enrichment-fields';
import { buildFieldCategories, isFieldHidden } from '@/components/search/event-flatten';

describe('enrichment field predicates (NAN-5271)', () => {
  it('recognises OCSF IOC columns as IOC', () => {
    expect(isIocField('enrichments.ioc_src_ip_threat_type')).toBe(true);
    expect(isIocField('enrichments.custom_ioc_hash_malware')).toBe(true);
    expect(isIocField('ioc_src_ip_threat_type')).toBe(true);
    expect(isIocField('src_endpoint.ip')).toBe(false);
  });
  it('recognises OCSF geo/ASN columns as enrichment', () => {
    expect(isGeoEnrichmentField('src_endpoint.location.country')).toBe(true);
    expect(isGeoEnrichmentField('dst_endpoint.autonomous_system.name')).toBe(true);
    expect(isGeoEnrichmentField('enrichments.custom_src_ip_tags')).toBe(true);
    expect(isGeoEnrichmentField('enrichments.ioc_tags')).toBe(false);
    expect(isGeoEnrichmentField('enriched_src_country')).toBe(true);
    expect(isGeoEnrichmentField('src_endpoint.hostname')).toBe(false);
  });
  it('files OCSF IOC and geo hits in their buckets, not Core', () => {
    const known = new Set(['src_endpoint.ip', 'src_endpoint.location.country', 'enrichments.ioc_src_ip_threat_type']);
    const cats = buildFieldCategories(
      [
        ['src_endpoint.ip', '1.2.3.4'],
        ['src_endpoint.location.country', 'RU'],
        ['enrichments.ioc_src_ip_threat_type', 'botnet_cc'],
      ],
      known,
      true,
    );
    const byLabel = Object.fromEntries(cats.map((c) => [c.label, c.fields.map(([k]) => k)]));
    expect(byLabel.IOC).toEqual(['enrichments.ioc_src_ip_threat_type']);
    expect(byLabel.Enrichment).toEqual(['src_endpoint.location.country']);
  });
  it('the IOC and geo toggles hide the OCSF columns', () => {
    expect(isFieldHidden('enrichments.ioc_src_ip_malware', new Set(['ioc']))).toBe(true);
    expect(isFieldHidden('src_endpoint.location.country', new Set(['geo']))).toBe(true);
    expect(isFieldHidden('src_endpoint.ip', new Set(['ioc', 'geo']))).toBe(false);
  });
});
