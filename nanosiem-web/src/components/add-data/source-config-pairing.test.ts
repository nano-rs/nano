// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-6036: the Add source wizard sent `ingestion_method: 'routed'` for every
 * source configuration, and the import refuses `routed` with anything but an
 * HTTP configuration. These pin the method per configuration type (the same
 * pairing as Rust `ingest_transport::dispatch_compatible`), the reasons a
 * configuration is shown disabled, when the wizard adds a rule or deploys,
 * and when the Transport choice is locked.
 */
import { describe, expect, it } from 'vitest';

import type { SourceConfigType } from '@/lib/api/types';
import { ingestionMethodForConfigType } from '@/lib/log-source-transports';
import {
  libraryNeedsConfigDeploy,
  NO_CREDENTIAL_PERMISSION_REASON,
  NO_DEPLOY_PERMISSION_REASON,
  NO_EDIT_PERMISSION_REASON,
  NOT_RUNNING_REASON,
  OTLP_LIBRARY_REASON,
  sourceConfigPairing,
  transportChoiceLocked,
  UNKNOWN_TYPE_REASON,
  wizardAddsRoutingRule,
  wizardRedeploysConfig,
  wizardSourceType,
} from './source-config-pairing';

// Every `SourceConfigType` and the method the backend pairs it with. `http`
// feeds `routed`; every other type feeds the method of the same name.
const EXPECTED: Record<SourceConfigType, string> = {
  http: 'routed',
  vector: 'vector',
  otlp: 'otlp',
  splunk_hec: 'splunk_hec',
  kafka: 'kafka',
  aws_s3: 'aws_s3',
  aws_sqs: 'aws_sqs',
  crowdstrike_fdr: 'crowdstrike_fdr',
  gcp_pubsub: 'gcp_pubsub',
  azure_event_hubs: 'azure_event_hubs',
};
const PULL = ['kafka', 'aws_s3', 'aws_sqs', 'crowdstrike_fdr', 'gcp_pubsub', 'azure_event_hubs'];
const ALL_GRANTS = { canEditSourceConfigs: true, canDeploySourceConfigs: true, canUseCredentials: true };
const repo = { repositorySource: true, ...ALL_GRANTS };
const custom = { repositorySource: false, ...ALL_GRANTS };

describe('ingestionMethodForConfigType', () => {
  it.each(Object.entries(EXPECTED))('%s feeds %s', (configType, method) => {
    expect(ingestionMethodForConfigType(configType)).toBe(method);
  });
  it('knows nothing it was not told', () => {
    expect(ingestionMethodForConfigType('carrier_pigeon')).toBeNull();
    expect(ingestionMethodForConfigType('')).toBeNull();
    expect(ingestionMethodForConfigType(undefined)).toBeNull();
  });
});

describe('sourceConfigPairing for a library source', () => {
  it.each(Object.entries(EXPECTED).filter(([t]) => t !== 'otlp'))('a deployed %s configuration imports with %s', (configType, method) => {
    expect(sourceConfigPairing({ config_type: configType, deployed: true }, repo)).toEqual({ usable: true, ingestionMethod: method });
  });

  it('the reported bug: a Vector configuration imports as vector, never routed', () => {
    expect(sourceConfigPairing({ config_type: 'vector', deployed: true }, repo)).toEqual({ usable: true, ingestionMethod: 'vector' });
  });

  it('neon P1-1: OTLP is not offered (an otlp log source fails every later save)', () => {
    expect(sourceConfigPairing({ config_type: 'otlp', deployed: true }, repo)).toEqual({ usable: false, reason: OTLP_LIBRARY_REASON });
  });

  it.each(PULL)('an undeployed %s configuration is disabled with a reason (its route does not exist yet)', (configType) => {
    expect(sourceConfigPairing({ config_type: configType, deployed: false }, repo)).toEqual({ usable: false, reason: NOT_RUNNING_REASON });
  });

  it.each(['http', 'vector', 'splunk_hec'])('an always-on %s listener is usable whether or not it is marked deployed', (configType) => {
    expect(sourceConfigPairing({ config_type: configType, deployed: false }, repo).usable).toBe(true);
  });

  it('an unknown configuration type is disabled, not guessed as routed', () => {
    expect(sourceConfigPairing({ config_type: 'carrier_pigeon', deployed: true }, repo)).toEqual({ usable: false, reason: UNKNOWN_TYPE_REASON });
  });
});

describe('sourceConfigPairing for a custom source', () => {
  it.each(Object.keys(EXPECTED))('%s stays routed (the wizard adds the routing rule itself)', (configType) => {
    expect(sourceConfigPairing({ config_type: configType, deployed: false }, custom)).toEqual({ usable: true, ingestionMethod: 'routed' });
  });
});

describe('permissions (neon P1-4)', () => {
  it.each([true, false])('without source_configs:edit every configuration is disabled (repository=%s)', (repositorySource) => {
    for (const configType of Object.keys(EXPECTED)) {
      expect(sourceConfigPairing({ config_type: configType, deployed: true }, { ...ALL_GRANTS, repositorySource, canEditSourceConfigs: false }))
        .toEqual({ usable: false, reason: NO_EDIT_PERMISSION_REASON });
    }
  });

  it.each([true, false])('without source_configs:deploy a deployed configuration is disabled (repository=%s)', (repositorySource) => {
    const ctx = { ...ALL_GRANTS, repositorySource, canDeploySourceConfigs: false };
    expect(sourceConfigPairing({ config_type: 'kafka', deployed: true }, ctx)).toEqual({ usable: false, reason: NO_DEPLOY_PERMISSION_REASON });
    expect(sourceConfigPairing({ config_type: 'http', deployed: true }, ctx)).toEqual({ usable: false, reason: NO_DEPLOY_PERMISSION_REASON });
  });

  it('without source_configs:deploy a custom source may still use an undeployed configuration (nothing is deployed)', () => {
    expect(sourceConfigPairing({ config_type: 'kafka', deployed: false }, { ...custom, canDeploySourceConfigs: false }).usable).toBe(true);
  });

  it('credentials:use is needed only when the wizard would redeploy a credential-backed configuration', () => {
    const noCreds = { ...ALL_GRANTS, canUseCredentials: false };
    const withCred = { config_type: 'kafka', deployed: true, credential_id: 'cred_1' };
    expect(sourceConfigPairing(withCred, { ...noCreds, repositorySource: false })).toEqual({ usable: false, reason: NO_CREDENTIAL_PERMISSION_REASON });
    // A library import never redeploys the configuration.
    expect(sourceConfigPairing(withCred, { ...noCreds, repositorySource: true }).usable).toBe(true);
    // No credential, nothing to use.
    expect(sourceConfigPairing({ config_type: 'kafka', deployed: true }, { ...noCreds, repositorySource: false }).usable).toBe(true);
  });
});

describe('deploys and rules (neon P1-2, P2-1)', () => {
  it('the wizard never redeploys Vector, OTLP, an undeployed configuration, or for a library source', () => {
    expect(wizardRedeploysConfig({ config_type: 'vector', deployed: true }, false)).toBe(false);
    expect(wizardRedeploysConfig({ config_type: 'otlp', deployed: true }, false)).toBe(false);
    expect(wizardRedeploysConfig({ config_type: 'kafka', deployed: false }, false)).toBe(false);
    expect(wizardRedeploysConfig({ config_type: 'kafka', deployed: true }, true)).toBe(false);
    expect(wizardRedeploysConfig({ config_type: 'kafka', deployed: true }, false)).toBe(true);
    expect(wizardRedeploysConfig({ config_type: 'http', deployed: true }, false)).toBe(true);
  });

  it('a library pull source tells the user its configuration needs a deploy; listeners and custom sources do not', () => {
    for (const t of PULL) expect(libraryNeedsConfigDeploy({ config_type: t, deployed: true }, true)).toBe(true);
    for (const t of ['http', 'vector', 'splunk_hec']) expect(libraryNeedsConfigDeploy({ config_type: t, deployed: true }, true)).toBe(false);
    expect(libraryNeedsConfigDeploy({ config_type: 'kafka', deployed: true }, false)).toBe(false);
    expect(libraryNeedsConfigDeploy(undefined, true)).toBe(false);
  });

  it('a routing rule is added once, only by the custom path, never on Vector/OTLP', () => {
    const kafka = { config_type: 'kafka', deployed: true };
    expect(wizardAddsRoutingRule(kafka, false, 'okta', [])).toBe(true);
    expect(wizardAddsRoutingRule(kafka, false, 'okta', [{ match_field: 'source_type', match_value: 'okta' }])).toBe(false);
    expect(wizardAddsRoutingRule(kafka, false, 'okta', [{ match_field: 'source_type', match_value: 'other' }])).toBe(true);
    expect(wizardAddsRoutingRule(kafka, true, 'okta', [])).toBe(false);
    expect(wizardAddsRoutingRule({ config_type: 'vector', deployed: true }, false, 'okta', [])).toBe(false);
    expect(wizardAddsRoutingRule({ config_type: 'otlp', deployed: true }, false, 'okta', [])).toBe(false);
  });
});

describe('wizardSourceType', () => {
  it('push transports save routed', () => {
    expect(wizardSourceType('push', { config_type: 'kafka', deployed: true }, { repositorySource: true })).toBe('routed');
    expect(wizardSourceType('push', undefined, { repositorySource: false })).toBe('routed');
  });
  it('a custom source read through a configuration saves routed', () => {
    expect(wizardSourceType('pull', { config_type: 'kafka', deployed: true }, { repositorySource: false })).toBe('routed');
  });
  it.each(Object.entries(EXPECTED))('a library source on %s keeps %s', (configType, method) => {
    expect(wizardSourceType('pull', { config_type: configType, deployed: true }, { repositorySource: true })).toBe(method);
  });
  it('no configuration chosen yet saves routed', () => {
    expect(wizardSourceType('pull', undefined, { repositorySource: true })).toBe('routed');
  });
});

describe('transportChoiceLocked (neon P1-3)', () => {
  it('nothing is locked before the source exists', () => {
    expect(transportChoiceLocked({ sourceExists: false, repositorySource: true, persistedSourceType: 'kafka' })).toBe(false);
  });
  it('an imported library source is locked, whatever its method', () => {
    expect(transportChoiceLocked({ sourceExists: true, repositorySource: true, persistedSourceType: 'routed' })).toBe(true);
    expect(transportChoiceLocked({ sourceExists: true, repositorySource: true, persistedSourceType: 'kafka' })).toBe(true);
  });
  it('a saved non-routed source (resumed pull source) is locked; a custom routed draft can still switch', () => {
    expect(transportChoiceLocked({ sourceExists: true, repositorySource: false, persistedSourceType: 'kafka' })).toBe(true);
    expect(transportChoiceLocked({ sourceExists: true, repositorySource: false, persistedSourceType: 'routed' })).toBe(false);
    expect(transportChoiceLocked({ sourceExists: true, repositorySource: false, persistedSourceType: null })).toBe(false);
  });
});
