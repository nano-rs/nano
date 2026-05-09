// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Enrichment Provider Components
 *
 * Each provider has its own configuration component that handles
 * the specific setup and management UI for that enrichment source.
 *
 * To add a new provider:
 * 1. Create a new component file (e.g., MaxMindProvider.tsx)
 * 2. Export it from this index file
 * 3. Add the mapping in EnrichmentDetail.tsx
 */

export { IPinfoLiteProvider } from './IPinfoLiteProvider';
export { ThreatFoxProvider } from './ThreatFoxProvider';
export { TorExitNodesProvider } from './TorExitNodesProvider';

// Future providers can be added here:
// export { MaxMindProvider } from './MaxMindProvider';
// export { VirusTotalProvider } from './VirusTotalProvider';
// export { AbuseIPDBProvider } from './AbuseIPDBProvider';
