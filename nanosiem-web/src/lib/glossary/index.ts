// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: the one shared glossary. Every domain term in the UI gets its
// plain-English definition here, so it reads the same on every page. Render a
// term with <Term id="sweep">sweeps</Term> (src/components/ui/term.tsx) on its
// first appearance in a component.
//
// Writing rules (Dan, 2026-11-23): 8th-grade reading level, definition first,
// short words, short sentences, no internal jargon. `short` is one sentence;
// `more` is at most two. US spelling, no em dashes.
//
// Sections: one file per product area, so area work never edits the same
// file. Open-core terms live in src/lib/glossary/*.ts; enterprise-only terms
// live in src/enterprise/lib/glossary/*.ts and are stripped from open core.

import { ENTERPRISE_GLOSSARY, ENTERPRISE_GLOSSARY_SECTIONS } from '@/enterprise/lib/glossary';
import { SHARED_GLOSSARY } from './shared';
import { SEARCH_GLOSSARY } from './search';
import { RULES_GLOSSARY } from './rules';
import { DATA_GLOSSARY } from './data';
import { SETTINGS_GLOSSARY } from './settings';
import type { GlossaryEntry } from './types';

export type { GlossaryEntry } from './types';
export { DOCS_PAGES } from './types';

export const CORE_GLOSSARY_SECTIONS = {
  shared: SHARED_GLOSSARY,
  search: SEARCH_GLOSSARY,
  rules: RULES_GLOSSARY,
  data: DATA_GLOSSARY,
  settings: SETTINGS_GLOSSARY,
} as const;

const CORE_GLOSSARY = {
  ...SHARED_GLOSSARY,
  ...SEARCH_GLOSSARY,
  ...RULES_GLOSSARY,
  ...DATA_GLOSSARY,
  ...SETTINGS_GLOSSARY,
} as const;

export const GLOSSARY = { ...CORE_GLOSSARY, ...ENTERPRISE_GLOSSARY } as const;

/** A glossary id. In the open edition only open-core ids type-check. */
export type GlossaryId = keyof typeof GLOSSARY;

/** All sections (core and enterprise), for tests. */
export function glossarySections(): Record<string, Readonly<Record<string, GlossaryEntry>>> {
  const out: Record<string, Readonly<Record<string, GlossaryEntry>>> = {};
  for (const [k, v] of Object.entries(CORE_GLOSSARY_SECTIONS)) out[`core:${k}`] = v;
  for (const [k, v] of Object.entries(ENTERPRISE_GLOSSARY_SECTIONS)) out[`enterprise:${k}`] = v;
  return out;
}

export function glossaryEntry(id: GlossaryId): GlossaryEntry {
  return (GLOSSARY as Record<string, GlossaryEntry>)[id];
}
