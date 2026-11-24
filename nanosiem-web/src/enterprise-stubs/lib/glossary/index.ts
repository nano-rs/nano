// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5867: open-edition stub. The open edition has no enterprise glossary
// terms or enterprise docs links, so `<Term id=...>` only accepts open-core
// ids there and <EnterpriseTerm> renders plain text.

import type { GlossaryEntry } from '@/lib/glossary/types';

export const ENTERPRISE_GLOSSARY_SECTIONS: Readonly<Record<string, Readonly<Record<never, GlossaryEntry>>>> = {};

export const ENTERPRISE_GLOSSARY: Readonly<Record<never, GlossaryEntry>> = {};

export const ENTERPRISE_DOCS_PAGES: Readonly<Record<never, string>> = {};

export const ENTERPRISE_DOCS_HREFS: ReadonlySet<string> = new Set();

export type EnterpriseGlossaryId = string;
