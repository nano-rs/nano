// SPDX-License-Identifier: AGPL-3.0-or-later

// Enterprise-stubs barrel — open-edition no-op replacements.
//
// In open-edition Vite builds, `VITE_EDITION=open` causes the alias
// `@/enterprise` to resolve to this directory instead of `enterprise/`. Each
// stub mirrors the public type surface of its enterprise counterpart but
// renders nothing / returns no-op values, so open-core code can import
// `@/enterprise/X` unconditionally and the bundle stays free of enterprise
// implementation code.
//
// Stubs land alongside their enterprise counterparts in Phase 5 of the
// open-core split. See ~/.claude/plans/buzzing-brewing-crown.md.

export {};
