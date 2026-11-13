-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5326: the AI assistant is "pivt" (formerly meloD). The `settings:ai`
-- permission description still read "Modify AI/meloD settings" in the role
-- matrix. Seeds in 001/177 are applied and immutable, so reword it here.
--
-- Forward-only and idempotent: only rewrites the untouched seeded text, so an
-- operator-customised description is left alone.

UPDATE permissions
   SET description = 'Modify AI (pivt) settings'
 WHERE id = 'settings:ai'
   AND description = 'Modify AI/meloD settings';
