// SPDX-License-Identifier: AGPL-3.0-or-later

// Re-export all settings pages
export { AccessControlPage } from './AccessControl';
export { UsersPage, UsersContent } from './Users';
export { GroupsPage, GroupsContent } from './Groups';
export { RolesPage, RolesContent } from './Roles';
// OidcProviders lifted to @/enterprise/pages/Settings/OidcProviders (NAN-745).
// Re-export from there so existing barrel consumers keep resolving in
// enterprise builds; open builds get the enterprise placeholder via the alias.
export { OidcProvidersPage, OidcProvidersContent } from '@/enterprise/pages/Settings/OidcProviders';
export { ApiKeysPage, ApiKeysContent } from './ApiKeys';
export { SessionsPage, SessionsContent } from './Sessions';
export { AuditLogPage, AuditLogContent } from './AuditLog';
export { RetentionSettings } from './RetentionSettings';
// RiskSettings lifted to @/enterprise/pages/Settings/RiskSettings (NAN-745).
// MelodSettings lifted to @/enterprise/pages/Settings/MelodSettings (NAN-745).
export { PrevalenceSettings } from './PrevalenceSettings';
export { DebugSettings } from './DebugSettings';
export { DeveloperSettings } from './DeveloperSettings';
// Feedback page lifted to @/enterprise/pages/Settings/Feedback (NAN-745).
export { EnrichmentDetail } from './EnrichmentDetail';

export { SearchSettings } from './SearchSettings';
// QueueSettings lifted to @/enterprise/pages/Settings/QueueSettings (NAN-745).
// Re-import directly from there if needed.

// Settings alias (was MelodSettings) removed in NAN-745. Open builds get
// no /settings/ai route since MelodSettings lives in src/enterprise/.
