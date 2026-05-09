// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-730 — curated icon catalog for custom rule folders.
//
// Kept as a fixed 20-icon set so the picker UI is dense and consistent. The
// slugs here are the source of truth for what the backend will accept; the
// API gates writes against the same allow-list (handlers/folder_settings.rs).
// If you add or remove an icon here, mirror the change in the backend's
// `ALLOWED_ICONS` constant.

import {
  Bookmark,
  Box,
  Bug,
  Cloud,
  Code,
  Database,
  Eye,
  FileText,
  Flag,
  Folder,
  Globe,
  Hash,
  Key,
  Lock,
  Mail,
  Server,
  Shield,
  Target,
  Terminal,
  User,
  type LucideIcon,
} from 'lucide-react';

export interface FolderIconDef {
  /** Slug stored on the server. Must match backend ALLOWED_ICONS. */
  slug: string;
  /** Lucide component used by RuleRail / meta-row chip. */
  Component: LucideIcon;
  /** Short label for accessibility / picker tooltips. */
  label: string;
}

export const FOLDER_ICONS: readonly FolderIconDef[] = [
  { slug: 'folder', Component: Folder, label: 'Folder' },
  { slug: 'globe', Component: Globe, label: 'Network' },
  { slug: 'user', Component: User, label: 'Identity' },
  { slug: 'box', Component: Box, label: 'Endpoint' },
  { slug: 'cloud', Component: Cloud, label: 'Cloud' },
  { slug: 'shield', Component: Shield, label: 'Defense' },
  { slug: 'bug', Component: Bug, label: 'Threat' },
  { slug: 'lock', Component: Lock, label: 'Access' },
  { slug: 'key', Component: Key, label: 'Credentials' },
  { slug: 'database', Component: Database, label: 'Data' },
  { slug: 'server', Component: Server, label: 'Infrastructure' },
  { slug: 'mail', Component: Mail, label: 'Email' },
  { slug: 'file-text', Component: FileText, label: 'Logs' },
  { slug: 'code', Component: Code, label: 'Code' },
  { slug: 'terminal', Component: Terminal, label: 'Shell' },
  { slug: 'eye', Component: Eye, label: 'Detection' },
  { slug: 'target', Component: Target, label: 'Hunting' },
  { slug: 'flag', Component: Flag, label: 'Flag' },
  { slug: 'bookmark', Component: Bookmark, label: 'Bookmark' },
  { slug: 'hash', Component: Hash, label: 'Tag' },
] as const;

const FOLDER_ICON_BY_SLUG: Record<string, LucideIcon> = Object.fromEntries(
  FOLDER_ICONS.map((d) => [d.slug, d.Component]),
);

/**
 * Look up an icon component by slug. Returns the generic Folder icon when
 * the slug is unknown (server might know about an icon that this client's
 * catalog hasn't picked up yet — fail soft).
 */
export function iconForSlug(slug: string | undefined | null): LucideIcon {
  if (!slug) return Folder;
  return FOLDER_ICON_BY_SLUG[slug] ?? Folder;
}

export const DEFAULT_FOLDER_ICON_SLUG = 'folder';
