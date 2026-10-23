// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * DSH16: structurally validate a parsed dashboard export before importing and
 * navigating into it. A hand-edited or older-tool JSON with a missing/misshaped
 * layout (e.g. `layout: {}` with no `items`, or `variables: {}`) would otherwise
 * import successfully and then crash `DashboardView` on render
 * (`layout.items.find(...)`, `for (const v of variables)`). Returns a
 * human-readable reason on failure, or null when the shape is acceptable.
 */
export function validateDashboardImportShape(parsed: unknown): string | null {
  if (typeof parsed !== 'object' || parsed === null) {
    return 'File is not a dashboard export object.';
  }
  const root = parsed as Record<string, unknown>;
  if (typeof root.version !== 'string' || root.version.trim() === '') {
    return 'Missing or invalid export "version".';
  }
  if (typeof root.dashboard !== 'object' || root.dashboard === null) {
    return 'Missing "dashboard" object.';
  }
  const d = root.dashboard as Record<string, unknown>;
  if (typeof d.name !== 'string' || d.name.trim() === '') {
    return 'Dashboard is missing a name.';
  }
  if (!Array.isArray(d.panels)) {
    return 'Dashboard "panels" must be an array.';
  }
  if (typeof d.layout !== 'object' || d.layout === null) {
    return 'Dashboard "layout" must be an object.';
  }
  const layout = d.layout as Record<string, unknown>;
  if (!Array.isArray(layout.items)) {
    return 'Dashboard "layout.items" must be an array.';
  }
  if (layout.variables !== undefined && !Array.isArray(layout.variables)) {
    return 'Dashboard "layout.variables" must be an array when present.';
  }
  return null;
}
