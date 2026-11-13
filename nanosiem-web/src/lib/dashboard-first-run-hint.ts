/**
 * NAN-5328: the pre-first-run banner only asks the user to set variables when
 * the dashboard has any. `layout.variables` may be missing or malformed on an
 * imported layout, so anything that is not a non-empty array counts as none.
 */
export function dashboardHasVariables(variables: unknown): boolean {
  return Array.isArray(variables) && variables.length > 0;
}
