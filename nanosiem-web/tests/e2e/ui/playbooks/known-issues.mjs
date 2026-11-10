// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pre-existing defects the playbook still observes on main (NAN-5085). A
// problem matching an entry is reported once in the "Known issues" section
// and downgrades its check to a warning instead of failing it, so the
// baseline-vs-branch diff shows real changes. Every entry names its tracking
// issue; delete the entry when that issue is fixed. Patterns are narrow on
// purpose: a NEW error on the same page still fails.
export const KNOWN_ISSUES = [
  // Unlicensed enterprise: NotebookContext + AI-availability poll call licensed
  // APIs on every page (only stacks whose licence is locked, e.g. main after #8862).
  { id: 'legacy-apikey-form-expiry-422', issue: 'NAN-5107', note: 'legacy API key form sends datetime-local as expires_at', re: /^click "Save Changes" -> HTTP 422 PUT \/api\/api-keys\/:id$/ },
  { id: 'notebook-generate-timeline-500', issue: 'NAN-5108', note: 'Generate Timeline 500s without an AI provider; Open in Search logs an explanation-lookup 404', re: /^click "Generate Timeline" -> HTTP 500 POST \/api\/melod\/notebook\/generate-timeline$|^click ".*" -> HTTP 404 POST \/api\/search\/explanation\/lookup$/ },
  { id: 'dialog-without-title', issue: 'NAN-5109', note: 'Radix DialogContent without DialogTitle (New Dashboard, New notebook)', re: /`DialogContent` requires a `DialogTitle`/ },
  { id: 'unlicensed-notebook-noise', issue: 'NAN-5103', note: 'unlicensed stack: notebook tabs/active + ai-availability 403s and console errors on every page', re: /Failed to load (notebook tabs|legacy active notebook): ApiClientError: This licensed feature is unavailable|^HTTP 403 GET \/api\/(notebooks\/(tabs|active)|settings\/ai-availability|cases\/my)$/ },
];

export function splitKnown(problems) {
  const known = []; const rest = [];
  for (const p of problems) {
    const k = KNOWN_ISSUES.find((e) => e.re.test(p));
    if (k) known.push({ id: k.id, problem: p }); else rest.push(p);
  }
  return { known, rest };
}
