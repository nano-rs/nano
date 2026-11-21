// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5709: the Rules > Repositories rail item, its route and the page's own
// API (`GET /api/rule-repositories`, gated on `rule_repositories:view` in
// nanosiem-api/src/handlers/rule_repositories/crud.rs) agree on ONE permission,
// so nobody lands on a page whose list call answers 403.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const read = (rel: string) => readFileSync(resolve(__dirname, rel), 'utf8');

describe('rule repositories permission gate (NAN-5709)', () => {
  it('route gates on rule_repositories:view', () => {
    const app = read('App.tsx');
    const route = app.slice(app.indexOf('<Route path="/rules/repositories"'));
    expect(route.slice(0, 200)).toMatch(/<PermissionRoute permission="rule_repositories:view"/);
  });

  it('rail item gates on rule_repositories:view', () => {
    const layout = read('components/layout/AppLayout.tsx');
    const line = layout.split('\n').find((l) => l.includes("href: '/rules/repositories'"));
    expect(line).toBeDefined();
    expect(line).toContain("permissions: 'rule_repositories:view'");
  });

  it('the list endpoint checks the same permission', () => {
    const crud = read('../../nanosiem-api/src/handlers/rule_repositories/crud.rs');
    const list = crud.slice(crud.indexOf('pub async fn list_repositories('));
    expect(list.slice(0, 400)).toContain('permissions::RULE_REPOSITORIES_VIEW');
  });

  it('the Rules page link to Repositories is gated too', () => {
    const rules = read('pages/Rules.tsx');
    expect(rules).toContain("hasPermission('rule_repositories:view')");
    expect(rules).toMatch(/\{canViewRepositories && \(\s*<Link\s+to="\/rules\/repositories"/);
  });
});
