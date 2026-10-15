import { describe, it, expect } from "vitest";
import { defaultSsoPolicy, googleInviteOnly, ssoGrantUuid } from "./sso-policy";
describe("SSO provider policy", () => {
  it("defaults to mapped groups with no grants", () => {
    expect(defaultSsoPolicy()).toMatchObject({
      mapped_groups_only: true,
      mappings: [],
      verified_domains: [],
    });
  });
  it("keeps Google invitation-only without either required credential component", () => {
    const policy = defaultSsoPolicy();
    expect(googleInviteOnly("https://accounts.google.com", false, policy)).toBe(
      true,
    );
    expect(googleInviteOnly("https://accounts.google.com", true, policy)).toBe(
      true,
    );
    policy.google_delegated_admin = "admin@example.com";
    expect(googleInviteOnly("https://accounts.google.com", false, policy)).toBe(
      true,
    );
    expect(googleInviteOnly("https://accounts.google.com", true, policy)).toBe(
      false,
    );
  });
  it("normalizes only role/group grant ids and rejects overflow or wrong namespaces", () => {
    expect(ssoGrantUuid("role_00000000000000000000000001")).toBe(
      "00000000-0000-0000-0000-000000000001",
    );
    expect(ssoGrantUuid("group_00000000000000000000000001")).toBe(
      "00000000-0000-0000-0000-000000000001",
    );
    for (const value of [
      "oidc_00000000000000000000000001",
      "role_80000000000000000000000001",
      "role_0000000000000000000000000i",
    ])
      expect(() => ssoGrantUuid(value)).toThrow();
  });
});
