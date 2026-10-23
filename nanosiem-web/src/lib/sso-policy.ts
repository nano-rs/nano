import type { SsoAccessPolicy } from "./api/types";
export function defaultSsoPolicy(): SsoAccessPolicy {
  return {
    mapped_groups_only: true,
    mappings: [],
    verified_domains: [],
    entra_tenant_id: null,
    google_delegated_admin: null,
  };
}
/** Policy UUIDs are canonical across hosted and dedicated APIs. */
export function ssoGrantUuid(id: string): string {
  if (/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id))
    return id.toLowerCase();
  const match = /^(?:role|group)_([0-9a-z]{26})$/.exec(id);
  if (!match || match[1][0] > "7")
    throw new Error("Invalid SSO grant identifier");
  const alphabet = "0123456789abcdefghjkmnpqrstvwxyz";
  let value = 0n;
  for (const c of match[1]) {
    const digit = alphabet.indexOf(c);
    if (digit < 0) throw new Error("Invalid SSO grant identifier");
    value = (value << 5n) | BigInt(digit);
  }
  const hex = value.toString(16).padStart(32, "0");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
export function googleInviteOnly(
  issuer: string,
  configured: boolean,
  policy: SsoAccessPolicy,
): boolean {
  return (
    issuer === "https://accounts.google.com" &&
    (!configured || !policy.google_delegated_admin)
  );
}

/** Only membership acquisition differs; all presets use the same access policy. */
export const ssoProviderPresets = {
  okta: {
    name: "Okta",
    slug: "okta",
    issuer: "https://YOUR-ORG.okta.com",
    scopes: "openid email profile groups",
    group_claim: "groups",
  },
  entra: {
    name: "Microsoft Entra ID",
    slug: "entra",
    issuer: "https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0",
    scopes: "openid email profile User.Read",
    group_claim: "groups",
  },
  google: {
    name: "Google Workspace",
    slug: "google",
    issuer: "https://accounts.google.com",
    scopes: "openid email profile",
    group_claim: "",
  },
} as const;
