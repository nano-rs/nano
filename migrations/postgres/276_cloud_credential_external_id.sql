-- NAN-2186: the `sts:ExternalId` for a cross-account AWS role assumption.
--
-- Deliberately UNENCRYPTED, alongside `description` and `region` in this
-- table's existing "metadata for display/selection" section — an ExternalId is
-- not a secret. It is an unguessable identifier the CUSTOMER must know in order
-- to write the trust policy that lets us assume their role.
--
-- Keeping it in the encrypted credential blob made it write-only in practice:
-- `GET /api/credentials/{id}` returns `CloudCredential`, which carries no
-- credential payload at all, so the value was visible exactly once — in the
-- creation form — and was unrecoverable afterwards. An operator who did not
-- copy it right then could neither hand it to the customer nor verify what the
-- customer had been told, and rotating to regenerate it invalidates the trust
-- policy they had already written.
--
-- Unguessability, not confidentiality, is what makes an ExternalId work: it
-- stops a third party who learns the role ARN from inducing us into assuming it
-- (the confused-deputy problem). Storing it readably costs nothing on that
-- front and makes the feature usable.

ALTER TABLE public.cloud_credentials
    ADD COLUMN IF NOT EXISTS external_id text;

COMMENT ON COLUMN public.cloud_credentials.external_id IS
    'sts:ExternalId for cross-account role assumption (NAN-2186). Not secret: the account owner needs this value for their role trust policy. NULL for static-key and ambient-identity credentials.';

-- Versioned alongside the payload, because an ExternalId is only meaningful
-- PAIRED with the role ARN it is a trust-policy condition on — and that ARN
-- lives in the encrypted payload, which IS versioned. Storing the id only on
-- the parent row would make rollback silently wrong: restoring version N's
-- payload (with its role) while leaving the current ExternalId in place yields
-- a combination that was never valid, and the resulting AssumeRole is rejected
-- by the customer's trust policy with an error that points nowhere near here.
ALTER TABLE public.cloud_credential_versions
    ADD COLUMN IF NOT EXISTS external_id text;

COMMENT ON COLUMN public.cloud_credential_versions.external_id IS
    'sts:ExternalId as of this version (NAN-2186). Rollback restores it with the payload so the id and the role ARN it conditions always move together.';
