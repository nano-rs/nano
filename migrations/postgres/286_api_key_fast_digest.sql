-- NAN-4902 (port of NAN-3798 to the single-tenant ClickHouse edition):
-- a fast verifier digest for API keys.
--
-- Every X-API-Key request ran a cost-12 bcrypt verify of the presented secret
-- (~0.25-0.45 s of CPU), after loading every api_keys row. A key's secret is 32
-- random bytes (256 bits) from the OS CSPRNG, so a slow KDF adds nothing: a
-- 256-bit preimage of a SHA-256 digest cannot be brute-forced. A fast digest
-- compared in constant time is the standard design for high-entropy tokens.
--
-- `key_digest` = SHA-256(domain tag || key_hash || secret), as computed by
-- `api_key_digest` in nanosiem-core/src/auth/api_key.rs. Because it is bound
-- to the row's bcrypt `key_hash`, a digest left behind by a writer that
-- changes the hash without rewriting the digest can never authenticate: the
-- verifier falls back to bcrypt on mismatch.
--
-- New keys and resets write the digest. Existing keys keep a NULL digest until
-- their next successful bcrypt verify backfills it, so no key needs rotating.
-- `key_hash` stays NOT NULL and authoritative.
ALTER TABLE public.api_keys ADD COLUMN IF NOT EXISTS key_digest BYTEA;

DO $api_key_digest$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid = 'public.api_keys'::regclass
           AND conname = 'api_keys_key_digest_len'
    ) THEN
        ALTER TABLE public.api_keys
            ADD CONSTRAINT api_keys_key_digest_len
            CHECK (key_digest IS NULL OR octet_length(key_digest) = 32);
    END IF;
END
$api_key_digest$;

-- Validation now looks keys up by prefix (idx_api_keys_prefix, migration 001)
-- instead of loading the whole table.

COMMENT ON COLUMN public.api_keys.key_digest IS
    'SHA-256 verifier bound to key_hash (NAN-3798/NAN-4902); NULL until the next bcrypt verify backfills it.';
