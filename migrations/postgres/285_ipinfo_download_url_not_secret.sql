-- NAN-2343: stop masking the IPinfo Lite download URL in the marketplace UI.
--
-- `download_url` was seeded with field_type 'secret' (migrations 101 and 177),
-- so the marketplace drawer renders it as a password input. Combined with the
-- drawer resetting its credential state to {} on open, that made the saved
-- value impossible to read back anywhere in that UI — the eight-dot display is
-- a placeholder, and the reveal toggle only unmasks local state, which is
-- empty. Operators could neither verify what was stored nor spot a bad paste.
--
-- The masking bought nothing. The same value is persisted in cleartext in
-- `enrichment_sources.download_url` and is returned in cleartext by
-- `GET /api/enrichment/sources`. All it did was hide exactly the paste
-- artifacts that break the URL — a missing scheme, wrapping quotes, angle
-- brackets, a copied `curl`/`wget` prefix — and those produce a parse failure
-- that surfaces much later as a confusing sync-time error.
--
-- The embedded token is real credential material, but it is already stored and
-- served in cleartext; masking one of several displays of it is theatre that
-- costs the operator all verifiability. Making the field readable is what lets
-- them self-diagnose, and it is a prerequisite for retiring the legacy
-- /enrichments/ipinfo_lite page, which was the only remaining surface showing
-- the URL in the clear.
--
-- Rewrites only the download_url element and only its field_type, preserving
-- any label/help/required customisation. Idempotent: re-running finds no
-- 'secret' element and updates nothing.

UPDATE marketplace_catalog
SET credential_fields = (
        SELECT jsonb_agg(
            CASE
                WHEN field->>'name' = 'download_url'
                    THEN jsonb_set(field, '{field_type}', '"text"')
                ELSE field
            END
            ORDER BY ordinality
        )
        FROM jsonb_array_elements(credential_fields) WITH ORDINALITY AS t(field, ordinality)
    ),
    updated_at = NOW()
WHERE native_source_id = 'ipinfo_lite'
  AND credential_fields @> '[{"name": "download_url", "field_type": "secret"}]';
