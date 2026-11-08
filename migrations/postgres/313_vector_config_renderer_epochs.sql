-- NAN-4973: durable renderer-identity -> epoch allocation for Vector config
-- publication (NAN-1779 / NAN-2304 protocol).
--
-- A renderer may republish a source revision only with a higher epoch than
-- the committed one. The epoch used to come solely from
-- VECTOR_CONFIG_RENDERER_EPOCH (default 0), so:
--   * a new build at the same semantic version (dev-<sha> images) rendered the
--     committed revision differently and was refused (DivergentRender): new
--     API pods served no generation and new Vector pods never became Ready;
--   * any deployer-derived counter (e.g. a Helm release revision) resets on a
--     reinstall onto retained data, fencing every API as a superseded renderer.
-- Each distinct renderer identity (version + build + render-affecting env) is
-- now allocated an epoch once, above every epoch seen so far, under the
-- publication-state row lock. The same identity always maps to the same epoch,
-- so replicas agree, a restarted older pod during a rollout keeps its lower
-- epoch (no flip-flop), and a reinstall of the same build rejoins the
-- committed generation. An explicit VECTOR_CONFIG_RENDERER_EPOCH still wins.
-- Forward-only, idempotent.

CREATE TABLE IF NOT EXISTS vector_config_renderer_epochs (
    identity TEXT PRIMARY KEY,
    epoch BIGINT NOT NULL,
    renderer_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vector_config_renderer_epochs_identity_format
        CHECK (identity ~ '^[0-9a-f]{64}$'),
    CONSTRAINT vector_config_renderer_epochs_epoch_positive CHECK (epoch > 0),
    CONSTRAINT vector_config_renderer_epochs_epoch_key UNIQUE (epoch)
);
