-- Cluster-visible fence used while the upgrade/backup coordinator captures a
-- PostgreSQL + ClickHouse recovery set.  There is deliberately one row: every
-- API replica observes the same state before accepting a mutating request.
CREATE TABLE backup_mutation_fence (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active boolean NOT NULL DEFAULT false,
    owner text,
    activated_at timestamptz,
    CHECK ((active AND owner IS NOT NULL AND activated_at IS NOT NULL)
        OR (NOT active AND owner IS NULL AND activated_at IS NULL))
);

INSERT INTO backup_mutation_fence (singleton) VALUES (true);
