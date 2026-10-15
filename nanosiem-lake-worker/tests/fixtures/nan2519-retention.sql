-- Full-chain disposable fixture: avoids the old reduced fixture's claim/pin
-- column mismatch and tests actual foreign keys, triggers, RLS and grants.
\ir ../../../scripts/prove-platform-stamping-retention.sql
