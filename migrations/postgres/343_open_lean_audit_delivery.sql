-- NAN-3492: durable delivery to the trusted-local Vector bronze lane.
-- A Vector 2xx proves bronze acknowledgement, not searchable part publication;
-- keep the hosted/gen1 component and composite acknowledgement fields intact.
--
-- Columns only (nullable, no default: metadata-only on every edition). The
-- pending partial index is NOT created here: on hosted these columns are never
-- set, so an index keyed on them would cover every audit row forever. The open
-- lean audit worker creates it at boot (LocalAuditDelivery::prepare), so it
-- exists only on trusted-local installs.
ALTER TABLE platform_audit_events
    ADD COLUMN IF NOT EXISTS lean_delivered_at timestamptz,
    ADD COLUMN IF NOT EXISTS lean_delivery_error text;
