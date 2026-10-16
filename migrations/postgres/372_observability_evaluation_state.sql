-- NAN-3894: cached hosted results; definitions remain the source of truth.
CREATE TABLE observability_slo_evaluations (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    slo_id UUID NOT NULL,
    current DOUBLE PRECISION,
    total BIGINT NOT NULL CHECK (total >= 0),
    no_data BOOLEAN NOT NULL,
    budget_remaining_pct DOUBLE PRECISION,
    burn_fast DOUBLE PRECISION,
    burn_slow DOUBLE PRECISION,
    status TEXT NOT NULL CHECK (status IN ('ok','at_risk','breaching','no_data','partial')),
    definition_updated_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, slo_id)
);
CREATE TABLE observability_metric_monitor_state (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    monitor_id UUID NOT NULL,
    series_key TEXT NOT NULL,
    value DOUBLE PRECISION,
    breaching BOOLEAN NOT NULL,
    no_data BOOLEAN NOT NULL,
    definition_updated_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, monitor_id, series_key)
);

-- Bound dedicated re-arm lookups; the enterprise overlay adds the tenant index.
-- Core migrations also run after hosted activation, when alerts is owned by
-- the NOLOGIN data owner. Open only the established managed-owner window.
DO $rearm_index$
DECLARE owner_role NAME; owner_token INTEGER := 0;
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;
    CREATE INDEX IF NOT EXISTS idx_alerts_observability_rearm
        ON public.alerts (kind, source_id, created_at DESC)
        WHERE kind IN ('metric_monitor','slo');
    IF owner_token <> 0 THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$rearm_index$;
