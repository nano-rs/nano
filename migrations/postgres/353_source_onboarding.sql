-- NAN-3684: user-owned planning fields; progress is never stored.
-- Numbered 353 / 9013420 (was 351 / 9013210): live control DBs already applied 352
-- and 9013220..9013400, so the original numbers would have applied out of order.
SET LOCAL lock_timeout = '5s';
CREATE TABLE IF NOT EXISTS public.source_onboarding_waves (
 tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
 id UUID NOT NULL DEFAULT gen_random_uuid(),
 name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
 target DATE, sort_order INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY (tenant_id,id)
);
CREATE TABLE IF NOT EXISTS public.source_onboarding_planned_sources (
 tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
 id UUID NOT NULL DEFAULT gen_random_uuid(),
 name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
 vendor TEXT NOT NULL DEFAULT '' CHECK (length(vendor)<=200),
 expected_type TEXT CHECK (length(expected_type)<=100),
 wave_id UUID, priority SMALLINT NOT NULL DEFAULT 2 CHECK (priority BETWEEN 1 AND 3),
 owner TEXT NOT NULL DEFAULT '' CHECK (length(owner)<=200), target DATE,
 notes TEXT NOT NULL DEFAULT '' CHECK (length(notes)<=10000),
 linked_log_source_id UUID, dismissed_log_source_ids UUID[] NOT NULL DEFAULT '{}',
 completed BOOLEAN NOT NULL DEFAULT FALSE, completed_at TIMESTAMPTZ, completed_by UUID,
 PRIMARY KEY (tenant_id,id),
 FOREIGN KEY (tenant_id,wave_id) REFERENCES public.source_onboarding_waves(tenant_id,id),
 CHECK (completed = (completed_at IS NOT NULL)),
 CHECK (completed = (completed_by IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS source_onboarding_plan_name
 ON public.source_onboarding_planned_sources(tenant_id,lower(name));
CREATE UNIQUE INDEX IF NOT EXISTS source_onboarding_plan_link
 ON public.source_onboarding_planned_sources(tenant_id,linked_log_source_id) WHERE linked_log_source_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS public.source_onboarding_settings (
 tenant_id UUID PRIMARY KEY REFERENCES public.tenants(id) ON DELETE CASCADE,
 group_by TEXT NOT NULL DEFAULT 'wave' CHECK (group_by IN ('wave','priority','none')),
 complete_gate BOOLEAN NOT NULL DEFAULT TRUE, auto_suggest BOOLEAN NOT NULL DEFAULT TRUE
);
