-- Add ownership and visibility to dashboards
-- Enables private dashboards tied to users

-- Add owner_id column (nullable initially for existing dashboards)
ALTER TABLE public.dashboards
ADD COLUMN owner_id uuid REFERENCES public.users(id) ON DELETE SET NULL;

-- Add is_private column (default false to keep existing dashboards public)
ALTER TABLE public.dashboards
ADD COLUMN is_private boolean DEFAULT false NOT NULL;

-- Create index for efficient user dashboard queries
CREATE INDEX idx_dashboards_owner_id ON public.dashboards(owner_id);

-- Create index for visibility filtering
CREATE INDEX idx_dashboards_visibility ON public.dashboards(is_private, owner_id);

-- Comment for documentation
COMMENT ON COLUMN public.dashboards.owner_id IS 'User who created/owns the dashboard. NULL for system/legacy dashboards.';
COMMENT ON COLUMN public.dashboards.is_private IS 'If true, only owner can view/edit. If false, visible to all users with dashboards:view permission.';
