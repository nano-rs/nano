-- Notebook Merge and Case Linking Enhancements
-- Allows merging multiple notebooks and linking existing notebooks to cases

-- Add merged_into_id to track merge relationships
ALTER TABLE public.notebooks ADD COLUMN merged_into_id uuid REFERENCES public.notebooks(id) ON DELETE SET NULL;

-- Add 'merged' as a valid status (read-only archive state after merge)
ALTER TABLE public.notebooks DROP CONSTRAINT IF EXISTS notebooks_status_check;
ALTER TABLE public.notebooks ADD CONSTRAINT notebooks_status_check
    CHECK (status = ANY (ARRAY['active'::text, 'paused'::text, 'closed'::text, 'merged'::text]));

-- Add columns to track merged entries (preserves original context)
ALTER TABLE public.notebook_entries ADD COLUMN merged_from_notebook_id uuid REFERENCES public.notebooks(id) ON DELETE SET NULL;
ALTER TABLE public.notebook_entries ADD COLUMN merged_from_notebook_title text;
ALTER TABLE public.notebook_entries ADD COLUMN original_created_at timestamp with time zone;

-- Index for finding merged notebooks
CREATE INDEX idx_notebooks_merged_into ON public.notebooks(merged_into_id) WHERE merged_into_id IS NOT NULL;

-- Index for merged entries
CREATE INDEX idx_notebook_entries_merged_from ON public.notebook_entries(merged_from_notebook_id) WHERE merged_from_notebook_id IS NOT NULL;

-- Drop the unique constraint on case_id to allow linking existing notebooks
-- (Previously enforced one notebook per case, but now we allow unlinking/relinking)
DROP INDEX IF EXISTS idx_notebooks_case_id;

-- Recreate as a regular index (not unique) - cases can have at most one ACTIVE notebook
-- but previously merged/closed notebooks may still reference the case
CREATE INDEX idx_notebooks_case_id ON public.notebooks(case_id) WHERE case_id IS NOT NULL;

COMMENT ON COLUMN public.notebooks.merged_into_id IS 'When non-null, this notebook was merged into another notebook and is read-only';
COMMENT ON COLUMN public.notebook_entries.merged_from_notebook_id IS 'Original notebook ID if this entry was merged from another notebook';
COMMENT ON COLUMN public.notebook_entries.merged_from_notebook_title IS 'Original notebook title at time of merge';
COMMENT ON COLUMN public.notebook_entries.original_created_at IS 'Original creation timestamp (for merged entries, preserves chronology)';
