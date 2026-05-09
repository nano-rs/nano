-- Case-Notebook Integration
-- Adds case_id to notebooks for linking investigation notebooks to cases

-- Add case_id column to notebooks table (nullable for regular notebooks)
-- ON DELETE CASCADE: When a case is deleted, its notebook is also deleted
ALTER TABLE public.notebooks ADD COLUMN case_id uuid REFERENCES public.cases(id) ON DELETE CASCADE;

-- Create unique partial index to ensure only one notebook per case
CREATE UNIQUE INDEX idx_notebooks_case_id ON public.notebooks(case_id) WHERE case_id IS NOT NULL;

-- Add index for fast case-notebook lookup
CREATE INDEX idx_notebooks_case_lookup ON public.notebooks(case_id) WHERE case_id IS NOT NULL;

-- Update notebook_references to include 'case' as a valid reference type
ALTER TABLE public.notebook_references DROP CONSTRAINT IF EXISTS notebook_references_type_check;
ALTER TABLE public.notebook_references ADD CONSTRAINT notebook_references_type_check
    CHECK (reference_type = ANY (ARRAY['alert'::text, 'detection'::text, 'saved_search'::text, 'case'::text]));

COMMENT ON COLUMN public.notebooks.case_id IS 'When non-null, this is a case notebook auto-created on assignment. NULL indicates a regular threat hunting notebook.';
