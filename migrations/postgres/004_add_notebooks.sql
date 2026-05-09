-- Investigation Notebooks
-- AI-powered shadow agent for tracking analyst investigations

-- Create notebooks table
CREATE TABLE public.notebooks (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    title text NOT NULL,
    owner_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    visibility text DEFAULT 'private'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    summary text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    CONSTRAINT notebooks_pkey PRIMARY KEY (id),
    CONSTRAINT notebooks_visibility_check CHECK (visibility = ANY (ARRAY['private'::text, 'shared'::text, 'public'::text])),
    CONSTRAINT notebooks_status_check CHECK (status = ANY (ARRAY['active'::text, 'paused'::text, 'closed'::text]))
);

-- Create notebook_shares table for granular sharing
CREATE TABLE public.notebook_shares (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    notebook_id uuid NOT NULL REFERENCES public.notebooks(id) ON DELETE CASCADE,
    shared_with_user_id uuid REFERENCES public.users(id) ON DELETE CASCADE,
    shared_with_group_id uuid REFERENCES public.groups(id) ON DELETE CASCADE,
    permission text DEFAULT 'view'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT notebook_shares_pkey PRIMARY KEY (id),
    CONSTRAINT notebook_shares_permission_check CHECK (permission = ANY (ARRAY['view'::text, 'edit'::text])),
    CONSTRAINT notebook_shares_target_check CHECK (
        (shared_with_user_id IS NOT NULL AND shared_with_group_id IS NULL) OR
        (shared_with_user_id IS NULL AND shared_with_group_id IS NOT NULL)
    )
);

-- Create notebook_entries table for investigation timeline
CREATE TABLE public.notebook_entries (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    notebook_id uuid NOT NULL REFERENCES public.notebooks(id) ON DELETE CASCADE,
    entry_type text NOT NULL,
    content jsonb DEFAULT '{}'::jsonb NOT NULL,
    source_url text,
    created_by uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT notebook_entries_pkey PRIMARY KEY (id),
    CONSTRAINT notebook_entries_type_check CHECK (entry_type = ANY (ARRAY[
        'manual_note'::text,
        'search_executed'::text,
        'search_refined'::text,
        'alert_viewed'::text,
        'alert_actioned'::text,
        'detection_viewed'::text,
        'detection_modified'::text,
        'ai_suggestion'::text,
        'ai_summary'::text
    ]))
);

-- Create notebook_references table for linking to alerts/detections
CREATE TABLE public.notebook_references (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    notebook_id uuid NOT NULL REFERENCES public.notebooks(id) ON DELETE CASCADE,
    reference_type text NOT NULL,
    reference_id uuid NOT NULL,
    reference_name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT notebook_references_pkey PRIMARY KEY (id),
    CONSTRAINT notebook_references_type_check CHECK (reference_type = ANY (ARRAY['alert'::text, 'detection'::text, 'saved_search'::text])),
    CONSTRAINT notebook_references_unique UNIQUE (notebook_id, reference_type, reference_id)
);

-- Create indexes for efficient queries
CREATE INDEX idx_notebooks_owner_id ON public.notebooks(owner_id);
CREATE INDEX idx_notebooks_status ON public.notebooks(status);
CREATE INDEX idx_notebooks_visibility ON public.notebooks(visibility, owner_id);
CREATE INDEX idx_notebook_shares_notebook_id ON public.notebook_shares(notebook_id);
CREATE INDEX idx_notebook_shares_user_id ON public.notebook_shares(shared_with_user_id);
CREATE INDEX idx_notebook_shares_group_id ON public.notebook_shares(shared_with_group_id);
CREATE INDEX idx_notebook_entries_notebook_id ON public.notebook_entries(notebook_id);
CREATE INDEX idx_notebook_entries_created_at ON public.notebook_entries(notebook_id, created_at);
CREATE INDEX idx_notebook_references_notebook_id ON public.notebook_references(notebook_id);
CREATE INDEX idx_notebook_references_ref ON public.notebook_references(reference_type, reference_id);

-- Comments for documentation
COMMENT ON TABLE public.notebooks IS 'Investigation notebooks for tracking analyst work with AI assistance';
COMMENT ON COLUMN public.notebooks.visibility IS 'private: only owner, shared: specific users/groups, public: all users';
COMMENT ON COLUMN public.notebooks.status IS 'active: in progress, paused: temporarily stopped, closed: completed with summary';
COMMENT ON COLUMN public.notebooks.summary IS 'AI-generated summary created when notebook is closed';
COMMENT ON TABLE public.notebook_shares IS 'Granular sharing permissions for notebooks';
COMMENT ON TABLE public.notebook_entries IS 'Timeline of investigation activities and notes';
COMMENT ON COLUMN public.notebook_entries.entry_type IS 'Type of entry: manual_note, search_*, alert_*, detection_*, ai_*';
COMMENT ON COLUMN public.notebook_entries.content IS 'JSON content varies by entry_type';
COMMENT ON TABLE public.notebook_references IS 'Links between notebooks and other entities (alerts, detections, saved searches)';
