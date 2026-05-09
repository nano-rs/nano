-- Notebook Tabs
-- Server-side persistence for multi-tab notebook interface
-- Allows users to have multiple notebooks open simultaneously across devices

CREATE TABLE public.notebook_tabs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    notebook_id uuid NOT NULL REFERENCES public.notebooks(id) ON DELETE CASCADE,
    is_pinned boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    tab_order integer NOT NULL,
    last_accessed_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT notebook_tabs_pkey PRIMARY KEY (id),
    CONSTRAINT notebook_tabs_unique_user_notebook UNIQUE (user_id, notebook_id)
);

-- Index for fast lookup of user's tabs
CREATE INDEX idx_notebook_tabs_user_id ON public.notebook_tabs(user_id);

-- Index for cleanup of stale tabs (unpinned tabs older than 7 days)
CREATE INDEX idx_notebook_tabs_last_accessed ON public.notebook_tabs(last_accessed_at) WHERE is_pinned = false;

-- Index for ordering tabs
CREATE INDEX idx_notebook_tabs_order ON public.notebook_tabs(user_id, tab_order);

-- Comments for documentation
COMMENT ON TABLE public.notebook_tabs IS 'User notebook tabs for multi-tab interface with server-side persistence';
COMMENT ON COLUMN public.notebook_tabs.is_pinned IS 'Pinned tabs are never auto-closed due to inactivity';
COMMENT ON COLUMN public.notebook_tabs.is_active IS 'Only one tab per user can be active at a time';
COMMENT ON COLUMN public.notebook_tabs.tab_order IS 'Order of tabs in the tab bar (lower = left)';
COMMENT ON COLUMN public.notebook_tabs.last_accessed_at IS 'Updated when tab becomes active, used for auto-close after 7 days';
