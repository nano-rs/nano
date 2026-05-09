-- Migration: 026_notifications
-- Description: Create notifications table for in-app user notifications

-- Notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id uuid PRIMARY KEY DEFAULT public.uuid_generate_v4(),
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    notification_type text NOT NULL,
    title text NOT NULL,
    message text,
    link text,
    metadata jsonb DEFAULT '{}'::jsonb,
    read_at timestamptz,
    created_at timestamptz DEFAULT now() NOT NULL,

    -- Constraint for valid notification types
    CONSTRAINT notifications_type_check CHECK (notification_type = ANY (ARRAY[
        'case_mention'::text,
        'case_assigned'::text,
        'case_status_change'::text,
        'alert_assigned'::text,
        'system'::text
    ]))
);

-- Index for fetching user's notifications (unread first, then by date)
CREATE INDEX IF NOT EXISTS idx_notifications_user_unread
ON notifications(user_id, created_at DESC) WHERE read_at IS NULL;

-- Index for fetching all notifications for a user
CREATE INDEX IF NOT EXISTS idx_notifications_user
ON notifications(user_id, created_at DESC);

-- Add notifications permissions
INSERT INTO public.permissions (id, name, description, category)
VALUES
    ('notifications:view', 'notifications:view', 'View own notifications', 'notifications'),
    ('notifications:manage', 'notifications:manage', 'Manage notification settings', 'notifications')
ON CONFLICT (id) DO NOTHING;

-- Grant notifications:view to Admin role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Admin' AND p.name = 'notifications:view'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant notifications:view to Editor role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Editor' AND p.name = 'notifications:view'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant notifications:view to ReadOnly role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'ReadOnly' AND p.name = 'notifications:view'
ON CONFLICT (role_id, permission_id) DO NOTHING;
