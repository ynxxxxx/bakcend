-- ==============================================================================
-- Migration: 20261023000002_batch_b1_atomic_ban.sql
-- Description: Batch B1 - Atomic Ban and Unban Functions with Rigorous RBAC
-- ==============================================================================

-- 1. Atomic Ban Function in private schema
CREATE OR REPLACE FUNCTION private.ban_user_atomic(
    p_actor_id UUID,
    p_target_user_id UUID,
    p_scope public.ban_scope,
    p_reason TEXT,
    p_expires_at TIMESTAMPTZ DEFAULT NULL,
    p_community_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_actor_role public.staff_role_type;
    v_target_role public.staff_role_type;
    v_ban_id UUID;
BEGIN
    -- Verify actor holds an active staff role
    SELECT role INTO v_actor_role
    FROM public.staff_roles
    WHERE user_id = p_actor_id;

    IF v_actor_role IS NULL THEN
        RAISE EXCEPTION 'Access denied: Actor % does not hold an active staff role', p_actor_id;
    END IF;

    -- Prevent self-ban
    IF p_actor_id = p_target_user_id THEN
        RAISE EXCEPTION 'Invalid operation: Staff cannot ban their own account';
    END IF;

    -- Moderator privilege ceiling: Cannot ban administrators
    SELECT role INTO v_target_role
    FROM public.staff_roles
    WHERE user_id = p_target_user_id;

    IF v_target_role = 'admin' AND v_actor_role = 'moderator' THEN
        RAISE EXCEPTION 'Access denied: Moderators cannot ban administrators';
    END IF;

    -- Atomic Insert into bans
    INSERT INTO public.bans (user_id, scope, community_id, reason, expires_at, banned_by)
    VALUES (p_target_user_id, p_scope, p_community_id, p_reason, p_expires_at, p_actor_id)
    RETURNING id INTO v_ban_id;

    -- Atomic Append to moderation_actions
    INSERT INTO public.moderation_actions (actor_id, action, target_type, target_id, reason)
    VALUES (p_actor_id, 'ban', 'user', p_target_user_id, p_reason);

    RETURN v_ban_id;
END;
$$;

-- 2. Thin Public Wrapper for PostgREST RPC
CREATE OR REPLACE FUNCTION public.admin_ban_user(
    p_actor_id UUID,
    p_target_user_id UUID,
    p_scope public.ban_scope,
    p_reason TEXT,
    p_expires_at TIMESTAMPTZ DEFAULT NULL,
    p_community_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT private.ban_user_atomic(p_actor_id, p_target_user_id, p_scope, p_reason, p_expires_at, p_community_id);
$$;

-- 3. Atomic Unban Function in private schema
CREATE OR REPLACE FUNCTION private.unban_user_atomic(
    p_actor_id UUID,
    p_target_user_id UUID,
    p_reason TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_actor_role public.staff_role_type;
BEGIN
    -- Verify actor holds an active staff role
    SELECT role INTO v_actor_role
    FROM public.staff_roles
    WHERE user_id = p_actor_id;

    IF v_actor_role IS NULL THEN
        RAISE EXCEPTION 'Access denied: Actor % does not hold an active staff role', p_actor_id;
    END IF;

    -- Remove or deactivate existing ban
    DELETE FROM public.bans
    WHERE user_id = p_target_user_id;

    -- Atomic Append to moderation_actions
    INSERT INTO public.moderation_actions (actor_id, action, target_type, target_id, reason)
    VALUES (p_actor_id, 'unban', 'user', p_target_user_id, p_reason);
END;
$$;

-- 4. Thin Public Wrapper for Unban
CREATE OR REPLACE FUNCTION public.admin_unban_user(
    p_actor_id UUID,
    p_target_user_id UUID,
    p_reason TEXT
)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT private.unban_user_atomic(p_actor_id, p_target_user_id, p_reason);
$$;

-- 5. Strict Privilege Boundaries: REVOKE from all, GRANT to service_role only
REVOKE ALL ON FUNCTION private.ban_user_atomic(UUID, UUID, public.ban_scope, TEXT, TIMESTAMPTZ, UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.admin_ban_user(UUID, UUID, public.ban_scope, TEXT, TIMESTAMPTZ, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION private.ban_user_atomic(UUID, UUID, public.ban_scope, TEXT, TIMESTAMPTZ, UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.admin_ban_user(UUID, UUID, public.ban_scope, TEXT, TIMESTAMPTZ, UUID) TO service_role;

REVOKE ALL ON FUNCTION private.unban_user_atomic(UUID, UUID, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.admin_unban_user(UUID, UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION private.unban_user_atomic(UUID, UUID, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.admin_unban_user(UUID, UUID, TEXT) TO service_role;
