-- ==============================================================================
-- Migration: 20261023000004_batch_b3_policy_hardening.sql
-- Description: Batch B3 - Hardened Policies for staff_roles, profiles, logs, and log_likes
-- ==============================================================================

-- 1. private.is_admin() with empty search_path and schema-qualified references
CREATE OR REPLACE FUNCTION private.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.staff_roles
        WHERE user_id = (SELECT auth.uid()) AND role = 'admin'
    );
$$;

-- 2. staff_roles_select: Own row OR private.is_admin()
DROP POLICY IF EXISTS "staff_roles_select" ON public.staff_roles;
CREATE POLICY "staff_roles_select" ON public.staff_roles
FOR SELECT USING (
    (SELECT auth.uid()) = user_id OR private.is_admin()
);

-- 3. profiles_select: Own profile always visible; hidden in BOTH block directions with table aliases
DROP POLICY IF EXISTS "profiles_select" ON public.profiles;
CREATE POLICY "profiles_select" ON public.profiles AS p
FOR SELECT USING (
    ((SELECT auth.uid()) IS NOT NULL AND (SELECT auth.uid()) = p.id)
    OR
    (
        NOT EXISTS (
            SELECT 1 FROM public.blocks b
            WHERE (b.blocker_id = (SELECT auth.uid()) AND b.blocked_id = p.id)
               OR (b.blocker_id = p.id AND b.blocked_id = (SELECT auth.uid()))
        )
    )
);

-- 4. Shared Log Visibility Function
CREATE OR REPLACE FUNCTION private.can_view_log(p_log_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.logs l
        WHERE l.id = p_log_id
          AND (
              l.user_id = (SELECT auth.uid())
              OR
              (
                  l.status = 'visible'
                  AND l.deleted_at IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM public.blocks b
                      WHERE (b.blocker_id = (SELECT auth.uid()) AND b.blocked_id = l.user_id)
                         OR (b.blocker_id = l.user_id AND b.blocked_id = (SELECT auth.uid()))
                  )
              )
          )
    );
$$;

-- 5. logs_select with explicit alias and mutual block checks
DROP POLICY IF EXISTS "logs_select" ON public.logs;
CREATE POLICY "logs_select" ON public.logs AS l
FOR SELECT USING (
    l.user_id = (SELECT auth.uid())
    OR
    (
        l.status = 'visible'
        AND l.deleted_at IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM public.blocks b
            WHERE (b.blocker_id = (SELECT auth.uid()) AND b.blocked_id = l.user_id)
               OR (b.blocker_id = l.user_id AND b.blocked_id = (SELECT auth.uid()))
        )
    )
);

-- 6. log_likes_select: Own likes OR likes on logs the viewer can see via shared visibility function
DROP POLICY IF EXISTS "log_likes_select" ON public.log_likes;
CREATE POLICY "log_likes_select" ON public.log_likes AS ll
FOR SELECT USING (
    ll.user_id = (SELECT auth.uid())
    OR
    private.can_view_log(ll.log_id)
);

-- 7. Grant execution on shared log visibility
REVOKE ALL ON FUNCTION private.can_view_log(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION private.can_view_log(UUID) TO authenticated, anon;
