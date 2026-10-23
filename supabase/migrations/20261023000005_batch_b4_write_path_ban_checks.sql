-- ==============================================================================
-- Migration: 20261023000005_batch_b4_write_path_ban_checks.sql
-- Description: Batch B4 - Rigorous IS DISTINCT FROM Ban Checks on Every Write Path
-- ==============================================================================

-- 1. LIBRARY ITEMS
DROP POLICY IF EXISTS "library_items_owner_insert" ON public.library_items;
CREATE POLICY "library_items_owner_insert" ON public.library_items
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

DROP POLICY IF EXISTS "library_items_owner_update" ON public.library_items;
CREATE POLICY "library_items_owner_update" ON public.library_items
FOR UPDATE USING (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
) WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

-- 2. SHOW PROGRESS
DROP POLICY IF EXISTS "show_progress_owner_insert" ON public.show_progress;
CREATE POLICY "show_progress_owner_insert" ON public.show_progress
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

DROP POLICY IF EXISTS "show_progress_owner_update" ON public.show_progress;
CREATE POLICY "show_progress_owner_update" ON public.show_progress
FOR UPDATE USING (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
) WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

-- 3. PRIVATE NOTES
DROP POLICY IF EXISTS "private_notes_owner_insert" ON public.private_notes;
CREATE POLICY "private_notes_owner_insert" ON public.private_notes
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

DROP POLICY IF EXISTS "private_notes_owner_update" ON public.private_notes;
CREATE POLICY "private_notes_owner_update" ON public.private_notes
FOR UPDATE USING (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
) WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

-- 4. LOGS
DROP POLICY IF EXISTS "logs_insert_owner" ON public.logs;
CREATE POLICY "logs_insert_owner" ON public.logs
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

DROP POLICY IF EXISTS "logs_update_owner" ON public.logs;
CREATE POLICY "logs_update_owner" ON public.logs
FOR UPDATE USING (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
) WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);

-- 5. LOG LIKES
DROP POLICY IF EXISTS "log_likes_insert_own" ON public.log_likes;
CREATE POLICY "log_likes_insert_own" ON public.log_likes
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) = user_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
    AND private.can_view_log(log_id)
);

-- 6. FOLLOWS
DROP POLICY IF EXISTS "follows_insert_own" ON public.follows;
CREATE POLICY "follows_insert_own" ON public.follows
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) = follower_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
    AND NOT public.is_blocked_between(follower_id, followee_id)
);

-- 7. BLOCKS
DROP POLICY IF EXISTS "blocks_insert_own" ON public.blocks;
CREATE POLICY "blocks_insert_own" ON public.blocks
FOR INSERT WITH CHECK (
    (SELECT auth.uid()) = blocker_id
    AND (private.is_banned((SELECT auth.uid())) IS DISTINCT FROM true)
);
