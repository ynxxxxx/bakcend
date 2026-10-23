-- ==============================================================================
-- COMPLETE PHASE 1 HARDENED SUPABASE POSTGRES SCHEMA
-- Project: ldiyekkmzhzmnztvdckc
-- Generated: 2026-10-23
-- ==============================================================================


-- >>> BEGIN MIGRATION: 20261023000001_phase1_initial_schema.sql <<<

-- ==============================================================================
-- Migration: 20261023000001_phase1_initial_schema.sql
-- Description: Phase 1 Foundation - Comprehensive Production-Hardened Engine
-- ==============================================================================

-- 1. SCHEMAS & EXTENSIONS
CREATE SCHEMA IF NOT EXISTS private;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "citext" WITH SCHEMA public;

-- 2. ENUM TYPES
DO $$ BEGIN
    CREATE TYPE tracking_status AS ENUM ('watching', 'watchlist', 'completed', 'paused', 'dropped');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE log_status AS ENUM ('visible', 'hidden', 'held', 'removed');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE staff_role_type AS ENUM ('admin', 'moderator');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE ban_scope AS ENUM ('global', 'community');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

-- 3. PROFILES (Public Identity Only)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username CITEXT UNIQUE,
    display_name TEXT,
    avatar_url TEXT,
    bio TEXT,
    onboarded BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT username_format_check CHECK (
        username IS NULL OR (username ~ '^[a-z0-9_]{3,20}$')
    ),
    CONSTRAINT username_not_reserved CHECK (
        username IS NULL OR username NOT IN (
            'admin', 'administrator', 'root', 'moderator', 'mod', 'serializd',
            'ullista', 'system', 'support', 'help', 'security', 'official',
            'anonymous', 'null', 'undefined', 'deleted_user', 'api', 'auth',
            'staff', 'owner', 'terms', 'privacy', 'about', 'contact'
        )
    ),
    CONSTRAINT display_name_length CHECK (
        display_name IS NULL OR length(display_name) <= 50
    ),
    CONSTRAINT bio_length CHECK (
        bio IS NULL OR length(bio) <= 300
    )
);

CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);

-- 4. USER FLAGS (Sensitive State - Owner Read-Only, No Client Writes)
CREATE TABLE IF NOT EXISTS public.user_flags (
    user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
    trust_level INT DEFAULT 0 NOT NULL CHECK (trust_level >= 0),
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 5. BANS
CREATE TABLE IF NOT EXISTS public.bans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    scope ban_scope DEFAULT 'global' NOT NULL,
    community_id UUID,
    reason TEXT NOT NULL,
    banned_by UUID,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT ban_reason_length CHECK (length(trim(reason)) >= 3)
);

CREATE INDEX IF NOT EXISTS idx_bans_user_scope ON public.bans(user_id, scope, expires_at);

-- 6. STAFF ROLES (RBAC)
CREATE TABLE IF NOT EXISTS public.staff_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    role staff_role_type NOT NULL,
    community_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_role_scope UNIQUE (user_id, role, community_id)
);

CREATE INDEX IF NOT EXISTS idx_staff_roles_lookup ON public.staff_roles(user_id, role);

-- 7. APPEND-ONLY MODERATION AUDIT LOG
CREATE TABLE IF NOT EXISTS public.moderation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES public.profiles(id),
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id UUID NOT NULL,
    reason TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT moderation_action_reason_check CHECK (length(trim(reason)) >= 3)
);

CREATE INDEX IF NOT EXISTS idx_moderation_actions_target ON public.moderation_actions(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_moderation_actions_created ON public.moderation_actions(created_at DESC);

-- 8. SOCIAL RELATIONSHIPS: FOLLOWS & BLOCKS
CREATE TABLE IF NOT EXISTS public.follows (
    follower_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    followee_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    PRIMARY KEY (follower_id, followee_id),
    CONSTRAINT no_self_follow CHECK (follower_id != followee_id)
);

CREATE INDEX IF NOT EXISTS idx_follows_followee ON public.follows(followee_id);

CREATE TABLE IF NOT EXISTS public.blocks (
    blocker_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    blocked_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    PRIMARY KEY (blocker_id, blocked_id),
    CONSTRAINT no_self_block CHECK (blocker_id != blocked_id)
);

CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON public.blocks(blocked_id);

-- 9. TRACKING: LIBRARY ITEMS & SHOW PROGRESS (Sync & Soft Deletes)
CREATE TABLE IF NOT EXISTS public.library_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    status tracking_status NOT NULL,
    client_updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_library_show UNIQUE (user_id, show_id)
);

CREATE INDEX IF NOT EXISTS idx_library_items_sync ON public.library_items(user_id, updated_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_library_items_status ON public.library_items(user_id, status) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS public.show_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    season INT DEFAULT 0 NOT NULL CHECK (season >= 0),
    episode INT DEFAULT 0 NOT NULL CHECK (episode >= 0),
    client_updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_show_progress UNIQUE (user_id, show_id)
);

CREATE INDEX IF NOT EXISTS idx_show_progress_sync ON public.show_progress(user_id, updated_at DESC, id);

-- 10. TRACKING: LOGS & DIARY
CREATE TABLE IF NOT EXISTS public.logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    show_name TEXT NOT NULL,
    show_poster_path TEXT,
    season_number INT CHECK (season_number IS NULL OR season_number >= 0),
    episode_number INT CHECK (episode_number IS NULL OR episode_number >= 0),
    rating NUMERIC(2,1) CHECK (
        rating IS NULL OR (rating >= 0.5 AND rating <= 5.0 AND mod(rating * 2, 1) = 0)
    ),
    review_text TEXT,
    contains_spoilers BOOLEAN DEFAULT false NOT NULL,
    is_rewatch BOOLEAN DEFAULT false NOT NULL,
    liked BOOLEAN DEFAULT false NOT NULL,
    watched_date DATE DEFAULT CURRENT_DATE NOT NULL,
    tags TEXT[] DEFAULT '{}'::text[] NOT NULL,
    like_count INT DEFAULT 0 NOT NULL CHECK (like_count >= 0),
    status log_status DEFAULT 'visible' NOT NULL,
    client_updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT review_text_limit CHECK (
        review_text IS NULL OR length(review_text) <= 5000
    ),
    CONSTRAINT tags_count_limit CHECK (
        cardinality(tags) <= 20
    )
);

CREATE INDEX IF NOT EXISTS idx_logs_feed ON public.logs(status, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_logs_user_sync ON public.logs(user_id, updated_at DESC, id);

-- 11. LOG LIKES
CREATE TABLE IF NOT EXISTS public.log_likes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    log_id UUID REFERENCES public.logs(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_log_like UNIQUE (user_id, log_id)
);

CREATE INDEX IF NOT EXISTS idx_log_likes_log ON public.log_likes(log_id);

-- 12. PRIVATE OWNER-ONLY NOTES
CREATE TABLE IF NOT EXISTS public.private_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    body TEXT NOT NULL,
    client_updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_show_note UNIQUE (user_id, show_id),
    CONSTRAINT private_note_limit CHECK (length(body) <= 10000)
);

CREATE INDEX IF NOT EXISTS idx_private_notes_sync ON public.private_notes(user_id, updated_at DESC, id);

-- ==============================================================================
-- 13. SECURITY FUNCTIONS IN PRIVATE SCHEMA
-- ==============================================================================

CREATE OR REPLACE FUNCTION private.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.staff_roles
        WHERE user_id = auth.uid() AND role = 'admin'
    );
$$;

-- Global ban checker with strict IS DISTINCT FROM probing defense
CREATE OR REPLACE FUNCTION private.is_banned(target_user_id UUID DEFAULT auth.uid())
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Anti-probing defense using IS DISTINCT FROM
    IF target_user_id IS DISTINCT FROM auth.uid() AND NOT private.is_admin() THEN
        RAISE EXCEPTION 'Access denied: Cannot probe ban status of other users';
    END IF;

    -- Only active unexpired GLOBAL bans restrict platform-wide writes
    RETURN EXISTS (
        SELECT 1 FROM public.bans
        WHERE user_id = target_user_id
          AND scope = 'global'
          AND (expires_at IS NULL OR expires_at > NOW())
    );
END;
$$;

-- ==============================================================================
-- 14. PUBLIC SECURITY DEFINER UTILITIES
-- ==============================================================================

CREATE OR REPLACE FUNCTION public.is_blocked_between(user_a UUID, user_b UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.blocks
        WHERE (blocker_id = user_a AND blocked_id = user_b)
           OR (blocker_id = user_b AND blocked_id = user_a)
    );
$$;

CREATE OR REPLACE FUNCTION public.get_my_blocked_users()
RETURNS TABLE (
    blocked_id UUID,
    username CITEXT,
    avatar_url TEXT,
    blocked_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT 
        b.blocked_id,
        p.username,
        p.avatar_url,
        b.created_at AS blocked_at
    FROM public.blocks b
    JOIN public.profiles p ON p.id = b.blocked_id
    WHERE b.blocker_id = auth.uid()
    ORDER BY b.created_at DESC;
$$;

CREATE OR REPLACE FUNCTION public.recount_likes(target_log_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actual_count INT;
BEGIN
    IF NOT private.is_admin() THEN
        RAISE EXCEPTION 'Access denied: Admin only';
    END IF;

    SELECT COUNT(*) INTO v_actual_count
    FROM public.log_likes
    WHERE log_id = target_log_id;

    UPDATE public.logs
    SET like_count = v_actual_count
    WHERE id = target_log_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.purge_soft_deleted_tombstones(retention_days INT DEFAULT 90)
RETURNS INT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_purged INT := 0;
    v_count INT;
    v_cutoff TIMESTAMPTZ := NOW() - (retention_days || ' days')::INTERVAL;
BEGIN
    DELETE FROM public.library_items WHERE deleted_at IS NOT NULL AND deleted_at < v_cutoff;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    v_purged := v_purged + v_count;

    DELETE FROM public.show_progress WHERE deleted_at IS NOT NULL AND deleted_at < v_cutoff;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    v_purged := v_purged + v_count;

    DELETE FROM public.private_notes WHERE deleted_at IS NOT NULL AND deleted_at < v_cutoff;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    v_purged := v_purged + v_count;

    DELETE FROM public.logs WHERE deleted_at IS NOT NULL AND deleted_at < v_cutoff;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    v_purged := v_purged + v_count;

    RETURN v_purged;
END;
$$;

-- ==============================================================================
-- 15. AUTOMATIC TRIGGERS & INTEGRITY GUARDS
-- ==============================================================================

CREATE OR REPLACE FUNCTION public.fn_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_profiles_updated_at ON public.profiles;
CREATE TRIGGER trg_profiles_updated_at BEFORE UPDATE ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_user_flags_updated_at ON public.user_flags;
CREATE TRIGGER trg_user_flags_updated_at BEFORE UPDATE ON public.user_flags
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

-- New user auth trigger
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO public.profiles (id, display_name, avatar_url, onboarded)
    VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', 'New Member'),
        NEW.raw_user_meta_data->>'avatar_url',
        false
    )
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO public.user_flags (user_id, trust_level)
    VALUES (NEW.id, 0)
    ON CONFLICT (user_id) DO NOTHING;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Mutual Follow Deletion Trigger on Block
CREATE OR REPLACE FUNCTION public.on_block_delete_follows()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    DELETE FROM public.follows
    WHERE (follower_id = NEW.blocker_id AND followee_id = NEW.blocked_id)
       OR (follower_id = NEW.blocked_id AND followee_id = NEW.blocker_id);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_block_delete_follows ON public.blocks;
CREATE TRIGGER trg_block_delete_follows AFTER INSERT ON public.blocks
FOR EACH ROW EXECUTE FUNCTION public.on_block_delete_follows();

-- Stale write & future clock clamping trigger
CREATE OR REPLACE FUNCTION public.protect_stale_upsert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_max_future TIMESTAMPTZ := NOW() + INTERVAL '5 minutes';
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.user_id != OLD.user_id THEN
        RAISE EXCEPTION 'Access denied: Cannot transfer ownership of records';
    END IF;

    IF NEW.client_updated_at > v_max_future THEN
        NEW.client_updated_at := v_max_future;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.client_updated_at < OLD.client_updated_at THEN
            RETURN OLD;
        END IF;
    END IF;

    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_library_items_stale_guard ON public.library_items;
CREATE TRIGGER trg_library_items_stale_guard BEFORE INSERT OR UPDATE ON public.library_items
FOR EACH ROW EXECUTE FUNCTION public.protect_stale_upsert();

DROP TRIGGER IF EXISTS trg_show_progress_stale_guard ON public.show_progress;
CREATE TRIGGER trg_show_progress_stale_guard BEFORE INSERT OR UPDATE ON public.show_progress
FOR EACH ROW EXECUTE FUNCTION public.protect_stale_upsert();

DROP TRIGGER IF EXISTS trg_logs_stale_guard ON public.logs;
CREATE TRIGGER trg_logs_stale_guard BEFORE INSERT OR UPDATE ON public.logs
FOR EACH ROW EXECUTE FUNCTION public.protect_stale_upsert();

DROP TRIGGER IF EXISTS trg_private_notes_stale_guard ON public.private_notes;
CREATE TRIGGER trg_private_notes_stale_guard BEFORE INSERT OR UPDATE ON public.private_notes
FOR EACH ROW EXECUTE FUNCTION public.protect_stale_upsert();

-- Comprehensive Log Moderation & Status Guard Trigger
CREATE OR REPLACE FUNCTION public.guard_log_tampering()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.user_id != OLD.user_id THEN
        RAISE EXCEPTION 'Access denied: Cannot transfer log ownership';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.like_count != 0 AND NOT private.is_admin() THEN
            NEW.like_count := 0;
        END IF;
        IF NEW.status != 'visible' AND NOT private.is_admin() THEN
            NEW.status := 'visible';
        END IF;

    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.like_count != OLD.like_count AND NOT private.is_admin() THEN
            RAISE EXCEPTION 'Access denied: like_count is server-maintained and cannot be edited';
        END IF;

        IF NOT private.is_admin() THEN
            IF OLD.status = 'removed' THEN
                RAISE EXCEPTION 'Access denied: Content has been removed by moderation';
            END IF;

            IF NEW.status != OLD.status THEN
                RAISE EXCEPTION 'Access denied: Cannot alter moderation status';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_log_tampering ON public.logs;
CREATE TRIGGER trg_guard_log_tampering BEFORE INSERT OR UPDATE ON public.logs
FOR EACH ROW EXECUTE FUNCTION public.guard_log_tampering();

-- Like count incrementer/decrementer trigger on log_likes
CREATE OR REPLACE FUNCTION public.update_log_like_count()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE public.logs
        SET like_count = like_count + 1
        WHERE id = NEW.log_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE public.logs
        SET like_count = GREATEST(0, like_count - 1)
        WHERE id = OLD.log_id;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_update_log_like_count ON public.log_likes;
CREATE TRIGGER trg_update_log_like_count AFTER INSERT OR DELETE ON public.log_likes
FOR EACH ROW EXECUTE FUNCTION public.update_log_like_count();

-- ==============================================================================
-- 16. PRIVILEGE AUDIT & DEFAULT PRIVILEGE REVOCATIONS
-- ==============================================================================

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC, anon, authenticated;

-- Default Privilege Hardening for all future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA private REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA private REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated;

-- Selective Table Grants
GRANT SELECT ON public.profiles TO anon;
GRANT SELECT ON public.logs TO anon;
GRANT SELECT ON public.log_likes TO anon;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.user_flags FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.bans FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.staff_roles FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.moderation_actions FROM authenticated;

-- Selective Function Grants
GRANT EXECUTE ON FUNCTION public.get_my_blocked_users TO authenticated;
GRANT EXECUTE ON FUNCTION private.is_banned TO authenticated;
GRANT EXECUTE ON FUNCTION private.is_admin TO authenticated;

-- ==============================================================================
-- 17. ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.moderation_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.follows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.library_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.show_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.log_likes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.private_notes ENABLE ROW LEVEL SECURITY;

-- PROFILES:
DROP POLICY IF EXISTS "profiles_select" ON public.profiles;
CREATE POLICY "profiles_select" ON public.profiles
FOR SELECT USING (
    (auth.uid() IS NOT NULL AND auth.uid() = id)
    OR
    (NOT public.is_blocked_between(auth.uid(), id))
);

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own" ON public.profiles
FOR UPDATE USING (
    auth.uid() = id AND NOT private.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = id AND NOT private.is_banned(auth.uid())
);

-- USER FLAGS:
DROP POLICY IF EXISTS "user_flags_select_own" ON public.user_flags;
CREATE POLICY "user_flags_select_own" ON public.user_flags
FOR SELECT USING (
    auth.uid() = user_id
);

-- BANS:
DROP POLICY IF EXISTS "bans_admin_all" ON public.bans;
CREATE POLICY "bans_admin_all" ON public.bans
FOR ALL USING (
    private.is_admin()
) WITH CHECK (
    private.is_admin()
);

-- STAFF ROLES:
DROP POLICY IF EXISTS "staff_roles_select" ON public.staff_roles;
CREATE POLICY "staff_roles_select" ON public.staff_roles
FOR SELECT USING (
    auth.uid() = user_id OR private.is_admin()
);

DROP POLICY IF EXISTS "staff_roles_admin_manage" ON public.staff_roles;
CREATE POLICY "staff_roles_admin_manage" ON public.staff_roles
FOR ALL USING (
    private.is_admin()
) WITH CHECK (
    private.is_admin()
);

-- MODERATION ACTIONS (Append-only audit log: Insert-only, No update or delete policies):
DROP POLICY IF EXISTS "moderation_actions_admin_select" ON public.moderation_actions;
CREATE POLICY "moderation_actions_admin_select" ON public.moderation_actions
FOR SELECT USING (
    private.is_admin()
);

DROP POLICY IF EXISTS "moderation_actions_admin_insert" ON public.moderation_actions;
CREATE POLICY "moderation_actions_admin_insert" ON public.moderation_actions
FOR INSERT WITH CHECK (
    private.is_admin()
);

-- FOLLOWS:
DROP POLICY IF EXISTS "follows_select" ON public.follows;
CREATE POLICY "follows_select" ON public.follows
FOR SELECT USING (
    auth.uid() = follower_id OR auth.uid() = followee_id
);

DROP POLICY IF EXISTS "follows_insert_own" ON public.follows;
CREATE POLICY "follows_insert_own" ON public.follows
FOR INSERT WITH CHECK (
    auth.uid() = follower_id
    AND NOT private.is_banned(auth.uid())
    AND NOT public.is_blocked_between(follower_id, followee_id)
);

DROP POLICY IF EXISTS "follows_delete_own" ON public.follows;
CREATE POLICY "follows_delete_own" ON public.follows
FOR DELETE USING (
    auth.uid() = follower_id
);

-- BLOCKS:
DROP POLICY IF EXISTS "blocks_select_own" ON public.blocks;
CREATE POLICY "blocks_select_own" ON public.blocks
FOR SELECT USING (
    auth.uid() = blocker_id
);

DROP POLICY IF EXISTS "blocks_insert_own" ON public.blocks;
CREATE POLICY "blocks_insert_own" ON public.blocks
FOR INSERT WITH CHECK (
    auth.uid() = blocker_id AND NOT private.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "blocks_delete_own" ON public.blocks;
CREATE POLICY "blocks_delete_own" ON public.blocks
FOR DELETE USING (
    auth.uid() = blocker_id
);

-- LIBRARY ITEMS:
DROP POLICY IF EXISTS "library_items_owner_select" ON public.library_items;
CREATE POLICY "library_items_owner_select" ON public.library_items
FOR SELECT USING (
    auth.uid() = user_id
);

DROP POLICY IF EXISTS "library_items_owner_insert" ON public.library_items;
CREATE POLICY "library_items_owner_insert" ON public.library_items
FOR INSERT WITH CHECK (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "library_items_owner_update" ON public.library_items;
CREATE POLICY "library_items_owner_update" ON public.library_items
FOR UPDATE USING (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
);

-- SHOW PROGRESS:
DROP POLICY IF EXISTS "show_progress_owner_select" ON public.show_progress;
CREATE POLICY "show_progress_owner_select" ON public.show_progress
FOR SELECT USING (
    auth.uid() = user_id
);

DROP POLICY IF EXISTS "show_progress_owner_insert" ON public.show_progress;
CREATE POLICY "show_progress_owner_insert" ON public.show_progress
FOR INSERT WITH CHECK (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "show_progress_owner_update" ON public.show_progress;
CREATE POLICY "show_progress_owner_update" ON public.show_progress
FOR UPDATE USING (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
);

-- PRIVATE NOTES:
DROP POLICY IF EXISTS "private_notes_owner_select" ON public.private_notes;
CREATE POLICY "private_notes_owner_select" ON public.private_notes
FOR SELECT USING (
    auth.uid() = user_id
);

DROP POLICY IF EXISTS "private_notes_owner_insert" ON public.private_notes;
CREATE POLICY "private_notes_owner_insert" ON public.private_notes
FOR INSERT WITH CHECK (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "private_notes_owner_update" ON public.private_notes;
CREATE POLICY "private_notes_owner_update" ON public.private_notes
FOR UPDATE USING (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
);

-- LOGS:
DROP POLICY IF EXISTS "logs_select" ON public.logs;
CREATE POLICY "logs_select" ON public.logs
FOR SELECT USING (
    (auth.uid() = user_id)
    OR
    (
        status = 'visible'
        AND deleted_at IS NULL
        AND NOT public.is_blocked_between(auth.uid(), user_id)
    )
);

DROP POLICY IF EXISTS "logs_insert_owner" ON public.logs;
CREATE POLICY "logs_insert_owner" ON public.logs
FOR INSERT WITH CHECK (
    auth.uid() = user_id
    AND NOT private.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "logs_update_owner" ON public.logs;
CREATE POLICY "logs_update_owner" ON public.logs
FOR UPDATE USING (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT private.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "logs_admin_delete" ON public.logs;
CREATE POLICY "logs_admin_delete" ON public.logs
FOR DELETE USING (
    private.is_admin()
);

-- LOG LIKES:
DROP POLICY IF EXISTS "log_likes_select" ON public.log_likes;
CREATE POLICY "log_likes_select" ON public.log_likes
FOR SELECT USING (
    auth.uid() = user_id
    OR
    EXISTS (
        SELECT 1 FROM public.logs l
        WHERE l.id = log_id
          AND l.status = 'visible'
          AND l.deleted_at IS NULL
          AND NOT public.is_blocked_between(auth.uid(), l.user_id)
    )
);

DROP POLICY IF EXISTS "log_likes_insert_own" ON public.log_likes;
CREATE POLICY "log_likes_insert_own" ON public.log_likes
FOR INSERT WITH CHECK (
    auth.uid() = user_id
    AND NOT private.is_banned(auth.uid())
    AND EXISTS (
        SELECT 1 FROM public.logs l
        WHERE l.id = log_id
          AND l.status = 'visible'
          AND l.deleted_at IS NULL
          AND NOT public.is_blocked_between(auth.uid(), l.user_id)
    )
);

DROP POLICY IF EXISTS "log_likes_delete_own" ON public.log_likes;
CREATE POLICY "log_likes_delete_own" ON public.log_likes
FOR DELETE USING (
    auth.uid() = user_id
);


-- >>> END MIGRATION: 20261023000001_phase1_initial_schema.sql <<<


-- >>> BEGIN MIGRATION: 20261023000002_batch_b1_atomic_ban.sql <<<

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


-- >>> END MIGRATION: 20261023000002_batch_b1_atomic_ban.sql <<<


-- >>> BEGIN MIGRATION: 20261023000003_batch_b2_moderation_actions_tamper_resistant.sql <<<

-- ==============================================================================
-- Migration: 20261023000003_batch_b2_moderation_actions_tamper_resistant.sql
-- Description: Batch B2 - Tamper-Resistant Moderation Actions (Append-Only)
-- ==============================================================================

-- 1. Trigger function that unconditionally rejects UPDATE, DELETE, TRUNCATE
CREATE OR REPLACE FUNCTION public.reject_moderation_action_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'moderation_actions is append-only and tamper-resistant: % is strictly prohibited across all roles', TG_OP;
END;
$$;

-- 2. Attach Row Trigger for UPDATE or DELETE
DROP TRIGGER IF EXISTS trg_prevent_update_delete_moderation_actions ON public.moderation_actions;
CREATE TRIGGER trg_prevent_update_delete_moderation_actions
BEFORE UPDATE OR DELETE ON public.moderation_actions
FOR EACH ROW EXECUTE FUNCTION public.reject_moderation_action_mutation();

-- 3. Attach Statement Trigger for TRUNCATE
DROP TRIGGER IF EXISTS trg_prevent_truncate_moderation_actions ON public.moderation_actions;
CREATE TRIGGER trg_prevent_truncate_moderation_actions
BEFORE TRUNCATE ON public.moderation_actions
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_moderation_action_mutation();

-- 4. Revoke UPDATE, DELETE, TRUNCATE from all roles including service_role
REVOKE UPDATE, DELETE, TRUNCATE ON public.moderation_actions FROM PUBLIC, anon, authenticated, service_role;

-- 5. Drop client INSERT policy (ensuring no client can insert directly; only service_role/SECURITY DEFINER)
DROP POLICY IF EXISTS "moderation_actions_admin_insert" ON public.moderation_actions;


-- >>> END MIGRATION: 20261023000003_batch_b2_moderation_actions_tamper_resistant.sql <<<


-- >>> BEGIN MIGRATION: 20261023000004_batch_b3_policy_hardening.sql <<<

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
CREATE POLICY "profiles_select" ON public.profiles
FOR SELECT USING (
    ((SELECT auth.uid()) IS NOT NULL AND (SELECT auth.uid()) = id)
    OR
    (
        NOT EXISTS (
            SELECT 1 FROM public.blocks b
            WHERE (b.blocker_id = (SELECT auth.uid()) AND b.blocked_id = profiles.id)
               OR (b.blocker_id = profiles.id AND b.blocked_id = (SELECT auth.uid()))
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
CREATE POLICY "logs_select" ON public.logs
FOR SELECT USING (
    user_id = (SELECT auth.uid())
    OR
    (
        status = 'visible'
        AND deleted_at IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM public.blocks b
            WHERE (b.blocker_id = (SELECT auth.uid()) AND b.blocked_id = logs.user_id)
               OR (b.blocker_id = logs.user_id AND b.blocked_id = (SELECT auth.uid()))
        )
    )
);

-- 6. log_likes_select: Own likes OR likes on logs the viewer can see via shared visibility function
DROP POLICY IF EXISTS "log_likes_select" ON public.log_likes;
CREATE POLICY "log_likes_select" ON public.log_likes
FOR SELECT USING (
    user_id = (SELECT auth.uid())
    OR
    private.can_view_log(log_id)
);

-- 7. Grant execution on shared log visibility
REVOKE ALL ON FUNCTION private.can_view_log(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION private.can_view_log(UUID) TO authenticated, anon;


-- >>> END MIGRATION: 20261023000004_batch_b3_policy_hardening.sql <<<


-- >>> BEGIN MIGRATION: 20261023000005_batch_b4_write_path_ban_checks.sql <<<

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


-- >>> END MIGRATION: 20261023000005_batch_b4_write_path_ban_checks.sql <<<
