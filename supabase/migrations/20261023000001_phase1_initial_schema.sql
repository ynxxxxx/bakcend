-- ==============================================================================
-- Migration: 20261023000001_phase1_initial_schema.sql
-- Description: Phase 1 Foundation (Refined)
--   - Public profiles separate from sensitive user_flags (trust_level)
--   - Dedicated bans table and is_banned() helper
--   - Blocks and get_my_blocked_users() security definer function
--   - Offline sync: client_updated_at, deleted_at, server updated_at, stale-write guard
--   - like_count derived via trigger, guarded from client modification
--   - Strict anon privilege revocation and pgTAP-ready RLS policy matrix
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "citext" WITH SCHEMA public;

-- 2. ENUM TYPES
DO $$ BEGIN
    CREATE TYPE tracking_status AS ENUM ('watching', 'watchlist', 'completed', 'paused', 'dropped');
EXCEPTION WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE log_status AS ENUM ('visible', 'hidden', 'removed');
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
    CONSTRAINT display_name_length CHECK (
        display_name IS NULL OR length(display_name) <= 50
    ),
    CONSTRAINT bio_length CHECK (
        bio IS NULL OR length(bio) <= 300
    )
);

CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);

-- 4. USER FLAGS (Sensitive Account State - Owner Read-Only, No Client Writes)
CREATE TABLE IF NOT EXISTS public.user_flags (
    user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
    trust_level INT DEFAULT 0 NOT NULL CHECK (trust_level >= 0),
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 5. BANS (Minimal Table for Phase 1 Safety)
CREATE TABLE IF NOT EXISTS public.bans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    scope ban_scope DEFAULT 'global' NOT NULL,
    community_id UUID,
    reason TEXT,
    banned_by UUID,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bans_user_active ON public.bans(user_id, expires_at);

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

-- 7. SOCIAL RELATIONSHIPS: FOLLOWS & BLOCKS
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

-- 8. TRACKING: LIBRARY ITEMS & SHOW PROGRESS (With Sync & Soft Deletes)
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

-- 9. TRACKING: LOGS & DIARY
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
    )
);

CREATE INDEX IF NOT EXISTS idx_logs_feed ON public.logs(status, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_logs_user_sync ON public.logs(user_id, updated_at DESC, id);

-- 10. LOG LIKES
CREATE TABLE IF NOT EXISTS public.log_likes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    log_id UUID REFERENCES public.logs(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_log_like UNIQUE (user_id, log_id)
);

CREATE INDEX IF NOT EXISTS idx_log_likes_log ON public.log_likes(log_id);

-- 11. PRIVATE OWNER-ONLY NOTES
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
-- 12. SECURITY DEFINER HELPER FUNCTIONS (Strict Fixed Search Path)
-- ==============================================================================

CREATE OR REPLACE FUNCTION public.is_admin()
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

CREATE OR REPLACE FUNCTION public.is_banned(target_user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.bans
        WHERE user_id = target_user_id
          AND (expires_at IS NULL OR expires_at > NOW())
    );
$$;

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

-- SECURITY DEFINER function allowing a blocker to retrieve list of blocked profiles for unblocking
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

-- Helper to recalculate log likes in case of drift or administrative reconciliation
CREATE OR REPLACE FUNCTION public.recount_likes(target_log_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actual_count INT;
BEGIN
    SELECT COUNT(*) INTO v_actual_count
    FROM public.log_likes
    WHERE log_id = target_log_id;

    UPDATE public.logs
    SET like_count = v_actual_count
    WHERE id = target_log_id;
END;
$$;

-- Scheduled Tombstone Purge (Cleans up soft-deleted rows older than retention period)
CREATE OR REPLACE FUNCTION public.purge_soft_deleted_tombstones(retention_days INT DEFAULT 30)
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
-- 13. AUTOMATIC TRIGGERS & INTEGRITY GUARDS
-- ==============================================================================

-- Timestamp updater
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

DROP TRIGGER IF EXISTS trg_library_items_updated_at ON public.library_items;
CREATE TRIGGER trg_library_items_updated_at BEFORE UPDATE ON public.library_items
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_show_progress_updated_at ON public.show_progress;
CREATE TRIGGER trg_show_progress_updated_at BEFORE UPDATE ON public.show_progress
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_logs_updated_at ON public.logs;
CREATE TRIGGER trg_logs_updated_at BEFORE UPDATE ON public.logs
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_private_notes_updated_at ON public.private_notes;
CREATE TRIGGER trg_private_notes_updated_at BEFORE UPDATE ON public.private_notes
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

-- New user auth trigger (populates public.profiles and public.user_flags)
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

-- Stale write protection & client clock clamping trigger
CREATE OR REPLACE FUNCTION public.protect_stale_upsert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_max_future TIMESTAMPTZ := NOW() + INTERVAL '5 minutes';
BEGIN
    -- Clamp client_updated_at to server now + 5 min tolerance to prevent future locking
    IF NEW.client_updated_at > v_max_future THEN
        NEW.client_updated_at := v_max_future;
    END IF;

    -- Stale write rejection: if existing record has newer client timestamp, retain old values
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

-- Guard trigger on logs: Block direct client writes to like_count
CREATE OR REPLACE FUNCTION public.guard_log_like_count()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.like_count != 0 AND NOT public.is_admin() THEN
            NEW.like_count := 0;
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.like_count != OLD.like_count AND NOT public.is_admin() THEN
            RAISE EXCEPTION 'Access denied: like_count is server-maintained and cannot be edited';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_guard_log_like_count ON public.logs;
CREATE TRIGGER trg_guard_log_like_count BEFORE INSERT OR UPDATE OF like_count ON public.logs
FOR EACH ROW EXECUTE FUNCTION public.guard_log_like_count();

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

-- Log status guard
CREATE OR REPLACE FUNCTION public.protect_log_integrity()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status != 'visible' AND NOT public.is_admin() THEN
            NEW.status := 'visible';
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NOT public.is_admin() THEN
            IF OLD.status = 'removed' THEN
                RAISE EXCEPTION 'Access denied: Removed content cannot be modified';
            END IF;
            IF NEW.status = 'removed' THEN
                RAISE EXCEPTION 'Access denied: Only moderators can mark content as removed';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_log_integrity ON public.logs;
CREATE TRIGGER trg_protect_log_integrity BEFORE INSERT OR UPDATE ON public.logs
FOR EACH ROW EXECUTE FUNCTION public.protect_log_integrity();

-- ==============================================================================
-- 14. PRIVILEGE REVOCATIONS (Zero-Trust Anon Baseline)
-- ==============================================================================

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon;

-- Grant selective read-only permissions to anon
GRANT SELECT ON public.profiles TO anon;
GRANT SELECT ON public.logs TO anon;
GRANT SELECT ON public.log_likes TO anon;

-- Authenticated gets standard table access subject to RLS
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;
-- Revoke write privileges on sensitive tables from authenticated users
REVOKE INSERT, UPDATE, DELETE ON public.user_flags FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.bans FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.staff_roles FROM authenticated;

-- ==============================================================================
-- 15. ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_roles ENABLE ROW LEVEL SECURITY;
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
    auth.uid() = id AND NOT public.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = id AND NOT public.is_banned(auth.uid())
);

-- USER FLAGS: Owner Read-Only, No Client Writes
DROP POLICY IF EXISTS "user_flags_select_own" ON public.user_flags;
CREATE POLICY "user_flags_select_own" ON public.user_flags
FOR SELECT USING (
    auth.uid() = user_id
);

-- BANS: Admin / Service Role Only
DROP POLICY IF EXISTS "bans_admin_all" ON public.bans;
CREATE POLICY "bans_admin_all" ON public.bans
FOR ALL USING (
    public.is_admin()
) WITH CHECK (
    public.is_admin()
);

-- STAFF ROLES:
DROP POLICY IF EXISTS "staff_roles_select" ON public.staff_roles;
CREATE POLICY "staff_roles_select" ON public.staff_roles
FOR SELECT USING (
    auth.uid() = user_id OR public.is_admin()
);

DROP POLICY IF EXISTS "staff_roles_admin_manage" ON public.staff_roles;
CREATE POLICY "staff_roles_admin_manage" ON public.staff_roles
FOR ALL USING (
    public.is_admin()
) WITH CHECK (
    public.is_admin()
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
    AND NOT public.is_banned(auth.uid())
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
    auth.uid() = blocker_id AND NOT public.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "blocks_delete_own" ON public.blocks;
CREATE POLICY "blocks_delete_own" ON public.blocks
FOR DELETE USING (
    auth.uid() = blocker_id
);

-- LIBRARY ITEMS (Owner-only, includes own soft-deletes):
DROP POLICY IF EXISTS "library_items_owner_select" ON public.library_items;
CREATE POLICY "library_items_owner_select" ON public.library_items
FOR SELECT USING (
    auth.uid() = user_id
);

DROP POLICY IF EXISTS "library_items_owner_insert" ON public.library_items;
CREATE POLICY "library_items_owner_insert" ON public.library_items
FOR INSERT WITH CHECK (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "library_items_owner_update" ON public.library_items;
CREATE POLICY "library_items_owner_update" ON public.library_items
FOR UPDATE USING (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
);

-- SHOW PROGRESS (Owner-only):
DROP POLICY IF EXISTS "show_progress_owner_select" ON public.show_progress;
CREATE POLICY "show_progress_owner_select" ON public.show_progress
FOR SELECT USING (
    auth.uid() = user_id
);

DROP POLICY IF EXISTS "show_progress_owner_insert" ON public.show_progress;
CREATE POLICY "show_progress_owner_insert" ON public.show_progress
FOR INSERT WITH CHECK (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "show_progress_owner_update" ON public.show_progress;
CREATE POLICY "show_progress_owner_update" ON public.show_progress
FOR UPDATE USING (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
);

-- PRIVATE NOTES (Owner-only):
DROP POLICY IF EXISTS "private_notes_owner_select" ON public.private_notes;
CREATE POLICY "private_notes_owner_select" ON public.private_notes
FOR SELECT USING (
    auth.uid() = user_id
);

DROP POLICY IF EXISTS "private_notes_owner_insert" ON public.private_notes;
CREATE POLICY "private_notes_owner_insert" ON public.private_notes
FOR INSERT WITH CHECK (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "private_notes_owner_update" ON public.private_notes;
CREATE POLICY "private_notes_owner_update" ON public.private_notes
FOR UPDATE USING (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
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
    AND NOT public.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "logs_update_owner" ON public.logs;
CREATE POLICY "logs_update_owner" ON public.logs
FOR UPDATE USING (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = user_id AND NOT public.is_banned(auth.uid())
);

DROP POLICY IF EXISTS "logs_admin_delete" ON public.logs;
CREATE POLICY "logs_admin_delete" ON public.logs
FOR DELETE USING (
    public.is_admin()
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
    AND NOT public.is_banned(auth.uid())
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
