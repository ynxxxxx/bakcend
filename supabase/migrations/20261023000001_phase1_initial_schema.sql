-- ==============================================================================
-- Migration: 20261023000001_phase1_initial_schema.sql
-- Description: Phase 1 Foundation - Core extensions, Identity, Tracking,
--              Logs, Social foundations, Helper functions, Triggers, and RLS.
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA public;
CREATE EXTENSION IF NOT EXISTS "citext" WITH SCHEMA public;

-- 2. ENUM TYPES
DO $$ BEGIN
    CREATE TYPE tracking_status AS ENUM ('watching', 'watchlist', 'completed', 'paused', 'dropped');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE log_status AS ENUM ('visible', 'hidden', 'removed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE staff_role_type AS ENUM ('admin', 'moderator');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 3. CORE IDENTITY: PROFILES
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username CITEXT UNIQUE,
    display_name TEXT,
    avatar_url TEXT,
    bio TEXT,
    onboarded BOOLEAN DEFAULT false NOT NULL,
    trust_level INT DEFAULT 0 NOT NULL,
    is_banned BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT username_format_check CHECK (
        username IS NULL OR (
            username ~ '^[a-z0-9_]{3,20}$'
        )
    ),
    CONSTRAINT display_name_length CHECK (
        display_name IS NULL OR length(display_name) <= 50
    ),
    CONSTRAINT bio_length CHECK (
        bio IS NULL OR length(bio) <= 300
    )
);

-- Index for username search and profile lookups
CREATE INDEX IF NOT EXISTS idx_profiles_username ON public.profiles(username);
CREATE INDEX IF NOT EXISTS idx_profiles_trust_banned ON public.profiles(trust_level, is_banned);

-- 4. STAFF ROLES (RBAC)
CREATE TABLE IF NOT EXISTS public.staff_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    role staff_role_type NOT NULL,
    community_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_role_scope UNIQUE (user_id, role, community_id)
);

CREATE INDEX IF NOT EXISTS idx_staff_roles_lookup ON public.staff_roles(user_id, role);

-- 5. SOCIAL RELATIONSHIPS: FOLLOWS & BLOCKS
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

-- 6. TRACKING: LIBRARY ITEMS & SHOW PROGRESS
CREATE TABLE IF NOT EXISTS public.library_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    status tracking_status NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_library_show UNIQUE (user_id, show_id)
);

CREATE INDEX IF NOT EXISTS idx_library_items_user_status ON public.library_items(user_id, status);

CREATE TABLE IF NOT EXISTS public.show_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    season INT DEFAULT 0 NOT NULL CHECK (season >= 0),
    episode INT DEFAULT 0 NOT NULL CHECK (episode >= 0),
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_show_progress UNIQUE (user_id, show_id)
);

CREATE INDEX IF NOT EXISTS idx_show_progress_user ON public.show_progress(user_id);

-- 7. TRACKING: LOGS & DIARY
CREATE TABLE IF NOT EXISTS public.logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    show_name TEXT NOT NULL,
    show_poster_path TEXT,
    season_number INT CHECK (season_number IS NULL OR season_number >= 0),
    episode_number INT CHECK (episode_number IS NULL OR episode_number >= 0),
    rating NUMERIC(2,1) CHECK (
        rating IS NULL OR (
            rating >= 0.5 AND rating <= 5.0 AND mod(rating * 2, 1) = 0
        )
    ),
    review_text TEXT,
    contains_spoilers BOOLEAN DEFAULT false NOT NULL,
    is_rewatch BOOLEAN DEFAULT false NOT NULL,
    liked BOOLEAN DEFAULT false NOT NULL,
    watched_date DATE DEFAULT CURRENT_DATE NOT NULL,
    tags TEXT[] DEFAULT '{}'::text[] NOT NULL,
    status log_status DEFAULT 'visible' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT review_text_limit CHECK (
        review_text IS NULL OR length(review_text) <= 5000
    )
);

CREATE INDEX IF NOT EXISTS idx_logs_feed ON public.logs(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_user_show ON public.logs(user_id, show_id);
CREATE INDEX IF NOT EXISTS idx_logs_watched_date ON public.logs(user_id, watched_date DESC);

-- 8. LOG LIKES
CREATE TABLE IF NOT EXISTS public.log_likes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    log_id UUID REFERENCES public.logs(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_log_like UNIQUE (user_id, log_id)
);

CREATE INDEX IF NOT EXISTS idx_log_likes_log ON public.log_likes(log_id);

-- 9. PRIVATE OWNER-ONLY NOTES
CREATE TABLE IF NOT EXISTS public.private_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE NOT NULL,
    show_id INT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_user_show_note UNIQUE (user_id, show_id),
    CONSTRAINT private_note_limit CHECK (length(body) <= 10000)
);

CREATE INDEX IF NOT EXISTS idx_private_notes_user ON public.private_notes(user_id);

-- ==============================================================================
-- 10. SECURITY DEFINER HELPER FUNCTIONS (Strict Search Path)
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
    SELECT COALESCE(
        (SELECT is_banned FROM public.profiles WHERE id = target_user_id),
        false
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

-- ==============================================================================
-- 11. AUTOMATIC TRIGGERS & INTEGRITY GUARDS
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
CREATE TRIGGER trg_profiles_updated_at
BEFORE UPDATE ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_library_items_updated_at ON public.library_items;
CREATE TRIGGER trg_library_items_updated_at
BEFORE UPDATE ON public.library_items
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_logs_updated_at ON public.logs;
CREATE TRIGGER trg_logs_updated_at
BEFORE UPDATE ON public.logs
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

DROP TRIGGER IF EXISTS trg_private_notes_updated_at ON public.private_notes;
CREATE TRIGGER trg_private_notes_updated_at
BEFORE UPDATE ON public.private_notes
FOR EACH ROW EXECUTE FUNCTION public.fn_set_updated_at();

-- New user auth trigger
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO public.profiles (id, display_name, avatar_url, onboarded, trust_level, is_banned)
    VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', 'New Member'),
        NEW.raw_user_meta_data->>'avatar_url',
        false,
        0,
        false
    )
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Profile security guard: Normal users cannot tamper with trust_level or is_banned
CREATE OR REPLACE FUNCTION public.protect_profile_security_fields()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NOT public.is_admin() THEN
        IF NEW.trust_level != OLD.trust_level THEN
            RAISE EXCEPTION 'Access denied: Cannot alter trust_level';
        END IF;
        IF NEW.is_banned != OLD.is_banned THEN
            RAISE EXCEPTION 'Access denied: Cannot alter is_banned';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_profile_security_fields ON public.profiles;
CREATE TRIGGER trg_protect_profile_security_fields
BEFORE UPDATE ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.protect_profile_security_fields();

-- Log security guard: Normal users cannot insert hidden/removed logs or edit status
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
        -- Allow owner to soft-delete by setting status = 'hidden'
        -- Disallow normal users from setting status = 'removed' or restoring 'removed'
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
CREATE TRIGGER trg_protect_log_integrity
BEFORE INSERT OR UPDATE ON public.logs
FOR EACH ROW EXECUTE FUNCTION public.protect_log_integrity();

-- ==============================================================================
-- 12. ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

-- Enable RLS across every public table
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.follows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.library_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.show_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.log_likes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.private_notes ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------------------
-- RLS: PROFILES
-- ------------------------------------------------------------------------------
DROP POLICY IF EXISTS "profiles_select_public" ON public.profiles;
CREATE POLICY "profiles_select_public" ON public.profiles
FOR SELECT USING (
    -- Profile is visible if viewer is authenticated AND not blocked between them
    (auth.uid() IS NOT NULL AND auth.uid() = id)
    OR
    (auth.uid() IS NOT NULL AND NOT public.is_blocked_between(auth.uid(), id))
);

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own" ON public.profiles
FOR UPDATE USING (
    auth.uid() = id AND NOT public.is_banned(auth.uid())
) WITH CHECK (
    auth.uid() = id AND NOT public.is_banned(auth.uid())
);

-- ------------------------------------------------------------------------------
-- RLS: STAFF ROLES
-- ------------------------------------------------------------------------------
DROP POLICY IF EXISTS "staff_roles_select" ON public.staff_roles;
CREATE POLICY "staff_roles_select" ON public.staff_roles
FOR SELECT USING (
    auth.uid() = user_id OR public.is_admin()
);

-- Writes are restricted entirely to service role or admin
DROP POLICY IF EXISTS "staff_roles_admin_manage" ON public.staff_roles;
CREATE POLICY "staff_roles_admin_manage" ON public.staff_roles
FOR ALL USING (
    public.is_admin()
) WITH CHECK (
    public.is_admin()
);

-- ------------------------------------------------------------------------------
-- RLS: FOLLOWS
-- ------------------------------------------------------------------------------
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

-- ------------------------------------------------------------------------------
-- RLS: BLOCKS
-- ------------------------------------------------------------------------------
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

-- ------------------------------------------------------------------------------
-- RLS: LIBRARY ITEMS (Owner-only)
-- ------------------------------------------------------------------------------
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

DROP POLICY IF EXISTS "library_items_owner_delete" ON public.library_items;
CREATE POLICY "library_items_owner_delete" ON public.library_items
FOR DELETE USING (
    auth.uid() = user_id
);

-- ------------------------------------------------------------------------------
-- RLS: SHOW PROGRESS (Owner-only)
-- ------------------------------------------------------------------------------
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

DROP POLICY IF EXISTS "show_progress_owner_delete" ON public.show_progress;
CREATE POLICY "show_progress_owner_delete" ON public.show_progress
FOR DELETE USING (
    auth.uid() = user_id
);

-- ------------------------------------------------------------------------------
-- RLS: PRIVATE NOTES (Owner-only)
-- ------------------------------------------------------------------------------
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

DROP POLICY IF EXISTS "private_notes_owner_delete" ON public.private_notes;
CREATE POLICY "private_notes_owner_delete" ON public.private_notes
FOR DELETE USING (
    auth.uid() = user_id
);

-- ------------------------------------------------------------------------------
-- RLS: LOGS
-- ------------------------------------------------------------------------------
DROP POLICY IF EXISTS "logs_select_visible_or_owner" ON public.logs;
CREATE POLICY "logs_select_visible_or_owner" ON public.logs
FOR SELECT USING (
    (auth.uid() = user_id)
    OR
    (
        status = 'visible'
        AND (auth.uid() IS NULL OR NOT public.is_blocked_between(auth.uid(), user_id))
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

-- Direct DELETE is forbidden; users soft-delete by setting status = 'hidden'
DROP POLICY IF EXISTS "logs_admin_delete" ON public.logs;
CREATE POLICY "logs_admin_delete" ON public.logs
FOR DELETE USING (
    public.is_admin()
);

-- ------------------------------------------------------------------------------
-- RLS: LOG LIKES
-- ------------------------------------------------------------------------------
DROP POLICY IF EXISTS "log_likes_select" ON public.log_likes;
CREATE POLICY "log_likes_select" ON public.log_likes
FOR SELECT USING (
    auth.uid() = user_id
    OR
    EXISTS (
        SELECT 1 FROM public.logs l
        WHERE l.id = log_id
          AND l.status = 'visible'
          AND (auth.uid() IS NULL OR NOT public.is_blocked_between(auth.uid(), l.user_id))
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
          AND NOT public.is_blocked_between(auth.uid(), l.user_id)
    )
);

DROP POLICY IF EXISTS "log_likes_delete_own" ON public.log_likes;
CREATE POLICY "log_likes_delete_own" ON public.log_likes
FOR DELETE USING (
    auth.uid() = user_id
);
