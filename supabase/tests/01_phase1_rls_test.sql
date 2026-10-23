-- ==============================================================================
-- Test Suite: 01_phase1_rls_test.sql
-- Description: Phase 1 Row Level Security (RLS) Policy & Escalation Matrix
-- Personas tested:
--   1. Anonymous (unauthenticated)
--   2. Normal User A (Alice - 11111111-1111-1111-1111-111111111111)
--   3. Other User B (Bob - 22222222-2222-2222-2222-222222222222)
--   4. Blocked User (Charlie - 33333333-3333-3333-3333-333333333333, blocked by Alice)
--   5. Banned User (Dave - 44444444-4444-4444-4444-444444444444, has active ban)
--   6. Admin (Eve - 55555555-5555-5555-5555-555555555555, staff_roles = admin)
-- ==============================================================================

BEGIN;

CREATE OR REPLACE FUNCTION set_actor(actor_id UUID, actor_role TEXT DEFAULT 'authenticated')
RETURNS VOID AS $$
BEGIN
    IF actor_id IS NULL THEN
        PERFORM set_config('request.jwt.claim.sub', '', true);
        PERFORM set_config('request.jwt.claim.role', 'anon', true);
    ELSE
        PERFORM set_config('request.jwt.claim.sub', actor_id::text, true);
        PERFORM set_config('request.jwt.claim.role', actor_role, true);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- 1. SETUP TEST FIXTURES
INSERT INTO auth.users (id, email, raw_user_meta_data)
VALUES 
    ('11111111-1111-1111-1111-111111111111', 'alice@test.com', '{"full_name": "Alice Wonderland"}'::jsonb),
    ('22222222-2222-2222-2222-222222222222', 'bob@test.com', '{"full_name": "Bob Builder"}'::jsonb),
    ('33333333-3333-3333-3333-333333333333', 'charlie@test.com', '{"full_name": "Charlie Chaplin"}'::jsonb),
    ('44444444-4444-4444-4444-444444444444', 'dave@test.com', '{"full_name": "Dave Dangerous"}'::jsonb),
    ('55555555-5555-5555-5555-555555555555', 'eve@test.com', '{"full_name": "Eve Administrator"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

UPDATE public.profiles SET username = 'alice', onboarded = true WHERE id = '11111111-1111-1111-1111-111111111111';
UPDATE public.profiles SET username = 'bob', onboarded = true WHERE id = '22222222-2222-2222-2222-222222222222';
UPDATE public.profiles SET username = 'charlie', onboarded = true WHERE id = '33333333-3333-3333-3333-333333333333';
UPDATE public.profiles SET username = 'dave', onboarded = true WHERE id = '44444444-4444-4444-4444-444444444444';
UPDATE public.profiles SET username = 'eve', onboarded = true WHERE id = '55555555-5555-5555-5555-555555555555';

-- Establish Eve as Admin
INSERT INTO public.staff_roles (user_id, role)
VALUES ('55555555-5555-5555-5555-555555555555', 'admin')
ON CONFLICT DO NOTHING;

-- Establish Dave as actively banned in bans table
INSERT INTO public.bans (user_id, scope, reason, banned_by)
VALUES ('44444444-4444-4444-4444-444444444444', 'global', 'Testing ban enforcement', '55555555-5555-5555-5555-555555555555')
ON CONFLICT DO NOTHING;

-- Alice blocks Charlie
INSERT INTO public.blocks (blocker_id, blocked_id)
VALUES ('11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333')
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------------------------
-- TEST 1: Anonymous Access (Must not read private data or user_flags)
-- ------------------------------------------------------------------------------
SELECT set_actor(NULL);

DO $$
DECLARE
    v_cnt INT;
BEGIN
    -- Anonymous should see 0 rows in user_flags
    SELECT COUNT(*) INTO v_cnt FROM public.user_flags;
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Anonymous read user_flags!';
    END IF;

    -- Anonymous should see 0 rows in private_notes
    SELECT COUNT(*) INTO v_cnt FROM public.private_notes;
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Anonymous read private_notes!';
    END IF;

    -- Anonymous should see 0 rows in library_items
    SELECT COUNT(*) INTO v_cnt FROM public.library_items;
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Anonymous read library_items!';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 2: Escalation Resistance on user_flags (Owner read-only, no client writes)
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111');

DO $$
DECLARE
    v_cnt INT;
BEGIN
    -- Alice can read her own user_flags
    SELECT COUNT(*) INTO v_cnt FROM public.user_flags WHERE user_id = '11111111-1111-1111-1111-111111111111';
    IF v_cnt != 1 THEN
        RAISE EXCEPTION 'TEST FAILED: Alice cannot read own user_flags!';
    END IF;

    -- Alice cannot read Bob's user_flags
    SELECT COUNT(*) INTO v_cnt FROM public.user_flags WHERE user_id = '22222222-2222-2222-2222-222222222222';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Alice read Bob user_flags!';
    END IF;

    -- Alice cannot update her trust_level
    BEGIN
        UPDATE public.user_flags SET trust_level = 5 WHERE user_id = '11111111-1111-1111-1111-111111111111';
        RAISE EXCEPTION 'TEST FAILED: Alice was able to update user_flags trust_level!';
    EXCEPTION
        WHEN insufficient_privilege THEN
            -- Expected: revoked write privileges
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 3: Blocked Isolation & get_my_blocked_users() Function
-- ------------------------------------------------------------------------------
-- Alice creates a visible log
SELECT set_actor('11111111-1111-1111-1111-111111111111');
INSERT INTO public.logs (id, user_id, show_id, show_name, review_text, status)
VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 1399, 'GoT', 'Alice review', 'visible')
ON CONFLICT (id) DO UPDATE SET review_text = 'Alice review';

-- Alice tests get_my_blocked_users()
DO $$
DECLARE
    v_cnt INT;
BEGIN
    SELECT COUNT(*) INTO v_cnt FROM public.get_my_blocked_users();
    IF v_cnt != 1 THEN
        RAISE EXCEPTION 'TEST FAILED: Alice get_my_blocked_users() did not return Charlie!';
    END IF;
END $$;

-- Charlie (blocked by Alice) tests access
SELECT set_actor('33333333-3333-3333-3333-333333333333');
DO $$
DECLARE
    v_cnt INT;
BEGIN
    -- Charlie cannot see Alice profile
    SELECT COUNT(*) INTO v_cnt FROM public.profiles WHERE id = '11111111-1111-1111-1111-111111111111';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Blocked Charlie can read Alice profile!';
    END IF;

    -- Charlie cannot see Alice log
    SELECT COUNT(*) INTO v_cnt FROM public.logs WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Blocked Charlie can read Alice log!';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 4: Banned User Write Denial Across All Tables
-- ------------------------------------------------------------------------------
SELECT set_actor('44444444-4444-4444-4444-444444444444');

DO $$
BEGIN
    -- Library item
    BEGIN
        INSERT INTO public.library_items (user_id, show_id, status)
        VALUES ('44444444-4444-4444-4444-444444444444', 100, 'watching');
        RAISE EXCEPTION 'TEST FAILED: Banned Dave inserted library_item!';
    EXCEPTION WHEN insufficient_privilege OR check_violation THEN END;

    -- Show progress
    BEGIN
        INSERT INTO public.show_progress (user_id, show_id, season, episode)
        VALUES ('44444444-4444-4444-4444-444444444444', 100, 1, 1);
        RAISE EXCEPTION 'TEST FAILED: Banned Dave inserted show_progress!';
    EXCEPTION WHEN insufficient_privilege OR check_violation THEN END;

    -- Log
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, review_text)
        VALUES ('44444444-4444-4444-4444-444444444444', 100, 'Breaking Bad', 'Spam');
        RAISE EXCEPTION 'TEST FAILED: Banned Dave inserted log!';
    EXCEPTION WHEN insufficient_privilege OR check_violation THEN END;

    -- Private note
    BEGIN
        INSERT INTO public.private_notes (user_id, show_id, body)
        VALUES ('44444444-4444-4444-4444-444444444444', 100, 'Spam note');
        RAISE EXCEPTION 'TEST FAILED: Banned Dave inserted private_note!';
    EXCEPTION WHEN insufficient_privilege OR check_violation THEN END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 5: Like Count Trigger & Guard Trigger
-- ------------------------------------------------------------------------------
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob

-- Bob likes Alice's visible log
INSERT INTO public.log_likes (user_id, log_id)
VALUES ('22222222-2222-2222-2222-222222222222', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');

DO $$
DECLARE
    v_likes INT;
BEGIN
    SELECT like_count INTO v_likes FROM public.logs WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    IF v_likes != 1 THEN
        RAISE EXCEPTION 'TEST FAILED: like_count trigger did not increment to 1 (got %)!', v_likes;
    END IF;
END $$;

-- Client cannot manually edit like_count directly
DO $$
BEGIN
    BEGIN
        UPDATE public.logs SET like_count = 999 WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
        RAISE EXCEPTION 'TEST FAILED: Client was able to manually alter like_count!';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE '%Access denied%' AND SQLERRM NOT LIKE '%server-maintained%' THEN
                RAISE EXCEPTION 'Unexpected error on like_count guard: %', SQLERRM;
            END IF;
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 6: Stale Write Rule & Clamping
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice

INSERT INTO public.library_items (id, user_id, show_id, status, client_updated_at)
VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '11111111-1111-1111-1111-111111111111', 500, 'watching', '2026-10-23 12:00:00+00');

-- Stale write attempt with older timestamp ('2026-10-23 11:00:00+00')
UPDATE public.library_items
SET status = 'dropped', client_updated_at = '2026-10-23 11:00:00+00'
WHERE id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

DO $$
DECLARE
    v_status tracking_status;
BEGIN
    SELECT status INTO v_status FROM public.library_items WHERE id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    IF v_status != 'watching' THEN
        RAISE EXCEPTION 'TEST FAILED: Stale write overwritten newer record (status changed to %)!', v_status;
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 7: Soft Delete Sync Visibility
-- ------------------------------------------------------------------------------
-- Alice soft-deletes her library item
UPDATE public.library_items
SET deleted_at = NOW(), client_updated_at = '2026-10-23 13:00:00+00'
WHERE id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

-- Alice CAN still see her soft-deleted item for sync
DO $$
DECLARE
    v_cnt INT;
BEGIN
    SELECT COUNT(*) INTO v_cnt FROM public.library_items WHERE id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    IF v_cnt != 1 THEN
        RAISE EXCEPTION 'TEST FAILED: Owner Alice cannot see her soft-deleted item!';
    END IF;
END $$;

-- Bob cannot see Alice's soft-deleted item
SELECT set_actor('22222222-2222-2222-2222-222222222222');
DO $$
DECLARE
    v_cnt INT;
BEGIN
    SELECT COUNT(*) INTO v_cnt FROM public.library_items WHERE id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Bob can see Alice soft-deleted item!';
    END IF;
END $$;

RAISE NOTICE 'ALL PHASE 1 REFINED RLS & ESCALATION TESTS PASSED!';

ROLLBACK;
