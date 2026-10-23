-- ==============================================================================
-- Test Suite: 01_phase1_rls_test.sql
-- Description: Phase 1 Row Level Security (RLS) Policy Matrix Test Suite.
-- Personas tested:
--   1. Anonymous (unauthenticated)
--   2. Normal User A (Alice - 11111111-1111-1111-1111-111111111111)
--   3. Other User B (Bob - 22222222-2222-2222-2222-222222222222)
--   4. Blocked User (Charlie - 33333333-3333-3333-3333-333333333333, blocked by Alice)
--   5. Banned User (Dave - 44444444-4444-4444-4444-444444444444, is_banned = true)
--   6. Admin (Eve - 55555555-5555-5555-5555-555555555555, staff_roles = admin)
-- ==============================================================================

BEGIN;

-- Helper routine to set simulated JWT identity
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
-- Insert simulated auth users
INSERT INTO auth.users (id, email, raw_user_meta_data)
VALUES 
    ('11111111-1111-1111-1111-111111111111', 'alice@test.com', '{"full_name": "Alice Wonderland"}'::jsonb),
    ('22222222-2222-2222-2222-222222222222', 'bob@test.com', '{"full_name": "Bob Builder"}'::jsonb),
    ('33333333-3333-3333-3333-333333333333', 'charlie@test.com', '{"full_name": "Charlie Chaplin"}'::jsonb),
    ('44444444-4444-4444-4444-444444444444', 'dave@test.com', '{"full_name": "Dave Dangerous"}'::jsonb),
    ('55555555-5555-5555-5555-555555555555', 'eve@test.com', '{"full_name": "Eve Administrator"}'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- Populate profiles (via trigger or direct update)
UPDATE public.profiles SET username = 'alice', onboarded = true WHERE id = '11111111-1111-1111-1111-111111111111';
UPDATE public.profiles SET username = 'bob', onboarded = true WHERE id = '22222222-2222-2222-2222-222222222222';
UPDATE public.profiles SET username = 'charlie', onboarded = true WHERE id = '33333333-3333-3333-3333-333333333333';
UPDATE public.profiles SET username = 'dave', onboarded = true, is_banned = true WHERE id = '44444444-4444-4444-4444-444444444444';
UPDATE public.profiles SET username = 'eve', onboarded = true WHERE id = '55555555-5555-5555-5555-555555555555';

-- Establish Eve as Admin
INSERT INTO public.staff_roles (user_id, role)
VALUES ('55555555-5555-5555-5555-555555555555', 'admin')
ON CONFLICT DO NOTHING;

-- Alice blocks Charlie
INSERT INTO public.blocks (blocker_id, blocked_id)
VALUES ('11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333')
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------------------------
-- TEST 1: Anonymous access restrictions
-- ------------------------------------------------------------------------------
SELECT set_actor(NULL);

DO $$
DECLARE
    v_cnt INT;
BEGIN
    -- Anonymous should see 0 private notes
    SELECT COUNT(*) INTO v_cnt FROM public.private_notes;
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Anonymous user read private notes!';
    END IF;

    -- Anonymous should see 0 library items
    SELECT COUNT(*) INTO v_cnt FROM public.library_items;
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Anonymous user read library items!';
    END IF;

    -- Anonymous cannot insert into logs
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name)
        VALUES ('11111111-1111-1111-1111-111111111111', 1399, 'Game of Thrones');
        RAISE EXCEPTION 'TEST FAILED: Anonymous insert into logs did not error!';
    EXCEPTION
        WHEN insufficient_privilege OR check_violation THEN
            -- Expected rejection
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 2: Alice creates private items, Bob cannot read or modify them
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111');

-- Alice inserts library item, progress, private note, and a public review log
INSERT INTO public.library_items (user_id, show_id, status)
VALUES ('11111111-1111-1111-1111-111111111111', 1399, 'watching');

INSERT INTO public.show_progress (user_id, show_id, season, episode)
VALUES ('11111111-1111-1111-1111-111111111111', 1399, 1, 5);

INSERT INTO public.private_notes (user_id, show_id, body)
VALUES ('11111111-1111-1111-1111-111111111111', 1399, 'Alice secret thoughts on Season 1');

INSERT INTO public.logs (id, user_id, show_id, show_name, rating, review_text, status)
VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 1399, 'Game of Thrones', 4.5, 'Incredible drama', 'visible');

-- Now switch to Bob
SELECT set_actor('22222222-2222-2222-2222-222222222222');

DO $$
DECLARE
    v_cnt INT;
BEGIN
    -- Bob cannot read Alice's library item
    SELECT COUNT(*) INTO v_cnt FROM public.library_items WHERE user_id = '11111111-1111-1111-1111-111111111111';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Bob can read Alice library items!';
    END IF;

    -- Bob cannot read Alice's show progress
    SELECT COUNT(*) INTO v_cnt FROM public.show_progress WHERE user_id = '11111111-1111-1111-1111-111111111111';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Bob can read Alice show progress!';
    END IF;

    -- Bob cannot read Alice's private notes
    SELECT COUNT(*) INTO v_cnt FROM public.private_notes WHERE user_id = '11111111-1111-1111-1111-111111111111';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Bob can read Alice private notes!';
    END IF;

    -- Bob cannot update Alice's private note
    UPDATE public.private_notes SET body = 'Bob tampering' WHERE user_id = '11111111-1111-1111-1111-111111111111';
    IF FOUND THEN
        RAISE EXCEPTION 'TEST FAILED: Bob was able to update Alice private note!';
    END IF;

    -- Bob CAN read Alice's public visible log
    SELECT COUNT(*) INTO v_cnt FROM public.logs WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    IF v_cnt != 1 THEN
        RAISE EXCEPTION 'TEST FAILED: Bob could not read Alice public visible log!';
    END IF;

    -- Bob CANNOT update Alice's log
    UPDATE public.logs SET review_text = 'Hacked by Bob' WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    IF FOUND THEN
        RAISE EXCEPTION 'TEST FAILED: Bob was able to update Alice review log!';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 3: Blocked User Isolation (Charlie blocked by Alice)
-- ------------------------------------------------------------------------------
SELECT set_actor('33333333-3333-3333-3333-333333333333');

DO $$
DECLARE
    v_cnt INT;
BEGIN
    -- Charlie CANNOT see Alice's profile
    SELECT COUNT(*) INTO v_cnt FROM public.profiles WHERE id = '11111111-1111-1111-1111-111111111111';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Blocked user Charlie can read Alice profile!';
    END IF;

    -- Charlie CANNOT see Alice's logs even when visible
    SELECT COUNT(*) INTO v_cnt FROM public.logs WHERE id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'TEST FAILED: Blocked user Charlie can read Alice visible log!';
    END IF;

    -- Charlie CANNOT like Alice's log
    BEGIN
        INSERT INTO public.log_likes (user_id, log_id)
        VALUES ('33333333-3333-3333-3333-333333333333', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
        RAISE EXCEPTION 'TEST FAILED: Blocked user Charlie was able to like Alice log!';
    EXCEPTION
        WHEN insufficient_privilege OR check_violation THEN
            -- Expected rejection
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 4: Banned User Write Denial (Dave is banned)
-- ------------------------------------------------------------------------------
SELECT set_actor('44444444-4444-4444-4444-444444444444');

DO $$
BEGIN
    -- Banned Dave cannot insert a library item
    BEGIN
        INSERT INTO public.library_items (user_id, show_id, status)
        VALUES ('44444444-4444-4444-4444-444444444444', 1399, 'watching');
        RAISE EXCEPTION 'TEST FAILED: Banned user Dave was able to insert a library item!';
    EXCEPTION
        WHEN insufficient_privilege OR check_violation THEN
            -- Expected rejection
    END;

    -- Banned Dave cannot insert a log
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, review_text)
        VALUES ('44444444-4444-4444-4444-444444444444', 1399, 'GoT', 'Spam review');
        RAISE EXCEPTION 'TEST FAILED: Banned user Dave was able to insert a review log!';
    EXCEPTION
        WHEN insufficient_privilege OR check_violation THEN
            -- Expected rejection
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 5: Security Privilege Escalation Guard (Alice cannot tamper with trust_level or is_banned)
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111');

DO $$
BEGIN
    -- Alice attempts to promote her trust_level
    BEGIN
        UPDATE public.profiles SET trust_level = 5 WHERE id = '11111111-1111-1111-1111-111111111111';
        RAISE EXCEPTION 'TEST FAILED: User was able to promote their own trust_level!';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE '%Access denied%' THEN
                RAISE EXCEPTION 'Unexpected error: %', SQLERRM;
            END IF;
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 6: Rating Constraint Checks
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111');

DO $$
BEGIN
    -- Invalid rating 3.7 (not in 0.5 increments)
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, rating)
        VALUES ('11111111-1111-1111-1111-111111111111', 1399, 'GoT', 3.7);
        RAISE EXCEPTION 'TEST FAILED: Log accepted non-0.5 step rating!';
    EXCEPTION
        WHEN check_violation THEN
            -- Expected rejection
    END;

    -- Invalid rating 5.5 (out of range 0.5 - 5.0)
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, rating)
        VALUES ('11111111-1111-1111-1111-111111111111', 1399, 'GoT', 5.5);
        RAISE EXCEPTION 'TEST FAILED: Log accepted out-of-range rating!';
    EXCEPTION
        WHEN check_violation THEN
            -- Expected rejection
    END;
END $$;

RAISE NOTICE 'ALL PHASE 1 RLS & DATA INTEGRITY TESTS PASSED SUCCESSFULLY!';

ROLLBACK;
