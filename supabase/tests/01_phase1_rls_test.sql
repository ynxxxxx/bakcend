-- ==============================================================================
-- Test Suite: 01_phase1_rls_test.sql
-- Description: Phase 1 Exhaustive Security, Escalation & Constraint Test Matrix
-- Target: Real Supabase Stack (PostgreSQL 15+ with auth schema & PostgREST JWT)
-- ==============================================================================

BEGIN;

-- Helper to set execution role and PostgREST JWT claims
CREATE OR REPLACE FUNCTION set_actor(
    actor_id UUID, 
    actor_role TEXT DEFAULT 'authenticated',
    actor_aal TEXT DEFAULT 'aal1'
)
RETURNS VOID AS $$
DECLARE
    v_claims TEXT;
BEGIN
    IF actor_id IS NULL THEN
        SET LOCAL ROLE anon;
        PERFORM set_config('request.jwt.claims', '{"role":"anon"}', true);
        PERFORM set_config('request.jwt.claim.sub', '', true);
        PERFORM set_config('request.jwt.claim.role', 'anon', true);
        PERFORM set_config('request.jwt.claim.aal', 'aal1', true);
    ELSE
        SET LOCAL ROLE authenticated;
        v_claims := json_build_object(
            'sub', actor_id::text,
            'role', actor_role,
            'email', actor_id::text || '@test.com',
            'aal', actor_aal
        )::text;
        PERFORM set_config('request.jwt.claims', v_claims, true);
        PERFORM set_config('request.jwt.claim.sub', actor_id::text, true);
        PERFORM set_config('request.jwt.claim.role', actor_role, true);
        PERFORM set_config('request.jwt.claim.aal', actor_aal, true);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- 1. FIXTURE SETUP: Insert into real auth.users
INSERT INTO auth.users (
    id, instance_id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at
)
VALUES 
    ('11111111-1111-1111-1111-111111111111', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'alice@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Alice Wonderland"}'::jsonb, now(), now()),
    ('22222222-2222-2222-2222-222222222222', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'bob@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Bob Builder"}'::jsonb, now(), now()),
    ('33333333-3333-3333-3333-333333333333', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'charlie@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Charlie Chaplin"}'::jsonb, now(), now()),
    ('44444444-4444-4444-4444-444444444444', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'dave@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Dave Dangerous"}'::jsonb, now(), now()),
    ('55555555-5555-5555-5555-555555555555', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'eve@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Eve Administrator"}'::jsonb, now(), now()),
    ('66666666-6666-6666-6666-666666666666', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'frank@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Frank Scoped"}'::jsonb, now(), now())
ON CONFLICT (id) DO NOTHING;

UPDATE public.profiles SET username = 'alice', onboarded = true WHERE id = '11111111-1111-1111-1111-111111111111';
UPDATE public.profiles SET username = 'bob', onboarded = true WHERE id = '22222222-2222-2222-2222-222222222222';
UPDATE public.profiles SET username = 'charlie', onboarded = true WHERE id = '33333333-3333-3333-3333-333333333333';
UPDATE public.profiles SET username = 'dave', onboarded = true WHERE id = '44444444-4444-4444-4444-444444444444';
UPDATE public.profiles SET username = 'eve', onboarded = true WHERE id = '55555555-5555-5555-5555-555555555555';
UPDATE public.profiles SET username = 'frank', onboarded = true WHERE id = '66666666-6666-6666-6666-666666666666';

-- Establish Eve as Admin
INSERT INTO public.staff_roles (user_id, role)
VALUES ('55555555-5555-5555-5555-555555555555', 'admin')
ON CONFLICT DO NOTHING;

-- Establish Dave as actively globally banned
INSERT INTO public.bans (user_id, scope, reason, banned_by)
VALUES ('44444444-4444-4444-4444-444444444444', 'global', 'Global ban test', '55555555-5555-5555-5555-555555555555')
ON CONFLICT DO NOTHING;

-- Establish Frank as community-only banned
INSERT INTO public.bans (user_id, scope, community_id, reason, banned_by)
VALUES ('66666666-6666-6666-6666-666666666666', 'community', gen_random_uuid(), 'Community ban only', '55555555-5555-5555-5555-555555555555')
ON CONFLICT DO NOTHING;

-- Report on pg_cron status without mocking
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        RAISE NOTICE 'pg_cron extension is NOT installed in this PostgreSQL stack';
    ELSE
        RAISE NOTICE 'pg_cron extension is verified present in this PostgreSQL stack';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 1: Anonymous Access (Must not read private data or user_flags)
-- ------------------------------------------------------------------------------
SELECT set_actor(NULL);

DO $$
DECLARE v_cnt INT;
BEGIN
    SELECT COUNT(*) INTO v_cnt FROM public.user_flags;
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Anon read user_flags!'; END IF;

    SELECT COUNT(*) INTO v_cnt FROM public.private_notes;
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Anon read private_notes!'; END IF;

    SELECT COUNT(*) INTO v_cnt FROM public.library_items;
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Anon read library_items!'; END IF;

    SELECT COUNT(*) INTO v_cnt FROM public.show_progress;
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Anon read show_progress!'; END IF;

    SELECT COUNT(*) INTO v_cnt FROM public.moderation_actions;
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Anon read moderation_actions!'; END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 2: Anti-Probing Defense in private.is_banned()
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice (non-admin)

DO $$
BEGIN
    PERFORM private.is_banned('11111111-1111-1111-1111-111111111111');

    BEGIN
        PERFORM private.is_banned('44444444-4444-4444-4444-444444444444');
        RAISE EXCEPTION 'FAIL: Non-admin was able to probe other user ban status!';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM NOT LIKE '%Cannot probe ban status%' THEN
                RAISE EXCEPTION 'Unexpected error probing ban: %', SQLERRM;
            END IF;
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 3: Community Ban Does NOT Block Global Writes
-- ------------------------------------------------------------------------------
SELECT set_actor('66666666-6666-6666-6666-666666666666'); -- Frank (community ban only)

DO $$
BEGIN
    INSERT INTO public.library_items (user_id, show_id, status)
    VALUES ('66666666-6666-6666-6666-666666666666', 101, 'watching');

    INSERT INTO public.logs (user_id, show_id, show_name, review_text)
    VALUES ('66666666-6666-6666-6666-666666666666', 101, 'Breaking Bad', 'Allowed review');
END $$;

-- ------------------------------------------------------------------------------
-- TEST 4: Global Ban Rejections (Dave has active global ban)
-- ------------------------------------------------------------------------------
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave

DO $$
BEGIN
    -- Follows
    BEGIN
        INSERT INTO public.follows (follower_id, followee_id)
        VALUES ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111');
        RAISE EXCEPTION 'FAIL: Banned user inserted follow!';
    EXCEPTION WHEN insufficient_privilege OR check_violation THEN END;

    -- Blocks
    BEGIN
        INSERT INTO public.blocks (blocker_id, blocked_id)
        VALUES ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111');
        RAISE EXCEPTION 'FAIL: Banned user inserted block!';
    EXCEPTION WHEN insufficient_privilege OR check_violation THEN END;

    -- Update profile
    UPDATE public.profiles SET bio = 'Banned bio update' WHERE id = '44444444-4444-4444-4444-444444444444';
    IF FOUND THEN RAISE EXCEPTION 'FAIL: Banned user updated profile!'; END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 5: Mutual Follow Deletion on Block
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice
INSERT INTO public.follows (follower_id, followee_id)
VALUES ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
ON CONFLICT DO NOTHING;

SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob
INSERT INTO public.follows (follower_id, followee_id)
VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111')
ON CONFLICT DO NOTHING;

-- Alice blocks Bob
SELECT set_actor('11111111-1111-1111-1111-111111111111');
INSERT INTO public.blocks (blocker_id, blocked_id)
VALUES ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
ON CONFLICT DO NOTHING;

DO $$
DECLARE v_cnt INT;
BEGIN
    SELECT COUNT(*) INTO v_cnt FROM public.follows
    WHERE (follower_id = '11111111-1111-1111-1111-111111111111' AND followee_id = '22222222-2222-2222-2222-222222222222')
       OR (follower_id = '22222222-2222-2222-2222-222222222222' AND followee_id = '11111111-1111-1111-1111-111111111111');
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Mutual follows were not deleted upon block!'; END IF;
END $$;

-- Alice unblocks Bob; follows must remain deleted
DELETE FROM public.blocks
WHERE blocker_id = '11111111-1111-1111-1111-111111111111' AND blocked_id = '22222222-2222-2222-2222-222222222222';

DO $$
DECLARE v_cnt INT;
BEGIN
    SELECT COUNT(*) INTO v_cnt FROM public.follows
    WHERE (follower_id = '11111111-1111-1111-1111-111111111111' AND followee_id = '22222222-2222-2222-2222-222222222222')
       OR (follower_id = '22222222-2222-2222-2222-222222222222' AND followee_id = '11111111-1111-1111-1111-111111111111');
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Unblocking resurrected follows!'; END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 6: Un-remove Attack & Moderation Tampering Guards on Logs
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111');
INSERT INTO public.logs (id, user_id, show_id, show_name, review_text, status)
VALUES ('77777777-7777-7777-7777-777777777777', '11111111-1111-1111-1111-111111111111', 200, 'The Wire', 'Classic', 'visible')
ON CONFLICT (id) DO UPDATE SET review_text = 'Classic';

DO $$
BEGIN
    -- visible -> hidden attempt
    BEGIN
        UPDATE public.logs SET status = 'hidden' WHERE id = '77777777-7777-7777-7777-777777777777';
        RAISE EXCEPTION 'FAIL: Client changed log status to hidden!';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%Cannot alter moderation status%' THEN RAISE EXCEPTION '%', SQLERRM; END IF;
    END;

    -- visible -> held attempt
    BEGIN
        UPDATE public.logs SET status = 'held' WHERE id = '77777777-7777-7777-7777-777777777777';
        RAISE EXCEPTION 'FAIL: Client changed log status to held!';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%Cannot alter moderation status%' THEN RAISE EXCEPTION '%', SQLERRM; END IF;
    END;
END $$;

-- Admin sets log status to 'removed'
SELECT set_actor('55555555-5555-5555-5555-555555555555'); -- Eve (Admin)
UPDATE public.logs SET status = 'removed' WHERE id = '77777777-7777-7777-7777-777777777777';

-- Alice attempts UN-REMOVE attack: removed -> visible
SELECT set_actor('11111111-1111-1111-1111-111111111111');
DO $$
BEGIN
    BEGIN
        UPDATE public.logs SET status = 'visible' WHERE id = '77777777-7777-7777-7777-777777777777';
        RAISE EXCEPTION 'FAIL: Client un-removed a moderated row!';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%removed by moderation%' AND SQLERRM NOT LIKE '%Cannot alter moderation status%' THEN
            RAISE EXCEPTION 'Unexpected error on un-remove attack: %', SQLERRM;
        END IF;
    END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 7: Append-Only Moderation Actions (Insert-only, No update/delete, No client access)
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111');
DO $$
DECLARE v_cnt INT;
BEGIN
    SELECT COUNT(*) INTO v_cnt FROM public.moderation_actions;
    IF v_cnt != 0 THEN RAISE EXCEPTION 'FAIL: Normal user read moderation_actions!'; END IF;

    BEGIN
        INSERT INTO public.moderation_actions (actor_id, action, target_type, target_id, reason)
        VALUES ('11111111-1111-1111-1111-111111111111', 'ban', 'user', '22222222-2222-2222-2222-222222222222', 'Rogue action');
        RAISE EXCEPTION 'FAIL: Normal user wrote to moderation_actions!';
    EXCEPTION WHEN insufficient_privilege THEN END;
END $$;

-- Admin (Eve) CAN write an audit record and read it
SELECT set_actor('55555555-5555-5555-5555-555555555555');
INSERT INTO public.moderation_actions (id, actor_id, action, target_type, target_id, reason)
VALUES ('ffffffff-ffff-ffff-ffff-ffffffffffff', '55555555-5555-5555-5555-555555555555', 'ban', 'user', '44444444-4444-4444-4444-444444444444', 'Audit ban verification');

-- Even Admin CANNOT update or delete from moderation_actions (append-only)
DO $$
BEGIN
    BEGIN
        UPDATE public.moderation_actions SET reason = 'Tampered reason' WHERE id = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
        RAISE EXCEPTION 'FAIL: moderation_actions row was updated!';
    EXCEPTION WHEN insufficient_privilege THEN END;

    BEGIN
        DELETE FROM public.moderation_actions WHERE id = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
        RAISE EXCEPTION 'FAIL: moderation_actions row was deleted!';
    EXCEPTION WHEN insufficient_privilege THEN END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 8: CHECK Constraint Rejections (Proving bad data is rejected)
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice

DO $$
BEGIN
    -- Reserved username: 'admin'
    BEGIN
        INSERT INTO auth.users (id, email) VALUES ('aaaaaaaa-1111-2222-3333-444444444444', 'admin@test.com');
        UPDATE public.profiles SET username = 'admin' WHERE id = 'aaaaaaaa-1111-2222-3333-444444444444';
        RAISE EXCEPTION 'FAIL: Profile accepted reserved username "admin"!';
    EXCEPTION WHEN check_violation THEN END;

    -- Invalid username regex: 'aa' (< 3 chars)
    BEGIN
        UPDATE public.profiles SET username = 'aa' WHERE id = '11111111-1111-1111-1111-111111111111';
        RAISE EXCEPTION 'FAIL: Profile accepted short username "aa"!';
    EXCEPTION WHEN check_violation THEN END;

    -- Invalid rating: 3.7 (not in 0.5 steps)
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, rating)
        VALUES ('11111111-1111-1111-1111-111111111111', 500, 'Test', 3.7);
        RAISE EXCEPTION 'FAIL: Log accepted invalid rating 3.7!';
    EXCEPTION WHEN check_violation THEN END;

    -- Tags count > 20 using cardinality(tags)
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, tags)
        VALUES ('11111111-1111-1111-1111-111111111111', 500, 'Test', ARRAY[
            't1','t2','t3','t4','t5','t6','t7','t8','t9','t10',
            't11','t12','t13','t14','t15','t16','t17','t18','t19','t20','t21'
        ]);
        RAISE EXCEPTION 'FAIL: Log accepted > 20 tags!';
    EXCEPTION WHEN check_violation THEN END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 9: Verify Every Public Table has Active RLS and At Least One Policy
-- ------------------------------------------------------------------------------
DO $$
DECLARE
    r RECORD;
    v_policy_count INT;
BEGIN
    FOR r IN (
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
    ) LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = r.tablename AND c.relrowsecurity = true
        ) THEN
            RAISE EXCEPTION 'FAIL: Table public.% does not have RLS enabled!', r.tablename;
        END IF;

        SELECT COUNT(*) INTO v_policy_count
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename = r.tablename;

        IF v_policy_count = 0 THEN
            RAISE EXCEPTION 'FAIL: Table public.% has no RLS policies defined!', r.tablename;
        END IF;
    END LOOP;
END $$;

RAISE NOTICE '============================================================';
RAISE NOTICE 'SUCCESS: ALL PHASE 1 EXHAUSTIVE RLS & INTEGRITY TESTS PASSED';
RAISE NOTICE '============================================================';

ROLLBACK;
