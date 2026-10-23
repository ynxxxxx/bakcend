-- ==============================================================================
-- Test Suite: 01_phase1_rls_test.sql
-- Description: Phase 1 Exhaustive Security, Escalation & Constraint Test Matrix
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

-- 1. FIXTURE SETUP
INSERT INTO auth.users (id, email, raw_user_meta_data)
VALUES 
    ('11111111-1111-1111-1111-111111111111', 'alice@test.com', '{"full_name": "Alice Wonderland"}'::jsonb),
    ('22222222-2222-2222-2222-222222222222', 'bob@test.com', '{"full_name": "Bob Builder"}'::jsonb),
    ('33333333-3333-3333-3333-333333333333', 'charlie@test.com', '{"full_name": "Charlie Chaplin"}'::jsonb),
    ('44444444-4444-4444-4444-444444444444', 'dave@test.com', '{"full_name": "Dave Dangerous"}'::jsonb),
    ('55555555-5555-5555-5555-555555555555', 'eve@test.com', '{"full_name": "Eve Administrator"}'::jsonb),
    ('66666666-6666-6666-6666-666666666666', 'frank@test.com', '{"full_name": "Frank Scoped"}'::jsonb)
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

-- Establish Frank as community-only banned (scope = community)
INSERT INTO public.bans (user_id, scope, community_id, reason, banned_by)
VALUES ('66666666-6666-6666-6666-666666666666', 'community', gen_random_uuid(), 'Community ban only', '55555555-5555-5555-5555-555555555555')
ON CONFLICT DO NOTHING;

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
END $$;

-- ------------------------------------------------------------------------------
-- TEST 2: Anti-Probing Defense in private.is_banned()
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice (non-admin)

DO $$
BEGIN
    -- Alice can check her own ban status
    PERFORM private.is_banned('11111111-1111-1111-1111-111111111111');

    -- Alice cannot check Dave's ban status
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
-- TEST 4: Banned User Write Rejections (Dave has active global ban)
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
-- TEST 5: Blocking Deletes Follows in Both Directions (Unblocking does not restore)
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice
-- Alice follows Bob
INSERT INTO public.follows (follower_id, followee_id)
VALUES ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222')
ON CONFLICT DO NOTHING;

SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob
-- Bob follows Alice
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
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'FAIL: Mutual follows were not deleted upon block!';
    END IF;
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
    IF v_cnt != 0 THEN
        RAISE EXCEPTION 'FAIL: Unblocking resurrected follows!';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 6: Un-remove Attack & Moderation Tampering Guards on Logs
-- ------------------------------------------------------------------------------
-- Alice creates a log
SELECT set_actor('11111111-1111-1111-1111-111111111111');
INSERT INTO public.logs (id, user_id, show_id, show_name, review_text, status)
VALUES ('77777777-7777-7777-7777-777777777777', '11111111-1111-1111-1111-111111111111', 200, 'The Wire', 'Classic', 'visible')
ON CONFLICT (id) DO UPDATE SET review_text = 'Classic';

-- Alice tries to change status: visible -> hidden (must be blocked; must use deleted_at)
DO $$
BEGIN
    BEGIN
        UPDATE public.logs SET status = 'hidden' WHERE id = '77777777-7777-7777-7777-777777777777';
        RAISE EXCEPTION 'FAIL: Client was able to change log status to hidden!';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%Cannot alter moderation status%' THEN RAISE EXCEPTION '%', SQLERRM; END IF;
    END;
END $$;

-- Alice tries to change status: visible -> held
DO $$
BEGIN
    BEGIN
        UPDATE public.logs SET status = 'held' WHERE id = '77777777-7777-7777-7777-777777777777';
        RAISE EXCEPTION 'FAIL: Client was able to change log status to held!';
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
-- TEST 7: User Ownership Transfer Lock & Stale Clock Guard on show_progress & private_notes
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice

INSERT INTO public.show_progress (id, user_id, show_id, season, episode, client_updated_at)
VALUES ('88888888-8888-8888-8888-888888888888', '11111111-1111-1111-1111-111111111111', 300, 1, 2, '2026-10-23 12:00:00+00')
ON CONFLICT DO NOTHING;

-- Alice attempts user_id transfer to Bob on show_progress
DO $$
BEGIN
    BEGIN
        UPDATE public.show_progress SET user_id = '22222222-2222-2222-2222-222222222222'
        WHERE id = '88888888-8888-8888-8888-888888888888';
        RAISE EXCEPTION 'FAIL: User was able to transfer ownership of show_progress!';
    EXCEPTION WHEN OTHERS THEN
        IF SQLERRM NOT LIKE '%Cannot transfer ownership%' THEN RAISE EXCEPTION '%', SQLERRM; END IF;
    END;
END $$;

-- Stale write attempt on show_progress
UPDATE public.show_progress
SET episode = 99, client_updated_at = '2026-10-23 11:00:00+00'
WHERE id = '88888888-8888-8888-8888-888888888888';

DO $$
DECLARE v_ep INT;
BEGIN
    SELECT episode INTO v_ep FROM public.show_progress WHERE id = '88888888-8888-8888-8888-888888888888';
    IF v_ep != 2 THEN
        RAISE EXCEPTION 'FAIL: Stale write overwritten show_progress (episode changed to %)!', v_ep;
    END IF;
END $$;

-- Stale write attempt on private_notes
INSERT INTO public.private_notes (id, user_id, show_id, body, client_updated_at)
VALUES ('99999999-9999-9999-9999-999999999999', '11111111-1111-1111-1111-111111111111', 300, 'Original note', '2026-10-23 12:00:00+00')
ON CONFLICT DO NOTHING;

UPDATE public.private_notes
SET body = 'Stale note overwrite', client_updated_at = '2026-10-23 11:00:00+00'
WHERE id = '99999999-9999-9999-9999-999999999999';

DO $$
DECLARE v_body TEXT;
BEGIN
    SELECT body INTO v_body FROM public.private_notes WHERE id = '99999999-9999-9999-9999-999999999999';
    IF v_body != 'Original note' THEN
        RAISE EXCEPTION 'FAIL: Stale write overwritten private_notes!';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 8: Non-Admin Writing to Bans / Staff Roles & Self Promotion
-- ------------------------------------------------------------------------------
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice

DO $$
BEGIN
    -- Write to bans
    BEGIN
        INSERT INTO public.bans (user_id, scope, reason) VALUES ('22222222-2222-2222-2222-222222222222', 'global', 'Rogue ban');
        RAISE EXCEPTION 'FAIL: Alice inserted into bans!';
    EXCEPTION WHEN insufficient_privilege THEN END;

    -- Self promotion into staff_roles
    BEGIN
        INSERT INTO public.staff_roles (user_id, role) VALUES ('11111111-1111-1111-1111-111111111111', 'admin');
        RAISE EXCEPTION 'FAIL: Alice promoted herself to admin in staff_roles!';
    EXCEPTION WHEN insufficient_privilege THEN END;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 9: Double Like Rejection & Clamping Below Zero
-- ------------------------------------------------------------------------------
-- Bob likes Alice's visible log
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob

-- Create fresh visible log for like testing
INSERT INTO public.logs (id, user_id, show_id, show_name, review_text, status)
VALUES ('10101010-1010-1010-1010-101010101010', '11111111-1111-1111-1111-111111111111', 400, 'Succession', 'Great show', 'visible')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.log_likes (user_id, log_id)
VALUES ('22222222-2222-2222-2222-222222222222', '10101010-1010-1010-1010-101010101010');

-- Double like attempt must violate unique constraint
DO $$
BEGIN
    BEGIN
        INSERT INTO public.log_likes (user_id, log_id)
        VALUES ('22222222-2222-2222-2222-222222222222', '10101010-1010-1010-1010-101010101010');
        RAISE EXCEPTION 'FAIL: Double like allowed!';
    EXCEPTION WHEN unique_violation THEN END;
END $$;

-- Bob unlikes
DELETE FROM public.log_likes
WHERE user_id = '22222222-2222-2222-2222-222222222222' AND log_id = '10101010-1010-1010-1010-101010101010';

-- Verify count is 0 and does not drop below 0
DO $$
DECLARE v_likes INT;
BEGIN
    SELECT like_count INTO v_likes FROM public.logs WHERE id = '10101010-1010-1010-1010-101010101010';
    IF v_likes != 0 THEN
        RAISE EXCEPTION 'FAIL: like_count is not 0 after unlike (got %)!', v_likes;
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 10: CHECK Constraint Rejections (Proving bad data is rejected)
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

    -- Invalid rating: 5.5 (> 5.0)
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, rating)
        VALUES ('11111111-1111-1111-1111-111111111111', 500, 'Test', 5.5);
        RAISE EXCEPTION 'FAIL: Log accepted out-of-range rating 5.5!';
    EXCEPTION WHEN check_violation THEN END;

    -- Review text > 5000 chars
    BEGIN
        INSERT INTO public.logs (user_id, show_id, show_name, review_text)
        VALUES ('11111111-1111-1111-1111-111111111111', 500, 'Test', repeat('A', 5001));
        RAISE EXCEPTION 'FAIL: Log accepted review > 5000 chars!';
    EXCEPTION WHEN check_violation THEN END;

    -- Tags count > 20
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
-- TEST 11: Verify Every Public Table has Active RLS and At Least One Policy
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
        -- Verify RLS enabled
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = r.tablename AND c.relrowsecurity = true
        ) THEN
            RAISE EXCEPTION 'FAIL: Table public.% does not have RLS enabled!', r.tablename;
        END IF;

        -- Verify at least one policy exists
        SELECT COUNT(*) INTO v_policy_count
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename = r.tablename;

        IF v_policy_count = 0 THEN
            RAISE EXCEPTION 'FAIL: Table public.% has no RLS policies defined!', r.tablename;
        END IF;
    END LOOP;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 12: Verify Idempotent pg_cron Tombstone Purge Job Exists
-- ------------------------------------------------------------------------------
DO $$
DECLARE v_job_count INT;
BEGIN
    SELECT COUNT(*) INTO v_job_count
    FROM cron.job
    WHERE jobname = 'purge-soft-deleted-tombstones';

    IF v_job_count != 1 THEN
        RAISE EXCEPTION 'FAIL: pg_cron tombstone purge job was not scheduled (found %)!', v_job_count;
    END IF;
END $$;

RAISE NOTICE '============================================================';
RAISE NOTICE 'SUCCESS: ALL 12 SECURITY, INTEGRITY & CONSTRAINT TESTS PASSED';
RAISE NOTICE '============================================================';

ROLLBACK;
