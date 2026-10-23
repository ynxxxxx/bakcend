-- ==============================================================================
-- Test Suite: 01_phase1_rls_test.sql
-- Description: Phase 1 Exhaustive Security, Escalation & Constraint Test Matrix
-- Framework: Real pgTAP against official Supabase Stack (Postgres 15+)
-- ==============================================================================

BEGIN;

-- 1. Initialize pgTAP plan (23 discrete assertions)
SELECT plan(23);

-- 2. Helper to set execution role and PostgREST JWT claims
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

-- 3. FIXTURE SETUP (Requires superuser / postgres rights)
RESET ROLE;

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

-- Report pg_cron presence (do not mock)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        RAISE NOTICE 'pg_cron extension is NOT installed in this PostgreSQL stack';
    ELSE
        RAISE NOTICE 'pg_cron extension is verified present in this PostgreSQL stack';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- TEST 1-5: Anonymous Access Lockdown (pgTAP is())
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor(NULL);

SELECT is(count(*)::int, 0, 'Anon cannot read user_flags') FROM public.user_flags;
SELECT is(count(*)::int, 0, 'Anon cannot read private_notes') FROM public.private_notes;
SELECT is(count(*)::int, 0, 'Anon cannot read library_items') FROM public.library_items;
SELECT is(count(*)::int, 0, 'Anon cannot read show_progress') FROM public.show_progress;
SELECT is(count(*)::int, 0, 'Anon cannot read moderation_actions') FROM public.moderation_actions;

-- ------------------------------------------------------------------------------
-- TEST 6-7: Anti-Probing Defense in private.is_banned() (lives_ok & throws_ok)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice (non-admin)

SELECT lives_ok(
    $$ SELECT private.is_banned('11111111-1111-1111-1111-111111111111') $$,
    'Non-admin can check own ban status'
);

SELECT throws_ok(
    $$ SELECT private.is_banned('44444444-4444-4444-4444-444444444444') $$,
    'P0001',
    'Cannot probe ban status of another user',
    'Non-admin cannot probe other user ban status'
);

-- ------------------------------------------------------------------------------
-- TEST 8: Community Ban Does NOT Block Global Writes (lives_ok)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('66666666-6666-6666-6666-666666666666'); -- Frank (community ban only)

SELECT lives_ok(
    $$ INSERT INTO public.library_items (user_id, show_id, status) VALUES ('66666666-6666-6666-6666-666666666666', 101, 'watching') $$,
    'Community-banned user can perform global library write'
);

-- ------------------------------------------------------------------------------
-- TEST 9-11: Global Ban Rejections (throws_ok)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (globally banned)

SELECT throws_ok(
    $$ INSERT INTO public.follows (follower_id, followee_id) VALUES ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111') $$,
    '42501',
    NULL,
    'Globally banned user cannot insert follows'
);

SELECT throws_ok(
    $$ INSERT INTO public.blocks (blocker_id, blocked_id) VALUES ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111') $$,
    '42501',
    NULL,
    'Globally banned user cannot insert blocks'
);

SELECT throws_ok(
    $$ UPDATE public.profiles SET bio = 'Banned bio update' WHERE id = '44444444-4444-4444-4444-444444444444' $$,
    '42501',
    NULL,
    'Globally banned user cannot update profile'
);

-- ------------------------------------------------------------------------------
-- TEST 12-13: Mutual Follow Deletion on Block (is())
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice follows Bob
INSERT INTO public.follows (follower_id, followee_id) VALUES ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222') ON CONFLICT DO NOTHING;

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob follows Alice
INSERT INTO public.follows (follower_id, followee_id) VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111') ON CONFLICT DO NOTHING;

-- Alice blocks Bob
RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111');
INSERT INTO public.blocks (blocker_id, blocked_id) VALUES ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222') ON CONFLICT DO NOTHING;

RESET ROLE;
SELECT is(
    count(*)::int, 0,
    'Mutual follows deleted upon block'
) FROM public.follows
WHERE (follower_id = '11111111-1111-1111-1111-111111111111' AND followee_id = '22222222-2222-2222-2222-222222222222')
   OR (follower_id = '22222222-2222-2222-2222-222222222222' AND followee_id = '11111111-1111-1111-1111-111111111111');

RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111');
DELETE FROM public.blocks WHERE blocker_id = '11111111-1111-1111-1111-111111111111' AND blocked_id = '22222222-2222-2222-2222-222222222222';

RESET ROLE;
SELECT is(
    count(*)::int, 0,
    'Unblocking does not resurrect deleted follows'
) FROM public.follows
WHERE (follower_id = '11111111-1111-1111-1111-111111111111' AND followee_id = '22222222-2222-2222-2222-222222222222')
   OR (follower_id = '22222222-2222-2222-2222-222222222222' AND followee_id = '11111111-1111-1111-1111-111111111111');

-- ------------------------------------------------------------------------------
-- TEST 14-15: Log Moderation & Un-Remove Attack Guards (throws_ok)
-- ------------------------------------------------------------------------------
RESET ROLE;
INSERT INTO public.logs (id, user_id, show_id, show_name, review_text, status)
VALUES ('77777777-7777-7777-7777-777777777777', '11111111-1111-1111-1111-111111111111', 200, 'The Wire', 'Classic', 'visible')
ON CONFLICT (id) DO UPDATE SET review_text = 'Classic';

RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice
SELECT throws_ok(
    $$ UPDATE public.logs SET status = 'hidden' WHERE id = '77777777-7777-7777-7777-777777777777' $$,
    'P0001',
    'Cannot alter moderation status on logs',
    'Client cannot mutate status to hidden'
);

RESET ROLE;
UPDATE public.logs SET status = 'removed' WHERE id = '77777777-7777-7777-7777-777777777777';

RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice attempts un-remove
SELECT throws_ok(
    $$ UPDATE public.logs SET status = 'visible' WHERE id = '77777777-7777-7777-7777-777777777777' $$,
    'P0001',
    NULL,
    'Client cannot un-remove a moderated log row'
);

-- ------------------------------------------------------------------------------
-- TEST 16-19: Append-Only Moderation Actions (throws_ok & lives_ok)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice
SELECT throws_ok(
    $$ INSERT INTO public.moderation_actions (actor_id, action, target_type, target_id, reason) VALUES ('11111111-1111-1111-1111-111111111111', 'ban', 'user', '22222222-2222-2222-2222-222222222222', 'Rogue') $$,
    '42501',
    NULL,
    'Normal user cannot insert into moderation_actions'
);

RESET ROLE;
SELECT set_actor('55555555-5555-5555-5555-555555555555'); -- Admin
SELECT lives_ok(
    $$ INSERT INTO public.moderation_actions (id, actor_id, action, target_type, target_id, reason) VALUES ('ffffffff-ffff-ffff-ffff-ffffffffffff', '55555555-5555-5555-5555-555555555555', 'ban', 'user', '44444444-4444-4444-4444-444444444444', 'Audit ban') $$,
    'Admin can append to moderation_actions'
);

SELECT throws_ok(
    $$ UPDATE public.moderation_actions SET reason = 'Tampered' WHERE id = 'ffffffff-ffff-ffff-ffff-ffffffffffff' $$,
    '42501',
    NULL,
    'Admin cannot update moderation_actions'
);

SELECT throws_ok(
    $$ DELETE FROM public.moderation_actions WHERE id = 'ffffffff-ffff-ffff-ffff-ffffffffffff' $$,
    '42501',
    NULL,
    'Admin cannot delete from moderation_actions'
);

-- ------------------------------------------------------------------------------
-- TEST 20-22: CHECK Constraints (throws_ok)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT throws_ok(
    $$ UPDATE public.profiles SET username = 'admin' WHERE id = '11111111-1111-1111-1111-111111111111' $$,
    '23514',
    NULL,
    'CHECK constraint rejects reserved username admin'
);

SELECT throws_ok(
    $$ UPDATE public.profiles SET username = 'aa' WHERE id = '11111111-1111-1111-1111-111111111111' $$,
    '23514',
    NULL,
    'CHECK constraint rejects short username < 3 chars'
);

SELECT throws_ok(
    $$ INSERT INTO public.logs (user_id, show_id, show_name, rating) VALUES ('11111111-1111-1111-1111-111111111111', 500, 'Test', 3.7) $$,
    '23514',
    NULL,
    'CHECK constraint rejects non-0.5 step rating'
);

-- ------------------------------------------------------------------------------
-- TEST 23: Complete RLS Activation Across Public Tables (is())
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT is(
    count(*)::int, 12,
    'All 12 public tables have active Row Level Security'
) FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity = true;

-- 4. Finish pgTAP Execution
SELECT * FROM finish();

ROLLBACK;
