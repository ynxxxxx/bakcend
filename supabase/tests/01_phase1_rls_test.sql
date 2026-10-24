-- ==============================================================================
-- Test Suite: 01_phase1_rls_test.sql
-- Description: Phase 1 Exhaustive Security, Escalation, Constraint & Write Path Test Matrix
-- Framework: Real pgTAP against official Supabase Stack (Postgres 15+)
-- Total Assertions: Exactly 51
-- ==============================================================================

BEGIN;

-- 1. Initialize pgTAP plan (51 discrete assertions)
SELECT plan(51);

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
    ('66666666-6666-6666-6666-666666666666', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'frank@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Frank Scoped"}'::jsonb, now(), now()),
    ('88888888-8888-8888-8888-888888888888', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'grace@test.com', '', now(), '{"provider":"email","providers":["email"]}'::jsonb, '{"full_name": "Grace Moderator"}'::jsonb, now(), now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.profiles (id, username, display_name, onboarded)
VALUES 
    ('11111111-1111-1111-1111-111111111111', 'alice', 'Alice Wonderland', true),
    ('22222222-2222-2222-2222-222222222222', 'bob', 'Bob Builder', true),
    ('33333333-3333-3333-3333-333333333333', 'charlie', 'Charlie Chaplin', true),
    ('44444444-4444-4444-4444-444444444444', 'dave', 'Dave Dangerous', true),
    ('55555555-5555-5555-5555-555555555555', 'eve', 'Eve Administrator', true),
    ('66666666-6666-6666-6666-666666666666', 'frank', 'Frank Scoped', true),
    ('88888888-8888-8888-8888-888888888888', 'grace', 'Grace Moderator', true)
ON CONFLICT (id) DO UPDATE SET 
    username = EXCLUDED.username, 
    display_name = EXCLUDED.display_name, 
    onboarded = EXCLUDED.onboarded;

-- Staff Roles: Eve = Admin, Grace = Moderator
DELETE FROM public.staff_roles WHERE user_id IN ('55555555-5555-5555-5555-555555555555', '88888888-8888-8888-8888-888888888888');
INSERT INTO public.staff_roles (user_id, role)
VALUES 
    ('55555555-5555-5555-5555-555555555555', 'admin'),
    ('88888888-8888-8888-8888-888888888888', 'moderator');

-- Bans Fixtures:
-- Dave: ACTIVE global ban (expires in 10 days)
INSERT INTO public.bans (user_id, scope, reason, banned_by, expires_at)
VALUES ('44444444-4444-4444-4444-444444444444', 'global', 'Active global ban test', '55555555-5555-5555-5555-555555555555', NOW() + INTERVAL '10 days')
ON CONFLICT DO NOTHING;

-- Charlie: EXPIRED global ban (expired 1 hour ago)
INSERT INTO public.bans (user_id, scope, reason, banned_by, expires_at)
VALUES ('33333333-3333-3333-3333-333333333333', 'global', 'Expired global ban test', '55555555-5555-5555-5555-555555555555', NOW() - INTERVAL '1 hour')
ON CONFLICT DO NOTHING;

-- Frank: Community-only ban
INSERT INTO public.bans (user_id, scope, community_id, reason, banned_by)
VALUES ('66666666-6666-6666-6666-666666666666', 'community', gen_random_uuid(), 'Community ban only', '55555555-5555-5555-5555-555555555555')
ON CONFLICT DO NOTHING;

-- Baseline visible log owned by Alice (for log_likes tests)
INSERT INTO public.logs (id, user_id, show_id, show_name, review_text, status)
VALUES ('77777777-7777-7777-7777-777777777777', '11111111-1111-1111-1111-111111111111', 200, 'The Wire', 'Classic review', 'visible')
ON CONFLICT (id) DO UPDATE SET status = 'visible';

-- ------------------------------------------------------------------------------
-- GROUP 1: Anonymous Access Lockdown (Tests 1-5, pgTAP is())
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor(NULL);

SELECT is(count(*)::int, 0, 'Anon cannot read user_flags') FROM public.user_flags;
SELECT is(count(*)::int, 0, 'Anon cannot read private_notes') FROM public.private_notes;
SELECT is(count(*)::int, 0, 'Anon cannot read library_items') FROM public.library_items;
SELECT is(count(*)::int, 0, 'Anon cannot read show_progress') FROM public.show_progress;
SELECT is(count(*)::int, 0, 'Anon cannot read moderation_actions') FROM public.moderation_actions;

-- ------------------------------------------------------------------------------
-- GROUP 2: Anti-Probing Defense in private.is_banned() (Tests 6-7)
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
    'Access denied: Cannot probe ban status of other users',
    'Non-admin cannot probe other user ban status'
);

-- ------------------------------------------------------------------------------
-- GROUP 3: Community Ban Scoping (Test 8)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('66666666-6666-6666-6666-666666666666'); -- Frank (community ban only)

SELECT lives_ok(
    $$ INSERT INTO public.library_items (user_id, show_id, status) VALUES ('66666666-6666-6666-6666-666666666666', 101, 'watching') $$,
    'Community-banned user can perform global library write'
);

-- ------------------------------------------------------------------------------
-- GROUP 4: Mutual Follow Deletion & Resurrect Guard (Tests 9-10)
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
-- GROUP 5: Log Moderation & Un-Remove Attack Guards (Tests 11-12)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice
SELECT throws_ok(
    $$ UPDATE public.logs SET status = 'hidden' WHERE id = '77777777-7777-7777-7777-777777777777' $$,
    'P0001',
    'Access denied: Cannot alter moderation status',
    'Client cannot mutate status to hidden'
);

RESET ROLE;
UPDATE public.logs SET status = 'removed' WHERE id = '77777777-7777-7777-7777-777777777777';

RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice attempts un-remove
SELECT throws_ok(
    $$ UPDATE public.logs SET status = 'visible' WHERE id = '77777777-7777-7777-7777-777777777777' $$,
    'P0001',
    'Access denied: Content has been removed by moderation',
    'Client cannot un-remove a moderated log row'
);

-- Restore log status to visible for subsequent tests
RESET ROLE;
UPDATE public.logs SET status = 'visible' WHERE id = '77777777-7777-7777-7777-777777777777';

-- ------------------------------------------------------------------------------
-- GROUP 6: B1 Atomic Ban & Unban Procedures (Tests 13-17)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice (non-staff)
SELECT throws_ok(
    $$ SELECT public.admin_ban_user('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'global', 'Rogue ban') $$,
    '42501',
    NULL,
    'Authenticated non-staff cannot invoke public.admin_ban_user'
);

RESET ROLE;
-- Superuser test for role ceiling: Grace (moderator) cannot ban Eve (admin)
SELECT throws_ok(
    $$ SELECT private.ban_user_atomic('88888888-8888-8888-8888-888888888888', '55555555-5555-5555-5555-555555555555', 'global', 'Mod banning admin') $$,
    'P0001',
    'Access denied: Moderators cannot ban administrators',
    'Moderator cannot ban Administrator'
);

RESET ROLE;
-- Superuser test: Staff cannot ban own account
SELECT throws_ok(
    $$ SELECT private.ban_user_atomic('55555555-5555-5555-5555-555555555555', '55555555-5555-5555-5555-555555555555', 'global', 'Self ban') $$,
    'P0001',
    'Invalid operation: Staff cannot ban their own account',
    'Staff cannot ban their own account'
);

RESET ROLE;
-- Admin Eve atomically bans Bob
SELECT lives_ok(
    $$ SELECT private.ban_user_atomic('55555555-5555-5555-5555-555555555555', '22222222-2222-2222-2222-222222222222', 'global', 'Atomic ban test') $$,
    'Admin can execute atomic ban'
);

RESET ROLE;
-- Admin Eve atomically unbans Bob
SELECT lives_ok(
    $$ SELECT private.unban_user_atomic('55555555-5555-5555-5555-555555555555', '22222222-2222-2222-2222-222222222222', 'Atomic unban test') $$,
    'Admin can execute atomic unban'
);

-- ------------------------------------------------------------------------------
-- GROUP 7: B2 Moderation Actions Tamper-Resistance (Tests 18-22)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('11111111-1111-1111-1111-111111111111'); -- Alice
SELECT throws_ok(
    $$ INSERT INTO public.moderation_actions (actor_id, action, target_type, target_id, reason) VALUES ('11111111-1111-1111-1111-111111111111', 'ban', 'user', '22222222-2222-2222-2222-222222222222', 'Direct client insert') $$,
    '42501',
    NULL,
    'Authenticated user cannot directly insert into moderation_actions'
);

SELECT throws_ok(
    $$ UPDATE public.moderation_actions SET reason = 'tampered' WHERE true $$,
    '42501',
    NULL,
    'Authenticated user cannot update moderation_actions'
);

RESET ROLE; -- Now as postgres / superuser / service_role
SELECT throws_ok(
    $$ UPDATE public.moderation_actions SET reason = 'tampered' WHERE true $$,
    'P0001',
    'moderation_actions is append-only and tamper-resistant: UPDATE is strictly prohibited across all roles',
    'Superuser/Service role cannot update moderation_actions'
);

SELECT throws_ok(
    $$ DELETE FROM public.moderation_actions WHERE true $$,
    'P0001',
    'moderation_actions is append-only and tamper-resistant: DELETE is strictly prohibited across all roles',
    'Superuser/Service role cannot delete from moderation_actions'
);

SELECT throws_ok(
    $$ TRUNCATE TABLE public.moderation_actions $$,
    'P0001',
    'moderation_actions is append-only and tamper-resistant: TRUNCATE is strictly prohibited across all roles',
    'Superuser/Service role cannot truncate moderation_actions'
);

-- ------------------------------------------------------------------------------
-- GROUP 8: B3 Hardened Policy Verification (Tests 23-26)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT set_actor('88888888-8888-8888-8888-888888888888'); -- Grace (Moderator)
SELECT lives_ok(
    $$ SELECT * FROM public.staff_roles WHERE user_id = '88888888-8888-8888-8888-888888888888' $$,
    'Non-admin can read own staff role row'
);

SELECT is(
    count(*)::int, 0,
    'Non-admin cannot read other staff role rows'
) FROM public.staff_roles WHERE user_id = '55555555-5555-5555-5555-555555555555';

-- Mutual blocking profile visibility check
RESET ROLE;
INSERT INTO public.blocks (blocker_id, blocked_id) VALUES ('11111111-1111-1111-1111-111111111111', '88888888-8888-8888-8888-888888888888') ON CONFLICT DO NOTHING;

RESET ROLE;
SELECT set_actor('88888888-8888-8888-8888-888888888888'); -- Grace was blocked by Alice
SELECT is(
    count(*)::int, 0,
    'Blocked user cannot see blocker profile'
) FROM public.profiles WHERE id = '11111111-1111-1111-1111-111111111111';

SELECT is(
    count(*)::int, 0,
    'Blocked user cannot see likes on blocker logs'
) FROM public.log_likes WHERE log_id = '77777777-7777-7777-7777-777777777777';

-- Clean up block fixture
RESET ROLE;
DELETE FROM public.blocks WHERE blocker_id = '11111111-1111-1111-1111-111111111111' AND blocked_id = '88888888-8888-8888-8888-888888888888';

-- ------------------------------------------------------------------------------
-- GROUP 9: B4 Ban Checks on Every Write Path (Tests 27-47, 3 per path * 7 paths)
-- Actors:
--   Dave ('44444444-4444-4444-4444-444444444444'): Active global ban
--   Charlie ('33333333-3333-3333-3333-333333333333'): Expired global ban
--   Bob ('22222222-2222-2222-2222-222222222222'): Unbanned
-- ------------------------------------------------------------------------------

-- 1. LIBRARY ITEMS
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (Active ban)
SELECT throws_ok(
    $$ INSERT INTO public.library_items (user_id, show_id, status) VALUES ('44444444-4444-4444-4444-444444444444', 301, 'watching') $$,
    '42501', NULL, 'Active ban rejects library_items insert'
);

RESET ROLE;
SELECT set_actor('33333333-3333-3333-3333-333333333333'); -- Charlie (Expired ban)
SELECT lives_ok(
    $$ INSERT INTO public.library_items (user_id, show_id, status) VALUES ('33333333-3333-3333-3333-333333333333', 301, 'watching') $$,
    'Expired ban allows library_items insert'
);

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob (Unbanned)
SELECT lives_ok(
    $$ INSERT INTO public.library_items (user_id, show_id, status) VALUES ('22222222-2222-2222-2222-222222222222', 301, 'watching') $$,
    'Unbanned user allows library_items insert'
);

-- 2. SHOW PROGRESS
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (Active ban)
SELECT throws_ok(
    $$ INSERT INTO public.show_progress (user_id, show_id, season, episode) VALUES ('44444444-4444-4444-4444-444444444444', 301, 1, 1) $$,
    '42501', NULL, 'Active ban rejects show_progress insert'
);

RESET ROLE;
SELECT set_actor('33333333-3333-3333-3333-333333333333'); -- Charlie (Expired ban)
SELECT lives_ok(
    $$ INSERT INTO public.show_progress (user_id, show_id, season, episode) VALUES ('33333333-3333-3333-3333-333333333333', 301, 1, 1) $$,
    'Expired ban allows show_progress insert'
);

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob (Unbanned)
SELECT lives_ok(
    $$ INSERT INTO public.show_progress (user_id, show_id, season, episode) VALUES ('22222222-2222-2222-2222-222222222222', 301, 1, 1) $$,
    'Unbanned user allows show_progress insert'
);

-- 3. PRIVATE NOTES
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (Active ban)
SELECT throws_ok(
    $$ INSERT INTO public.private_notes (user_id, show_id, body) VALUES ('44444444-4444-4444-4444-444444444444', 301, 'Confidential') $$,
    '42501', NULL, 'Active ban rejects private_notes insert'
);

RESET ROLE;
SELECT set_actor('33333333-3333-3333-3333-333333333333'); -- Charlie (Expired ban)
SELECT lives_ok(
    $$ INSERT INTO public.private_notes (user_id, show_id, body) VALUES ('33333333-3333-3333-3333-333333333333', 301, 'Confidential') $$,
    'Expired ban allows private_notes insert'
);

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob (Unbanned)
SELECT lives_ok(
    $$ INSERT INTO public.private_notes (user_id, show_id, body) VALUES ('22222222-2222-2222-2222-222222222222', 301, 'Confidential') $$,
    'Unbanned user allows private_notes insert'
);

-- 4. LOGS
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (Active ban)
SELECT throws_ok(
    $$ INSERT INTO public.logs (user_id, show_id, show_name, review_text) VALUES ('44444444-4444-4444-4444-444444444444', 301, 'Show 301', 'Banned review') $$,
    '42501', NULL, 'Active ban rejects logs insert'
);

RESET ROLE;
SELECT set_actor('33333333-3333-3333-3333-333333333333'); -- Charlie (Expired ban)
SELECT lives_ok(
    $$ INSERT INTO public.logs (user_id, show_id, show_name, review_text) VALUES ('33333333-3333-3333-3333-333333333333', 301, 'Show 301', 'Pardoned review') $$,
    'Expired ban allows logs insert'
);

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob (Unbanned)
SELECT lives_ok(
    $$ INSERT INTO public.logs (user_id, show_id, show_name, review_text) VALUES ('22222222-2222-2222-2222-222222222222', 301, 'Show 301', 'Clean review') $$,
    'Unbanned user allows logs insert'
);

-- 5. LOG LIKES (Target: Alice\'s log 77777777-7777-7777-7777-777777777777)
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (Active ban)
SELECT throws_ok(
    $$ INSERT INTO public.log_likes (user_id, log_id) VALUES ('44444444-4444-4444-4444-444444444444', '77777777-7777-7777-7777-777777777777') $$,
    '42501', NULL, 'Active ban rejects log_likes insert'
);

RESET ROLE;
SELECT set_actor('33333333-3333-3333-3333-333333333333'); -- Charlie (Expired ban)
SELECT lives_ok(
    $$ INSERT INTO public.log_likes (user_id, log_id) VALUES ('33333333-3333-3333-3333-333333333333', '77777777-7777-7777-7777-777777777777') $$,
    'Expired ban allows log_likes insert'
);

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob (Unbanned)
SELECT lives_ok(
    $$ INSERT INTO public.log_likes (user_id, log_id) VALUES ('22222222-2222-2222-2222-222222222222', '77777777-7777-7777-7777-777777777777') $$,
    'Unbanned user allows log_likes insert'
);

-- 6. FOLLOWS (Target: Alice)
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (Active ban)
SELECT throws_ok(
    $$ INSERT INTO public.follows (follower_id, followee_id) VALUES ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111') $$,
    '42501', NULL, 'Active ban rejects follows insert'
);

RESET ROLE;
SELECT set_actor('33333333-3333-3333-3333-333333333333'); -- Charlie (Expired ban)
SELECT lives_ok(
    $$ INSERT INTO public.follows (follower_id, followee_id) VALUES ('33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111') $$,
    'Expired ban allows follows insert'
);

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob (Unbanned)
SELECT lives_ok(
    $$ INSERT INTO public.follows (follower_id, followee_id) VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111') $$,
    'Unbanned user allows follows insert'
);

-- 7. BLOCKS (Target: Frank)
RESET ROLE;
SELECT set_actor('44444444-4444-4444-4444-444444444444'); -- Dave (Active ban)
SELECT throws_ok(
    $$ INSERT INTO public.blocks (blocker_id, blocked_id) VALUES ('44444444-4444-4444-4444-444444444444', '66666666-6666-6666-6666-666666666666') $$,
    '42501', NULL, 'Active ban rejects blocks insert'
);

RESET ROLE;
SELECT set_actor('33333333-3333-3333-3333-333333333333'); -- Charlie (Expired ban)
SELECT lives_ok(
    $$ INSERT INTO public.blocks (blocker_id, blocked_id) VALUES ('33333333-3333-3333-3333-333333333333', '66666666-6666-6666-6666-666666666666') $$,
    'Expired ban allows blocks insert'
);

RESET ROLE;
SELECT set_actor('22222222-2222-2222-2222-222222222222'); -- Bob (Unbanned)
SELECT lives_ok(
    $$ INSERT INTO public.blocks (blocker_id, blocked_id) VALUES ('22222222-2222-2222-2222-222222222222', '66666666-6666-6666-6666-666666666666') $$,
    'Unbanned user allows blocks insert'
);

-- ------------------------------------------------------------------------------
-- GROUP 10: CHECK Constraints (Tests 48-50, throws_ok)
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT throws_ok(
    $$ UPDATE public.profiles SET username = 'admin' WHERE id = '11111111-1111-1111-1111-111111111111' $$,
    '23514', NULL, 'CHECK constraint rejects reserved username admin'
);

SELECT throws_ok(
    $$ UPDATE public.profiles SET username = 'aa' WHERE id = '11111111-1111-1111-1111-111111111111' $$,
    '23514', NULL, 'CHECK constraint rejects short username < 3 chars'
);

SELECT throws_ok(
    $$ INSERT INTO public.logs (user_id, show_id, show_name, rating) VALUES ('11111111-1111-1111-1111-111111111111', 500, 'Test', 3.7) $$,
    '23514', NULL, 'CHECK constraint rejects non-0.5 step rating'
);

-- ------------------------------------------------------------------------------
-- GROUP 11: Complete RLS Activation Across Public Tables (Test 51, is())
-- ------------------------------------------------------------------------------
RESET ROLE;
SELECT is(
    count(*)::int, 12,
    'All 12 public tables have active Row Level Security'
) FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity = true;

-- 4. Finish pgTAP Execution
RESET ROLE;
SELECT * FROM finish();

ROLLBACK;