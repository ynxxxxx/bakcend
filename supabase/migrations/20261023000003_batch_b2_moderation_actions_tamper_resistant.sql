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
