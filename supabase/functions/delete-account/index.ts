// Edge Function: delete-account
// Stores-compliant account deletion: removes user and cascades/anonymizes user data.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req: Request) => {
  const reqId = crypto.randomUUID();

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed", reqId }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const authHeader = req.headers.get("Authorization");
  if (!authHeader) {
    return new Response(JSON.stringify({ error: "Unauthorized", reqId }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

    // 1. Authenticate caller using their JWT
    const clientUser = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: { user }, error: userError } = await clientUser.auth.getUser();
    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Invalid session", reqId }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const userId = user.id;

    // 2. Perform deletion using Admin Client
    const adminClient = createClient(supabaseUrl, supabaseServiceKey);

    // Anonymize profile first (clear PII: bio, avatar, display name, username)
    await adminClient
      .from("profiles")
      .update({
        username: `deleted_${userId.substring(0, 8)}`,
        display_name: "Deleted User",
        avatar_url: null,
        bio: null,
      })
      .eq("id", userId);

    // Delete user from auth.users (cascades or cleans up auth sessions)
    const { error: deleteError } = await adminClient.auth.admin.deleteUser(userId);
    if (deleteError) {
      console.error(`[${reqId}] Failed to delete auth user:`, deleteError.message);
      return new Response(JSON.stringify({ error: "Account deletion failed", reqId }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    console.info(`[${reqId}] Successfully processed account deletion for user: ${userId}`);

    return new Response(
      JSON.stringify({ success: true, message: "Account deleted successfully", reqId }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err: unknown) {
    console.error(`[${reqId}] Exception in delete-account:`, err instanceof Error ? err.message : String(err));
    return new Response(
      JSON.stringify({ error: "Internal server error", reqId }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
