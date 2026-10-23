// Edge Function: check-username
// Validates username format, reserved terms, and uniqueness in public.profiles.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.0";

const RESERVED_USERNAMES = new Set([
  "admin", "administrator", "root", "moderator", "mod", "serializd",
  "ullista", "system", "support", "help", "security", "official",
  "anonymous", "null", "undefined", "deleted_user", "api", "auth",
  "staff", "owner", "terms", "privacy", "about", "contact"
]);

const USERNAME_REGEX = /^[a-z0-9_]{3,20}$/;

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

  try {
    const body = await req.json().catch(() => ({}));
    const rawUsername = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";

    if (!rawUsername) {
      return new Response(
        JSON.stringify({ available: false, error: "Username is required", reqId }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 1. Format validation
    if (!USERNAME_REGEX.test(rawUsername)) {
      return new Response(
        JSON.stringify({
          available: false,
          error: "Username must be 3-20 lowercase alphanumeric characters or underscores",
          reqId,
        }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 2. Reserved words validation
    if (RESERVED_USERNAMES.has(rawUsername)) {
      return new Response(
        JSON.stringify({ available: false, error: "This username is reserved", reqId }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 3. Database uniqueness check
    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    const { data, error } = await supabase
      .from("profiles")
      .select("id")
      .ilike("username", rawUsername)
      .maybeSingle();

    if (error) {
      console.error(`[${reqId}] DB query error:`, error.message);
      return new Response(
        JSON.stringify({ error: "Unable to verify username", reqId }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const isAvailable = data === null;

    return new Response(
      JSON.stringify({ available: isAvailable, reqId }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err: unknown) {
    console.error(`[${reqId}] Unexpected exception:`, err instanceof Error ? err.message : String(err));
    return new Response(
      JSON.stringify({ error: "Internal server error", reqId }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
