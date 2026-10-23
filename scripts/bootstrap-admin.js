#!/usr/bin/env node
/**
 * One-Time Staff & Admin Bootstrap CLI Tool
 * Capabilities:
 *   1. Create first administrator or moderator
 *   2. Reset staff member MFA factors (in case of lost authenticator)
 *   3. List current staff accounts
 *
 * Usage:
 *   node scripts/bootstrap-admin.js create --email admin@example.com --password StrongPassword123! --role admin
 *   node scripts/bootstrap-admin.js reset-mfa --email admin@example.com
 *   node scripts/bootstrap-admin.js list
 */

const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

// Load environment from .env if present
const envPath = path.resolve(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
      const idx = trimmed.indexOf('=');
      const key = trimmed.substring(0, idx).trim();
      const val = trimmed.substring(idx + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    }
  }
}

const supabaseUrl = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !serviceKey) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables required.');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, serviceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const args = process.argv.slice(2);
const command = args[0];

function getArg(flag) {
  const idx = args.indexOf(flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
}

async function main() {
  if (command === 'create') {
    const email = getArg('--email');
    const password = getArg('--password');
    const role = getArg('--role') || 'admin';

    if (!email || !password) {
      console.error('Usage: create --email <email> --password <password> [--role admin|moderator]');
      process.exit(1);
    }

    console.log(`Creating staff account for: ${email} (Role: ${role})...`);

    // 1. Create Auth User
    const { data: userData, error: userError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: 'Platform Staff' },
    });

    if (userError) {
      console.error('Failed to create auth user:', userError.message);
      process.exit(1);
    }

    const userId = userData.user.id;

    // 2. Insert into public.staff_roles
    const { error: staffError } = await supabase
      .from('staff_roles')
      .upsert({ user_id: userId, role });

    if (staffError) {
      console.error('Failed to assign staff role:', staffError.message);
      process.exit(1);
    }

    // 3. Write to moderation_actions
    await supabase.from('moderation_actions').insert({
      actor_id: userId,
      action: 'bootstrap_admin',
      target_type: 'user',
      target_id: userId,
      reason: 'Initial platform administrator setup via CLI',
      metadata: { role },
    });

    console.log(`SUCCESS: Staff member ${email} created with ID: ${userId} and role: ${role}`);
    console.log('User must now log into the admin dashboard and enroll TOTP MFA.');

  } else if (command === 'reset-mfa') {
    const email = getArg('--email');
    const userIdArg = getArg('--user-id');

    let userId = userIdArg;
    if (!userId && email) {
      const { data: users, error: listError } = await supabase.auth.admin.listUsers();
      if (listError) {
        console.error('Error fetching users:', listError.message);
        process.exit(1);
      }
      const match = users.users.find((u) => u.email === email);
      if (!match) {
        console.error(`No user found with email: ${email}`);
        process.exit(1);
      }
      userId = match.id;
    }

    if (!userId) {
      console.error('Usage: reset-mfa --email <email> OR --user-id <uuid>');
      process.exit(1);
    }

    console.log(`Resetting MFA factors for user ID: ${userId}...`);

    // List factors
    const { data: factors, error: factorsError } = await supabase.auth.admin.mfa.listFactors({ userId });
    if (factorsError) {
      console.error('Error listing MFA factors:', factorsError.message);
      process.exit(1);
    }

    const allFactors = factors?.factors || [];
    console.log(`Found ${allFactors.length} enrolled factor(s).`);

    for (const factor of allFactors) {
      const { error: deleteError } = await supabase.auth.admin.mfa.deleteFactor({
        userId,
        id: factor.id,
      });
      if (deleteError) {
        console.error(`Failed to delete factor ${factor.id}:`, deleteError.message);
      } else {
        console.log(`Deleted factor: ${factor.id} (${factor.friendly_name || factor.factor_type})`);
      }
    }

    // Audit write
    await supabase.from('moderation_actions').insert({
      action: 'mfa_reset_cli',
      target_type: 'user',
      target_id: userId,
      reason: 'Staff MFA reset via CLI',
      metadata: { deleted_factor_count: allFactors.length },
    });

    console.log(`SUCCESS: MFA factors reset for ${userId}. User can now re-enroll upon login.`);

  } else if (command === 'list') {
    const { data: staff, error } = await supabase
      .from('staff_roles')
      .select('*, profiles(username, display_name)');

    if (error) {
      console.error('Error querying staff directory:', error.message);
      process.exit(1);
    }

    console.log('=== Active Platform Staff Directory ===');
    console.table(staff.map((s) => ({
      userId: s.user_id,
      role: s.role,
      username: s.profiles?.username || 'unregistered',
      scope: s.community_id || 'global',
      created: s.created_at,
    })));

  } else {
    console.log('Staff Bootstrap CLI Tool');
    console.log('Commands:');
    console.log('  create     --email <email> --password <pwd> --role <admin|moderator>');
    console.log('  reset-mfa  --email <email> | --user-id <uuid>');
    console.log('  list');
  }
}

main().catch(console.error);
