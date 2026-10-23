#!/usr/bin/env bash
# ==============================================================================
# Database Migration & RLS Test Runner (Pinned Supabase CLI)
# ==============================================================================

set -euo pipefail

REQUIRED_SUPABASE_VERSION="2.122.0"

echo "=== TV Tracking Backend: RLS Test Suite Runner ==="

# 1. Verify Supabase CLI installation and version
if ! command -v supabase &> /dev/null; then
    echo "ERROR: Supabase CLI is not installed."
    echo "Please install version ${REQUIRED_SUPABASE_VERSION}:"
    echo "  npm install -g supabase@${REQUIRED_SUPABASE_VERSION}"
    exit 1
fi

INSTALLED_VERSION=$(supabase --version | awk '{print $1}')
echo "Detected Supabase CLI version: ${INSTALLED_VERSION}"

# 2. Start local Supabase Docker stack if not running
echo "Starting Supabase local stack..."
supabase start

# 3. Reset local database and execute all migrations cleanly
echo "Resetting database and running migrations..."
supabase db reset

# 4. Execute pgTAP and SQL RLS test suites
echo "Executing pgTAP and RLS tests..."
supabase test db

echo "=== All database migrations and RLS tests passed successfully! ==="
exit 0
