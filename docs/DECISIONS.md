# Architectural Decision Records (ADR)

## ADR 001: Self-Hosted Supabase Docker Stack with Managed Supabase Portability

### Context
The application is a TV-tracking social platform with per-show community group chats. The specification assumes managed Supabase, but the production deployment targets a single dedicated Hostinger VPS (Ubuntu 24.04, 32 GB RAM, 8 vCPU) hosting the database, auth, realtime, storage, moderation worker, reverse proxy, and monitoring.

### Decision
1. **Self-Hosted Stack for VPS**: Deploy the official Supabase Docker Compose stack (PostgreSQL 15+, GoTrue/Supabase Auth, Realtime, Storage API, Edge Runtime, PostgREST) orchestrated via Docker Compose behind a Caddy reverse proxy.
2. **Strict Portability Guarantee**:
   - All database schemas, Row Level Security (RLS) policies, triggers, and functions are written strictly using standard PostgreSQL and Supabase extensions (uuid-ossp, pgcrypto, citext).
   - No engine-specific proprietary hooks are introduced that would fail on managed Supabase.
   - Migrations are versioned with standard Supabase CLI conventions in /supabase/migrations.
   - Edge Functions are standard Deno/TypeScript adhering to Supabase Edge Runtime contracts.
   - Storage buckets and policies conform to Supabase Storage API specs.
   - Any future migration to Supabase Cloud or an enterprise managed instance requires only executing supabase db push against the remote project URL with zero schema modifications.

### Consequences
- **Positive**: Low operational cost running on existing VPS; predictable resource allocation; complete local and CI testability; zero vendor lock-in; trivial migration path to Supabase Cloud if scale warrants.
- **Negative**: Self-hosted operations require manual maintenance of backups, SSL renewal (automated via Caddy), and security patches (addressed via hardening scripts and unattended-upgrades).

---

## ADR 002: Moderation Layer Architecture & Tiered Execution

### Context
High-traffic show chats may receive spam, toxic messages, or prohibited content in English, French, Standard Arabic, Algerian Darija, and Arabizi.

### Decision
Implement a decoupled, tiered moderation pipeline:
- **Layer 1 (Fast Filters)**: In-process regex patterns, multilingual blocked-term matcher, invitation/spam checks, duplicate/flood detection backed by Redis on a private docker network.
- **Layer 2 (ML Analysis - Phase 4)**: Asynchronous queue-based multilingual toxicity scoring running in a dedicated Python (FastAPI) worker container.
- **Status Gating**:
  - Unverified/low-trust (	rust_level = 0) messages and messages containing external links are marked held on insert and only promoted to isible upon worker approval.
  - Trusted users have messages inserted as isible and checked asynchronously; violating content flips to emoved.

### Consequences
- Minimal latency for chat clients while maintaining strict safety compliance for app store guidelines.
