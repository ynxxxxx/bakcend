# TV Tracking Social Platform - Backend Engine

A secure, scalable backend and moderation pipeline for a TV tracking and social community platform.

## Architecture Highlights
- **Core Engine**: Supabase (PostgreSQL 15+, GoTrue Auth, Realtime, PostgREST, Storage, Edge Runtime)
- **Moderation Engine**: Python (FastAPI) + Redis on internal network for multi-language moderation (English, French, Arabic, Algerian Darija, Arabizi).
- **Reverse Proxy**: Caddy behind Cloudflare.
- **Admin & Observability**: Appsmith, Metabase (read-only role), Uptime Kuma.
- **Deployment**: Single Ubuntu 24.04 VPS (32 GB RAM, 8 vCPU) via Docker Compose.
- **Strict Portability**: 100% compatible with Supabase Cloud for future scale-out.

## Repository Structure
`
+-- .github/workflows/   # CI/CD pipelines (migrations & RLS tests in Linux containers)
+-- docs/                # Architecture decisions, API reference, deployment guides
+-- infra/               # Docker Compose stack, Caddyfile, environment configurations
+-- scripts/             # Health checks, VPS security hardening, database maintenance
+-- supabase/
¦   +-- functions/       # Deno/TypeScript Edge Functions (tmdb-proxy, moderation, auth)
¦   +-- migrations/      # Versioned idempotent SQL migrations & RLS policies
¦   +-- tests/           # Automated SQL RLS test suites
+-- worker/              # FastAPI background moderation service + Redis queue
`

## Security Guarantees
- Row Level Security (RLS) enabled on every public table.
- UUID primary keys throughout; zero sequential IDs.
- Client never sees the service role key.
- Soft-delete pattern with immutable moderation audit trails.
- Zero-trust input validation with CHECK constraints and Zod schemas.
