# Database Schema Reference (Phase 1: Foundation - Refined)

All tables use `UUID` primary keys (`gen_random_uuid()`), foreign keys with cascade constraints, server-maintained `updated_at` timestamps, and client sync markers (`client_updated_at`, `deleted_at`).

---

## 1. `public.profiles`
Public-facing user identity. Excludes sensitive account flags.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, `REFERENCES auth.users(id) ON DELETE CASCADE` | Matches Supabase Auth user ID |
| `username` | `CITEXT` | `UNIQUE`, regex `^[a-z0-9_]{3,20}$` | Case-insensitive handle |
| `display_name`| `TEXT` | Max length 50 | Public display name |
| `avatar_url` | `TEXT` | Nullable | Avatar image URL |
| `bio` | `TEXT` | Max length 300 | Profile bio |
| `onboarded` | `BOOLEAN`| `NOT NULL`, default `false` | True after user selects username |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Account creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Auto-updated via trigger |

---

## 2. `public.user_flags`
Sensitive user account status. Separated from `profiles` to eliminate column-leak vectors.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `user_id` | `UUID` | `PK`, `REFERENCES profiles(id) ON DELETE CASCADE` | Associated user |
| `trust_level`| `INT` | `NOT NULL`, default `0`, check `>= 0` | Trust tier |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Created timestamp |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Auto-updated via trigger |

*Security*: Authenticated users have `SELECT` on their own row only. Write privileges are completely revoked from clients.

---

## 3. `public.bans`
Active and historical account bans.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, default `gen_random_uuid()` | Ban record ID |
| `user_id` | `UUID` | `REFERENCES profiles(id) ON DELETE CASCADE` | Banned user |
| `scope` | `ban_scope` | Enum (`global`, `community`) | Scope of ban |
| `community_id` | `UUID` | Nullable | Scoped community ID |
| `reason` | `TEXT` | Nullable | Ban rationale |
| `banned_by` | `UUID` | Nullable | Staff actor |
| `expires_at` | `TIMESTAMPTZ` | Nullable | Expiry (null = permanent) |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Ban issued date |

*Helper*: `is_banned(target_user_id)` checks for active bans where `expires_at IS NULL OR expires_at > NOW()`.

---

## 4. `public.follows` & `public.blocks`
Directional social graphs with strict self-reference prevention (`CHECK (user_a != user_b)`).

- **`blocks`**: `blocker_id` (PK), `blocked_id` (PK), `created_at`.
- **`get_my_blocked_users()`**: `SECURITY DEFINER` function with fixed search_path allowing the blocker to list blocked usernames/avatars for unblocking without violating the mutual block barrier.

---

## 5. `public.library_items`, `public.show_progress`, `public.private_notes`
User shelf tracking, progress, and private show notes with offline-first synchronization columns.

| Sync Column | Type | Purpose |
| :--- | :--- | :--- |
| `client_updated_at` | `TIMESTAMPTZ` | Client timestamp; stale updates (`client_updated_at < OLD.client_updated_at`) are rejected. Clamped to `NOW() + 5 min`. |
| `deleted_at` | `TIMESTAMPTZ` | Soft delete tombstone. Visible to owner for sync; purged after 30 days via `purge_soft_deleted_tombstones()`. |
| `updated_at` | `TIMESTAMPTZ` | Server-authoritative timestamp for cursor sync: `(updated_at, id)`. |

---

## 6. `public.logs` & `public.log_likes`
User diary entries and reviews.

| Column | Type | Details |
| :--- | :--- | :--- |
| `like_count` | `INT` | Maintained exclusively by `update_log_like_count` trigger on `log_likes`. Client edits blocked by `guard_log_like_count`. Check `>= 0`. |
| `client_updated_at` | `TIMESTAMPTZ` | Client timestamp protected by stale-write guard. |
| `deleted_at` | `TIMESTAMPTZ` | Soft-delete tombstone. |
| `status` | `log_status` | Enum (`visible`, `hidden`, `removed`). Inserts forced to `visible`; non-moderators cannot set `removed`. |
