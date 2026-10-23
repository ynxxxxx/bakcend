# Database Schema Reference (Phase 1: Foundation)

All tables use `UUID` primary keys (`gen_random_uuid()`), enforce explicit foreign keys with cascade rules, and maintain `created_at` and `updated_at` timestamps.

---

## 1. `public.profiles`
User identity and social profile. Created automatically via `handle_new_user` trigger on `auth.users` insert.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, `REFERENCES auth.users(id) ON DELETE CASCADE` | Matches Supabase Auth user ID |
| `username` | `CITEXT` | `UNIQUE`, regex `^[a-z0-9_]{3,20}$` | Case-insensitive unique handle |
| `display_name`| `TEXT` | Max length 50 | Public display name |
| `avatar_url` | `TEXT` | Nullable | Avatar image URL |
| `bio` | `TEXT` | Max length 300 | Profile bio |
| `onboarded` | `BOOLEAN`| `NOT NULL`, default `false` | True after user selects username |
| `trust_level`| `INT` | `NOT NULL`, default `0` | Automated moderation trust tier |
| `is_banned` | `BOOLEAN`| `NOT NULL`, default `false` | Global ban status flag |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Account creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Auto-updated via trigger |

**Integrity Guard**: `protect_profile_security_fields` trigger prevents non-admin users from altering `trust_level` or `is_banned`.

---

## 2. `public.staff_roles`
RBAC table for platform administrators and scoped community moderators.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, default `gen_random_uuid()` | Role grant ID |
| `user_id` | `UUID` | `REFERENCES profiles(id) ON DELETE CASCADE` | Assigned user |
| `role` | `staff_role_type` | Enum (`admin`, `moderator`) | Role type |
| `community_id` | `UUID` | Nullable | Community scope (null = global) |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Grant timestamp |

---

## 3. `public.follows` & `public.blocks`
Directional social graphs with strict self-reference prevention (`CHECK (user_a != user_b)`).

- **`follows`**: `follower_id` (PK), `followee_id` (PK), `created_at`.
- **`blocks`**: `blocker_id` (PK), `blocked_id` (PK), `created_at`.

---

## 4. `public.library_items`
User shelf tracking for TV shows.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, default `gen_random_uuid()` | Library record ID |
| `user_id` | `UUID` | `REFERENCES profiles(id) ON DELETE CASCADE` | Record owner |
| `show_id` | `INT` | `NOT NULL` | TMDb TV Show ID |
| `status` | `tracking_status` | Enum (`watching`, `watchlist`, `completed`, `paused`, `dropped`) | Shelf category |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Creation date |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Auto-updated via trigger |

*Unique constraint*: `(user_id, show_id)`.

---

## 5. `public.show_progress`
Episode-level progress tracking.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, default `gen_random_uuid()` | Progress record ID |
| `user_id` | `UUID` | `REFERENCES profiles(id) ON DELETE CASCADE` | Record owner |
| `show_id` | `INT` | `NOT NULL` | TMDb TV Show ID |
| `season` | `INT` | `NOT NULL`, check `>= 0` | Watched season number |
| `episode` | `INT` | `NOT NULL`, check `>= 0` | Watched episode number |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Timestamp for offline sync LWW |

*Unique constraint*: `(user_id, show_id)`.

---

## 6. `public.logs`
User diary entries, episode logs, and public/private reviews.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, default `gen_random_uuid()` | Log ID |
| `user_id` | `UUID` | `REFERENCES profiles(id) ON DELETE CASCADE` | Author |
| `show_id` | `INT` | `NOT NULL` | TMDb Show ID |
| `show_name` | `TEXT` | `NOT NULL` | Name of the series |
| `show_poster_path` | `TEXT` | Nullable | TMDb poster asset path |
| `season_number` | `INT` | Nullable, `>= 0` | Logged season |
| `episode_number` | `INT` | Nullable, `>= 0` | Logged episode |
| `rating` | `NUMERIC(2,1)` | Check: 0.5 to 5.0 in 0.5 steps | Star rating |
| `review_text` | `TEXT` | Max length 5000 chars | User review text |
| `contains_spoilers` | `BOOLEAN` | `NOT NULL`, default `false` | Spoiler warning tag |
| `is_rewatch` | `BOOLEAN` | `NOT NULL`, default `false` | Rewatch indicator |
| `liked` | `BOOLEAN` | `NOT NULL`, default `false` | Quick like flag |
| `watched_date` | `DATE` | `NOT NULL`, default `CURRENT_DATE` | Date watched |
| `tags` | `TEXT[]` | Default `'{}'` | Custom log tags |
| `status` | `log_status` | Enum (`visible`, `hidden`, `removed`) | Moderation status |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Log creation date |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Auto-updated via trigger |

**Integrity Guard**: `protect_log_integrity` trigger forces new user logs to `visible` (disallows user-forged `removed` states) and disallows non-moderators from altering moderation status.

---

## 7. `public.log_likes`
Likes on diary reviews.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, default `gen_random_uuid()` | Like ID |
| `user_id` | `UUID` | `REFERENCES profiles(id) ON DELETE CASCADE` | User liking |
| `log_id` | `UUID` | `REFERENCES logs(id) ON DELETE CASCADE` | Target log |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Creation date |

*Unique constraint*: `(user_id, log_id)`.

---

## 8. `public.private_notes`
Owner-only notes for shows (personal thoughts, private timestamps).

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | `PK`, default `gen_random_uuid()` | Note ID |
| `user_id` | `UUID` | `REFERENCES profiles(id) ON DELETE CASCADE` | Note owner |
| `show_id` | `INT` | `NOT NULL` | TMDb Show ID |
| `body` | `TEXT` | Max length 10000 chars | Private note content |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Creation date |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL`, default `NOW()` | Auto-updated via trigger |

*Unique constraint*: `(user_id, show_id)`.
