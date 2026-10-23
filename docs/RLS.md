# Row Level Security (RLS) Policy Matrix (Phase 1: Foundation - Refined)

Row Level Security is enabled on **every** table. Zero tables exist without active policies.

---

## Policy Matrix by Table and Persona

| Table | Operation | Anonymous | Normal User (Alice) | Other User (Bob) | Blocked User (Charlie) | Banned User (Dave) | Admin (Eve) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`profiles`** | `SELECT` | ? Unblocked | ? Read own | ? Read unblocked | ? Denied if blocked | ? Read unblocked | ? Read all |
| | `UPDATE` | ? Denied | ? Update own | ? Denied on Alice | ? Denied | ? Denied on write | ? Read/update |
| | `INSERT` | ? Denied | ?? Trigger only | ?? Trigger only | ?? Trigger only | ?? Trigger only | ?? Trigger only |
| | `DELETE` | ? Denied | ? Denied | ? Denied | ? Denied | ? Denied | ?? Edge Fn / Admin |
| **`user_flags`** | `SELECT` | ? Denied | ? Read own only | ? Denied on Alice | ? Denied | ? Denied on others | ? Read all |
| | `WRITES` | ? Denied | ? Denied (Revoked) | ? Denied (Revoked) | ? Denied | ? Denied | ?? Service role |
| **`bans`** | `ALL` | ? Denied | ? Denied | ? Denied | ? Denied | ? Denied | ? Admin only |
| **`staff_roles`** | `SELECT` | ? Denied | ? Read own role | ? Read own role | ? Denied on others | ? Denied on others | ? Read all roles |
| | `ALL` | ? Denied | ? Denied | ? Denied | ? Denied | ? Denied | ? Admin only |
| **`follows`** | `SELECT` | ? Denied | ? Read own | ? Read own | ? Denied if mutual | ? Denied on others | ? Read all |
| | `INSERT` | ? Denied | ? Follow unblocked | ? Follow unblocked | ? Denied if blocked | ? Denied (is_banned) | ? Full |
| | `DELETE` | ? Denied | ? Unfollow own | ? Unfollow own | ? Denied on others | ? Denied on others | ? Full |
| **`blocks`** | `SELECT` | ? Denied | ? Read own blocks | ? Read own blocks | ? Denied on others | ? Denied on others | ? Read all |
| | `INSERT` | ? Denied | ? Block user | ? Block user | ? Denied on others | ? Denied (is_banned) | ? Full |
| | `DELETE` | ? Denied | ? Unblock user | ? Unblock user | ? Denied on others | ? Denied on others | ? Full |
| **`library_items`** | `SELECT` | ? Denied | ? Read own (incl. soft-del) | ? Denied on Alice | ? Denied on Alice | ? Denied on Alice | ? Read own |
| | `INSERT` | ? Denied | ? Insert own | ? Insert own | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `UPDATE` | ? Denied | ? Update own | ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| **`show_progress`** | `SELECT` | ? Denied | ? Read own (incl. soft-del) | ? Denied on Alice | ? Denied on Alice | ? Denied on Alice | ? Read own |
| | `INSERT` | ? Denied | ? Insert own | ? Insert own | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `UPDATE` | ? Denied | ? Update own | ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| **`private_notes`** | `SELECT` | ? Denied | ? Read own (incl. soft-del) | ? Denied on Alice | ? Denied on Alice | ? Denied on Alice | ? Read own |
| | `INSERT` | ? Denied | ? Insert own | ? Insert own | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `UPDATE` | ? Denied | ? Update own | ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| **`logs`** | `SELECT` | ? Visible non-deleted | ? Read own (incl. soft-del) + visible unblocked | ? Read own + visible unblocked | ? Denied on Alice logs | ? Read own + visible | ? Read all logs |
| | `INSERT` | ? Denied | ? Insert own (visible) | ? Insert own (visible) | ? Denied on Alice | ? Denied (is_banned) | ? Insert own |
| | `UPDATE` | ? Denied | ? Update own (soft-del) | ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Update / mod |
| | `DELETE` | ? Denied | ? Denied (Soft-del) | ? Denied | ? Denied | ? Denied | ? Admin purge |
| **`log_likes`** | `SELECT` | ? Unblocked visible | ? Read unblocked | ? Read unblocked | ? Denied on Alice logs | ? Read unblocked | ? Read all |
| | `INSERT` | ? Denied | ? Like unblocked visible | ? Like unblocked visible | ? Denied on Alice logs | ? Denied (is_banned) | ? Like |
| | `DELETE` | ? Denied | ? Unlike own like | ? Unlike own like | ? Denied on others | ? Denied on others | ? Unlike |

---

## Security Invariants
1. **Zero-Trust Anon Baseline**: All public table privileges are explicitly revoked from `anon`. Selective `GRANT SELECT` is granted only to `profiles`, `logs` (visible non-deleted), and `log_likes`.
2. **Column Protection via Table Splitting**: `trust_level` is stored in `public.user_flags` (owner read-only, write revoked from all clients). `is_banned` is derived via `is_banned()` checking the dedicated `bans` table.
3. **Stale Overwrite Protection**: `protect_stale_upsert()` trigger rejects incoming writes where `client_updated_at < OLD.client_updated_at` and clamps client future clocks.
4. **Server-Maintained Counters**: `like_count` cannot be modified by clients. An atomic trigger on `log_likes` manages the count with a floor at 0.
