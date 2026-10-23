# Row Level Security (RLS) Policy Matrix (Phase 1)

Row Level Security is enabled on **every** table. Zero tables exist without active policies.

---

## Policy Matrix by Table and Persona

| Table | Operation | Anonymous | Normal User (Alice) | Other User (Bob) | Blocked User (Charlie) | Banned User (Dave) | Admin (Eve) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`profiles`** | `SELECT` | ? Denied | ? Read own | ? Read unblocked | ? Denied if blocked | ? Read unblocked | ? Read all |
| | `UPDATE` | ? Denied | ? Update own profile | ? Denied on Alice | ? Denied | ? Denied on write | ? Read/update |
| | `INSERT` | ? Denied | ?? Trigger only | ?? Trigger only | ?? Trigger only | ?? Trigger only | ?? Trigger only |
| | `DELETE` | ? Denied | ? Denied (Edge Fn) | ? Denied | ? Denied | ? Denied | ?? Edge Fn / Service |
| **`staff_roles`** | `SELECT` | ? Denied | ? Read own role | ? Read own role | ? Denied on others | ? Denied on others | ? Read all roles |
| | `ALL` | ? Denied | ? Denied | ? Denied | ? Denied | ? Denied | ? Full control |
| **`follows`** | `SELECT` | ? Denied | ? Read own | ? Read own | ? Denied if mutual | ? Denied on others | ? Read all |
| | `INSERT` | ? Denied | ? Follow unblocked | ? Follow unblocked | ? Denied if blocked | ? Denied (is_banned) | ? Full |
| | `DELETE` | ? Denied | ? Unfollow own | ? Unfollow own | ? Denied on others | ? Denied on others | ? Full |
| **`blocks`** | `SELECT` | ? Denied | ? Read own blocks | ? Read own blocks | ? Denied on others | ? Denied on others | ? Read all |
| | `INSERT` | ? Denied | ? Block another user | ? Block another user | ? Denied on others | ? Denied (is_banned) | ? Full |
| | `DELETE` | ? Denied | ? Unblock own block | ? Unblock own block | ? Denied on others | ? Denied on others | ? Full |
| **`library_items`** | `SELECT` | ? Denied | ? Read own library | ? Denied on Alice | ? Denied on Alice | ? Denied on Alice | ? Read own |
| | `INSERT` | ? Denied | ? Insert own items | ? Insert own items | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `UPDATE` | ? Denied | ? Update own items | ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `DELETE` | ? Denied | ? Delete own items | ? Denied on Alice | ? Denied on Alice | ? Denied on others | ? Own / Admin |
| **`show_progress`** | `SELECT` | ? Denied | ? Read own progress | ? Denied on Alice | ? Denied on Alice | ? Denied on Alice | ? Read own |
| | `INSERT` | ? Denied | ? Insert own | ? Insert own | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `UPDATE` | ? Denied | ? Update own | ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `DELETE` | ? Denied | ? Delete own | ? Denied on Alice | ? Denied on Alice | ? Denied on others | ? Own / Admin |
| **`private_notes`** | `SELECT` | ? Denied | ? Read own notes | ? Denied on Alice | ? Denied on Alice | ? Denied on Alice | ? Read own |
| | `INSERT` | ? Denied | ? Insert own note | ? Insert own note | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `UPDATE` | ? Denied | ? Update own note | ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Own / Admin |
| | `DELETE` | ? Denied | ? Delete own note | ? Denied on Alice | ? Denied on Alice | ? Denied on others | ? Own / Admin |
| **`logs`** | `SELECT` | ? Visible logs | ? Read own + visible | ? Read own + visible | ? Denied on Alice logs | ? Read own + visible | ? Read all logs |
| | `INSERT` | ? Denied | ? Insert own (visible) | ? Insert own (visible) | ? Denied on Alice | ? Denied (is_banned) | ? Insert own |
| | `UPDATE` | ? Denied | ? Update own (soft-hide)| ? Denied on Alice | ? Denied on Alice | ? Denied (is_banned) | ? Update / mod |
| | `DELETE` | ? Denied | ? Denied (Soft-delete) | ? Denied | ? Denied | ? Denied | ? Admin purge |
| **`log_likes`** | `SELECT` | ? Unblocked visible | ? Read unblocked | ? Read unblocked | ? Denied on Alice logs | ? Read unblocked | ? Read all |
| | `INSERT` | ? Denied | ? Like unblocked log | ? Like unblocked log | ? Denied on Alice logs | ? Denied (is_banned) | ? Like |
| | `DELETE` | ? Denied | ? Unlike own like | ? Unlike own like | ? Denied on others | ? Denied on others | ? Unlike |

---

## Security Invariants
1. **Zero-Trust Token Fallback**: Even if a banned user holds an active JWT token before expiration, every write policy explicitly enforces `NOT public.is_banned(auth.uid())`.
2. **Mutual Blocking Barrier**: The `public.is_blocked_between(user_a, user_b)` security definer function filters both directions—if A blocks B, neither A nor B can see the other's content in public queries.
3. **Escalation Proofing**: A database trigger (`protect_profile_security_fields`) rejects any attempt by non-admins to alter `trust_level` or `is_banned`.
