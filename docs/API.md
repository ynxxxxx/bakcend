# API Reference: Edge Functions (Phase 1)

All Edge Functions run on Deno/TypeScript, enforce input validation schemas, sanitize errors, log structured request IDs (`reqId`), and reject unauthorized callers.

---

## 1. `POST /functions/v1/check-username`

Checks if a candidate username is available, complies with syntax rules, and does not collide with reserved platform handles.

### Headers
| Header | Value | Required |
| :--- | :--- | :--- |
| `Content-Type` | `application/json` | Yes |
| `apikey` | `<supabase-anon-key>` | Yes |

### Request Body
```json
{
  "username": "cinephile_99"
}
```

### Constraints
- Length: 3 to 20 characters.
- Character set: `^[a-z0-9_]{3,20}$` (lowercase letters, digits, underscore).
- Reserved words: `admin`, `system`, `support`, `official`, `serializd`, `ullista`, etc.

### Responses
- `200 OK`:
  ```json
  {
    "available": true,
    "reqId": "d3b07384-d113-4674-bc48-c89b27b32231"
  }
  ```
- `200 OK` (Reserved):
  ```json
  {
    "available": false,
    "error": "This username is reserved",
    "reqId": "d3b07384-d113-4674-bc48-c89b27b32231"
  }
  ```
- `400 Bad Request` (Invalid format or empty):
  ```json
  {
    "available": false,
    "error": "Username must be 3-20 lowercase alphanumeric characters or underscores",
    "reqId": "d3b07384-d113-4674-bc48-c89b27b32231"
  }
  ```

---

## 2. `POST /functions/v1/delete-account`

App Store and Google Play compliant user account deletion. Anonymizes public content and deletes the auth user from Supabase.

### Headers
| Header | Value | Required |
| :--- | :--- | :--- |
| `Authorization` | `Bearer <user-jwt-token>` | Yes |
| `apikey` | `<supabase-anon-key>` | Yes |

### Request Body
None required (or optional `{ "confirmation": true }`).

### Behavior
1. Validates the caller JWT via `supabase.auth.getUser()`.
2. Sanitizes profile PII: clears `bio`, `avatar_url`, sets `display_name = 'Deleted User'`, changes `username = 'deleted_<uid>'`.
3. Calls Supabase Auth Admin API: `auth.admin.deleteUser(user_id)`.
4. PostgreSQL cascading deletes drop private notes, shelf library items, show progress, and notification subscriptions while preserving diary reviews under "Deleted User".

### Responses
- `200 OK`:
  ```json
  {
    "success": true,
    "message": "Account deleted successfully",
    "reqId": "e1f13b52-4740-410c-99d8-9a3b2b8c5e93"
  }
  ```
- `401 Unauthorized`:
  ```json
  {
    "error": "Invalid session",
    "reqId": "e1f13b52-4740-410c-99d8-9a3b2b8c5e93"
  }
  ```
