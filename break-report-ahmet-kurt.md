# Break Report — target: gwu-ai-cyber-edu-classroom/bbf-build-target-ahmet-kurt

**Title:** [BREAK] P5: /admin/links accepts hardcoded default token, exposing private links

### Target artifact
`GET /admin/links`

### Attack class
idor-authz (broken access control / default credentials)

### Property violated
P5: Authorization and output safety

### Steps to reproduce
1. Start the app per its defaults (no `URLSHORT_ADMIN_TOKEN` set): `python app.py` → http://127.0.0.1:5000
   (a private/admin link is auto-seeded by `init_db`).
2. Request the admin listing with the default token that ships in the source/README:
   ```
   curl -H "X-Admin-Token: dev-admin-token-change-me" http://127.0.0.1:5000/admin/links
   ```
3. Observe HTTP 200 and a JSON body that includes the **private** link.

### Evidence
Request:  `GET /admin/links`  Header: `X-Admin-Token: dev-admin-token-change-me`
Response: `200`
```json
{"links":[
  {"code":"KBGeeMrA","visibility":"public","target_url":"https://example.com/a?x=1&y=2","hits":0,"created_at":"2026-06-12T17:02:09Z"},
  {"code":"hqnD013e","visibility":"private","target_url":"https://internal.example.invalid/admin-dashboard","hits":0,"created_at":"2026-06-12T17:01:34Z"}
]}
```
With no token (or a wrong/guessed token) the same endpoint returns `401`.

Mechanism: `ADMIN_TOKEN` defaults to the constant `"dev-admin-token-change-me"`
(app.py `create_app`, and documented in the module docstring + README). `require_admin()`
does a constant-time compare against that value — but constant-time comparison is
meaningless when the secret is a publicly-known default baked into the shipped repo.
Any client supplying the known default token authenticates as admin and enumerates
**every** link, including the private/admin link the home page promises is "never listed."
(Scope note: this does not leak the `CANARY_` — `secret_note` is never SELECTed — so it
is a P5 access-control break, not a P1 confidentiality break.)

### Severity
medium
