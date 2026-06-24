# promethyx-auth

The **one** source of truth for PromethyX SSO — so every tool doesn't carry its
own drifting copy of the auth code.

- **`promethyx_auth.py`** — backend: verifies the shared Supabase session JWT
  (JWKS / ES256, or legacy HS256) and exposes Flask guards:
  `require_auth`, `require_app_access(slug)`, `require_app_role(slug, *roles)`,
  `current_user()`. Enforces suspended-account and email-2FA claims.
- **`auth.js`** — frontend: wires `supabase-js` to the shared `.promethyx.com`
  session cookie (single sign-on) + `PromethyxAuth.requireAuth(slug)`.

Contains **no secrets** — the module reads config from env vars, and the anon key
in `auth.js` is the public publishable key shipped to browsers by design.

## Use it in a tool (backend)

Pin the version in your tool's `requirements.txt` instead of copying the file:

```
promethyx-auth @ git+https://github.com/Jiddo-Management/promethyx-auth@v0.1.0
```

Delete the tool's local `promethyx_auth.py`. The import is unchanged:

```python
from promethyx_auth import require_app_access, require_app_role, current_user
```

## Release an auth change (fix once, roll out everywhere)

1. Edit `promethyx_auth.py` (and/or `auth.js`) here.
2. Bump `version` in `pyproject.toml`, commit, and tag: `git tag v0.1.1 && git push --tags`.
3. In each tool, bump the pin to `@v0.1.1` and redeploy.

No more hand-editing the same file in six repos — and no more "fixed five of six,
left one on the old code" security gaps.

## Frontend (`auth.js`)

Currently each tool still serves its own `auth.js`. Next step is to serve this
canonical copy from one place and point every tool's `<script src>` at it (same
single-source idea, JS side). Until then, this file is the reference copy.
