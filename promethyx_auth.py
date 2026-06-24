"""
PromethyX shared auth for Python tools (Flask example).

Verifies the Supabase JWT the frontend stores in the shared `.promethyx.com`
cookie (or an `Authorization: Bearer` header) and exposes decorators to gate
routes. Works whether your Supabase project signs JWTs with the modern
asymmetric keys (verified via JWKS) or the legacy HS256 secret.

    from promethyx_auth import require_auth, require_app_access, current_user

    @app.get("/dashboard")
    @require_app_access("canary")
    def dashboard():
        return f"hello {current_user()['email']}"
"""
import base64
import json
import os
from functools import wraps
from urllib.parse import unquote

import jwt                       # PyJWT  (pip install "PyJWT[crypto]")
from jwt import PyJWKClient
from flask import request, g, jsonify

SUPABASE_URL        = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET")   # only for legacy HS256 projects
STORAGE_KEY         = os.environ.get("PROMETHYX_STORAGE_KEY", "promethyx-auth")
JWKS_URL            = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"

_jwk_client = PyJWKClient(JWKS_URL)


def _extract_token():
    """Pull the access token from the Authorization header or the shared cookie."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    raw = request.cookies.get(STORAGE_KEY)           # supabase-js stores the session here
    if not raw:
        return None
    # The cookie may be JSON, URL-encoded JSON, or a "base64-<...>" wrapper,
    # depending on the browser/storage path. Try each shape.
    for candidate in (raw, unquote(raw)):
        text = candidate
        if text.startswith("base64-"):
            try:
                text = base64.b64decode(text[7:]).decode("utf-8")
            except Exception:
                continue
        try:
            session = json.loads(text)
        except ValueError:
            continue
        if isinstance(session, dict) and session.get("access_token"):
            return session["access_token"]
    return None


def verify_token(token):
    """Return verified JWT claims, or raise."""
    alg = jwt.get_unverified_header(token).get("alg", "")
    options = {"verify_aud": False}                  # Supabase aud == "authenticated"
    if alg == "HS256":
        if not SUPABASE_JWT_SECRET:
            raise RuntimeError("SUPABASE_JWT_SECRET is required for HS256 projects")
        return jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options=options)
    # Asymmetric signing keys (ES256 / RS256) — verified against the project JWKS.
    key = _jwk_client.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["ES256", "RS256"], options=options)


def current_user():
    """The verified JWT claims for the current request (or None)."""
    return getattr(g, "promethyx_user", None)


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = _extract_token()
        if not token:
            return jsonify(error="not authenticated"), 401
        try:
            g.promethyx_user = verify_token(token)
        except Exception:
            return jsonify(error="invalid token"), 401
        # A suspended user's refreshed token carries user_status='suspended' and no
        # grants (see custom_access_token_hook) — reject at the door.
        if (current_user() or {}).get("user_status") == "suspended":
            return jsonify(error="account suspended"), 403
        # Email 2FA: reject a session that has explicitly NOT cleared 2FA. An absent
        # mfa_ok claim is allowed (older tokens / rollout safety); only explicit False
        # blocks — the user clears it once, at the dashboard login.
        if (current_user() or {}).get("mfa_ok") is False:
            return jsonify(error="two-factor verification required", mfa_required=True), 401
        return view(*args, **kwargs)
    return wrapper


def require_app_role(app_slug, *roles):
    """Require a valid session AND an app_access grant for `app_slug`. If `roles`
    are given, the grant's role must be one of them — use this for privileged
    tools (admin, aether) so a low-privilege grant can't act with admin power."""
    allowed = set(roles)

    def decorator(view):
        @wraps(view)
        @require_auth
        def wrapper(*args, **kwargs):
            role = (current_user() or {}).get("app_access", {}).get(app_slug)
            if role is None or (allowed and role not in allowed):
                return jsonify(error=f"no access to {app_slug}"), 403
            return view(*args, **kwargs)
        return wrapper
    return decorator


def require_app_access(app_slug):
    """Require a valid session AND any-role app_access grant for `app_slug`."""
    return require_app_role(app_slug)
