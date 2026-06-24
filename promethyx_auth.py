"""
PromethyX shared auth for Python tools.

Verifies the Supabase JWT the frontend stores in the shared `.promethyx.com`
cookie (or an `Authorization: Bearer` header). Works whether the project signs
JWTs with modern asymmetric keys (verified via JWKS) or the legacy HS256 secret.

Two layers, one source of truth for the security-critical bits:

  • Pure core (no env, no Flask, no config): `verify_jwt()` + `extract_token()`.
    Any tool can call these directly — e.g. a config-driven one that doesn't use
    the decorators (see Canary's thin adapter).

  • Env-configured Flask adapter (the common case): `require_auth`,
    `require_app_access(slug)`, `require_app_role(slug, *roles)`, `current_user()`.

    from promethyx_auth import require_app_access, current_user

    @app.get("/dashboard")
    @require_app_access("canary")
    def dashboard():
        return f"hello {current_user()['email']}"

Env reading is lazy (at call time, not import) so the module imports cleanly even
where SUPABASE_URL isn't in the environment.
"""
import base64
import json
import os
import re
import threading
from functools import wraps
from urllib.parse import unquote

import jwt                       # PyJWT  (pip install "PyJWT[crypto]")
from jwt import PyJWKClient
from flask import request, g, jsonify

# ── Pure verification core (no env, no Flask, no config) ─────────────────────
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_jwks_clients = {}
_jwks_lock = threading.Lock()


def _jwks_client(url):
    """One cached PyJWKClient per JWKS URL (thread-safe)."""
    with _jwks_lock:
        c = _jwks_clients.get(url)
        if c is None:
            try:
                c = PyJWKClient(url, cache_keys=True, lifespan=3600)
            except TypeError:                      # older PyJWT signature
                c = PyJWKClient(url)
            _jwks_clients[url] = c
    return c


def verify_jwt(token, *, jwks_url=None, hs256_secret=None):
    """Verify a Supabase JWT and return its claims, or raise. Pure: the caller
    supplies the JWKS URL (asymmetric ES256/RS256) and/or the HS256 secret."""
    alg = jwt.get_unverified_header(token).get("alg", "")
    options = {"verify_aud": False}                # Supabase aud == "authenticated"
    if alg == "HS256":
        if not hs256_secret:
            raise RuntimeError("hs256_secret is required for HS256 tokens")
        return jwt.decode(token, hs256_secret, algorithms=["HS256"], options=options)
    if not jwks_url:
        raise RuntimeError("jwks_url is required for asymmetric (ES256/RS256) tokens")
    key = _jwks_client(jwks_url).get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["ES256", "RS256"], options=options)


def _session_to_token(text):
    """Pull access_token out of a cookie payload: raw JSON, a `base64-<json>`
    wrapper, a `[token, ...]` array, or a bare JWT."""
    if text.startswith("base64-"):
        try:
            inner = text[7:]
            text = base64.b64decode(inner + "=" * (-len(inner) % 4)).decode("utf-8", "replace")
        except Exception:
            return None
    text = text.strip()
    if text[:1] not in ("{", "["):
        return text if _JWT_RE.match(text) else None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict):
        return data.get("access_token")
    if isinstance(data, list) and data:
        first = data[0]
        return first if isinstance(first, str) else (first or {}).get("access_token")
    return None


def extract_token(cookies, authorization=None, *, cookie_name="promethyx-auth", project_ref=None):
    """Return the access token from an Authorization header or the shared session
    cookie, or None. Handles supabase-js JSON / `base64-` wrappers and, when
    `project_ref` is given, the @supabase/ssr `sb-<ref>-auth-token` format
    (single or chunked `.0`/`.1`). `cookies` is a mapping (e.g. request.cookies)."""
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip()
    raw = cookies.get(cookie_name)
    if raw:
        for candidate in (raw, unquote(raw)):
            tok = _session_to_token(candidate)
            if tok:
                return tok
    if project_ref:
        ssr = "sb-%s-auth-token" % project_ref
        raw = cookies.get(ssr)
        if raw is None:
            parts, i = [], 0
            while True:
                piece = cookies.get("%s.%d" % (ssr, i))
                if piece is None:
                    break
                parts.append(piece); i += 1
            raw = "".join(parts) if parts else None
        if raw:
            for candidate in (raw, unquote(raw)):
                tok = _session_to_token(candidate)
                if tok:
                    return tok
    return None


# ── Env-configured Flask adapter ─────────────────────────────────────────────
def _supabase_url():
    url = os.environ.get("SUPABASE_URL")
    if not url:
        raise RuntimeError("SUPABASE_URL is not set")
    return url.rstrip("/")


def _storage_key():
    return os.environ.get("PROMETHYX_STORAGE_KEY", "promethyx-auth")


def _extract_token():
    return extract_token(request.cookies, request.headers.get("Authorization", ""),
                         cookie_name=_storage_key())


def verify_token(token):
    """Return verified JWT claims, or raise. Env-configured wrapper over verify_jwt."""
    return verify_jwt(
        token,
        jwks_url=_supabase_url() + "/auth/v1/.well-known/jwks.json",
        hs256_secret=os.environ.get("SUPABASE_JWT_SECRET"),   # only for legacy HS256 projects
    )


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
