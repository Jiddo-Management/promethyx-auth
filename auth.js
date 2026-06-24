// ============================================================================
// PromethyX shared auth (vanilla JS) — drop into every *.promethyx.com tool.
//
// Wires supabase-js to store its session in a cookie scoped to `.promethyx.com`
// instead of localStorage, so signing in on ANY subdomain signs you into ALL of
// them (single sign-on). Load supabase-js first:
//
//   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
//   <script src="/auth.js"></script>
//   <script>PromethyxAuth.requireAuth('canary');</script>   // gate a page
//
// NOTE: the supabase client is kept in a const named `client` (NOT `supabase`).
// supabase-js's UMD build defines a global `supabase`, so a top-level
// `const supabase` here would throw "Identifier already declared" and abort.
// ============================================================================

const SUPABASE_URL      = 'https://kztaplaixbzfomwhsljc.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_Xi90DjAoHi3vfgGHlG329g_SbqN7hYs';  // publishable — safe in browser
const COOKIE_DOMAIN     = '.promethyx.com';                      // shared across subdomains
const LOGIN_URL         = 'https://promethyx.com/';              // the dashboard hosts the inline login
const STORAGE_KEY       = 'promethyx-auth';                      // one shared session, all tools

// --- cookie helpers, scoped to the parent domain ---------------------------
// NOTE: a Supabase session is a few KB; cookies cap at ~4KB. Keep custom JWT
// claims small. If you ever overflow, switch to @supabase/ssr-style chunking.
function setCookie(name, value) {
  document.cookie =
    `${name}=${encodeURIComponent(value)}; Domain=${COOKIE_DOMAIN}; Path=/; ` +
    `Max-Age=${60 * 60 * 24 * 365}; Secure; SameSite=Lax`;
}
function getCookie(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[-.]/g, '\\$&') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function delCookie(name) {
  document.cookie = `${name}=; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=0; Secure; SameSite=Lax`;
}

// supabase-js storage adapter backed by the shared cookie.
const cookieStorage = {
  getItem:    (key) => getCookie(key),
  setItem:    (key, value) => setCookie(key, value),
  removeItem: (key) => delCookie(key),
};

const client = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    storage: cookieStorage,
    storageKey: STORAGE_KEY,
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,   // completes magic-link / OAuth redirects
  },
});

const PromethyxAuth = {
  supabase: client,

  async getSession() {
    const { data } = await client.auth.getSession();
    return data.session;
  },

  async getUser() {
    const { data } = await client.auth.getUser();
    return data.user;
  },

  // Roles/grants are embedded in the JWT by the access-token hook (db/schema.sql).
  async appAccess() {
    const session = await this.getSession();
    if (!session) return {};
    const payload = JSON.parse(atob(session.access_token.split('.')[1]));
    return payload.app_access || {};
  },

  async hasAppAccess(app) {
    return Object.prototype.hasOwnProperty.call(await this.appAccess(), app);
  },

  // Gate a page: bounce to login if signed out; show "no access" if signed in
  // but not granted `app`. Returns the session when allowed, else null.
  async requireAuth(app) {
    const session = await this.getSession();
    if (!session) {
      window.location.href = `${LOGIN_URL}?redirect=${encodeURIComponent(window.location.href)}`;
      return null;
    }
    // Email 2FA: if a code is required and not yet cleared this session, finish it
    // at the hub (the backend enforces this too — this is just the friendly bounce).
    const claims = JSON.parse(atob(session.access_token.split('.')[1]));
    if (claims.mfa_required && !claims.mfa_ok) {
      window.location.href = `${LOGIN_URL}?redirect=${encodeURIComponent(window.location.href)}`;
      return null;
    }
    if (app && !(await this.hasAppAccess(app))) {
      document.body.innerHTML =
        '<main style="font-family:system-ui;max-width:32rem;margin:15vh auto;text-align:center">' +
        '<h1>No access</h1><p>Your account isn’t granted access to this tool. ' +
        'Ask an admin at <a href="https://admin.promethyx.com">admin.promethyx.com</a>.</p></main>';
      return null;
    }
    return session;
  },

  async signOut() {
    await client.auth.signOut();
    window.location.reload();
  },
};

window.PromethyxAuth = PromethyxAuth;
