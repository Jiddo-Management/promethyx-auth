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

// ============================================================================
// Platform-wide announcement bar.
//
// One announcement, edited in Admin (admin_settings.announcement), shown sticky
// at the top of every tool that loads this file. Reads public.get_announcement()
// — the RPC returns the row ONLY when enabled, so toggling it off in Admin hides
// the bar everywhere with no redeploy. Dismissal is platform-wide: the dismissed
// id is stored in a cookie on `.promethyx.com` (reusing setCookie above), so an ×
// on any subdomain hides it on all; a new admin save mints a new id → re-shows.
// Self-contained (injects its own CSS + DOM); fails silent when signed out.
// ============================================================================
const ANN_DISMISS_COOKIE = 'promethyx-ann-dismissed';

function mountAnnouncement() {
  if (window.__pxAnnMounted) return;             // once per page
  if (!document.body) {                           // body not parsed yet — wait
    document.addEventListener('DOMContentLoaded', mountAnnouncement, { once: true });
    return;
  }
  window.__pxAnnMounted = true;

  const style = document.createElement('style');
  style.textContent =
    '.pxann{position:sticky;top:0;z-index:99999;background:#EE7A3A;color:#1B1F2A;' +
    'font-family:inherit;animation:pxann-in .4s cubic-bezier(.2,.7,.1,1) both}' +
    '@keyframes pxann-in{from{transform:translateY(-100%)}to{transform:translateY(0)}}' +
    '.pxann-inner{max-width:1280px;margin:0 auto;display:flex;align-items:center;' +
    'gap:14px;padding:9px clamp(16px,4vw,56px)}' +
    '.pxann-msg{flex:1;min-width:0;font-size:13.5px;font-weight:500;line-height:1.45;letter-spacing:.01em}' +
    '.pxann-msg a{color:#1B1F2A;text-decoration:underline;text-underline-offset:2px}' +
    '.pxann-x{flex:0 0 auto;width:28px;height:28px;padding:0;display:grid;place-items:center;' +
    'color:#1B1F2A;background:rgba(27,31,42,.12);border:none;border-radius:8px;cursor:pointer;transition:background .15s}' +
    '.pxann-x:hover{background:rgba(27,31,42,.22)}' +
    '.pxann-x svg{width:14px;height:14px;display:block}';
  document.head.appendChild(style);

  const bar = document.createElement('div');
  bar.className = 'pxann'; bar.setAttribute('role', 'status'); bar.hidden = true;
  const inner = document.createElement('div'); inner.className = 'pxann-inner';
  const msg = document.createElement('span'); msg.className = 'pxann-msg';
  const x = document.createElement('button');
  x.type = 'button'; x.className = 'pxann-x'; x.setAttribute('aria-label', 'Dismiss announcement');
  x.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" ' +
    'stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>';
  inner.append(msg, x); bar.append(inner);
  document.body.insertBefore(bar, document.body.firstChild);

  // Only fetch once the session is loaded — the RPC is authenticated-only, so a
  // signed-out page (which requireAuth will bounce anyway) simply shows no bar.
  PromethyxAuth.getSession().then((session) => {
    if (!session) return null;
    return client.rpc('get_announcement');
  }).then((res) => {
    if (!res) return;
    const { data, error } = res;
    if (error || !data || !data.message) return;                 // none / disabled
    if (data.id && getCookie(ANN_DISMISS_COOKIE) === String(data.id)) return;  // dismissed
    if (data.link) {
      const a = document.createElement('a');
      a.href = data.link; a.target = '_blank'; a.rel = 'noopener'; a.textContent = data.message;
      msg.appendChild(a);
    } else {
      msg.textContent = data.message;
    }
    x.onclick = () => { bar.hidden = true; if (data.id) setCookie(ANN_DISMISS_COOKIE, String(data.id)); };
    bar.hidden = false;
  }).catch(() => {});
}

mountAnnouncement();
