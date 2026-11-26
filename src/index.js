/**
 * retrac.link — a small link shortener for Cloudflare Workers.
 *
 * Bindings (see wrangler.toml):
 *   DB                  D1 database (tables are created automatically)
 *   DASHBOARD_PASSWORD  Secret — the password for /dashboard
 *
 * Routes:
 *   /                   Master link (redirects wherever you set it in the dashboard)
 *   /qr/<slug>          Same as /<slug>, but the click is also counted as a QR scan
 *   /dashboard          Password-protected dashboard
 *   /api/*              JSON API used by the dashboard (session cookie required)
 *   /<slug>             Short link redirect (asks for a password if the link has one)
 */

import { qrEncode } from "./qr.js";
import FAVICON from "./favicon.png";

const RESERVED_SLUGS = new Set(["dashboard", "api", "favicon.ico", "robots.txt"]);
const SLUG_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const SLUG_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
const SESSION_COOKIE = "rl_session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 100000; // Maximum Workers allows for PBKDF2.
const CSRF_HEADER = "X-Requested-With";
const CSRF_VALUE = "retrac-dashboard";

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (err) {
      if (err instanceof HttpError) {
        return json({ error: err.message }, err.status);
      }
      console.error(err);
      return htmlResponse(
        messagePage("Something went wrong", "An unexpected error occurred. Please try again."),
        500,
      );
    }
  },
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/* -------------------------------------------------------------------------- */
/* Routing                                                                    */
/* -------------------------------------------------------------------------- */

async function route(request, env, ctx) {
  const url = new URL(request.url);
  let path;
  try {
    path = decodeURIComponent(url.pathname);
  } catch {
    return notFound();
  }
  path = path.replace(/\/+$/, "") || "/";
  const method = request.method;

  if (path === "/robots.txt") {
    return new Response("User-agent: *\nDisallow: /\n", { headers: { "Content-Type": "text/plain" } });
  }
  if (path === "/favicon.ico" || path === "/favicon.png") {
    return new Response(FAVICON, {
      headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" },
    });
  }

  if (!env.DB) {
    return htmlResponse(
      messagePage(
        "Setup needed",
        "No D1 database is bound to this Worker. Add a D1 binding named DB (see the README).",
      ),
      500,
    );
  }
  await ensureSchema(env.DB);

  if (path === "/dashboard") {
    if (method !== "GET" && method !== "HEAD") return methodNotAllowed();
    return dashboard(request, env);
  }
  if (path === "/dashboard/login") {
    if (method !== "POST") return redirect("/dashboard", 303);
    return login(request, env);
  }
  if (path === "/dashboard/logout") {
    if (method !== "POST") return redirect("/dashboard", 303);
    return logout();
  }
  if (path === "/api" || path.startsWith("/api/")) {
    return api(request, env, path);
  }
  if (path === "/") {
    if (method !== "GET" && method !== "HEAD") return methodNotAllowed();
    return masterLink(env);
  }

  // QR codes point at /qr/<slug> so scans can be counted separately.
  const qr = path.match(/^\/qr\/([^/]+)$/);
  if (qr) return followLink(request, env, ctx, qr[1], true);

  const slug = path.slice(1);
  if (slug.includes("/")) return notFound();
  return followLink(request, env, ctx, slug, false);
}

/* -------------------------------------------------------------------------- */
/* Database                                                                   */
/* -------------------------------------------------------------------------- */

let schemaReady = null;

function ensureSchema(db) {
  if (!schemaReady) {
    schemaReady = db
      .batch([
        db.prepare(
          `CREATE TABLE IF NOT EXISTS links (
            slug TEXT PRIMARY KEY COLLATE NOCASE,
            url TEXT NOT NULL,
            nickname TEXT,
            pw_hash TEXT,
            pw_salt TEXT,
            clicks INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            expires_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          )`,
        ),
        db.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`),
        // Extra short codes that point at a link. `slug` is the link's main slug.
        db.prepare(
          `CREATE TABLE IF NOT EXISTS aliases (
            alias TEXT PRIMARY KEY COLLATE NOCASE,
            slug TEXT NOT NULL COLLATE NOCASE
          )`,
        ),
        db.prepare(`CREATE INDEX IF NOT EXISTS aliases_slug ON aliases (slug)`),
      ])
      // Added after launch, so existing databases need the column too.
      .then(() =>
        db
          .prepare("ALTER TABLE links ADD COLUMN qr_clicks INTEGER NOT NULL DEFAULT 0")
          .run()
          .catch((err) => {
            if (!/duplicate column/i.test(String(err && err.message))) throw err;
          }),
      )
      .catch((err) => {
        schemaReady = null;
        throw err;
      });
  }
  return schemaReady;
}

function getLink(db, slug) {
  return db.prepare("SELECT * FROM links WHERE slug = ?").bind(slug).first();
}

// Finds a link by its main slug or by one of its aliases.
async function resolveLink(db, code) {
  return (
    (await getLink(db, code)) ||
    db
      .prepare("SELECT l.* FROM aliases a JOIN links l ON l.slug = a.slug WHERE a.alias = ?")
      .bind(code)
      .first()
  );
}

async function getAliases(db, slug) {
  const { results } = await db
    .prepare("SELECT alias FROM aliases WHERE slug = ? ORDER BY alias")
    .bind(slug)
    .all();
  return results.map((r) => r.alias);
}

async function getLinkWithAliases(db, slug) {
  const row = await getLink(db, slug);
  return row ? toPublicLink(row, await getAliases(db, row.slug)) : null;
}

async function getMaster(db) {
  const row = await db.prepare("SELECT value FROM settings WHERE key = 'master'").first();
  const fallback = { url: "", enabled: false };
  if (!row) return fallback;
  try {
    return { ...fallback, ...JSON.parse(row.value) };
  } catch {
    return fallback;
  }
}

function toPublicLink(row, aliases = []) {
  return {
    slug: row.slug,
    aliases,
    url: row.url,
    nickname: row.nickname || "",
    hasPassword: Boolean(row.pw_hash),
    clicks: row.clicks,
    qrClicks: row.qr_clicks ?? 0,
    enabled: Boolean(row.enabled),
    expiresAt: row.expires_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function isUniqueViolation(err) {
  return /UNIQUE constraint failed/i.test(String(err && err.message));
}

/* -------------------------------------------------------------------------- */
/* Public routes                                                              */
/* -------------------------------------------------------------------------- */

async function masterLink(env) {
  const master = await getMaster(env.DB);
  if (master.enabled && master.url) return redirect(master.url, 302);
  return htmlResponse(messagePage("retrac.link", "Short links live here."), 200);
}

async function followLink(request, env, ctx, slug, fromQr) {
  const link = await resolveLink(env.DB, slug);
  if (!link || !link.enabled) return notFound();
  if (link.expires_at && link.expires_at <= Date.now()) {
    return htmlResponse(messagePage("Link expired", "This link is no longer available."), 410);
  }

  const countClick = () =>
    ctx.waitUntil(
      env.DB.prepare(
        fromQr
          ? "UPDATE links SET clicks = clicks + 1, qr_clicks = qr_clicks + 1 WHERE slug = ?"
          : "UPDATE links SET clicks = clicks + 1 WHERE slug = ?",
      )
        .bind(link.slug)
        .run(),
    );

  if (!link.pw_hash) {
    if (request.method !== "GET" && request.method !== "HEAD") return methodNotAllowed();
    if (request.method === "GET") countClick();
    return redirect(link.url, 302);
  }

  if (request.method === "GET" || request.method === "HEAD") {
    return htmlResponse(passwordPage(), 200);
  }
  if (request.method !== "POST") return methodNotAllowed();

  let password = "";
  try {
    const form = await request.formData();
    password = String(form.get("password") || "");
  } catch {
    // fall through with an empty password
  }
  if (!password || !(await verifyPassword(password, link.pw_salt, link.pw_hash))) {
    return htmlResponse(passwordPage("Incorrect password. Try again."), 401);
  }
  countClick();
  return redirect(link.url, 303);
}

/* -------------------------------------------------------------------------- */
/* Dashboard auth                                                             */
/* -------------------------------------------------------------------------- */

async function dashboard(request, env) {
  if (!env.DASHBOARD_PASSWORD) {
    return htmlResponse(
      messagePage(
        "Setup needed",
        "Set a secret named DASHBOARD_PASSWORD in your Worker's settings (Settings → Variables and Secrets), then reload this page.",
      ),
      500,
    );
  }
  if (await isAuthed(request, env)) {
    return htmlResponse(dashboardPage(), 200);
  }
  return htmlResponse(loginPage(), 200);
}

async function login(request, env) {
  if (!env.DASHBOARD_PASSWORD) return redirect("/dashboard", 303);
  let password = "";
  try {
    const form = await request.formData();
    password = String(form.get("password") || "");
  } catch {
    // treat as empty
  }
  if (!(await constantTimeEqual(password, env.DASHBOARD_PASSWORD))) {
    return htmlResponse(loginPage("Incorrect password."), 401);
  }
  const token = await createSession(env.DASHBOARD_PASSWORD);
  return new Response(null, {
    status: 303,
    headers: {
      Location: "/dashboard",
      "Set-Cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`,
      "Cache-Control": "no-store",
    },
  });
}

function logout() {
  return new Response(null, {
    status: 303,
    headers: {
      Location: "/dashboard",
      "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      "Cache-Control": "no-store",
    },
  });
}

// Sessions are signed with the dashboard password, so changing the password
// signs everyone out.
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("retrac-session:" + secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function createSession(secret) {
  const exp = String(Date.now() + SESSION_TTL_MS);
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(exp));
  return `${exp}.${b64url(sig)}`;
}

async function isAuthed(request, env) {
  if (!env.DASHBOARD_PASSWORD) return false;
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return false;
  const [exp, sig] = token.split(".");
  if (!exp || !sig || !/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  let sigBytes;
  try {
    sigBytes = b64urlDecode(sig);
  } catch {
    return false;
  }
  return crypto.subtle.verify(
    "HMAC",
    await hmacKey(env.DASHBOARD_PASSWORD),
    sigBytes,
    new TextEncoder().encode(exp),
  );
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Crypto helpers                                                             */
/* -------------------------------------------------------------------------- */

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

async function constantTimeEqual(a, b) {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

async function deriveHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await deriveHash(password, salt);
  return { salt: b64url(salt), hash: b64url(hash) };
}

async function verifyPassword(password, saltB64, hashB64) {
  try {
    const expected = b64urlDecode(hashB64);
    const actual = await deriveHash(password, b64urlDecode(saltB64));
    return expected.length === actual.length && crypto.subtle.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function b64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomSlug(length = 6) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (const b of bytes) out += SLUG_ALPHABET[b % SLUG_ALPHABET.length];
  return out;
}

/* -------------------------------------------------------------------------- */
/* API                                                                        */
/* -------------------------------------------------------------------------- */

async function api(request, env, path) {
  if (!(await isAuthed(request, env))) return json({ error: "Not signed in." }, 401);
  const method = request.method;
  // CSRF defence in depth (on top of SameSite=Strict cookies): browsers won't
  // send this custom header cross-origin without a CORS preflight we never allow.
  if (method !== "GET" && request.headers.get(CSRF_HEADER) !== CSRF_VALUE) {
    return json({ error: "Missing request header." }, 400);
  }

  const parts = path.split("/").slice(2); // "/api/links/abc" -> ["links", "abc"]
  const db = env.DB;
  const host = new URL(request.url).host;

  if (parts[0] === "links" && parts.length === 1) {
    if (method === "GET") {
      const [links, aliases] = await db.batch([
        db.prepare("SELECT * FROM links ORDER BY created_at DESC"),
        db.prepare("SELECT alias, slug FROM aliases ORDER BY alias"),
      ]);
      const bySlug = new Map();
      for (const { alias, slug } of aliases.results) {
        const key = slug.toLowerCase();
        if (!bySlug.has(key)) bySlug.set(key, []);
        bySlug.get(key).push(alias);
      }
      return json({
        links: links.results.map((row) => toPublicLink(row, bySlug.get(row.slug.toLowerCase()) || [])),
      });
    }
    if (method === "POST") return json(await createLink(db, await readJson(request), host), 201);
    return methodNotAllowed();
  }

  if (parts[0] === "links" && parts.length === 2) {
    const slug = parts[1];
    if (method === "PATCH") return json(await updateLink(db, slug, await readJson(request), host));
    if (method === "DELETE") {
      const link = await getLink(db, slug);
      if (!link) throw new HttpError(404, "Link not found.");
      await db.batch([
        db.prepare("DELETE FROM aliases WHERE slug = ?").bind(link.slug),
        db.prepare("DELETE FROM links WHERE slug = ?").bind(link.slug),
      ]);
      return json({ ok: true });
    }
    return methodNotAllowed();
  }

  if (parts[0] === "master" && parts.length === 1) {
    if (method === "GET") return json(await getMaster(db));
    if (method === "PUT") return json(await setMaster(db, await readJson(request), host));
    return methodNotAllowed();
  }

  return json({ error: "Not found." }, 404);
}

async function readJson(request) {
  try {
    const body = await request.json();
    if (body && typeof body === "object" && !Array.isArray(body)) return body;
  } catch {
    // fall through
  }
  throw new HttpError(400, "Invalid JSON body.");
}

// `ownCodes` are the slug and aliases of the link being saved ("" for the
// master link), so a link can't redirect to itself.
function normalizeUrl(input, host, ownCodes) {
  let value = String(input ?? "").trim();
  if (!value) throw new HttpError(400, "Destination URL is required.");
  if (!/^[a-z][a-z0-9+.-]*:/i.test(value)) value = "https://" + value;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new HttpError(400, "That doesn't look like a valid URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new HttpError(400, "Only http:// and https:// URLs are allowed.");
  }
  if (parsed.host.toLowerCase() === host.toLowerCase()) {
    let p = parsed.pathname;
    try {
      p = decodeURIComponent(p);
    } catch {
      // keep the raw path
    }
    p = p.replace(/\/+$/, "").slice(1).toLowerCase();
    if (ownCodes.some((code) => code.toLowerCase() === p)) {
      throw new HttpError(400, "A link can't point to itself.");
    }
  }
  return parsed.href;
}

function validateSlug(input, label = "Short code") {
  const slug = String(input ?? "").trim();
  if (!SLUG_RE.test(slug)) {
    throw new HttpError(
      400,
      `${label} "${slug}" isn't valid. Use 1–64 letters, numbers, dashes or underscores (not starting with a dash or underscore).`,
    );
  }
  if (RESERVED_SLUGS.has(slug.toLowerCase())) throw new HttpError(400, `"${slug}" is reserved.`);
  return slug;
}

const MAX_ALIASES = 20;

// Accepts an array or a comma/space separated string. Returns unique aliases
// (case-insensitive), silently dropping the link's own slug.
function parseAliases(input, slug) {
  const raw = Array.isArray(input) ? input : String(input ?? "").split(/[\s,]+/);
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    const value = String(item ?? "").trim().replace(/^\/+/, "");
    if (!value) continue;
    const alias = validateSlug(value, "Alias");
    const key = alias.toLowerCase();
    if (key === slug.toLowerCase() || seen.has(key)) continue;
    seen.add(key);
    out.push(alias);
  }
  if (out.length > MAX_ALIASES) throw new HttpError(400, `A link can have at most ${MAX_ALIASES} aliases.`);
  return out;
}

// Makes sure none of `codes` is already used as another link's slug or alias.
// `ownSlug` is the link being saved (null when creating).
async function assertCodesFree(db, codes, ownSlug) {
  if (!codes.length) return;
  const list = JSON.stringify(codes);
  const [slugs, aliases] = await db.batch([
    db
      .prepare("SELECT slug AS code FROM links WHERE slug IN (SELECT value FROM json_each(?)) AND slug != ?")
      .bind(list, ownSlug ?? ""),
    db
      .prepare("SELECT alias AS code FROM aliases WHERE alias IN (SELECT value FROM json_each(?)) AND slug != ?")
      .bind(list, ownSlug ?? ""),
  ]);
  const taken = slugs.results[0] || aliases.results[0];
  if (taken) throw new HttpError(409, `retrac.link/${taken.code} is already taken.`);
}

function cleanNickname(input) {
  const nickname = String(input ?? "").trim();
  if (nickname.length > 100) throw new HttpError(400, "Nickname must be 100 characters or fewer.");
  return nickname || null;
}

function parseExpiry(input) {
  if (input === null || input === undefined || input === "") return null;
  const ms = typeof input === "number" ? input : Date.parse(String(input));
  if (!Number.isFinite(ms)) throw new HttpError(400, "Invalid expiry date.");
  return Math.round(ms);
}

function validatePassword(input) {
  const pw = String(input);
  if (pw.length > 256) throw new HttpError(400, "Password must be 256 characters or fewer.");
  return pw;
}

async function createLink(db, body, host) {
  let slug;
  if (body.slug && String(body.slug).trim()) {
    slug = validateSlug(body.slug);
  } else {
    for (let i = 0; i < 8 && !slug; i++) {
      const candidate = randomSlug(i < 4 ? 6 : 8);
      if (!(await resolveLink(db, candidate))) slug = candidate;
    }
    if (!slug) throw new HttpError(500, "Couldn't generate a short code. Try again.");
  }

  const aliases = parseAliases(body.aliases, slug);
  await assertCodesFree(db, [slug, ...aliases], null);
  const url = normalizeUrl(body.url, host, [slug, ...aliases]);
  const nickname = cleanNickname(body.nickname);
  const expiresAt = parseExpiry(body.expiresAt);
  const pw = body.password ? await hashPassword(validatePassword(body.password)) : null;
  const now = Date.now();

  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO links (slug, url, nickname, pw_hash, pw_salt, clicks, enabled, expires_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, ?)`,
        )
        .bind(slug, url, nickname, pw?.hash ?? null, pw?.salt ?? null, expiresAt, now, now),
      ...aliases.map((alias) => db.prepare("INSERT INTO aliases (alias, slug) VALUES (?, ?)").bind(alias, slug)),
    ]);
  } catch (err) {
    if (isUniqueViolation(err)) throw new HttpError(409, "That short code or alias is already taken.");
    throw err;
  }
  return getLinkWithAliases(db, slug);
}

async function updateLink(db, slug, body, host) {
  const link = await getLink(db, slug);
  if (!link) throw new HttpError(404, "Link not found.");

  const updates = {};
  let newSlug = link.slug;
  if ("slug" in body) {
    newSlug = validateSlug(body.slug);
    if (newSlug !== link.slug) updates.slug = newSlug;
  }
  const replaceAliases = "aliases" in body;
  const currentAliases = await getAliases(db, link.slug);
  // Renaming a link to one of its own aliases promotes that alias.
  const aliases = parseAliases(replaceAliases ? body.aliases : currentAliases, newSlug);
  await assertCodesFree(db, [newSlug, ...aliases], link.slug);

  if ("url" in body) updates.url = normalizeUrl(body.url, host, [newSlug, ...aliases]);
  if ("nickname" in body) updates.nickname = cleanNickname(body.nickname);
  if ("enabled" in body) updates.enabled = body.enabled ? 1 : 0;
  if ("expiresAt" in body) updates.expires_at = parseExpiry(body.expiresAt);
  if (body.removePassword) {
    updates.pw_hash = null;
    updates.pw_salt = null;
  } else if (typeof body.password === "string" && body.password !== "") {
    const pw = await hashPassword(validatePassword(body.password));
    updates.pw_hash = pw.hash;
    updates.pw_salt = pw.salt;
  }
  if (body.resetClicks) {
    updates.clicks = 0;
    updates.qr_clicks = 0;
  }
  updates.updated_at = Date.now();

  // Column names come from the fixed keys above, never from user input.
  const cols = Object.keys(updates);
  try {
    // A batch runs as one transaction, so the link and its aliases stay in sync.
    await db.batch([
      db
        .prepare(`UPDATE links SET ${cols.map((c) => `${c} = ?`).join(", ")} WHERE slug = ?`)
        .bind(...cols.map((c) => updates[c]), link.slug),
      db.prepare("DELETE FROM aliases WHERE slug = ?").bind(link.slug),
      ...aliases.map((alias) => db.prepare("INSERT INTO aliases (alias, slug) VALUES (?, ?)").bind(alias, newSlug)),
    ]);
  } catch (err) {
    if (isUniqueViolation(err)) throw new HttpError(409, "That short code or alias is already taken.");
    throw err;
  }
  return getLinkWithAliases(db, newSlug);
}

async function setMaster(db, body, host) {
  const enabled = Boolean(body.enabled);
  const raw = String(body.url ?? "").trim();
  if (enabled && !raw) throw new HttpError(400, "Enter a destination URL to turn on the master link.");
  const url = raw ? normalizeUrl(raw, host, [""]) : "";
  const value = JSON.stringify({ url, enabled });
  await db
    .prepare("INSERT INTO settings (key, value) VALUES ('master', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .bind(value)
    .run();
  return { url, enabled };
}

/* -------------------------------------------------------------------------- */
/* Responses                                                                  */
/* -------------------------------------------------------------------------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function redirect(location, status) {
  return new Response(null, {
    status,
    headers: { Location: location, "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer-when-downgrade" },
  });
}

function notFound() {
  return htmlResponse(messagePage("Link not found", "This short link doesn't exist."), 404);
}

function methodNotAllowed() {
  return new Response("Method not allowed", { status: 405 });
}

function htmlResponse({ html, nonce }, status) {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": [
        "default-src 'none'",
        `script-src 'nonce-${nonce}'`,
        "style-src 'unsafe-inline' https://fonts.googleapis.com",
        "font-src https://fonts.gstatic.com",
        "connect-src 'self'",
        "img-src 'self' data:",
        "base-uri 'none'",
        "frame-ancestors 'none'",
      ].join("; "),
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
    },
  });
}

/* -------------------------------------------------------------------------- */
/* HTML                                                                       */
/* -------------------------------------------------------------------------- */

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

const CSS = `
:root {
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-2: #f1f3f6;
  --border: #e3e6eb;
  --text: #0f1419;
  --muted: #5d6673;
  --accent: #4f46e5;
  --accent-hover: #4338ca;
  --accent-text: #ffffff;
  --accent-soft: #eef0ff;
  --danger: #dc2626;
  --danger-soft: #fdecec;
  --warn: #b45309;
  --warn-soft: #fef3e2;
  --ok: #15803d;
  --ok-soft: #e7f6ec;
  --shadow: 0 1px 2px rgba(15, 20, 25, 0.04), 0 4px 16px rgba(15, 20, 25, 0.06);
  --radius: 12px;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0c0e12;
    --surface: #14171c;
    --surface-2: #1b1f26;
    --border: #272c35;
    --text: #e8eaee;
    --muted: #9099a6;
    --accent: #7c74ff;
    --accent-hover: #918aff;
    --accent-text: #0c0e12;
    --accent-soft: #1f1d3a;
    --danger: #f87171;
    --danger-soft: #3a1717;
    --warn: #fbbf24;
    --warn-soft: #3a2a0c;
    --ok: #4ade80;
    --ok-soft: #10301c;
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.3), 0 4px 16px rgba(0, 0, 0, 0.3);
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; }
body {
  font-family: "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;
  font-feature-settings: "cv11", "ss01";
  background: var(--bg);
  color: var(--text);
  font-size: 15px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); }
h1, h2, h3 { margin: 0; letter-spacing: -0.02em; }
.center {
  min-height: 100vh; display: grid; place-items: center; padding: 24px 16px;
}
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 24px;
}
.narrow { width: 100%; max-width: 380px; }
.brand { font-weight: 700; font-size: 18px; letter-spacing: -0.03em; color: var(--text); text-decoration: none; }
.brand span { color: var(--accent); }
.muted { color: var(--muted); }
.small { font-size: 13px; }
label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; }
input[type=text], input[type=url], input[type=password], input[type=datetime-local], input[type=search] {
  width: 100%; font: inherit; color: var(--text); background: var(--surface);
  border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; outline: none;
  transition: border-color .15s, box-shadow .15s;
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
.field { margin-bottom: 14px; }
.prefix { display: flex; align-items: stretch; }
.prefix span {
  display: flex; align-items: center; padding: 0 10px; background: var(--surface-2);
  border: 1px solid var(--border); border-right: 0; border-radius: 8px 0 0 8px;
  color: var(--muted); font-size: 14px; white-space: nowrap;
}
.prefix input { border-radius: 0 8px 8px 0; min-width: 0; }
button, .btn {
  font: inherit; font-weight: 600; font-size: 14px; border-radius: 8px; padding: 9px 16px;
  border: 1px solid transparent; cursor: pointer; background: var(--accent); color: var(--accent-text);
  transition: background .15s, border-color .15s; display: inline-flex; align-items: center; gap: 6px;
}
button:hover { background: var(--accent-hover); }
button:disabled { opacity: .6; cursor: default; }
button.secondary { background: var(--surface); color: var(--text); border-color: var(--border); }
button.secondary:hover { background: var(--surface-2); }
button.ghost { background: transparent; color: var(--muted); padding: 6px 10px; }
button.ghost:hover { background: var(--surface-2); color: var(--text); }
button.danger { background: var(--danger); color: #fff; }
button.danger:hover { filter: brightness(1.08); }
button.ghost.danger-text:hover { color: var(--danger); background: var(--danger-soft); }
.full { width: 100%; justify-content: center; }
.error {
  background: var(--danger-soft); color: var(--danger); border-radius: 8px; padding: 9px 12px;
  font-size: 14px; margin-bottom: 14px;
}
.toggle { display: inline-flex; align-items: center; gap: 10px; cursor: pointer; font-size: 14px; font-weight: 500; margin: 0; }
.toggle input { appearance: none; width: 36px; height: 20px; border-radius: 999px; background: var(--border); position: relative; cursor: pointer; transition: background .15s; margin: 0; flex: none; }
.toggle input::after { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%; background: #fff; transition: transform .15s; box-shadow: 0 1px 2px rgba(0,0,0,.2); }
.toggle input:checked { background: var(--accent); }
.toggle input:checked::after { transform: translateX(16px); }
select {
  width: 100%; font: inherit; color: var(--text); background: var(--surface);
  border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; outline: none;
}
select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
select:disabled { opacity: .6; }
input[type=color] {
  width: 100%; height: 38px; padding: 3px; border: 1px solid var(--border); border-radius: 8px;
  background: var(--surface); cursor: pointer;
}
input[type=range] { width: 100%; accent-color: var(--accent); margin: 8px 0 0; }
.check { display: inline-flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 400; margin: 0; cursor: pointer; }
`;

function layout(title, body, script = "") {
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap">
<style>${CSS}</style>
</head>
<body>
${body}
${script ? `<script nonce="${nonce}">${script}</script>` : ""}
</body>
</html>`;
  return { html, nonce };
}

function messagePage(title, message) {
  return layout(
    title,
    `<main class="center"><div class="card narrow" style="text-align:center">
      <a class="brand" href="/">retrac<span>.</span>link</a>
      <h1 style="font-size:22px;margin:18px 0 6px">${escapeHtml(title)}</h1>
      <p class="muted" style="margin:0">${escapeHtml(message)}</p>
    </div></main>`,
  );
}

function passwordPage(error = "") {
  return layout(
    "Password required",
    `<main class="center"><form class="card narrow" method="post">
      <div class="brand">retrac<span>.</span>link</div>
      <h1 style="font-size:22px;margin:18px 0 4px">Password required</h1>
      <p class="muted" style="margin:0 0 18px">This link is password protected.</p>
      ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required autofocus>
      </div>
      <button class="full" type="submit">Continue</button>
    </form></main>`,
  );
}

function loginPage(error = "") {
  return layout(
    "Sign in · retrac.link",
    `<main class="center"><form class="card narrow" method="post" action="/dashboard/login">
      <div class="brand">retrac<span>.</span>link</div>
      <h1 style="font-size:22px;margin:18px 0 4px">Dashboard</h1>
      <p class="muted" style="margin:0 0 18px">Enter your password to manage links.</p>
      ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required autofocus>
      </div>
      <button class="full" type="submit">Sign in</button>
    </form></main>`,
  );
}

const DASHBOARD_CSS = `
.wrap { max-width: 980px; margin: 0 auto; padding: 0 16px 64px; }
header.top {
  display: flex; align-items: center; justify-content: space-between; padding: 18px 0; margin-bottom: 8px;
}
header.top form { margin: 0; }
.grid { display: grid; gap: 16px; grid-template-columns: 1fr; }
@media (min-width: 860px) { .grid { grid-template-columns: 1.4fr 1fr; } }
.card h2 { font-size: 16px; margin-bottom: 4px; }
.card .sub { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
.row { display: grid; gap: 12px; grid-template-columns: 1fr; }
@media (min-width: 560px) { .row.two { grid-template-columns: 1fr 1fr; } }
details.more { margin: 2px 0 14px; }
details.more summary { cursor: pointer; font-size: 13px; font-weight: 500; color: var(--muted); list-style: none; user-select: none; }
details.more summary::-webkit-details-marker { display: none; }
details.more summary::before { content: "+ "; }
details.more[open] summary::before { content: "− "; }
details.more[open] summary { margin-bottom: 12px; }
.actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; align-items: center; }
.master-status { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; padding: 3px 8px; border-radius: 999px; }
.master-status.on { background: var(--ok-soft); color: var(--ok); }
.master-status.off { background: var(--surface-2); color: var(--muted); }
.list-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin: 28px 0 12px; flex-wrap: wrap; }
.list-head h2 { font-size: 18px; }
.list-head input { max-width: 280px; }
.links { display: flex; flex-direction: column; gap: 10px; }
.link {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 14px 16px; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center;
}
.link.inactive { opacity: .65; }
.link .title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-weight: 600; }
.link .short { color: var(--accent); text-decoration: none; font-weight: 600; word-break: break-all; }
.link .short:hover { text-decoration: underline; }
.link .nick { color: var(--text); }
.hint { color: var(--muted); font-size: 12px; margin: 6px 0 0; }
.link .aliases { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; font-size: 13px; color: var(--muted); align-items: center; }
.link .aliases a { color: var(--accent); text-decoration: none; background: var(--accent-soft); padding: 1px 8px; border-radius: 999px; font-weight: 500; }
.link .aliases a:hover { text-decoration: underline; }
.link .dest { color: var(--muted); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 2px; }
.link .meta { color: var(--muted); font-size: 12px; margin-top: 4px; display: flex; gap: 12px; flex-wrap: wrap; }
.link .btns { display: flex; gap: 4px; }
.badge { font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 999px; text-transform: uppercase; letter-spacing: .03em; }
.badge.lock { background: var(--accent-soft); color: var(--accent); }
.badge.off { background: var(--surface-2); color: var(--muted); }
.badge.exp { background: var(--warn-soft); color: var(--warn); }
@media (max-width: 560px) {
  .link { grid-template-columns: 1fr; }
  .link .btns { justify-content: flex-start; margin-left: -10px; }
  .list-head input { max-width: none; }
}
.empty { text-align: center; padding: 40px 16px; color: var(--muted); border: 1px dashed var(--border); border-radius: var(--radius); }
dialog {
  border: 1px solid var(--border); border-radius: var(--radius); padding: 0; width: min(520px, calc(100vw - 32px));
  background: var(--surface); color: var(--text); box-shadow: 0 20px 60px rgba(0,0,0,.25);
}
dialog::backdrop { background: rgba(10, 12, 16, .5); }
dialog form { padding: 24px; margin: 0; }
dialog h2 { font-size: 18px; margin-bottom: 16px; }
dialog.wide { width: min(760px, calc(100vw - 32px)); }
.qr-layout { display: grid; gap: 20px; grid-template-columns: 1fr; }
@media (min-width: 680px) { .qr-layout { grid-template-columns: 260px minmax(0, 1fr); } }
.qr-preview {
  border: 1px solid var(--border); border-radius: var(--radius); padding: 14px; align-self: start;
  background-color: var(--surface-2);
  background-image: linear-gradient(45deg, var(--border) 25%, transparent 25%, transparent 75%, var(--border) 75%),
    linear-gradient(45deg, var(--border) 25%, transparent 25%, transparent 75%, var(--border) 75%);
  background-size: 16px 16px; background-position: 0 0, 8px 8px;
}
.qr-preview canvas { display: block; width: 100%; height: auto; max-width: 260px; margin: 0 auto; border-radius: 4px; }
.qr-url { display: flex; align-items: center; gap: 6px; margin: 10px 0 0; font-size: 13px; }
.qr-url code { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }
.qr-controls .row.three { display: grid; gap: 12px; grid-template-columns: repeat(3, minmax(0, 1fr)); }
.qr-controls .field { margin-bottom: 12px; }
.qr-controls label .val { color: var(--muted); font-weight: 400; }
.toast-wrap { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); display: flex; flex-direction: column; gap: 8px; z-index: 50; width: max-content; max-width: calc(100vw - 32px); }
.toast { background: var(--text); color: var(--bg); padding: 10px 16px; border-radius: 10px; font-size: 14px; font-weight: 500; box-shadow: var(--shadow); animation: pop .18s ease-out; }
.toast.err { background: var(--danger); color: #fff; }
@keyframes pop { from { transform: translateY(8px); opacity: 0; } }
`;

function dashboardPage() {
  const body = `
<style>${DASHBOARD_CSS}</style>
<div class="wrap">
  <header class="top">
    <a class="brand" href="/dashboard">retrac<span>.</span>link</a>
    <form method="post" action="/dashboard/logout"><button class="ghost" type="submit">Sign out</button></form>
  </header>

  <div class="grid">
    <form class="card" id="create-form" autocomplete="off">
      <h2>Create a link</h2>
      <p class="sub">Shorten any URL. Leave the short code blank for a random one.</p>
      <div class="field">
        <label for="c-url">Destination URL</label>
        <input type="text" id="c-url" placeholder="https://example.com/a/very/long/page" required>
      </div>
      <div class="row two">
        <div class="field">
          <label for="c-slug">Short code</label>
          <div class="prefix"><span class="host-label"></span><input type="text" id="c-slug" placeholder="random"></div>
        </div>
        <div class="field">
          <label for="c-nick">Nickname</label>
          <input type="text" id="c-nick" placeholder="e.g. Portfolio">
        </div>
      </div>
      <details class="more">
        <summary>More options</summary>
        <div class="field">
          <label for="c-aliases">Aliases (optional)</label>
          <input type="text" id="c-aliases" placeholder="e.g. gh, git">
          <p class="hint">Extra short codes that go to the same link. Separate with commas or spaces.</p>
        </div>
        <div class="row two">
          <div class="field">
            <label for="c-pass">Password (optional)</label>
            <input type="password" id="c-pass" placeholder="No password" autocomplete="new-password">
          </div>
          <div class="field">
            <label for="c-exp">Expires (optional)</label>
            <input type="datetime-local" id="c-exp">
          </div>
        </div>
      </details>
      <div class="actions"><button type="submit">Create link</button></div>
    </form>

    <form class="card" id="master-form" autocomplete="off">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:4px">
        <h2>Master link</h2>
        <span class="master-status off" id="m-status">Off</span>
      </div>
      <p class="sub">Where <strong class="host-plain"></strong> itself sends visitors.</p>
      <div class="field">
        <label for="m-url">Destination URL</label>
        <input type="text" id="m-url" placeholder="https://your-main-site.com">
      </div>
      <div class="actions" style="justify-content:space-between">
        <label class="toggle"><input type="checkbox" id="m-enabled"> Enabled</label>
        <button type="submit" class="secondary">Save</button>
      </div>
    </form>
  </div>

  <div class="list-head">
    <h2>Your links <span class="muted" id="count" style="font-weight:500"></span></h2>
    <input type="search" id="search" placeholder="Search links…">
  </div>
  <div class="links" id="links"><div class="empty">Loading…</div></div>
</div>

<dialog id="edit-dialog">
  <form method="dialog" id="edit-form" autocomplete="off">
    <h2>Edit link</h2>
    <div class="field">
      <label for="e-url">Destination URL</label>
      <input type="text" id="e-url" required>
    </div>
    <div class="row two">
      <div class="field">
        <label for="e-slug">Short code</label>
        <div class="prefix"><span class="host-label"></span><input type="text" id="e-slug" required></div>
      </div>
      <div class="field">
        <label for="e-nick">Nickname</label>
        <input type="text" id="e-nick">
      </div>
    </div>
    <div class="field">
      <label for="e-aliases">Aliases</label>
      <input type="text" id="e-aliases" placeholder="None">
      <p class="hint">Extra short codes that go to the same link. Separate with commas or spaces.</p>
    </div>
    <div class="row two">
      <div class="field">
        <label for="e-pass" id="e-pass-label">Password</label>
        <input type="password" id="e-pass" autocomplete="new-password">
      </div>
      <div class="field">
        <label for="e-exp">Expires</label>
        <input type="datetime-local" id="e-exp">
      </div>
    </div>
    <div class="field" id="e-remove-wrap">
      <label class="check"><input type="checkbox" id="e-remove-pass"> Remove password protection</label>
    </div>
    <div class="field" style="display:flex;gap:18px;flex-wrap:wrap">
      <label class="toggle"><input type="checkbox" id="e-enabled"> Enabled</label>
      <label class="check"><input type="checkbox" id="e-reset"> Reset click count</label>
    </div>
    <div class="actions">
      <button type="button" class="secondary" id="e-cancel">Cancel</button>
      <button type="submit" id="e-save">Save changes</button>
    </div>
  </form>
</dialog>

<dialog id="delete-dialog">
  <form method="dialog">
    <h2>Delete link?</h2>
    <p class="muted" style="margin:0 0 20px"><strong id="d-name" style="color:var(--text)"></strong> will stop working immediately. This can't be undone.</p>
    <div class="actions">
      <button type="button" class="secondary" id="d-cancel">Cancel</button>
      <button type="button" class="danger" id="d-confirm">Delete</button>
    </div>
  </form>
</dialog>

<dialog id="qr-dialog" class="wide">
  <form method="dialog" autocomplete="off">
    <h2>QR code</h2>
    <div class="qr-layout">
      <div>
        <div class="qr-preview"><canvas id="qr-canvas" width="520" height="520"></canvas></div>
        <div class="qr-url"><code id="qr-url"></code><button type="button" class="ghost" id="qr-copy-url">Copy</button></div>
        <p class="hint">Scans go through <strong>/qr/</strong> so they're counted separately from regular clicks.</p>
      </div>
      <div class="qr-controls">
        <div class="row two">
          <div class="field">
            <label for="qr-dots">Dot style</label>
            <select id="qr-dots">
              <option value="square">Square</option>
              <option value="rounded">Rounded</option>
              <option value="dots">Dots</option>
            </select>
          </div>
          <div class="field">
            <label for="qr-eyes">Corner style</label>
            <select id="qr-eyes">
              <option value="square">Square</option>
              <option value="rounded">Rounded</option>
              <option value="circle">Circle</option>
            </select>
          </div>
        </div>
        <div class="row three">
          <div class="field"><label for="qr-fg">Dots</label><input type="color" id="qr-fg"></div>
          <div class="field"><label for="qr-eye">Corners</label><input type="color" id="qr-eye"></div>
          <div class="field"><label for="qr-bg">Background</label><input type="color" id="qr-bg"></div>
        </div>
        <div class="field">
          <label class="check"><input type="checkbox" id="qr-transparent"> Transparent background</label>
        </div>
        <div class="row two">
          <div class="field">
            <label for="qr-logo">Center logo</label>
            <select id="qr-logo">
              <option value="none">None</option>
              <option value="site">retrac.link icon</option>
              <option value="custom">Upload image…</option>
            </select>
            <input type="file" id="qr-logo-file" accept="image/png,image/jpeg,image/webp,image/gif" hidden>
          </div>
          <div class="field">
            <label for="qr-ecl">Error correction</label>
            <select id="qr-ecl">
              <option value="L">Low (7%)</option>
              <option value="M">Medium (15%)</option>
              <option value="Q">Quartile (25%)</option>
              <option value="H">High (30%)</option>
            </select>
          </div>
        </div>
        <div class="row two">
          <div class="field">
            <label for="qr-margin">Margin <span class="val" id="qr-margin-val"></span></label>
            <input type="range" id="qr-margin" min="0" max="8" step="1">
          </div>
          <div class="field">
            <label for="qr-size">PNG size</label>
            <select id="qr-size">
              <option value="256">256 × 256</option>
              <option value="512">512 × 512</option>
              <option value="1024">1024 × 1024</option>
              <option value="2048">2048 × 2048</option>
            </select>
          </div>
        </div>
        <p class="hint" id="qr-hint" style="margin:-4px 0 14px"></p>
      </div>
    </div>
    <div class="actions" style="justify-content:space-between">
      <button type="button" class="ghost" id="qr-reset">Reset style</button>
      <div class="actions">
        <button type="button" class="secondary" id="qr-close">Close</button>
        <button type="button" class="secondary" id="qr-copy-img">Copy image</button>
        <button type="button" class="secondary" id="qr-svg">SVG</button>
        <button type="button" id="qr-png">Download PNG</button>
      </div>
    </div>
  </form>
</dialog>

<div class="toast-wrap" id="toasts"></div>`;
  // Wrangler's bundler (esbuild with keepNames) injects `__name(fn, "name")`
  // calls into every function, including this one. Those calls survive
  // Function#toString, so define a no-op `__name` for the browser.
  return layout(
    "Dashboard · retrac.link",
    body,
    `var __name = (fn) => fn;\n(${dashboardApp.toString()})(${qrEncode.toString()});`,
  );
}

/**
 * Client-side dashboard code. Serialized with Function#toString and inlined
 * into the page, so it must not reference anything outside its own body.
 * `qrEncode` (from ./qr.js) is inlined the same way and passed in as `encodeQr`.
 */
function dashboardApp(encodeQr) {
  const $ = (sel) => document.querySelector(sel);
  const host = location.host;
  let links = [];
  let editing = null;
  let deleting = null;

  document.querySelectorAll(".host-label").forEach((el) => (el.textContent = host + "/"));
  document.querySelectorAll(".host-plain").forEach((el) => (el.textContent = host));

  async function api(method, path, body) {
    const res = await fetch("/api" + path, {
      method,
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Requested-With": "retrac-dashboard" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 401) {
      location.reload();
      throw new Error("Your session expired.");
    }
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
    return data;
  }

  function toast(message, isError) {
    const el = document.createElement("div");
    el.className = "toast" + (isError ? " err" : "");
    el.textContent = message;
    $("#toasts").appendChild(el);
    setTimeout(() => el.remove(), isError ? 5000 : 2600);
  }

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  function toLocalInput(ms) {
    if (!ms) return "";
    const d = new Date(ms);
    return new Date(ms - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  }

  function fromLocalInput(value) {
    return value ? new Date(value).getTime() : null;
  }

  function fmtDate(ms) {
    return new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  async function busy(button, fn) {
    button.disabled = true;
    try {
      await fn();
    } catch (err) {
      toast(err.message, true);
    } finally {
      button.disabled = false;
    }
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast("Copied " + text.replace(/^https?:\/\//, ""));
    } catch {
      toast("Couldn't copy to clipboard", true);
    }
  }

  function render() {
    const q = $("#search").value.trim().toLowerCase();
    const list = $("#links");
    list.replaceChildren();
    const shown = links.filter(
      (l) => !q || [l.slug, l.url, l.nickname, ...l.aliases].some((v) => v && v.toLowerCase().includes(q)),
    );
    $("#count").textContent = links.length ? `(${links.length})` : "";
    if (!links.length) {
      list.append(h("div", { class: "empty" }, "No links yet. Create your first one above."));
      return;
    }
    if (!shown.length) {
      list.append(h("div", { class: "empty" }, "No links match your search."));
      return;
    }
    const now = Date.now();
    for (const link of shown) {
      const shortUrl = location.origin + "/" + link.slug;
      const expired = link.expiresAt && link.expiresAt <= now;
      list.append(
        h(
          "div",
          { class: "link" + (!link.enabled || expired ? " inactive" : "") },
          h(
            "div",
            { style: "min-width:0" },
            h(
              "div",
              { class: "title" },
              link.nickname ? h("span", { class: "nick" }, link.nickname) : null,
              h("a", { class: "short", href: shortUrl, target: "_blank", rel: "noopener" }, host + "/" + link.slug),
              link.hasPassword ? h("span", { class: "badge lock" }, "Password") : null,
              !link.enabled ? h("span", { class: "badge off" }, "Disabled") : null,
              expired ? h("span", { class: "badge exp" }, "Expired") : null,
            ),
            link.aliases.length
              ? h(
                  "div",
                  { class: "aliases" },
                  "Also:",
                  link.aliases.map((a) =>
                    h("a", { href: location.origin + "/" + a, target: "_blank", rel: "noopener" }, "/" + a),
                  ),
                )
              : null,
            h("div", { class: "dest", title: link.url }, "→ " + link.url),
            h(
              "div",
              { class: "meta" },
              h("span", {}, `${link.clicks} click${link.clicks === 1 ? "" : "s"}`),
              link.qrClicks ? h("span", {}, `${link.qrClicks} from QR`) : null,
              h("span", {}, "Created " + fmtDate(link.createdAt)),
              link.expiresAt && !expired ? h("span", {}, "Expires " + fmtDate(link.expiresAt)) : null,
            ),
          ),
          h(
            "div",
            { class: "btns" },
            h("button", { class: "ghost", type: "button", onclick: () => copy(shortUrl) }, "Copy"),
            h("button", { class: "ghost", type: "button", onclick: () => openQr(link) }, "QR"),
            h("button", { class: "ghost", type: "button", onclick: () => openEdit(link) }, "Edit"),
            h("button", { class: "ghost danger-text", type: "button", onclick: () => openDelete(link) }, "Delete"),
          ),
        ),
      );
    }
  }

  async function loadLinks() {
    try {
      links = (await api("GET", "/links")).links;
      render();
    } catch (err) {
      $("#links").replaceChildren(h("div", { class: "empty" }, "Couldn't load links: " + err.message));
    }
  }

  function setMasterStatus(enabled) {
    const el = $("#m-status");
    el.textContent = enabled ? "On" : "Off";
    el.className = "master-status " + (enabled ? "on" : "off");
  }

  async function loadMaster() {
    try {
      const m = await api("GET", "/master");
      $("#m-url").value = m.url || "";
      $("#m-enabled").checked = Boolean(m.enabled);
      setMasterStatus(m.enabled);
    } catch (err) {
      toast("Couldn't load master link: " + err.message, true);
    }
  }

  // Create
  $("#create-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const btn = e.submitter || $("#create-form button[type=submit]");
    busy(btn, async () => {
      const link = await api("POST", "/links", {
        url: $("#c-url").value,
        slug: $("#c-slug").value,
        nickname: $("#c-nick").value,
        aliases: $("#c-aliases").value,
        password: $("#c-pass").value,
        expiresAt: fromLocalInput($("#c-exp").value),
      });
      links.unshift(link);
      render();
      $("#create-form").reset();
      copy(location.origin + "/" + link.slug);
    });
  });

  // Master link
  $("#master-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const btn = e.submitter || $("#master-form button[type=submit]");
    busy(btn, async () => {
      const m = await api("PUT", "/master", { url: $("#m-url").value, enabled: $("#m-enabled").checked });
      $("#m-url").value = m.url;
      setMasterStatus(m.enabled);
      toast(m.enabled ? `${host} now redirects to ${m.url}` : "Master link saved (off)");
    });
  });

  // Edit
  const editDialog = $("#edit-dialog");
  function openEdit(link) {
    editing = link;
    $("#e-url").value = link.url;
    $("#e-slug").value = link.slug;
    $("#e-nick").value = link.nickname;
    $("#e-aliases").value = link.aliases.join(", ");
    $("#e-pass").value = "";
    $("#e-pass").placeholder = link.hasPassword ? "Leave blank to keep current" : "No password";
    $("#e-pass-label").textContent = link.hasPassword ? "New password" : "Password";
    $("#e-remove-wrap").style.display = link.hasPassword ? "" : "none";
    $("#e-remove-pass").checked = false;
    $("#e-exp").value = toLocalInput(link.expiresAt);
    $("#e-enabled").checked = link.enabled;
    $("#e-reset").checked = false;
    editDialog.showModal();
  }
  $("#e-cancel").addEventListener("click", () => editDialog.close());
  $("#edit-form").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!editing) return;
    busy($("#e-save"), async () => {
      const updated = await api("PATCH", "/links/" + encodeURIComponent(editing.slug), {
        url: $("#e-url").value,
        slug: $("#e-slug").value,
        nickname: $("#e-nick").value,
        aliases: $("#e-aliases").value,
        password: $("#e-remove-pass").checked ? "" : $("#e-pass").value,
        removePassword: $("#e-remove-pass").checked,
        expiresAt: fromLocalInput($("#e-exp").value),
        enabled: $("#e-enabled").checked,
        resetClicks: $("#e-reset").checked,
      });
      links = links.map((l) => (l.slug === editing.slug ? updated : l));
      editing = null;
      editDialog.close();
      render();
      toast("Link updated");
    });
  });

  // Delete
  const deleteDialog = $("#delete-dialog");
  function openDelete(link) {
    deleting = link;
    $("#d-name").textContent = host + "/" + link.slug;
    deleteDialog.showModal();
  }
  $("#d-cancel").addEventListener("click", () => deleteDialog.close());
  $("#d-confirm").addEventListener("click", () => {
    if (!deleting) return;
    busy($("#d-confirm"), async () => {
      await api("DELETE", "/links/" + encodeURIComponent(deleting.slug));
      links = links.filter((l) => l.slug !== deleting.slug);
      deleting = null;
      deleteDialog.close();
      render();
      toast("Link deleted");
    });
  });

  // QR codes
  const QR_DEFAULTS = {
    dots: "square",
    eyes: "square",
    fg: "#0f1419",
    eye: "#0f1419",
    bg: "#ffffff",
    transparent: false,
    logo: "none",
    ecl: "M",
    margin: 4,
    size: 1024,
  };
  const QR_STORE = "retrac-qr-style";
  const QR_CHOICES = {
    dots: ["square", "rounded", "dots"],
    eyes: ["square", "rounded", "circle"],
    logo: ["none", "site", "custom"],
    ecl: ["L", "M", "Q", "H"],
    size: [256, 512, 1024, 2048],
  };
  const qrDialog = $("#qr-dialog");
  const qrLogos = { site: null, custom: null }; // { img, dataUrl }
  let qrStyle = loadQrStyle();
  let qrLink = null;
  let qrRenderId = 0;

  function cleanQrStyle(raw) {
    const style = { ...QR_DEFAULTS };
    const isColor = (v) => typeof v === "string" && /^#[0-9a-f]{6}$/i.test(v);
    for (const key of ["fg", "eye", "bg"]) if (isColor(raw[key])) style[key] = raw[key];
    for (const [key, options] of Object.entries(QR_CHOICES)) if (options.includes(raw[key])) style[key] = raw[key];
    const margin = Number(raw.margin);
    if (Number.isInteger(margin) && margin >= 0 && margin <= 8) style.margin = margin;
    style.transparent = raw.transparent === true;
    return style;
  }

  function loadQrStyle() {
    try {
      return cleanQrStyle(JSON.parse(localStorage.getItem(QR_STORE)) || {});
    } catch {
      return { ...QR_DEFAULTS };
    }
  }

  function saveQrStyle() {
    try {
      localStorage.setItem(QR_STORE, JSON.stringify(qrStyle));
    } catch {
      // Storage can be unavailable (private mode); the style just won't be remembered.
    }
  }

  const qrUrl = (link) => location.origin + "/qr/" + encodeURIComponent(link.slug);

  function syncQrControls() {
    if (qrStyle.logo === "custom" && !qrLogos.custom) qrStyle.logo = "none";
    $("#qr-dots").value = qrStyle.dots;
    $("#qr-eyes").value = qrStyle.eyes;
    $("#qr-fg").value = qrStyle.fg;
    $("#qr-eye").value = qrStyle.eye;
    $("#qr-bg").value = qrStyle.bg;
    $("#qr-transparent").checked = qrStyle.transparent;
    $("#qr-bg").disabled = qrStyle.transparent;
    $("#qr-logo").value = qrStyle.logo;
    // A logo covers part of the code, so it always uses the highest level.
    $("#qr-ecl").value = qrStyle.logo === "none" ? qrStyle.ecl : "H";
    $("#qr-ecl").disabled = qrStyle.logo !== "none";
    $("#qr-margin").value = qrStyle.margin;
    $("#qr-margin-val").textContent = `(${qrStyle.margin})`;
    $("#qr-size").value = String(qrStyle.size);
  }

  function readQrControls() {
    qrStyle = cleanQrStyle({
      dots: $("#qr-dots").value,
      eyes: $("#qr-eyes").value,
      fg: $("#qr-fg").value,
      eye: $("#qr-eye").value,
      bg: $("#qr-bg").value,
      transparent: $("#qr-transparent").checked,
      logo: $("#qr-logo").value,
      ecl: $("#qr-ecl").disabled ? qrStyle.ecl : $("#qr-ecl").value,
      margin: Number($("#qr-margin").value),
      size: Number($("#qr-size").value),
    });
  }

  function readAsDataUrl(blob) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error("Couldn't read the image."));
      reader.readAsDataURL(blob);
    });
  }

  function loadImage(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error("Couldn't load the image."));
      img.src = src;
    });
  }

  async function getQrLogo() {
    if (qrStyle.logo === "custom") return qrLogos.custom;
    if (qrStyle.logo !== "site") return null;
    if (!qrLogos.site) {
      const res = await fetch("/favicon.png");
      if (!res.ok) throw new Error("Couldn't load the retrac.link icon.");
      const dataUrl = await readAsDataUrl(await res.blob());
      qrLogos.site = { img: await loadImage(dataUrl), dataUrl };
    }
    return qrLogos.site;
  }

  // Builds the code as SVG path data in module units (1 unit = 1 module).
  function qrGeometry(text, style) {
    const qr = encodeQr(text, style.logo === "none" ? style.ecl : "H");
    const n = qr.size;
    const m = style.margin;
    const total = n + m * 2;

    let logoBox = null;
    let hidden = () => false;
    if (style.logo !== "none") {
      let span = Math.round(n * 0.24);
      if ((n - span) % 2) span++;
      const lo = (n - span) / 2;
      logoBox = { x: lo + m, y: lo + m, size: span };
      hidden = (x, y) => x >= lo && x < lo + span && y >= lo && y < lo + span;
    }
    const dark = (x, y) =>
      x >= 0 && y >= 0 && x < n && y < n && qr.modules[y][x] && !qr.isFinder(x, y) && !hidden(x, y);

    const f = (v) => +v.toFixed(3);
    // Rounded rectangle; corner radii are given clockwise from the top left.
    const rect = (x, y, w, h, tl = 0, tr = tl, br = tl, bl = tl) =>
      `M${f(x + tl)} ${f(y)}H${f(x + w - tr)}` +
      (tr ? `A${f(tr)} ${f(tr)} 0 0 1 ${f(x + w)} ${f(y + tr)}` : "") +
      `V${f(y + h - br)}` +
      (br ? `A${f(br)} ${f(br)} 0 0 1 ${f(x + w - br)} ${f(y + h)}` : "") +
      `H${f(x + bl)}` +
      (bl ? `A${f(bl)} ${f(bl)} 0 0 1 ${f(x)} ${f(y + h - bl)}` : "") +
      `V${f(y + tl)}` +
      (tl ? `A${f(tl)} ${f(tl)} 0 0 1 ${f(x + tl)} ${f(y)}` : "") +
      "Z";
    const circle = (cx, cy, r) =>
      `M${f(cx - r)} ${f(cy)}A${f(r)} ${f(r)} 0 1 1 ${f(cx + r)} ${f(cy)}A${f(r)} ${f(r)} 0 1 1 ${f(cx - r)} ${f(cy)}Z`;

    let dots = "";
    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        if (!dark(x, y)) continue;
        if (style.dots === "dots") {
          dots += circle(x + m + 0.5, y + m + 0.5, 0.42);
        } else if (style.dots === "rounded") {
          // Round a corner only when neither neighbour on that corner is dark.
          const up = dark(x, y - 1);
          const down = dark(x, y + 1);
          const left = dark(x - 1, y);
          const right = dark(x + 1, y);
          const r = 0.5;
          dots += rect(
            x + m, y + m, 1, 1,
            !up && !left ? r : 0,
            !up && !right ? r : 0,
            !down && !right ? r : 0,
            !down && !left ? r : 0,
          );
        } else {
          // Merge horizontal runs into one rectangle.
          let run = 1;
          while (dark(x + run, y)) run++;
          dots += rect(x + m, y + m, run, 1);
          x += run - 1;
        }
      }
    }

    // Finder patterns ("eyes"), drawn with the even-odd rule so the ring has a hole.
    let eyes = "";
    for (const [ex, ey] of [[0, 0], [n - 7, 0], [0, n - 7]]) {
      const x = ex + m;
      const y = ey + m;
      if (style.eyes === "circle") {
        eyes += circle(x + 3.5, y + 3.5, 3.5) + circle(x + 3.5, y + 3.5, 2.5) + circle(x + 3.5, y + 3.5, 1.5);
      } else {
        const rounded = style.eyes === "rounded";
        eyes += rect(x, y, 7, 7, rounded ? 2 : 0) + rect(x + 1, y + 1, 5, 5, rounded ? 1.2 : 0) + rect(x + 2, y + 2, 3, 3, rounded ? 0.9 : 0);
      }
    }

    return { n, total, dots, eyes, logoBox };
  }

  // Fits the logo inside its box (keeping its aspect ratio).
  function logoPlacement(geo, logo) {
    const pad = 0.6;
    const box = geo.logoBox;
    const avail = box.size - pad * 2;
    const ratio = logo.img.naturalWidth / logo.img.naturalHeight || 1;
    const w = ratio >= 1 ? avail : avail * ratio;
    const h = ratio >= 1 ? avail / ratio : avail;
    return { x: box.x + (box.size - w) / 2, y: box.y + (box.size - h) / 2, w, h };
  }

  function drawQr(canvas, px, geo, style, logo) {
    canvas.width = px;
    canvas.height = px;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, px, px);
    if (!style.transparent) {
      ctx.fillStyle = style.bg;
      ctx.fillRect(0, 0, px, px);
    }
    ctx.save();
    ctx.scale(px / geo.total, px / geo.total);
    ctx.fillStyle = style.fg;
    ctx.fill(new Path2D(geo.dots));
    ctx.fillStyle = style.eye;
    ctx.fill(new Path2D(geo.eyes), "evenodd");
    if (logo && geo.logoBox) {
      const p = logoPlacement(geo, logo);
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = "high";
      ctx.drawImage(logo.img, p.x, p.y, p.w, p.h);
    }
    ctx.restore();
  }

  function qrSvg(geo, style, logo) {
    const t = geo.total;
    let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${t} ${t}" width="${t * 10}" height="${t * 10}" shape-rendering="geometricPrecision">`;
    if (!style.transparent) svg += `<rect width="${t}" height="${t}" fill="${style.bg}"/>`;
    svg += `<path fill="${style.fg}" d="${geo.dots}"/>`;
    svg += `<path fill="${style.eye}" fill-rule="evenodd" d="${geo.eyes}"/>`;
    if (logo && geo.logoBox) {
      const p = logoPlacement(geo, logo);
      svg += `<image x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" preserveAspectRatio="xMidYMid meet" href="${logo.dataUrl}"/>`;
    }
    return svg + "</svg>";
  }

  function luminance(hex) {
    const [r, g, b] = [1, 3, 5].map((i) => {
      const c = parseInt(hex.slice(i, i + 2), 16) / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }

  function qrHint(geo, style) {
    const notes = [`${geo.n} × ${geo.n} modules.`];
    if (style.logo !== "none") notes.push("High error correction is used so the code still scans under the logo.");
    if (style.transparent) {
      notes.push("Make sure the surface behind it contrasts with the dots.");
    } else {
      const fg = Math.min(luminance(style.fg), luminance(style.eye));
      const bg = luminance(style.bg);
      if (fg > bg) notes.push("Light dots on a dark background don't scan in every app.");
      else if ((bg + 0.05) / (Math.max(luminance(style.fg), luminance(style.eye)) + 0.05) < 3)
        notes.push("Low contrast: the code may be hard to scan.");
    }
    if (style.margin < 2) notes.push("A margin of at least 2 helps scanners find the code.");
    return notes.join(" ");
  }

  async function renderQr() {
    if (!qrLink) return;
    const id = ++qrRenderId;
    syncQrControls();
    saveQrStyle();
    const style = qrStyle;
    let geo;
    try {
      geo = qrGeometry(qrUrl(qrLink), style);
    } catch (err) {
      $("#qr-hint").textContent = err.message;
      return;
    }
    let logo = null;
    try {
      logo = await getQrLogo();
    } catch (err) {
      toast(err.message, true);
    }
    if (id !== qrRenderId) return;
    drawQr($("#qr-canvas"), 520, geo, style, logo);
    $("#qr-hint").textContent = qrHint(geo, style);
  }

  async function qrPngBlob() {
    const canvas = document.createElement("canvas");
    drawQr(canvas, qrStyle.size, qrGeometry(qrUrl(qrLink), qrStyle), qrStyle, await getQrLogo());
    return new Promise((resolve, reject) =>
      canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("Couldn't create the image."))), "image/png"),
    );
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const qrFilename = (ext) => `${host.replace(/[^a-z0-9.-]/gi, "-")}-${qrLink.slug}-qr.${ext}`;

  function openQr(link) {
    qrLink = link;
    $("#qr-url").textContent = qrUrl(link).replace(/^https?:\/\//, "");
    $("#qr-url").title = qrUrl(link);
    qrDialog.showModal();
    renderQr();
  }

  for (const id of ["#qr-dots", "#qr-eyes", "#qr-fg", "#qr-eye", "#qr-bg", "#qr-transparent", "#qr-ecl", "#qr-margin", "#qr-size"]) {
    $(id).addEventListener("input", () => {
      readQrControls();
      renderQr();
    });
  }
  $("#qr-logo").addEventListener("change", () => {
    if ($("#qr-logo").value === "custom") {
      // Keep the current choice until an image is actually picked.
      $("#qr-logo").value = qrStyle.logo;
      $("#qr-logo-file").value = "";
      $("#qr-logo-file").click();
      return;
    }
    readQrControls();
    renderQr();
  });
  $("#qr-logo-file").addEventListener("change", async () => {
    const file = $("#qr-logo-file").files[0];
    if (!file) return;
    if (!file.type.startsWith("image/")) return toast("Choose an image file.", true);
    if (file.size > 2 * 1024 * 1024) return toast("Logo images must be 2 MB or smaller.", true);
    try {
      const dataUrl = await readAsDataUrl(file);
      qrLogos.custom = { img: await loadImage(dataUrl), dataUrl };
      qrStyle.logo = "custom";
      renderQr();
    } catch (err) {
      toast(err.message, true);
    }
  });
  $("#qr-reset").addEventListener("click", () => {
    qrStyle = { ...QR_DEFAULTS };
    renderQr();
  });
  $("#qr-close").addEventListener("click", () => qrDialog.close());
  qrDialog.addEventListener("close", () => {
    qrLink = null;
  });
  $("#qr-copy-url").addEventListener("click", () => qrLink && copy(qrUrl(qrLink)));
  $("#qr-png").addEventListener("click", () => {
    if (!qrLink) return;
    busy($("#qr-png"), async () => downloadBlob(await qrPngBlob(), qrFilename("png")));
  });
  $("#qr-svg").addEventListener("click", () => {
    if (!qrLink) return;
    busy($("#qr-svg"), async () => {
      const svg = qrSvg(qrGeometry(qrUrl(qrLink), qrStyle), qrStyle, await getQrLogo());
      downloadBlob(new Blob([svg], { type: "image/svg+xml" }), qrFilename("svg"));
    });
  });
  $("#qr-copy-img").addEventListener("click", () => {
    if (!qrLink) return;
    busy($("#qr-copy-img"), async () => {
      if (typeof ClipboardItem === "undefined" || !navigator.clipboard || !navigator.clipboard.write) {
        throw new Error("Your browser can't copy images. Download it instead.");
      }
      // Passing the promise (not the blob) keeps Safari's user-gesture check happy.
      await navigator.clipboard.write([new ClipboardItem({ "image/png": qrPngBlob() })]);
      toast("QR code copied");
    });
  });

  $("#search").addEventListener("input", render);

  loadLinks();
  loadMaster();
}
