import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
loadEnv(join(__dirname, ".env"));

const PORT = Number(process.env.PORT || 3000);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const MAX_RESULTS = 100;
const DEFAULT_MAX_PAGES = 5;
const APP_ROOT = join(__dirname, "..");
const INDEX_PATH = join(APP_ROOT, "index.html");
const AUTH_STATE_PATH = join(__dirname, "auth-state.json");
const TRACKER_STATE_PATH = join(__dirname, "tracker-state.json");
const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || DAY_MS);
const AUTH_APP_ID = process.env.AUTH_APP_ID || "kalshi-x-tracker";
const DEFAULT_DAILY_PASSWORD = process.env.AUTH_DAILY_PASSWORD || "CHANGE_ME_DAILY";
const DEFAULT_ADMIN_KEY = process.env.AUTH_ADMIN_KEY || "CHANGE_ME_ADMIN_KEY";

function loadEnv(path) {
  if (!existsSync(path)) return;

  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^["']|["']$/g, "");
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-session-token, x-admin-key"
  });
  response.end(JSON.stringify(payload, null, 2));
}

function sendText(response, statusCode, body, contentType = "text/plain; charset=utf-8") {
  response.writeHead(statusCode, {
    "Content-Type": contentType,
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN
  });
  response.end(body);
}

function sendFile(response, path) {
  const typeByExt = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml"
  };
  try {
    const body = readFileSync(path);
    response.writeHead(200, {
      "Content-Type": typeByExt[extname(path).toLowerCase()] || "application/octet-stream"
    });
    response.end(body);
  } catch {
    sendText(response, 404, "Not found");
  }
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", chunk => {
      body += chunk.toString("utf8");
      if (body.length > 200000) request.destroy();
    });
    request.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

function sanitizeAuthState(raw) {
  const state = raw && typeof raw === "object" ? raw : {};
  return {
    enabled: state.enabled !== false,
    appId: String(state.appId || AUTH_APP_ID).trim() || AUTH_APP_ID,
    dailyPassword: String(state.dailyPassword || DEFAULT_DAILY_PASSWORD).trim() || DEFAULT_DAILY_PASSWORD,
    adminKey: String(state.adminKey || DEFAULT_ADMIN_KEY).trim() || DEFAULT_ADMIN_KEY,
    sessions: state.sessions && typeof state.sessions === "object" ? state.sessions : {},
    loginEvents: Array.isArray(state.loginEvents) ? state.loginEvents : [],
    updatedAt: state.updatedAt || new Date().toISOString()
  };
}

function loadAuthState() {
  try {
    return sanitizeAuthState(JSON.parse(readFileSync(AUTH_STATE_PATH, "utf8")));
  } catch {
    return sanitizeAuthState({});
  }
}

function saveAuthState(state) {
  const next = sanitizeAuthState(state);
  next.updatedAt = new Date().toISOString();
  writeFileSync(AUTH_STATE_PATH, JSON.stringify(next, null, 2), "utf8");
  return next;
}

function sanitizeTrackerState(raw) {
  const state = raw && typeof raw === "object" ? raw : {};
  return {
    version: 1,
    updatedAt: state.updatedAt || new Date().toISOString(),
    posts: state.posts && typeof state.posts === "object" ? state.posts : {},
    settings: state.settings && typeof state.settings === "object" ? state.settings : {}
  };
}

function loadTrackerState() {
  try {
    return sanitizeTrackerState(JSON.parse(readFileSync(TRACKER_STATE_PATH, "utf8")));
  } catch {
    return sanitizeTrackerState({});
  }
}

function saveTrackerState(state) {
  const next = sanitizeTrackerState(state);
  next.updatedAt = new Date().toISOString();
  writeFileSync(TRACKER_STATE_PATH, JSON.stringify(next, null, 2), "utf8");
  return next;
}

function mergeTrackerStates(baseState, incomingState) {
  const base = sanitizeTrackerState(baseState);
  const incoming = sanitizeTrackerState(incomingState);
  const merged = {
    ...base,
    settings: { ...base.settings, ...incoming.settings },
    posts: { ...base.posts }
  };

  for (const [postId, incomingPost] of Object.entries(incoming.posts || {})) {
    const existingPost = merged.posts[postId] || {};
    merged.posts[postId] = {
      ...existingPost,
      ...incomingPost,
      quotes: {
        ...(existingPost.quotes || {}),
        ...(incomingPost.quotes || {})
      }
    };
  }

  return saveTrackerState(merged);
}

function pruneSessions(sessions) {
  const now = Date.now();
  return Object.fromEntries(Object.entries(sessions || {}).filter(([, session]) =>
    session && !session.revoked && Number(session.expiresAt || 0) > now
  ));
}

function clientIp(request) {
  const forwardedFor = request.headers["x-forwarded-for"];
  if (forwardedFor) return String(forwardedFor).split(",")[0].trim();
  return request.socket?.remoteAddress || "";
}

function validSession(request, state) {
  const authHeader = String(request.headers.authorization || "");
  const bearerToken = authHeader.toLowerCase().startsWith("bearer ") ? authHeader.slice(7).trim() : "";
  const token = String(request.headers["x-session-token"] || bearerToken || "").trim();
  if (!state.enabled) return false;
  if (!token) return false;
  state.sessions = pruneSessions(state.sessions);
  const session = state.sessions[token];
  if (!session || session.revoked) return false;
  session.lastSeenAt = Date.now();
  saveAuthState(state);
  return true;
}

function assertAdmin(request, state) {
  const key = String(request.headers["x-admin-key"] || "").trim();
  return Boolean(key && key === state.adminKey);
}

async function handleLogin(request, response, state) {
  let body;
  try {
    body = await readJsonBody(request);
  } catch {
    return sendJson(response, 400, { ok: false, message: "Invalid JSON." });
  }

  if (!state.enabled) return sendJson(response, 403, { ok: false, message: "Access disabled by admin." });
  if (String(body.appId || "") !== state.appId) return sendJson(response, 403, { ok: false, message: "Unknown app id." });
  if (String(body.password || "") !== state.dailyPassword) return sendJson(response, 401, { ok: false, message: "Wrong password." });

  state.sessions = pruneSessions(state.sessions);
  const token = randomBytes(24).toString("hex");
  const createdAt = Date.now();
  state.sessions[token] = {
    username: "daily-password",
    deviceId: String(body.deviceId || "unknown-device"),
    createdAt,
    lastSeenAt: createdAt,
    expiresAt: createdAt + SESSION_TTL_MS,
    ip: clientIp(request),
    userAgent: String(request.headers["user-agent"] || ""),
    revoked: false
  };
  state.loginEvents.push({
    at: new Date().toISOString(),
    username: "daily-password",
    deviceId: String(body.deviceId || "unknown-device"),
    ip: clientIp(request),
    event: "login"
  });
  if (state.loginEvents.length > 1000) state.loginEvents = state.loginEvents.slice(-1000);
  saveAuthState(state);
  return sendJson(response, 200, { ok: true, token, expiresAt: state.sessions[token].expiresAt });
}

async function handleCheck(request, response, state) {
  let body;
  try {
    body = await readJsonBody(request);
  } catch {
    return sendJson(response, 400, { ok: false, message: "Invalid JSON." });
  }
  if (String(body.appId || "") !== state.appId) return sendJson(response, 403, { ok: false, message: "Unknown app id." });
  const token = String(body.token || "").trim();
  state.sessions = pruneSessions(state.sessions);
  if (!token || !state.sessions[token] || state.sessions[token].revoked) {
    return sendJson(response, 401, { ok: false, message: "Session invalid." });
  }
  return sendJson(response, 200, { ok: true, message: "Valid session." });
}

function adminData(state) {
  const now = Date.now();
  const sessions = Object.entries(pruneSessions(state.sessions)).map(([token, session]) => ({
    token,
    username: session.username,
    deviceId: session.deviceId,
    createdAt: session.createdAt,
    lastSeenAt: session.lastSeenAt,
    expiresAt: session.expiresAt,
    ip: session.ip || "",
    userAgent: session.userAgent || "",
    online: now - Number(session.lastSeenAt || 0) < 8 * 60 * 1000
  }));
  sessions.sort((a, b) => Number(b.lastSeenAt || 0) - Number(a.lastSeenAt || 0));
  return {
    enabled: state.enabled,
    appId: state.appId,
    dailyPassword: state.dailyPassword,
    updatedAt: state.updatedAt,
    activeSessions: sessions,
    loginEvents: state.loginEvents.slice(-120).reverse()
  };
}

async function handleAdminUpdate(request, response, state) {
  if (!assertAdmin(request, state)) return sendJson(response, 403, { ok: false, message: "Invalid admin key." });
  let body;
  try {
    body = await readJsonBody(request);
  } catch {
    return sendJson(response, 400, { ok: false, message: "Invalid JSON." });
  }
  if (typeof body.enabled === "boolean") state.enabled = body.enabled;
  if (typeof body.appId === "string" && body.appId.trim()) state.appId = body.appId.trim();
  if (typeof body.dailyPassword === "string" && body.dailyPassword.trim()) state.dailyPassword = body.dailyPassword.trim();
  saveAuthState(state);
  return sendJson(response, 200, { ok: true, message: "Updated." });
}

async function handleAdminRevoke(request, response, state) {
  if (!assertAdmin(request, state)) return sendJson(response, 403, { ok: false, message: "Invalid admin key." });
  let body;
  try {
    body = await readJsonBody(request);
  } catch {
    return sendJson(response, 400, { ok: false, message: "Invalid JSON." });
  }
  const token = String(body.token || "").trim();
  if (!token || !state.sessions[token]) return sendJson(response, 404, { ok: false, message: "Session not found." });
  state.sessions[token].revoked = true;
  state.loginEvents.push({ at: new Date().toISOString(), username: state.sessions[token].username || "", deviceId: state.sessions[token].deviceId || "", ip: "", event: "revoke-session" });
  saveAuthState(state);
  return sendJson(response, 200, { ok: true, message: "Session revoked." });
}

async function handleTrackerStateSave(request, response) {
  let body;
  try {
    body = await readJsonBody(request);
  } catch {
    return sendJson(response, 400, { ok: false, message: "Invalid JSON." });
  }

  if (body.replace) {
    const replaced = saveTrackerState(body.state || body);
    return sendJson(response, 200, { ok: true, state: replaced });
  }

  const merged = mergeTrackerStates(loadTrackerState(), body.state || body);
  return sendJson(response, 200, { ok: true, state: merged });
}

function isQuoteOfOriginal(tweet, originalTweetId) {
  return (tweet.referenced_tweets || []).some(reference =>
    reference.type === "quoted" && String(reference.id) === String(originalTweetId)
  );
}

function normalizeQuote(tweet, users) {
  const user = users.get(String(tweet.author_id)) || {};
  const metrics = tweet.public_metrics || {};

  return {
    id: String(tweet.id),
    url: user.username ? `https://x.com/${user.username}/status/${tweet.id}` : "",
    text: tweet.text || "",
    created_at: tweet.created_at || "",
    author: {
      id: String(user.id || tweet.author_id || ""),
      username: user.username || "",
      name: user.name || "",
      profile_image_url: user.profile_image_url || ""
    },
    metrics: {
      views: metrics.impression_count ?? null,
      likes: metrics.like_count ?? null,
      retweets: metrics.retweet_count ?? null
    }
  };
}

function normalizeOriginalPost(tweet, users) {
  const user = users.get(String(tweet.author_id)) || {};
  const metrics = tweet.public_metrics || {};

  return {
    id: String(tweet.id),
    url: user.username ? `https://x.com/${user.username}/status/${tweet.id}` : `https://x.com/i/web/status/${tweet.id}`,
    text: tweet.text || "",
    created_at: tweet.created_at || "",
    author: {
      id: String(user.id || tweet.author_id || ""),
      username: user.username || "",
      name: user.name || "",
      profile_image_url: user.profile_image_url || ""
    },
    metrics: {
      views: metrics.impression_count ?? null,
      likes: metrics.like_count ?? null,
      retweets: metrics.retweet_count ?? null
    }
  };
}

async function fetchOriginalPost(tweetId) {
  const params = new URLSearchParams({
    expansions: "author_id",
    "tweet.fields": "created_at,public_metrics,text",
    "user.fields": "id,name,username,profile_image_url"
  });

  const response = await fetch(`https://api.twitter.com/2/tweets/${tweetId}?${params}`, {
    headers: {
      Authorization: `Bearer ${process.env.X_BEARER_TOKEN}`
    }
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) return null;

  const users = new Map((payload.includes?.users || []).map(user => [String(user.id), user]));
  return payload.data ? normalizeOriginalPost(payload.data, users) : null;
}

async function fetchQuotePage(tweetId, nextToken) {
  const params = new URLSearchParams({
    expansions: "author_id",
    exclude: "retweets,replies",
    "tweet.fields": "created_at,public_metrics,referenced_tweets,text",
    "user.fields": "id,name,username,profile_image_url",
    max_results: String(MAX_RESULTS)
  });

  if (nextToken) params.set("pagination_token", nextToken);

  const response = await fetch(`https://api.twitter.com/2/tweets/${tweetId}/quote_tweets?${params}`, {
    headers: {
      Authorization: `Bearer ${process.env.X_BEARER_TOKEN}`
    }
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload.detail || payload.title || payload.error || `X API returned ${response.status}`;
    throw new Error(detail);
  }

  return payload;
}

async function fetchQuotes(tweetId, maxPages) {
  const quotes = [];
  let nextToken = "";

  for (let page = 0; page < maxPages; page += 1) {
    const payload = await fetchQuotePage(tweetId, nextToken);
    const users = new Map((payload.includes?.users || []).map(user => [String(user.id), user]));

    for (const tweet of payload.data || []) {
      if (!isQuoteOfOriginal(tweet, tweetId)) continue;
      quotes.push(normalizeQuote(tweet, users));
    }

    nextToken = payload.meta?.next_token || "";
    if (!nextToken) break;
  }

  return quotes;
}

const server = createServer(async (request, response) => {
  if (request.method === "OPTIONS") {
    return sendJson(response, 200, { ok: true });
  }

  const url = new URL(request.url, `http://${request.headers.host}`);
  const authState = loadAuthState();

  if (url.pathname === "/health") {
    return sendJson(response, 200, { ok: true });
  }

  if (request.method === "GET" && url.pathname === "/") {
    return sendFile(response, INDEX_PATH);
  }

  if (request.method === "GET" && url.pathname === "/assets/kalshi-logo.png") {
    return sendFile(response, join(APP_ROOT, "assets", "kalshi-logo.png"));
  }

  if (request.method === "GET" && url.pathname === "/admin") {
    return sendFile(response, join(__dirname, "admin.html"));
  }

  if (request.method === "POST" && url.pathname === "/auth/login") return handleLogin(request, response, authState);
  if (request.method === "POST" && url.pathname === "/auth/check") return handleCheck(request, response, authState);

  if (request.method === "GET" && url.pathname === "/admin/data") {
    if (!assertAdmin(request, authState)) return sendJson(response, 403, { ok: false, message: "Invalid admin key." });
    return sendJson(response, 200, { ok: true, data: adminData(authState) });
  }
  if (request.method === "POST" && url.pathname === "/admin/update") return handleAdminUpdate(request, response, authState);
  if (request.method === "POST" && url.pathname === "/admin/revoke-session") return handleAdminRevoke(request, response, authState);

  if (url.pathname === "/state") {
    if (!validSession(request, authState)) return sendJson(response, 401, { error: "Login required." });
    if (request.method === "GET") return sendJson(response, 200, { ok: true, state: loadTrackerState() });
    if (request.method === "POST") return handleTrackerStateSave(request, response);
    return sendJson(response, 405, { error: "Method not allowed." });
  }

  if (url.pathname !== "/quotes") {
    return sendJson(response, 404, { error: "Use /quotes?tweetId=1234567890" });
  }

  if (!validSession(request, authState)) {
    return sendJson(response, 401, { error: "Login required." });
  }

  if (!process.env.X_BEARER_TOKEN || process.env.X_BEARER_TOKEN.includes("replace_with")) {
    return sendJson(response, 500, { error: "Add X_BEARER_TOKEN to api/.env first." });
  }

  const tweetId = url.searchParams.get("tweetId");
  if (!tweetId || !/^\d+$/.test(tweetId)) {
    return sendJson(response, 400, { error: "Missing or invalid tweetId." });
  }

  const maxPages = Math.max(1, Math.min(Number(url.searchParams.get("maxPages") || DEFAULT_MAX_PAGES), 5));

  try {
    const [originalPost, quotes] = await Promise.all([
      fetchOriginalPost(tweetId),
      fetchQuotes(tweetId, maxPages)
    ]);
    return sendJson(response, 200, {
      tweetId,
      fetchedAt: new Date().toISOString(),
      originalPost,
      quotes
    });
  } catch (error) {
    return sendJson(response, 502, { error: error.message || "Failed to fetch from X API." });
  }
});

server.listen(PORT, () => {
  console.log(`Kalshi X tracker running at http://localhost:${PORT}`);
  console.log(`Admin page: http://localhost:${PORT}/admin`);
});
