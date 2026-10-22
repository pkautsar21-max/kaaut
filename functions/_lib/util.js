// Shared helpers for all /api routes.

export const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// Wrap a handler so thrown HttpErrors become JSON {error} responses.
export const handle = fn => async ctx => {
  try {
    if (!ctx.env.DB) throw new HttpError(500, 'Server isn’t set up yet (database missing).');
    return await fn(ctx);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: 'Something went wrong on the server. Try again in a moment.' }, 500);
  }
};

export async function readBody(request) {
  const text = await request.text();
  if (text.length > 400000) throw new HttpError(413, 'That request was too big.');
  try { const b = JSON.parse(text || '{}'); return b && typeof b === 'object' ? b : {}; }
  catch { throw new HttpError(400, 'Bad request.'); }
}

/* ---------- crypto ---------- */
const enc = new TextEncoder();
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));

export async function sha256(str) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(str)));
}
export const randomHex = n => toHex(crypto.getRandomValues(new Uint8Array(n)));

// PBKDF2 is built into Workers; 100,000 iterations is the maximum Cloudflare allows.
async function pbkdf2(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: 100000 }, key, 256));
}
export async function hashPassword(password) {
  const salt = randomHex(16);
  return { salt, hash: await pbkdf2(password, salt) };
}
export async function checkPassword(password, salt, hash) {
  if (!salt || !hash) return false;
  const a = await pbkdf2(password, salt);
  if (a.length !== hash.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ hash.charCodeAt(i);
  return d === 0;
}

/* ---------- validation ---------- */
const ID_RE = /^[0-9a-zA-Z-]{16,64}$/;
const TOKEN_RE = /^[0-9a-zA-Z]{16,96}$/;
const SLUG_RE = /^[a-zA-Z0-9_-]{1,30}$/;
export const USERNAME_RE = /^[a-z0-9_.-]{3,20}$/;

export const validCreds = (id, token) => typeof id === 'string' && typeof token === 'string' && ID_RE.test(id) && TOKEN_RE.test(token);
export const cleanSlug = v => (typeof v === 'string' && SLUG_RE.test(v) ? v : null);

export function cleanName(v) {
  const name = String(v ?? '').replace(/[\u0000-\u001f\u007f<>]/g, '').replace(/\s+/g, ' ').trim();
  const len = [...name].length;
  if (len < 2 || len > 20) throw new HttpError(400, 'Pick a name with 2–20 characters.');
  return name;
}

/* ---------- sessions / auth ---------- */
const SESSION_CAP = 20;

export async function getPlayer(db, id) {
  return db.prepare('SELECT * FROM players WHERE id = ?').bind(id).first();
}

// Returns the player row if (id, token) is a valid session, else null.
export async function authenticate(db, id, token) {
  if (!validCreds(id, token)) return null;
  const th = await sha256(token);
  return db.prepare(
    'SELECT p.* FROM sessions s JOIN players p ON p.id = s.player_id WHERE s.token_hash = ? AND p.id = ?'
  ).bind(th, id).first();
}

export async function addSession(db, playerId, token) {
  const th = await sha256(token);
  const now = Date.now();
  await db.batch([
    db.prepare('INSERT OR IGNORE INTO sessions (token_hash, player_id, created_at) VALUES (?, ?, ?)').bind(th, playerId, now),
    db.prepare(`DELETE FROM sessions WHERE player_id = ? AND token_hash NOT IN
      (SELECT token_hash FROM sessions WHERE player_id = ? ORDER BY created_at DESC LIMIT ${SESSION_CAP})`).bind(playerId, playerId),
  ]);
}

// Sign in with (id, token). If the player doesn't exist yet, create a guest row for it.
export async function authOrCreate(db, id, token) {
  if (!validCreds(id, token)) throw new HttpError(400, 'Bad request.');
  const existing = await getPlayer(db, id);
  if (!existing) {
    const now = Date.now();
    await db.prepare('INSERT OR IGNORE INTO players (id, created_at, updated_at) VALUES (?, ?, ?)').bind(id, now, now).run();
    await addSession(db, id, token);
  }
  const p = await authenticate(db, id, token);
  if (!p) throw new HttpError(401, 'You’re signed out on this device. Please log in again.');
  return p;
}

/* ---------- progress snapshots ---------- */
const num = (v, lo, hi) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.round(v))) : null);
const shortKey = k => typeof k === 'string' && k.length > 0 && k.length <= 60;

export function cleanProgress(p) {
  const out = { best: {}, ach: {}, col: {}, stats: {} };
  if (!p || typeof p !== 'object') return out;
  for (const [k, v] of Object.entries(p.best || {}).slice(0, 300)) {
    const n = num(v, 0, 100); if (shortKey(k) && n != null) out.best[k] = n;
  }
  const ach = Array.isArray(p.ach) ? Object.fromEntries(p.ach.map(k => [k, 1])) : p.ach || {};
  for (const [k, v] of Object.entries(ach).slice(0, 300)) {
    const n = num(Number(v), 0, 9e15); if (shortKey(k) && n != null) out.ach[k] = n;
  }
  for (const [k, v] of Object.entries(p.col || {}).slice(0, 400)) {
    const n = num(v, 0, 1e6); if (shortKey(k) && n != null) out.col[k] = n;
  }
  const s = p.stats && typeof p.stats === 'object' ? p.stats : {};
  for (const f of ['answered', 'correct', 'quizzes', 'totalMs', 'totalQ', 'tips', 'bestStreak']) {
    const n = num(s[f], 0, 9e12); if (n != null) out.stats[f] = n;
  }
  out.stats.medals = {};
  for (const m of ['gold', 'silver', 'bronze']) out.stats.medals[m] = num(s.medals?.[m], 0, 1e6) ?? 0;
  out.stats.days = (Array.isArray(s.days) ? s.days : []).filter(d => typeof d === 'string' && d.length <= 12).slice(-90);
  for (const f of ['speedy', 'night', 'comeback']) out.stats[f] = !!s[f];
  out.stats.low = {};
  for (const [k, v] of Object.entries(s.low || {}).slice(0, 300)) {
    const n = num(v, 0, 101); if (shortKey(k) && n != null) out.stats.low[k] = n;
  }
  return out;
}

export function mergeProgress(a, b) {
  const A = cleanProgress(a), B = cleanProgress(b);
  const out = { best: { ...A.best }, ach: { ...A.ach }, col: { ...A.col }, stats: { ...A.stats } };
  for (const [k, v] of Object.entries(B.best)) out.best[k] = Math.max(out.best[k] ?? 0, v);
  for (const [k, v] of Object.entries(B.ach)) out.ach[k] = out.ach[k] ? Math.min(out.ach[k], v) : v;
  for (const [k, v] of Object.entries(B.col)) out.col[k] = Math.max(out.col[k] || 0, v);
  for (const f of ['answered', 'correct', 'quizzes', 'totalMs', 'totalQ', 'tips', 'bestStreak'])
    out.stats[f] = Math.max(A.stats[f] || 0, B.stats[f] || 0);
  out.stats.medals = {};
  for (const m of ['gold', 'silver', 'bronze']) out.stats.medals[m] = Math.max(A.stats.medals[m], B.stats.medals[m]);
  out.stats.days = [...new Set([...A.stats.days, ...B.stats.days])].sort().slice(-90);
  for (const f of ['speedy', 'night', 'comeback']) out.stats[f] = A.stats[f] || B.stats[f];
  out.stats.low = { ...B.stats.low };
  for (const [k, v] of Object.entries(A.stats.low)) out.stats.low[k] = Math.min(out.stats.low[k] ?? 101, v);
  return out;
}

/* ---------- runs ---------- */
export const xpFor = r => r.correct * 10 + 30 + (r.score === 100 ? 100 : r.score >= 85 ? 60 : r.score >= 70 ? 30 : 0);

function cleanRun(r) {
  if (!r || typeof r !== 'object') return null;
  const id = typeof r.id === 'string' && /^[0-9a-zA-Z-]{8,64}$/.test(r.id) ? r.id : null;
  const module = typeof r.module === 'string' && r.module.length > 0 && r.module.length <= 60 && !/[\u0000-\u001f]/.test(r.module) ? r.module : null;
  const questions = Number.isInteger(r.questions) ? r.questions : null;
  const correct = Number.isInteger(r.correct) ? r.correct : null;
  const durationMs = Number.isFinite(r.durationMs) ? Math.round(r.durationMs) : null;
  const at = Number.isFinite(r.at) ? Math.round(r.at) : null;
  if (!id || !module || questions == null || correct == null || durationMs == null || at == null) return null;
  if (questions < 1 || questions > 200 || correct < 0 || correct > questions) return null;
  if (durationMs < questions * 400 || durationMs > 2 * 3600 * 1000) return null; // too fast to be real / absurdly long
  if (at < Date.UTC(2020, 0, 1) || at > Date.now() + 86400000) return null;
  const streak = Math.min(questions, Math.max(0, Number.isInteger(r.streak) ? r.streak : 0));
  const score = Math.round((correct / questions) * 100);
  const run = { id, module, correct, questions, durationMs, streak, score, at };
  run.xp = xpFor(run);
  return run;
}

// Saves valid runs for a player. Returns {saved: [ids], rejected: [ids]} (both count as "done" for the client).
export async function ingestRuns(db, playerId, rawRuns) {
  const list = (Array.isArray(rawRuns) ? rawRuns : []).slice(0, 100);
  const saved = [], rejected = [], fresh = [];
  const rawIds = list.map(r => (r && typeof r.id === 'string' ? r.id : null)).filter(Boolean);
  const owners = new Map();
  for (let i = 0; i < rawIds.length; i += 50) {
    const part = rawIds.slice(i, i + 50);
    const { results } = await db.prepare(`SELECT id, player_id FROM runs WHERE id IN (${part.map(() => '?').join(',')})`).bind(...part).all();
    for (const row of results) owners.set(row.id, row.player_id);
  }
  const seen = new Set();
  for (const raw of list) {
    const run = cleanRun(raw);
    if (!run) { if (raw && typeof raw.id === 'string') rejected.push(raw.id); continue; }
    if (seen.has(run.id)) continue; seen.add(run.id);
    if (owners.has(run.id)) { (owners.get(run.id) === playerId ? saved : rejected).push(run.id); continue; }
    fresh.push(run); saved.push(run.id);
  }
  if (fresh.length) {
    await db.batch(fresh.map(r => db.prepare(
      'INSERT OR IGNORE INTO runs (id, player_id, module, correct, questions, duration_ms, streak, score, xp, at) VALUES (?,?,?,?,?,?,?,?,?,?)'
    ).bind(r.id, playerId, r.module, r.correct, r.questions, r.durationMs, r.streak, r.score, r.xp, r.at)));
  }
  return { saved, rejected };
}

// What the page gets back when it restores / logs in.
export async function buildProgress(db, player) {
  let stored = {};
  try { stored = JSON.parse(player.progress || '{}'); } catch {}
  const prog = cleanProgress(stored);
  const bests = await db.prepare('SELECT module, MAX(score) AS b FROM runs WHERE player_id = ? GROUP BY module').bind(player.id).all();
  for (const r of bests.results) prog.best[r.module] = Math.max(prog.best[r.module] ?? 0, r.b);
  const xpRow = await db.prepare('SELECT COALESCE(SUM(xp),0) AS xp FROM runs WHERE player_id = ?').bind(player.id).first();
  const recent = await db.prepare(
    'SELECT id, module, correct, questions, duration_ms, streak, score, at FROM runs WHERE player_id = ? ORDER BY at DESC LIMIT 300'
  ).bind(player.id).all();
  const runs = recent.results.reverse().map(r => ({
    id: r.id, module: r.module, correct: r.correct, questions: r.questions,
    durationMs: r.duration_ms, streak: r.streak, score: r.score, at: r.at,
  }));
  return { ...prog, xp: xpRow.xp, runs };
}

// Save a snapshot (without runs/xp, which live in the runs table) onto the player row.
export async function saveProgress(db, playerId, progress, extra = {}) {
  const sets = ['updated_at = ?'], vals = [Date.now()];
  if (progress && typeof progress === 'object') { sets.push('progress = ?'); vals.push(JSON.stringify(cleanProgress(progress))); }
  if (extra.title) { sets.push('title = ?'); vals.push(extra.title); }
  if (extra.avatar) { sets.push('avatar = ?'); vals.push(extra.avatar); }
  if (extra.name) { sets.push('name = ?'); vals.push(extra.name); }
  await db.prepare(`UPDATE players SET ${sets.join(', ')} WHERE id = ?`).bind(...vals, playerId).run();
}
