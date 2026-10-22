import { json, handle } from '../_lib/util.js';

const LIMIT = 50;       // rows shown
const MIN_FOR_RANK = 3; // modules (or fast runs) needed for a numbered rank
const spq = (ms, q) => (q ? Math.round(ms / q / 100) / 10 : null);

export const onRequestGet = handle(async ({ request, env }) => {
  const db = env.DB, url = new URL(request.url);
  const mod = (url.searchParams.get('module') || '').slice(0, 60);
  const board = ['score', 'speed', 'xp'].includes(url.searchParams.get('board')) ? url.searchParams.get('board') : 'score';
  const me = url.searchParams.get('me') || '';

  const { results: players } = await db.prepare("SELECT id, name, avatar, title FROM players WHERE name != ''").all();
  const info = new Map(players.map(p => [p.id, p]));
  const entry = (id, extra) => {
    const p = info.get(id);
    return { id, name: p.name, avatar: p.avatar, title: p.title, me: id === me, ...extra };
  };
  let ranked = [], provisional = [];

  if (mod) {
    // Each player's best attempt on one module; ties go to the faster one.
    const { results } = await db.prepare('SELECT player_id, score, duration_ms, questions FROM runs WHERE module = ?').bind(mod).all();
    const by = new Map();
    for (const r of results) {
      if (!info.has(r.player_id)) continue;
      const cur = by.get(r.player_id) || { attempts: 0, score: -1, ms: 0, q: 1 };
      cur.attempts++;
      const faster = r.duration_ms / r.questions < cur.ms / cur.q;
      if (r.score > cur.score || (r.score === cur.score && faster)) { cur.score = r.score; cur.ms = r.duration_ms; cur.q = r.questions; }
      by.set(r.player_id, cur);
    }
    ranked = [...by].map(([id, v]) => entry(id, { score: v.score, secPerQ: spq(v.ms, v.q), attempts: v.attempts, _s: v.score, _t: v.ms / v.q }))
      .sort((a, b) => b._s - a._s || a._t - b._t);
  } else {
    const { results: bests } = await db.prepare('SELECT player_id, COUNT(*) AS n, AVG(b) AS avg FROM (SELECT player_id, module, MAX(score) AS b FROM runs GROUP BY player_id, module) GROUP BY player_id').all();
    const { results: all } = await db.prepare('SELECT player_id, COUNT(*) AS runs, SUM(duration_ms) AS ms, SUM(questions) AS q, SUM(xp) AS xp FROM runs GROUP BY player_id').all();
    const { results: fast } = await db.prepare('SELECT player_id, COUNT(*) AS n, SUM(duration_ms) AS ms, SUM(questions) AS q FROM runs WHERE score >= 70 GROUP BY player_id').all();
    const B = new Map(bests.map(r => [r.player_id, r])), A = new Map(all.map(r => [r.player_id, r])), F = new Map(fast.map(r => [r.player_id, r]));
    const rows = [];
    for (const id of info.keys()) {
      const a = A.get(id), bb = B.get(id); if (!a || !bb) continue;
      const f = F.get(id);
      rows.push({ id, modules: bb.n, avgScore: Math.round(bb.avg), runs: a.runs, xp: a.xp,
        secPerQ: spq(a.ms, a.q), fastN: f?.n || 0, fastSec: f ? spq(f.ms, f.q) : null });
    }
    if (board === 'xp') {
      ranked = rows.map(r => entry(r.id, { xp: r.xp, runs: r.runs, _s: r.xp, _t: 0 })).sort((a, b) => b._s - a._s);
    } else if (board === 'speed') {
      const list = rows.filter(r => r.fastN > 0).map(r => ({ r, e: entry(r.id, {
        secPerQ: r.fastSec, avgScore: r.avgScore, modules: r.modules, _s: r.fastSec, _t: 0 }), ok: r.fastN >= MIN_FOR_RANK }));
      list.sort((a, b) => a.e._s - b.e._s);
      ranked = list.filter(x => x.ok).map(x => x.e); provisional = list.filter(x => !x.ok).map(x => x.e);
    } else {
      const list = rows.map(r => ({ e: entry(r.id, { avgScore: r.avgScore, modules: r.modules, secPerQ: r.secPerQ, _s: r.avgScore, _t: r.secPerQ ?? 999 }),
        ok: r.modules >= MIN_FOR_RANK }));
      list.sort((a, b) => b.e._s - a.e._s || a.e._t - b.e._t);
      ranked = list.filter(x => x.ok).map(x => x.e); provisional = list.filter(x => !x.ok).map(x => x.e);
    }
  }

  ranked.forEach((e, i) => { e.rank = i + 1; });
  provisional.forEach(e => { e.rank = null; });
  const full = [...ranked, ...provisional];
  let entries = full.slice(0, LIMIT);
  const mine = full.find(e => e.me);
  if (mine && !entries.includes(mine)) entries.push(mine); // always show the player their own place
  entries = entries.map(({ _s, _t, ...rest }) => rest);
  return json({ entries });
});
