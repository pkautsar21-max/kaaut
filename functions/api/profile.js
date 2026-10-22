import { json, handle } from '../_lib/util.js';

// Public details for other players (shown when you tap someone on the leaderboard).
export const onRequestGet = handle(async ({ request, env }) => {
  const ids = (new URL(request.url).searchParams.get('ids') || '').split(',')
    .map(s => s.trim()).filter(s => /^[0-9a-zA-Z-]{16,64}$/.test(s)).slice(0, 40);
  const players = {};
  if (ids.length) {
    const q = `SELECT p.id, p.name, p.avatar, p.title, p.progress, COALESCE(x.xp,0) AS xp FROM players p
      LEFT JOIN (SELECT player_id, SUM(xp) AS xp FROM runs GROUP BY player_id) x ON x.player_id = p.id
      WHERE p.name != '' AND p.id IN (${ids.map(() => '?').join(',')})`;
    const { results } = await env.DB.prepare(q).bind(...ids).all();
    for (const r of results) {
      let pr = {}; try { pr = JSON.parse(r.progress || '{}'); } catch {}
      const s = pr.stats || {};
      players[r.id] = {
        id: r.id, name: r.name, avatar: r.avatar, title: r.title, xp: r.xp,
        ach: Object.keys(pr.ach || {}).filter(k => !k.startsWith('title_')),
        col: pr.col || {}, best: pr.best || {},
        stats: { bestStreak: s.bestStreak || 0, totalMs: s.totalMs || 0, totalQ: s.totalQ || 0, quizzes: s.quizzes || 0,
          correct: s.correct || 0, answered: s.answered || 0, medals: s.medals || { gold: 0, silver: 0, bronze: 0 } },
      };
    }
  }
  return json({ players });
});
