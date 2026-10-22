import { json, handle, readBody, authOrCreate, authenticate, cleanName, cleanSlug, ingestRuns, saveProgress, buildProgress, HttpError } from '../_lib/util.js';

// Save / update a player (join the leaderboard, change name, title or picture).
export const onRequestPost = handle(async ({ request, env }) => {
  const b = await readBody(request);
  const player = await authOrCreate(env.DB, b.id, b.token);
  const name = b.name !== undefined && b.name !== '' ? cleanName(b.name) : null;
  if (!name && !player.name) throw new HttpError(400, 'Pick a name with 2–20 characters.');
  if (b.progress) await ingestRuns(env.DB, player.id, b.progress.runs);
  await saveProgress(env.DB, player.id, b.progress, { name, title: cleanSlug(b.title), avatar: cleanSlug(b.avatar) });
  return json({ ok: true, name: name || player.name });
});

// Restore progress on another device using the device code (id + token in headers).
export const onRequestGet = handle(async ({ request, env }) => {
  const id = request.headers.get('x-player-id'), token = request.headers.get('x-player-token');
  const player = await authenticate(env.DB, id, token);
  if (!player || !player.name) throw new HttpError(401, 'That code isn’t valid. Check it and try again.');
  return json({
    id: player.id, name: player.name, title: player.title, avatar: player.avatar,
    username: player.username || '', progress: await buildProgress(env.DB, player),
  });
});
