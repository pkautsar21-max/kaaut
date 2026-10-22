import { json, handle, readBody, authenticate, cleanSlug, ingestRuns, saveProgress, HttpError } from '../_lib/util.js';

// Upload finished module runs. The page retries until a run is in `saved` or `rejected`.
export const onRequestPost = handle(async ({ request, env }) => {
  const b = await readBody(request);
  const player = await authenticate(env.DB, b.id, b.token);
  if (!player) throw new HttpError(401, 'You’re signed out on this device. Please log in again.');
  const result = await ingestRuns(env.DB, player.id, b.runs);
  await saveProgress(env.DB, player.id, b.progress, { title: cleanSlug(b.title) });
  return json(result);
});
