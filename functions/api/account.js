import {
  json, handle, readBody, HttpError, USERNAME_RE, validCreds, randomHex, hashPassword, checkPassword, sha256,
  getPlayer, authenticate, authOrCreate, addSession, cleanName, cleanSlug, cleanProgress, mergeProgress,
  ingestRuns, saveProgress, buildProgress,
} from '../_lib/util.js';

export const onRequestPost = handle(async ({ request, env }) => {
  const db = env.DB, b = await readBody(request);
  switch (b.action) {
    case 'register': return register(db, b);
    case 'login': return login(db, b);
    case 'password': return changePassword(db, b);
    case 'logout': return logout(db, b);
    default: throw new HttpError(400, 'Bad request.');
  }
});

async function register(db, b) {
  const username = String(b.username ?? '').trim().toLowerCase();
  const password = String(b.password ?? '');
  if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Usernames need 3–20 letters, numbers, dots, dashes or underscores.');
  if (password.length < 6 || password.length > 200) throw new HttpError(400, 'Passwords need at least 6 characters.');
  const player = await authOrCreate(db, b.id, b.token);
  if (player.username) throw new HttpError(409, 'This device is already logged in to an account.');
  const taken = await db.prepare('SELECT 1 FROM players WHERE username = ?').bind(username).first();
  if (taken) throw new HttpError(409, 'That username is taken. Try another one.');
  let name = player.name;
  if (b.name) { try { name = cleanName(b.name); } catch { name = player.name || username; } }
  if (!name) name = username;
  const { salt, hash } = await hashPassword(password);
  try {
    await db.prepare('UPDATE players SET username = ?, pass_hash = ?, pass_salt = ?, name = ?, updated_at = ? WHERE id = ?')
      .bind(username, hash, salt, name, Date.now(), player.id).run();
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'That username is taken. Try another one.');
    throw e;
  }
  if (b.progress) await ingestRuns(db, player.id, b.progress.runs);
  await saveProgress(db, player.id, b.progress, { title: cleanSlug(b.title), avatar: cleanSlug(b.avatar) });
  return json({ username, name });
}

async function login(db, b) {
  const username = String(b.username ?? '').trim().toLowerCase();
  const password = String(b.password ?? '');
  const bad = new HttpError(401, 'Wrong username or password.');
  if (!USERNAME_RE.test(username) || !password) throw bad;
  const acct = await db.prepare('SELECT * FROM players WHERE username = ?').bind(username).first();
  if (!acct) { await hashPassword(password); throw bad; } // keep timing similar
  if (!(await checkPassword(password, acct.pass_salt, acct.pass_hash))) throw bad;

  // Optionally fold a guest's progress on this device into the account.
  const g = b.mergeFrom;
  if (g && validCreds(g.id, g.token) && g.id !== acct.id) {
    const guest = await authenticate(db, g.id, g.token);
    if (guest && !guest.username) {
      const merged = mergeProgress(
        (await safeParse(acct.progress)), (await safeParse(guest.progress)));
      await db.batch([
        db.prepare('UPDATE runs SET player_id = ? WHERE player_id = ?').bind(acct.id, guest.id),
        db.prepare('DELETE FROM sessions WHERE player_id = ?').bind(guest.id),
        db.prepare('DELETE FROM players WHERE id = ?').bind(guest.id),
        db.prepare('UPDATE players SET progress = ?, updated_at = ? WHERE id = ?').bind(JSON.stringify(merged), Date.now(), acct.id),
      ]);
      acct.progress = JSON.stringify(merged);
    }
  }

  const token = randomHex(24);
  await addSession(db, acct.id, token);
  return json({
    id: acct.id, token, username: acct.username, name: acct.name || acct.username,
    title: acct.title, avatar: acct.avatar, progress: await buildProgress(db, acct),
  });
}

async function changePassword(db, b) {
  const player = await authenticate(db, b.id, b.token);
  if (!player || !player.username) throw new HttpError(401, 'You’re signed out on this device. Please log in again.');
  const next = String(b.newPassword ?? '');
  if (next.length < 6 || next.length > 200) throw new HttpError(400, 'Passwords need at least 6 characters.');
  if (!(await checkPassword(String(b.password ?? ''), player.pass_salt, player.pass_hash)))
    throw new HttpError(403, 'Your current password isn’t right.');
  const { salt, hash } = await hashPassword(next);
  const keep = await sha256(b.token);
  await db.batch([
    db.prepare('UPDATE players SET pass_hash = ?, pass_salt = ?, updated_at = ? WHERE id = ?').bind(hash, salt, Date.now(), player.id),
    // Sign out every other device.
    db.prepare('DELETE FROM sessions WHERE player_id = ? AND token_hash != ?').bind(player.id, keep),
  ]);
  return json({ ok: true });
}

async function logout(db, b) {
  if (validCreds(b.id, b.token)) {
    await db.prepare('DELETE FROM sessions WHERE token_hash = ? AND player_id = ?').bind(await sha256(b.token), b.id).run();
  }
  return json({ ok: true });
}

async function safeParse(s) { try { return JSON.parse(s || '{}'); } catch { return {}; } }
