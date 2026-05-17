import { APP_HTML, SPEC_HTML, SPEC_MARKDOWN } from "./generated";

type Role = "viewer" | "maintainer" | "owner";

type RuntimeEnv = Env & {
  DB: D1Database;
  CRABYARD_BOOTSTRAP_TOKEN?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GITHUB_ORG?: string;
};

type User = {
  subject: string;
  login: string | null;
  email: string | null;
  name: string | null;
  role: Role;
  allowed: boolean;
  teams: string[];
};

type GitHubProfile = {
  id: number;
  login: string;
  email: string | null;
  name: string | null;
};

type Card = {
  id: string;
  title: string;
  prompt: string;
  repo: string;
  source: string;
  runtime: string;
  policy: string;
  lane: string;
  owner: string;
  startedAt: number | null;
  createdAt: number;
  logs: string[];
};

const encoder = new TextEncoder();
const sessionCookie = "crabyard_session";
const oauthStateCookie = "crabyard_oauth_state";
const bootstrapSessionSeconds = 60 * 60;
const githubSessionSeconds = 60 * 15;
const lanes = ["Todo", "Running", "Human Review", "Done"];

export default {
  async fetch(request: Request, env: RuntimeEnv): Promise<Response> {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/healthz") {
        return text("ok\n", "text/plain; charset=utf-8");
      }

      if (url.pathname === "/docs/spec.md") {
        return text(SPEC_MARKDOWN, "text/markdown; charset=utf-8");
      }

      if (url.pathname === "/docs/spec" || url.pathname === "/docs/spec/") {
        if (wantsMarkdown(request)) {
          return text(SPEC_MARKDOWN, "text/markdown; charset=utf-8", { vary: "Accept" });
        }

        return text(SPEC_HTML, "text/html; charset=utf-8", { vary: "Accept" });
      }

      if (url.pathname === "/login/github") {
        return await githubLogin(request, env);
      }

      if (url.pathname === "/auth/github/callback") {
        return await githubCallback(request, env);
      }

      if (url.pathname.startsWith("/api/")) {
        return await api(request, env);
      }

      if (url.pathname === "/" || url.pathname === "/app" || url.pathname === "/app/") {
        return text(APP_HTML, "text/html; charset=utf-8", { vary: "Accept" });
      }

      return new Response("Not found\n", {
        status: 404,
        headers: securityHeaders("text/plain; charset=utf-8"),
      });
    } catch (error) {
      const hasStatus = typeof error === "object" && error && "status" in error;
      const status = hasStatus ? Number(error.status) : 500;
      const message = hasStatus && error instanceof Error ? error.message : "internal error";
      return json({ error: message }, { status: Number.isFinite(status) ? status : 500 });
    }
  },
} satisfies ExportedHandler<RuntimeEnv>;

async function api(request: Request, env: RuntimeEnv): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "POST" && url.pathname === "/api/login/token") {
    return tokenLogin(request, env);
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    return logout(request, env);
  }

  if (request.method === "GET" && url.pathname === "/api/auth") {
    return json({ auth: authMethods(env) });
  }

  const user = await requireUser(request, env);

  if (request.method === "GET" && url.pathname === "/api/session") {
    return json({ user, auth: authMethods(env) });
  }

  if (request.method === "GET" && url.pathname === "/api/state") {
    return json(await readState(env, user));
  }

  if (request.method === "POST" && url.pathname === "/api/cards") {
    requireRole(user, "maintainer");
    return json(await createCard(request, env, user), { status: 201 });
  }

  if (request.method === "PUT" && url.pathname === "/api/admin/policy") {
    requireRole(user, "owner");
    return json(await updatePolicy(request, env, user));
  }

  const actionMatch = url.pathname.match(/^\/api\/cards\/([^/]+)\/actions$/);
  if (request.method === "POST" && actionMatch) {
    const body = await readJson<{ action?: string }>(request);
    const action = body.action ?? "";
    requireRole(user, action === "attach" || action === "watch" ? "viewer" : "maintainer");
    return json(await mutateCard(env, user, decodeURIComponent(actionMatch[1] ?? ""), action));
  }

  if (request.method === "POST" && url.pathname === "/api/admin/allow") {
    requireRole(user, "owner");
    return json(await addAllowEntry(request, env, user), { status: 201 });
  }

  const allowMatch = url.pathname.match(/^\/api\/admin\/allow\/(.+)$/);
  if (request.method === "DELETE" && allowMatch) {
    requireRole(user, "owner");
    return json(await removeAllowEntry(env, user, decodeURIComponent(allowMatch[1] ?? "")));
  }

  if (request.method === "POST" && url.pathname === "/api/admin/repos") {
    requireRole(user, "owner");
    return json(await addRepo(request, env, user), { status: 201 });
  }

  const repoMatch = url.pathname.match(/^\/api\/admin\/repos\/(.+)$/);
  if (request.method === "DELETE" && repoMatch) {
    requireRole(user, "owner");
    return json(await removeRepo(env, user, decodeURIComponent(repoMatch[1] ?? "")));
  }

  return json({ error: "not found" }, { status: 404 });
}

async function tokenLogin(request: Request, env: RuntimeEnv): Promise<Response> {
  const { token } = await readJson<{ token?: string }>(request);
  if (!env.CRABYARD_BOOTSTRAP_TOKEN || token !== env.CRABYARD_BOOTSTRAP_TOKEN) {
    return json({ error: "invalid token" }, { status: 401 });
  }

  const now = Date.now();
  const subject = await bootstrapSubject(env);
  const user: User = {
    subject,
    login: "bootstrap",
    email: null,
    name: "Bootstrap Admin",
    role: "owner",
    allowed: true,
    teams: [],
  };
  await upsertUser(env, user, now);
  const cookieHeader = await createSession(env, user.subject, now);
  return json({ user, auth: authMethods(env) }, { headers: { "set-cookie": cookieHeader } });
}

async function githubLogin(request: Request, env: RuntimeEnv): Promise<Response> {
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return text("GitHub OAuth is not configured.\n", "text/plain; charset=utf-8", {}, 503);
  }

  const url = new URL(request.url);
  const redirectUri = `${url.origin}/auth/github/callback`;
  const state = crypto.randomUUID();
  const target = new URL("https://github.com/login/oauth/authorize");
  target.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  target.searchParams.set("redirect_uri", redirectUri);
  target.searchParams.set("scope", "read:user read:org");
  target.searchParams.set("state", state);

  return redirect(target.toString(), {
    "set-cookie": cookie(oauthStateCookie, state, 600),
  });
}

async function githubCallback(request: Request, env: RuntimeEnv): Promise<Response> {
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return text("GitHub OAuth is not configured.\n", "text/plain; charset=utf-8", {}, 503);
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state || state !== cookies(request).get(oauthStateCookie)) {
    return text("Invalid OAuth state.\n", "text/plain; charset=utf-8", {}, 400);
  }

  const redirectUri = `${url.origin}/auth/github/callback`;
  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": "crabyard-ai",
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
      state,
    }),
  });
  const tokenBody = await tokenResponse.json<{ access_token?: string; error?: string }>();
  if (!tokenBody.access_token) {
    return text(
      tokenBody.error ?? "OAuth token exchange failed.\n",
      "text/plain; charset=utf-8",
      {},
      401,
    );
  }

  const freshUser = await refreshGitHubUser(env, tokenBody.access_token).catch(() => {
    throw serviceUnavailable("GitHub membership refresh failed; retry later");
  });
  if (!freshUser) {
    return text(
      "GitHub user is not an active OpenClaw org member.\n",
      "text/plain; charset=utf-8",
      {},
      403,
    );
  }
  const authorized = await authorize(env, freshUser);
  if (!authorized.allowed) {
    return text(
      "GitHub user is not in the Crabyard allowlist.\n",
      "text/plain; charset=utf-8",
      {},
      403,
    );
  }

  const now = Date.now();
  await upsertUser(env, authorized, now);
  const session = await createSession(env, authorized.subject, now, githubSessionSeconds);
  return redirect("/app", { "set-cookie": session });
}

async function logout(request: Request, env: RuntimeEnv): Promise<Response> {
  const token = cookies(request).get(sessionCookie);
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(await sha256(token))
      .run();
  }
  return json({ ok: true }, { headers: { "set-cookie": cookie(sessionCookie, "", 0) } });
}

async function requireUser(request: Request, env: RuntimeEnv): Promise<User> {
  const token = cookies(request).get(sessionCookie);
  if (!token) throw unauthorized();
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    `SELECT u.subject, u.login, u.email, u.name, u.role, u.allowed, u.teams
      FROM sessions s
      JOIN users u ON u.subject = s.subject
      WHERE s.token_hash = ? AND s.expires_at > ?`,
  )
    .bind(tokenHash, Date.now())
    .first<{
      subject: string;
      login: string | null;
      email: string | null;
      name: string | null;
      role: Role;
      allowed: number;
      teams: string;
    }>();
  if (!row) throw unauthorized();

  const user = {
    subject: row.subject,
    login: row.login,
    email: row.email,
    name: row.name,
    role: row.role,
    allowed: row.allowed === 1,
    teams: parseJson(row.teams, []),
  };

  if (user.subject.startsWith("bootstrap:")) {
    if (!env.CRABYARD_BOOTSTRAP_TOKEN || user.subject !== (await bootstrapSubject(env))) {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
      throw unauthorized();
    }
    return user;
  }

  if (!user.subject.startsWith("github:")) return user;

  const authorized = await authorize(env, user);
  if (!authorized.allowed) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    throw forbidden("user is no longer allowlisted");
  }
  if (authorized.role !== user.role || authorized.allowed !== user.allowed) {
    await upsertUser(env, authorized, Date.now());
  }
  return authorized;
}

async function readState(env: RuntimeEnv, user: User): Promise<Record<string, unknown>> {
  const [settings, allow, repos, cards] = await Promise.all([
    readSettings(env),
    env.DB.prepare("SELECT value, role FROM allow_entries ORDER BY value").all<{
      value: string;
      role: Role;
    }>(),
    env.DB.prepare("SELECT repo FROM repos WHERE enabled = 1 ORDER BY repo").all<{
      repo: string;
    }>(),
    readCards(env),
  ]);

  return {
    user,
    auth: authMethods(env),
    org: settings.org ?? "OpenClaw",
    cap: numberSetting(settings.cap, 20),
    retention: settings.retention ?? "30",
    merge: settings.merge ?? "guarded",
    allow: user.role === "owner" ? (allow.results ?? []) : [],
    repos: (repos.results ?? []).map((row) => row.repo),
    cards,
  };
}

async function createCard(request: Request, env: RuntimeEnv, user: User): Promise<{ card: Card }> {
  const body = await readJson<{
    title?: string;
    prompt?: string;
    repo?: string;
    source?: string;
    runtime?: string;
    policy?: string;
  }>(request);
  const title = clean(body.title, 140);
  const prompt = clean(body.prompt, 4000);
  const repo = normalizeRepo(body.repo);
  if (!title || !prompt || !repo) throw badRequest("title, prompt, and repo are required");
  await requireRepo(env, repo);

  const source = oneOf(body.source, ["Prompt", "Issue", "PR"], "Prompt");
  const runtime = oneOf(body.runtime, ["auto", "container", "crabbox"], "auto");
  const policy = oneOf(
    body.policy,
    ["open_pr", "merge_when_green", "fix_until_green_and_merge"],
    "open_pr",
  );
  const now = Date.now();
  const owner = user.login ?? user.email ?? user.subject;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const id = await nextCardId(env);
    try {
      await env.DB.prepare(
        `INSERT INTO cards
          (id, title, prompt, repo, source, runtime, policy, lane, owner, started_at, created_at, updated_at, last_event)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'Todo', ?, NULL, ?, ?, ?)`,
      )
        .bind(id, title, prompt, repo, source, runtime, policy, owner, now, now, "card created")
        .run();
      await env.DB.batch([
        eventInsert(env, id, actor(user), "card created", now),
        eventInsert(env, id, actor(user), "repo allowlist ok", now + 1),
      ]);
      return { card: (await readCard(env, id)) as Card };
    } catch (error) {
      if (!isConstraintError(error) || attempt === 2) throw error;
    }
  }
  throw new Error("failed to allocate card id");
}

async function claimRunning(
  env: RuntimeEnv,
  user: User,
  card: Card,
  now: number,
): Promise<boolean> {
  await requireRepo(env, card.repo);
  const settings = await readSettings(env);
  const cap = numberSetting(settings.cap, 20);
  const transition = await env.DB.prepare(
    `UPDATE cards
      SET lane = 'Running', started_at = ?, updated_at = ?, last_event = ?
      WHERE id = ?
        AND lane <> 'Running'
        AND (SELECT count(*) FROM cards WHERE lane = 'Running') < ?`,
  )
    .bind(now, now, "run started", card.id, cap)
    .run();
  if ((transition.meta.changes ?? 0) === 0) {
    await appendEvent(env, card.id, user, `capacity blocked at cap ${cap}`, now);
    return false;
  }
  await appendEvent(env, card.id, user, `scheduler claimed ${card.repo}`, now + 1);
  await appendEvent(env, card.id, user, `runtime=${card.runtime} policy=${card.policy}`, now + 2);
  return true;
}

async function mutateCard(
  env: RuntimeEnv,
  user: User,
  id: string,
  action: string,
): Promise<{ card: Card }> {
  const card = await readCard(env, id);
  if (!card) throw notFound("card not found");
  const now = Date.now();

  if (action === "start" || action === "pulse") {
    if (card.lane !== "Running") {
      if (!(await claimRunning(env, user, card, now))) {
        return { card: (await readCard(env, id)) as Card };
      }
    }
    await appendEvent(env, card.id, user, "heartbeat ok", now + 3);
    return { card: (await readCard(env, id)) as Card };
  }

  if (action === "advance") {
    const nextLane = lanes[(lanes.indexOf(card.lane) + 1) % lanes.length] ?? "Todo";
    if (nextLane === "Running") {
      await claimRunning(env, user, card, now);
      return { card: (await readCard(env, id)) as Card };
    }
    const startedAt = nextLane === "Running" ? now : card.startedAt;
    await env.DB.prepare(
      "UPDATE cards SET lane = ?, started_at = ?, updated_at = ?, last_event = ? WHERE id = ?",
    )
      .bind(nextLane, startedAt, now, `moved to ${nextLane}`, card.id)
      .run();
    await appendEvent(env, card.id, user, `moved to ${nextLane}`, now);
    return { card: (await readCard(env, id)) as Card };
  }

  if (action === "attach") {
    return { card: (await readCard(env, id)) as Card };
  }

  if (action === "watch") {
    await appendEvent(env, card.id, user, "watch attached", now);
    return { card: (await readCard(env, id)) as Card };
  }

  if (action === "takeover") {
    await appendEvent(env, card.id, user, "operator takeover granted", now);
    return { card: (await readCard(env, id)) as Card };
  }

  if (action === "stall") {
    await env.DB.prepare(
      "UPDATE cards SET lane = 'Human Review', updated_at = ?, last_event = ? WHERE id = ?",
    )
      .bind(now, "stalled; workspace preserved", card.id)
      .run();
    await appendEvent(env, card.id, user, "stalled; workspace preserved", now);
    return { card: (await readCard(env, id)) as Card };
  }

  throw badRequest("unknown action");
}

async function updatePolicy(
  request: Request,
  env: RuntimeEnv,
  user: User,
): Promise<Record<string, unknown>> {
  const body = await readJson<{ cap?: number; retention?: string; merge?: string }>(request);
  const cap = Math.min(200, Math.max(1, Number.isFinite(body.cap) ? Number(body.cap) : 20));
  const retention = oneOf(body.retention, ["14", "30", "60"], "30");
  const merge = oneOf(body.merge, ["guarded", "maintainers", "disabled"], "guarded");
  const now = Date.now();
  await env.DB.batch([
    settingUpdate(env, "cap", String(cap)),
    settingUpdate(env, "retention", retention),
    settingUpdate(env, "merge", merge),
  ]);
  await audit(env, user, `policy updated cap=${cap} retention=${retention} merge=${merge}`, now);
  return readState(env, user);
}

async function addAllowEntry(
  request: Request,
  env: RuntimeEnv,
  user: User,
): Promise<Record<string, unknown>> {
  const body = await readJson<{ value?: string; role?: Role }>(request);
  const value = normalizeAllow(body.value);
  if (!value) throw badRequest("allow value is required");
  const role = oneOf(body.role, ["viewer", "maintainer", "owner"], "maintainer") as Role;
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO allow_entries (value, role, created_at, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(value) DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at`,
  )
    .bind(value, role, now, now)
    .run();
  await audit(env, user, `allowlist updated ${value} role=${role}`, now);
  return readState(env, user);
}

async function removeAllowEntry(
  env: RuntimeEnv,
  user: User,
  value: string,
): Promise<Record<string, unknown>> {
  const normalized = normalizeAllow(value);
  await env.DB.prepare("DELETE FROM allow_entries WHERE value = ?").bind(normalized).run();
  await audit(env, user, `allowlist removed ${normalized}`, Date.now());
  return readState(env, user);
}

async function addRepo(
  request: Request,
  env: RuntimeEnv,
  user: User,
): Promise<Record<string, unknown>> {
  const body = await readJson<{ repo?: string }>(request);
  const repo = normalizeRepo(body.repo);
  if (!repo) throw badRequest("repo is required");
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO repos (repo, enabled, created_at, updated_at)
      VALUES (?, 1, ?, ?)
      ON CONFLICT(repo) DO UPDATE SET enabled = 1, updated_at = excluded.updated_at`,
  )
    .bind(repo, now, now)
    .run();
  await audit(env, user, `repo allowlisted ${repo}`, now);
  return readState(env, user);
}

async function removeRepo(
  env: RuntimeEnv,
  user: User,
  repo: string,
): Promise<Record<string, unknown>> {
  const normalized = normalizeRepo(repo);
  await env.DB.prepare("UPDATE repos SET enabled = 0, updated_at = ? WHERE repo = ?")
    .bind(Date.now(), normalized)
    .run();
  await audit(env, user, `repo removed ${normalized}`, Date.now());
  return readState(env, user);
}

async function readCards(env: RuntimeEnv): Promise<Card[]> {
  const rows = await env.DB.prepare(
    `SELECT id, title, prompt, repo, source, runtime, policy, lane, owner, started_at, created_at
      FROM cards
      ORDER BY updated_at DESC, created_at DESC`,
  ).all<{
    id: string;
    title: string;
    prompt: string;
    repo: string;
    source: string;
    runtime: string;
    policy: string;
    lane: string;
    owner: string;
    started_at: number | null;
    created_at: number;
  }>();
  const cards = rows.results ?? [];
  if (!cards.length) return [];
  const eventRows = await env.DB.prepare(
    `SELECT card_id, message, created_at
      FROM (
        SELECT card_id, message, created_at, id,
          row_number() OVER (PARTITION BY card_id ORDER BY created_at DESC, id DESC) AS rank
        FROM events
        WHERE card_id IN (SELECT id FROM cards)
      )
      WHERE rank <= 80
      ORDER BY card_id ASC, created_at ASC, id ASC`,
  ).all<{ card_id: string; message: string; created_at: number }>();
  const logs = new Map<string, string[]>();
  for (const row of eventRows.results ?? []) {
    const line = `${new Date(row.created_at).toLocaleTimeString("en-GB")} ${row.message}`;
    logs.set(row.card_id, [...(logs.get(row.card_id) ?? []), line]);
  }
  return cards.map((card) => ({
    id: card.id,
    title: card.title,
    prompt: card.prompt,
    repo: card.repo,
    source: card.source,
    runtime: card.runtime,
    policy: card.policy,
    lane: card.lane,
    owner: card.owner,
    startedAt: card.started_at,
    createdAt: card.created_at,
    logs: logs.get(card.id) ?? [],
  }));
}

async function readCard(env: RuntimeEnv, id: string): Promise<Card | null> {
  const card = await env.DB.prepare(
    `SELECT id, title, prompt, repo, source, runtime, policy, lane, owner, started_at, created_at
      FROM cards
      WHERE id = ?`,
  )
    .bind(id)
    .first<{
      id: string;
      title: string;
      prompt: string;
      repo: string;
      source: string;
      runtime: string;
      policy: string;
      lane: string;
      owner: string;
      started_at: number | null;
      created_at: number;
    }>();
  if (!card) return null;
  const eventRows = await env.DB.prepare(
    `SELECT message, created_at
      FROM (
        SELECT message, created_at, id
        FROM events
        WHERE card_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 80
      )
      ORDER BY created_at ASC, id ASC`,
  )
    .bind(card.id)
    .all<{ message: string; created_at: number }>();
  return {
    id: card.id,
    title: card.title,
    prompt: card.prompt,
    repo: card.repo,
    source: card.source,
    runtime: card.runtime,
    policy: card.policy,
    lane: card.lane,
    owner: card.owner,
    startedAt: card.started_at,
    createdAt: card.created_at,
    logs: (eventRows.results ?? []).map(
      (row) => `${new Date(row.created_at).toLocaleTimeString("en-GB")} ${row.message}`,
    ),
  };
}

async function readSettings(env: RuntimeEnv): Promise<Record<string, string>> {
  const rows = await env.DB.prepare("SELECT key, value FROM settings").all<{
    key: string;
    value: string;
  }>();
  return Object.fromEntries((rows.results ?? []).map((row) => [row.key, row.value]));
}

async function authorize(env: RuntimeEnv, user: User): Promise<User> {
  const entries = await env.DB.prepare("SELECT value, role FROM allow_entries").all<{
    value: string;
    role: Role;
  }>();
  const candidates = new Set([
    user.login ? `@${user.login.toLowerCase()}` : "",
    user.email ? user.email.toLowerCase() : "",
    ...user.teams.map((team) => team.toLowerCase()),
  ]);
  let role: Role | null = null;
  for (const row of entries.results ?? []) {
    if (!candidates.has(row.value.toLowerCase())) continue;
    role = strongerRole(role, row.role);
  }
  return { ...user, role: role ?? "viewer", allowed: role !== null };
}

async function upsertUser(env: RuntimeEnv, user: User, now: number): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO users (subject, login, email, name, role, allowed, teams, created_at, updated_at, last_seen_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(subject) DO UPDATE SET
        login = excluded.login,
        email = excluded.email,
        name = excluded.name,
        role = excluded.role,
        allowed = excluded.allowed,
        teams = excluded.teams,
        updated_at = excluded.updated_at,
        last_seen_at = excluded.last_seen_at`,
  )
    .bind(
      user.subject,
      user.login,
      user.email,
      user.name,
      user.role,
      user.allowed ? 1 : 0,
      JSON.stringify(user.teams),
      now,
      now,
      now,
    )
    .run();
}

async function createSession(
  env: RuntimeEnv,
  subject: string,
  now: number,
  maxAgeSeconds = bootstrapSessionSeconds,
): Promise<string> {
  const token = crypto.randomUUID() + crypto.randomUUID();
  const tokenHash = await sha256(token);
  const expires = now + maxAgeSeconds * 1000;
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, subject, expires_at, created_at) VALUES (?, ?, ?, ?)",
  )
    .bind(tokenHash, subject, expires, now)
    .run();
  return cookie(sessionCookie, token, maxAgeSeconds);
}

async function nextCardId(env: RuntimeEnv): Promise<string> {
  const row = await env.DB.prepare(
    "SELECT max(CAST(substr(id, 4) AS INTEGER)) AS max_id FROM cards WHERE id LIKE 'CY-%'",
  ).first<{ max_id: number | null }>();
  return `CY-${String((row?.max_id ?? 100) + 1)}`;
}

async function requireRepo(env: RuntimeEnv, repo: string): Promise<void> {
  const row = await env.DB.prepare("SELECT repo FROM repos WHERE repo = ? AND enabled = 1")
    .bind(repo)
    .first<{ repo: string }>();
  if (!row) throw forbidden(`repo blocked by allowlist: ${repo}`);
}

async function appendEvent(
  env: RuntimeEnv,
  cardId: string,
  user: User,
  message: string,
  now: number,
): Promise<void> {
  await env.DB.batch([
    eventInsert(env, cardId, actor(user), message, now),
    env.DB.prepare("UPDATE cards SET updated_at = ?, last_event = ? WHERE id = ?").bind(
      now,
      message,
      cardId,
    ),
  ]);
}

async function audit(env: RuntimeEnv, user: User, message: string, now: number): Promise<void> {
  await env.DB.prepare("INSERT INTO audit_events (actor, message, created_at) VALUES (?, ?, ?)")
    .bind(actor(user), message, now)
    .run();
}

function eventInsert(
  env: RuntimeEnv,
  cardId: string,
  actorName: string,
  message: string,
  now: number,
): D1PreparedStatement {
  return env.DB.prepare(
    "INSERT INTO events (card_id, actor, message, created_at) VALUES (?, ?, ?, ?)",
  ).bind(cardId, actorName, message, now);
}

function settingUpdate(env: RuntimeEnv, key: string, value: string): D1PreparedStatement {
  return env.DB.prepare(
    `INSERT INTO settings (key, value)
      VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
  ).bind(key, value);
}

async function githubFetch<T>(path: string, token: string): Promise<T> {
  const response = await fetch(`https://api.github.com${path}`, {
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "user-agent": "crabyard-ai",
      "x-github-api-version": "2022-11-28",
    },
  });
  if (!response.ok) throw new GitHubApiError(response.status);
  return response.json<T>();
}

async function githubFetchPages<T>(path: string, token: string): Promise<T[]> {
  const rows: T[] = [];
  for (let page = 1; page <= 10; page += 1) {
    const separator = path.includes("?") ? "&" : "?";
    const batch = await githubFetch<T[]>(`${path}${separator}per_page=100&page=${page}`, token);
    rows.push(...batch);
    if (batch.length < 100) break;
  }
  return rows;
}

async function refreshGitHubUser(env: RuntimeEnv, token: string): Promise<User | null> {
  const org = env.GITHUB_ORG ?? "openclaw";
  const [githubUser, emails, membership, teamRows] = await Promise.all([
    githubFetch<GitHubProfile>("/user", token),
    githubFetch<Array<{ email: string; primary: boolean; verified: boolean }>>(
      "/user/emails",
      token,
    ).catch(() => []),
    githubFetch<{ state: string }>(`/user/memberships/orgs/${org}`, token).catch((error) => {
      if (error instanceof GitHubApiError && error.status === 404) return null;
      throw error;
    }),
    githubFetchPages<{ slug: string; organization?: { login?: string } }>("/user/teams", token),
  ]);
  if (membership?.state !== "active") return null;
  const email =
    githubUser.email ??
    emails.find((item) => item.primary && item.verified)?.email ??
    emails.find((item) => item.verified)?.email ??
    null;
  const teams = teamRows
    .filter((team) => (team.organization?.login ?? "").toLowerCase() === org.toLowerCase())
    .map((team) => `@${org}/${team.slug}`);
  return {
    subject: `github:${githubUser.id}`,
    login: githubUser.login,
    email,
    name: githubUser.name,
    role: "viewer",
    allowed: false,
    teams,
  };
}

class GitHubApiError extends Error {
  constructor(readonly status: number) {
    super(`GitHub API failed: ${status}`);
  }
}

function requireRole(user: User, needed: Role): void {
  const rank: Record<Role, number> = { viewer: 1, maintainer: 2, owner: 3 };
  if (rank[user.role] < rank[needed]) throw forbidden("insufficient role");
}

function strongerRole(left: Role | null, right: Role): Role {
  const rank: Record<Role, number> = { viewer: 1, maintainer: 2, owner: 3 };
  if (!left) return right;
  return rank[right] > rank[left] ? right : left;
}

function authMethods(env: RuntimeEnv): Record<string, boolean> {
  return {
    github: Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET),
    token: Boolean(env.CRABYARD_BOOTSTRAP_TOKEN),
  };
}

function actor(user: User): string {
  return user.login ?? user.email ?? user.subject;
}

async function readJson<T>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    throw badRequest("invalid json");
  }
}

function parseJson<T>(value: string, fallback: T): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function cookies(request: Request): Map<string, string> {
  const result = new Map<string, string>();
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    result.set(part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim()));
  }
  return result;
}

function cookie(name: string, value: string, maxAge: number): string {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function bootstrapSubject(env: RuntimeEnv): Promise<string> {
  if (!env.CRABYARD_BOOTSTRAP_TOKEN) throw unauthorized();
  return `bootstrap:${(await sha256(env.CRABYARD_BOOTSTRAP_TOKEN)).slice(0, 24)}`;
}

function normalizeRepo(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/^https:\/\/github\.com\//, "")
    .replace(/\.git$/, "")
    .replace(/\/+$/, "");
}

function normalizeAllow(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  if (raw.includes("@")) return raw.toLowerCase();
  return `@${raw.toLowerCase()}`;
}

function clean(value: unknown, max: number): string {
  return String(value ?? "")
    .trim()
    .slice(0, max);
}

function oneOf<T extends string>(value: unknown, options: readonly T[], fallback: T): T {
  return options.includes(value as T) ? (value as T) : fallback;
}

function numberSetting(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function isConstraintError(error: unknown): boolean {
  return error instanceof Error && /constraint|unique/i.test(error.message);
}

function wantsMarkdown(request: Request): boolean {
  const accept = request.headers.get("accept") ?? "";
  return accept.includes("text/markdown");
}

function text(
  body: string,
  contentType: string,
  extraHeaders: HeadersInit = {},
  status = 200,
): Response {
  return new Response(body, {
    status,
    headers: {
      ...securityHeaders(contentType),
      ...extraHeaders,
      "content-length": String(encoder.encode(body).byteLength),
    },
  });
}

function json(body: unknown, init: ResponseInit & { headers?: HeadersInit } = {}): Response {
  const textBody = JSON.stringify(body);
  return new Response(textBody, {
    ...init,
    headers: {
      ...securityHeaders("application/json; charset=utf-8", false),
      ...init.headers,
      "content-length": String(encoder.encode(textBody).byteLength),
    },
  });
}

function redirect(location: string, headers: HeadersInit = {}): Response {
  return new Response(null, {
    status: 302,
    headers: {
      location,
      ...headers,
    },
  });
}

function securityHeaders(contentType: string, cache = true): HeadersInit {
  return {
    "content-type": contentType,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": cache ? "public, max-age=300" : "no-store",
  };
}

function unauthorized(): Error {
  return Object.assign(new Error("unauthorized"), { status: 401 });
}

function forbidden(message: string): Error {
  return Object.assign(new Error(message), { status: 403 });
}

function serviceUnavailable(message: string): Error {
  return Object.assign(new Error(message), { status: 503 });
}

function badRequest(message: string): Error {
  return Object.assign(new Error(message), { status: 400 });
}

function notFound(message: string): Error {
  return Object.assign(new Error(message), { status: 404 });
}
