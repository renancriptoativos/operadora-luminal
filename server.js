import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { JsonStore } from './lib/store.js';
import { DEFAULT_SEED, conventionalNumberFromLine, nextLineNumber } from './lib/numbers.js';
import { hashPassword, verifyPassword } from './lib/password.js';
import { PLANS, getPlan } from './lib/plans.js';
import { computeUsage } from './lib/usage.js';
import { readSmtpConfig, sendMail } from './lib/mailer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');
const DEFAULT_DATA_DIR = path.join(__dirname, 'data');

const SESSION_COOKIE = 'luminal_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const EMAIL_CONFIRMATION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_SMS_BODY = 480;
const MAX_SMS_DESTINATION_DIGITS = 47;
const RECEIVED_MESSAGE_TTL_MS = 60 * 60 * 1000;
const MESSAGE_SWEEP_INTERVAL_MS = 60 * 1000;
const MAX_SYNC_BODY_BYTES = 8 * 1024 * 1024;
const MAX_SYNC_USERS = 10_000;
const MAX_SYNC_LINES = 10_000;
const MAX_SYNC_MESSAGES = 100_000;
const MIN_SYNC_KEY_LENGTH = 16;
const SYNC_FETCH_TIMEOUT_MS = 20_000;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

const API_PATHS = new Set([
  '/api/plans',
  '/api/session',
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/confirm-email',
  '/api/auth/confirm-code',
  '/api/auth/resend-confirmation',
  '/api/line',
  '/api/line/activate',
  '/api/line/plan',
  '/api/sms',
  '/api/sms/send',
  '/api/sms/delete',
  '/api/sync/export',
  '/api/sync/import',
  '/api/sync/pull',
  '/api/sync/sms',
  '/api/sync/sms/delete',
]);

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function createApp({ dataDir = DEFAULT_DATA_DIR } = {}) {
  const db = new JsonStore(dataDir, {
    counter: DEFAULT_SEED,
    users: [],
    lines: [],
    sessions: [],
    messages: [],
  });
  seedWelcomeMessages(db);

  const server = http.createServer((req, res) => {
    applySecurityHeaders(res);

    (async () => {
      const url = new URL(req.url ?? '/', 'http://localhost');

      if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
        await handleApi(db, req, res, url);
        return;
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        sendJson(res, 405, { error: 'Método não permitido.' }, { Allow: 'GET, HEAD' });
        return;
      }

      await serveStatic(req, res, url);
    })().catch((error) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (error instanceof ApiError) {
        sendJson(res, error.status, { error: error.message });
        return;
      }
      console.error(error);
      sendJson(res, 500, { error: 'Erro interno do servidor.' });
    });
  });

  const sweep = setInterval(() => purgeExpiredMessages(db), MESSAGE_SWEEP_INTERVAL_MS);
  sweep.unref();
  server.once('close', () => clearInterval(sweep));

  return server;
}

async function handleApi(db, req, res, url) {
  try {
    await routeApi(db, req, res, url);
  } catch (error) {
    if (res.headersSent) {
      res.end();
      return;
    }
    if (error instanceof ApiError) {
      sendJson(res, error.status, { error: error.message });
      return;
    }
    console.error(error);
    sendJson(res, 500, { error: 'Erro interno do servidor.' });
  }
}

async function routeApi(db, req, res, url) {
  const { pathname } = url;
  const method = req.method ?? 'GET';

  if (pathname === '/api/plans' && method === 'GET') {
    sendJson(res, 200, { plans: PLANS });
    return;
  }

  if (pathname === '/api/session' && method === 'GET') {
    const user = getSessionUser(db, req);
    sendJson(res, 200, buildSessionPayload(db, user));
    return;
  }

  if (pathname === '/api/auth/register' && method === 'POST') {
    await handleRegister(db, req, res);
    return;
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    await handleLogin(db, req, res);
    return;
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    handleLogout(db, req, res);
    return;
  }

  if (pathname === '/api/auth/confirm-email' && method === 'POST') {
    await handleConfirmEmail(db, req, res);
    return;
  }

  if (pathname === '/api/auth/confirm-code' && method === 'POST') {
    await handleConfirmCode(db, req, res);
    return;
  }

  if (pathname === '/api/auth/resend-confirmation' && method === 'POST') {
    await handleResendConfirmation(db, req, res);
    return;
  }

  if (pathname === '/api/line' && method === 'GET') {
    const user = requireUser(db, req);
    const line = findLineByUser(db, user.id);
    if (!line) throw new ApiError(404, 'Nenhuma linha ativa encontrada.');
    sendJson(res, 200, { line: buildLinePayload(line) });
    return;
  }

  if (pathname === '/api/line/activate' && method === 'POST') {
    await handleActivate(db, req, res);
    return;
  }

  if (pathname === '/api/line/plan' && method === 'POST') {
    await handleChangePlan(db, req, res);
    return;
  }

  if (pathname === '/api/sms' && method === 'GET') {
    handleListSms(db, req, res);
    return;
  }

  if (pathname === '/api/sms/send' && method === 'POST') {
    await handleSendSms(db, req, res);
    return;
  }

  if (pathname === '/api/sms/delete' && method === 'POST') {
    await handleDeleteSms(db, req, res);
    return;
  }

  if (pathname === '/api/sync/export' && method === 'GET') {
    handleSyncExport(db, req, res);
    return;
  }

  if (pathname === '/api/sync/import' && method === 'POST') {
    await handleSyncImport(db, req, res, url);
    return;
  }

  if (pathname === '/api/sync/pull' && method === 'POST') {
    await handleSyncPull(db, req, res);
    return;
  }

  if (pathname === '/api/sync/sms' && method === 'GET') {
    handleSyncSmsList(db, req, res, url);
    return;
  }

  if (pathname === '/api/sync/sms/delete' && method === 'POST') {
    await handleSyncSmsDelete(db, req, res);
    return;
  }

  if (API_PATHS.has(pathname)) {
    sendJson(res, 405, { error: 'Método não permitido.' });
    return;
  }

  sendJson(res, 404, { error: 'Rota não encontrada.' });
}

async function handleRegister(db, req, res) {
  const body = await readJson(req);
  const name = normalizeName(body.name);
  const email = normalizeEmail(body.email);
  const password = String(body.password ?? '');

  if (name.length < 2 || name.length > 80) {
    throw new ApiError(400, 'Informe seu nome completo.');
  }
  if (!isValidEmail(email)) {
    throw new ApiError(400, 'Informe um e-mail válido.');
  }
  if (password.length < 8 || password.length > 128) {
    throw new ApiError(400, 'A senha deve ter entre 8 e 128 caracteres.');
  }
  if (db.data.users.some((user) => user.email === email)) {
    throw new ApiError(409, 'Este e-mail já está cadastrado.');
  }

  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    passwordHash: hashPassword(password),
    emailVerified: false,
    emailVerifiedAt: null,
    createdAt: new Date().toISOString(),
  };
  db.data.users.push(user);

  const token = issueSession(db, user.id);
  const verification = issueEmailConfirmation(user);
  db.save();
  setSessionCookie(res, token);
  const delivery = await deliverConfirmationEmail(user, verification, req);
  sendJson(res, 201, {
    ...buildSessionPayload(db, user),
    verification: { ...verification, delivery },
  });
}

async function handleLogin(db, req, res) {
  const body = await readJson(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password ?? '');

  const user = db.data.users.find((candidate) => candidate.email === email);
  const passwordOk = password.length <= 128 && user && verifyPassword(password, user.passwordHash);

  if (!passwordOk) {
    throw new ApiError(401, 'E-mail ou senha incorretos.');
  }

  const token = issueSession(db, user.id);
  db.save();
  setSessionCookie(res, token);
  sendJson(res, 200, buildSessionPayload(db, user));
}

async function handleConfirmEmail(db, req, res) {
  const body = await readJson(req);
  const token = String(body.token ?? '').trim();
  if (!token || token.length > 200) {
    throw new ApiError(400, 'Link de confirmação inválido.');
  }

  const tokenHash = hashToken(token);
  const user = db.data.users.find(
    (candidate) => candidate.emailConfirmation?.tokenHash === tokenHash
  );
  if (!user) {
    throw new ApiError(400, 'Link inválido ou já utilizado.');
  }
  if (new Date(user.emailConfirmation.expiresAt).getTime() <= Date.now()) {
    user.emailConfirmation = null;
    db.save();
    throw new ApiError(400, 'Link expirado. Peça um novo e-mail.');
  }

  user.emailVerified = true;
  user.emailVerifiedAt = new Date().toISOString();
  user.emailConfirmation = null;

  const sessionToken = issueSession(db, user.id);
  db.save();
  setSessionCookie(res, sessionToken);
  sendJson(res, 200, { confirmed: true, ...buildSessionPayload(db, user) });
}

async function handleConfirmCode(db, req, res) {
  const body = await readJson(req);
  const email = normalizeEmail(body.email);
  const code = String(body.code ?? '').replace(/\D/g, '');

  if (!isValidEmail(email) || !/^\d{8}$/.test(code)) {
    throw new ApiError(400, 'Código inválido ou expirado.');
  }

  const user = db.data.users.find((candidate) => candidate.email === email);
  const confirmation = user?.emailConfirmation;
  if (!confirmation) {
    throw new ApiError(400, 'Código inválido ou expirado.');
  }
  if (new Date(confirmation.expiresAt).getTime() <= Date.now()) {
    user.emailConfirmation = null;
    db.save();
    throw new ApiError(400, 'Código expirado. Peça um novo código.');
  }
  if (!confirmation.codeHash || hashToken(code) !== confirmation.codeHash) {
    confirmation.attempts = Number(confirmation.attempts ?? 0) + 1;
    if (confirmation.attempts >= MAX_CODE_ATTEMPTS) {
      user.emailConfirmation = null;
      db.save();
      throw new ApiError(400, 'Muitas tentativas. Peça um novo código.');
    }
    db.save();
    throw new ApiError(400, 'Código incorreto. Tente novamente.');
  }

  user.emailVerified = true;
  user.emailVerifiedAt = new Date().toISOString();
  user.emailConfirmation = null;

  const sessionToken = issueSession(db, user.id);
  db.save();
  setSessionCookie(res, sessionToken);
  sendJson(res, 200, { confirmed: true, ...buildSessionPayload(db, user) });
}

async function handleResendConfirmation(db, req, res) {
  const user = requireUser(db, req);
  if (user.emailVerified !== false) {
    throw new ApiError(409, 'Seu e-mail já está confirmado.');
  }

  const verification = issueEmailConfirmation(user);
  db.save();
  const delivery = await deliverConfirmationEmail(user, verification, req);
  sendJson(res, 200, { ok: true, verification: { ...verification, delivery } });
}

function handleLogout(db, req, res) {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (token) {
    const tokenHash = hashToken(token);
    const before = db.data.sessions.length;
    db.data.sessions = db.data.sessions.filter((session) => session.tokenHash !== tokenHash);
    if (db.data.sessions.length !== before) db.save();
  }

  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );
  sendJson(res, 200, { ok: true });
}

async function handleActivate(db, req, res) {
  const user = requireUser(db, req);
  if (user.emailVerified === false) {
    throw new ApiError(403, 'Confirme seu e-mail antes de ativar sua linha.');
  }
  const body = await readJson(req);

  const plan = getPlan(body.planId ?? 'free');
  if (!plan) throw new ApiError(400, 'Escolha um plano válido.');
  if (findLineByUser(db, user.id)) {
    throw new ApiError(409, 'Você já possui uma linha ativa.');
  }

  const allocation = nextLineNumber(db.data.counter);
  const line = {
    id: crypto.randomUUID(),
    userId: user.id,
    number: allocation.number,
    sequence: allocation.sequence,
    planId: plan.id,
    status: 'active',
    activatedAt: new Date().toISOString(),
    seed: crypto.randomInt(0, 1000) / 1000,
    iccid: buildIccid(allocation.number),
    activationCode: buildActivationCode(),
    smdp: 'rsp.luminal.demo',
    welcomeSent: true,
  };

  db.data.counter = allocation.nextCounter;
  db.data.lines.push(line);

  db.data.messages ??= [];
  db.data.messages.push(buildWelcomeMessage(line));

  db.save();

  sendJson(res, 201, { line: buildLinePayload(line) });
}

function seedWelcomeMessages(db) {
  db.data.messages ??= [];
  const notified = new Set(db.data.messages.map((message) => message.lineId));
  let changed = false;

  for (const line of db.data.lines) {
    if (line.welcomeSent) continue;
    if (!notified.has(line.id)) {
      db.data.messages.push(buildWelcomeMessage(line));
    }
    line.welcomeSent = true;
    changed = true;
  }

  if (changed) db.save();
}

function purgeExpiredMessages(db, now = Date.now()) {
  const messages = db.data.messages ?? [];
  const kept = messages.filter((message) => {
    if (message.direction !== 'in') return true;
    const receivedAt = new Date(message.createdAt).getTime();
    return !Number.isFinite(receivedAt) || now - receivedAt < RECEIVED_MESSAGE_TTL_MS;
  });
  if (kept.length === messages.length) return 0;

  const removed = messages.length - kept.length;
  db.data.messages = kept;
  db.save();
  return removed;
}

function buildWelcomeMessage(line) {
  return {
    id: crypto.randomUUID(),
    lineId: line.id,
    userId: line.userId,
    direction: 'in',
    from: 'Luminal',
    to: line.number,
    body: 'Bem-vindo à Luminal! Sua linha está ativa e já recebe SMS ilimitados, sem mensalidade e para sempre.',
    createdAt: line.activatedAt,
  };
}

async function handleChangePlan(db, req, res) {
  const user = requireUser(db, req);
  const body = await readJson(req);

  const plan = getPlan(body.planId);
  if (!plan) throw new ApiError(400, 'Escolha um plano válido.');

  const line = findLineByUser(db, user.id);
  if (!line) throw new ApiError(404, 'Ative uma linha antes de escolher um plano.');
  if (line.planId === plan.id) {
    throw new ApiError(409, 'Sua linha já está neste plano.');
  }

  line.planId = plan.id;
  db.save();

  sendJson(res, 200, { line: buildLinePayload(line) });
}

function handleListSms(db, req, res) {
  const user = requireUser(db, req);
  const line = findLineByUser(db, user.id);
  if (!line) throw new ApiError(404, 'Nenhuma linha ativa encontrada.');

  purgeExpiredMessages(db);

  const messages = (db.data.messages ?? [])
    .filter((message) => message.lineId === line.id)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(buildSmsPayload);
  sendJson(res, 200, { messages });
}

async function handleSendSms(db, req, res) {
  const user = requireUser(db, req);
  const line = findLineByUser(db, user.id);
  if (!line) throw new ApiError(404, 'Ative uma linha antes de enviar SMS.');

  const body = await readJson(req);
  const rawTo = String(body.to ?? '').trim();
  const to = rawTo.replace(/\D/g, '');
  const text = String(body.body ?? '').trim();

  if (!/^\+?[\d\s().-]+$/.test(rawTo) || to.length < 3 || to.length > MAX_SMS_DESTINATION_DIGITS) {
    throw new ApiError(400, 'Informe um número de destino válido.');
  }
  if (!text || text.length > MAX_SMS_BODY) {
    throw new ApiError(400, `A mensagem deve ter entre 1 e ${MAX_SMS_BODY} caracteres.`);
  }

  const message = {
    id: crypto.randomUUID(),
    lineId: line.id,
    userId: user.id,
    direction: 'out',
    from: line.number,
    to,
    body: text,
    createdAt: new Date().toISOString(),
  };

  db.data.messages ??= [];
  db.data.messages.push(message);
  db.save();

  sendJson(res, 201, { message: buildSmsPayload(message) });
}

async function handleDeleteSms(db, req, res) {
  const user = requireUser(db, req);
  const line = findLineByUser(db, user.id);
  if (!line) throw new ApiError(404, 'Nenhuma linha ativa encontrada.');

  const body = await readJson(req);
  const deleted = deleteSmsByIds(db, line.id, body.ids);
  sendJson(res, 200, { deleted });
}

function deleteSmsByIds(db, lineId, rawIds) {
  if (!Array.isArray(rawIds) || rawIds.length === 0 || rawIds.length > 500) {
    throw new ApiError(400, 'Selecione ao menos uma mensagem para apagar.');
  }

  const ids = new Set(
    rawIds
      .map((id) => String(id))
      .filter((id) => id.length > 0 && id.length <= 100)
  );
  if (ids.size === 0) {
    throw new ApiError(400, 'Selecione ao menos uma mensagem para apagar.');
  }

  const before = (db.data.messages ?? []).length;
  db.data.messages = (db.data.messages ?? []).filter(
    (message) => !(message.lineId === lineId && ids.has(message.id))
  );
  const deleted = before - db.data.messages.length;
  if (deleted > 0) db.save();

  return deleted;
}

const syncLocks = new WeakSet();

function readSyncConfig(env = process.env) {
  const apiKey = String(env.SYNC_API_KEY ?? '').trim();
  return {
    apiKey,
    enabled: apiKey.length >= MIN_SYNC_KEY_LENGTH,
    sourceUrl: String(env.SYNC_SOURCE_URL ?? '').trim().replace(/\/+$/, ''),
    sourceKey: String(env.SYNC_SOURCE_KEY ?? '').trim() || apiKey,
  };
}

function requireSyncAccess(req) {
  const config = readSyncConfig();
  if (!config.enabled) {
    throw new ApiError(
      503,
      `Sincronização desativada. Defina SYNC_API_KEY com pelo menos ${MIN_SYNC_KEY_LENGTH} caracteres.`
    );
  }

  const header = String(req.headers.authorization ?? '').trim();
  const bearer = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : '';
  const token = bearer || String(req.headers['x-api-key'] ?? '').trim();

  if (!token || !safeEqual(token, config.apiKey)) {
    throw new ApiError(401, 'Chave de sincronização inválida.');
  }

  return config;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left), 'utf8');
  const b = Buffer.from(String(right), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function beginSync(db) {
  if (syncLocks.has(db)) {
    throw new ApiError(409, 'Já existe uma sincronização em andamento.');
  }
  syncLocks.add(db);
}

function endSync(db) {
  syncLocks.delete(db);
}

function handleSyncExport(db, req, res) {
  requireSyncAccess(req);
  purgeExpiredMessages(db);
  sendJson(res, 200, buildSyncSnapshot(db), { 'Cache-Control': 'no-store' });
}

function handleSyncSmsList(db, req, res, url) {
  requireSyncAccess(req);
  purgeExpiredMessages(db);
  const line = findSyncLine(db, url.searchParams.get('line'));
  const user = db.data.users.find((candidate) => candidate.id === line.userId) ?? null;
  const messages = (db.data.messages ?? [])
    .filter((message) => message.lineId === line.id)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(buildSmsPayload);

  sendJson(
    res,
    200,
    {
      line: { id: line.id, number: line.number },
      user: user ? { id: user.id, name: user.name, email: user.email } : null,
      messages,
    },
    { 'Cache-Control': 'no-store' }
  );
}

async function handleSyncSmsDelete(db, req, res) {
  requireSyncAccess(req);
  const body = await readJson(req);
  const line = findSyncLine(db, body.line);
  const deleted = deleteSmsByIds(db, line.id, body.ids);
  sendJson(res, 200, { line: { id: line.id, number: line.number }, deleted });
}

async function handleSyncImport(db, req, res, url) {
  requireSyncAccess(req);
  const mirror = isEnabledFlag(url.searchParams.get('mirror'));

  beginSync(db);
  try {
    const snapshot = await readJson(req, MAX_SYNC_BODY_BYTES);
    const summary = importSyncSnapshot(db, snapshot, { mirror });
    sendJson(res, 200, { ok: true, mirror, summary });
  } finally {
    endSync(db);
  }
}

async function handleSyncPull(db, req, res) {
  requireSyncAccess(req);
  const config = readSyncConfig();
  const sourceUrl = normalizeSourceUrl(config.sourceUrl);

  if (!sourceUrl) {
    throw new ApiError(400, 'Configure SYNC_SOURCE_URL com a URL base do servidor de origem.');
  }
  if (!config.sourceKey) {
    throw new ApiError(400, 'Configure SYNC_SOURCE_KEY com a chave do servidor de origem.');
  }

  const body = await readJson(req);
  const mirror = body.mirror === true;

  beginSync(db);
  try {
    const snapshot = await fetchSyncSnapshot(sourceUrl, config.sourceKey);
    const summary = importSyncSnapshot(db, snapshot, { mirror });
    sendJson(res, 200, {
      ok: true,
      sourceUrl,
      exportedAt: snapshot.exportedAt ?? null,
      mirror,
      summary,
    });
  } finally {
    endSync(db);
  }
}

function findSyncLine(db, value) {
  const key = String(value ?? '').trim();
  if (!key || key.length > 100) {
    throw new ApiError(400, 'Informe a linha pelo id ou pelo número universal.');
  }

  const line = (db.data.lines ?? []).find(
    (candidate) => candidate.id === key || candidate.number === key
  );
  if (!line) throw new ApiError(404, 'Linha não encontrada.');
  return line;
}

function isEnabledFlag(value) {
  const text = String(value ?? '').trim().toLowerCase();
  return text === '1' || text === 'true' || text === 'yes';
}

function normalizeSourceUrl(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';

  let url;
  try {
    url = new URL(raw);
  } catch {
    return '';
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';
  if (url.username || url.password || url.search || url.hash) return '';
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

async function fetchSyncSnapshot(sourceUrl, sourceKey) {
  const endpoint = `${sourceUrl}/api/sync/export`;
  let response;

  try {
    response = await fetch(endpoint, {
      headers: {
        authorization: `Bearer ${sourceKey}`,
        accept: 'application/json',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(SYNC_FETCH_TIMEOUT_MS),
    });
  } catch (error) {
    if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
      throw new ApiError(504, 'O servidor de origem demorou demais para responder.');
    }
    throw new ApiError(502, 'Não foi possível conectar ao servidor de origem.');
  }

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new ApiError(502, 'O servidor de origem recusou a chave de sincronização.');
    }
    throw new ApiError(502, `O servidor de origem respondeu com HTTP ${response.status}.`);
  }

  const contentType = String(response.headers.get('content-type') ?? '').toLowerCase();
  if (!contentType.includes('application/json')) {
    throw new ApiError(502, 'O servidor de origem não devolveu JSON.');
  }

  const declaredSize = Number(response.headers.get('content-length') ?? 0);
  if (declaredSize > MAX_SYNC_BODY_BYTES) {
    throw new ApiError(502, 'O snapshot do servidor de origem é muito grande.');
  }

  let text;
  try {
    text = await readLimitedBody(response, MAX_SYNC_BODY_BYTES);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
      throw new ApiError(504, 'O servidor de origem demorou demais para enviar os dados.');
    }
    throw new ApiError(502, 'Falha ao ler a resposta do servidor de origem.');
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(502, 'O servidor de origem devolveu um snapshot inválido.');
  }
}

async function readLimitedBody(response, limit) {
  if (!response.body) return '';

  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new ApiError(502, 'O snapshot do servidor de origem é muito grande.');
    }
    chunks.push(Buffer.from(value));
  }

  return Buffer.concat(chunks).toString('utf8');
}

function buildSmsPayload(message) {
  return {
    id: message.id,
    direction: message.direction,
    from: message.from,
    to: message.to,
    body: message.body,
    createdAt: message.createdAt,
  };
}

const PASSWORD_HASH_PATTERN = /^[0-9a-f]{32}:[0-9a-f]{128}$/;

function buildSyncSnapshot(db) {
  return {
    version: 1,
    exportedAt: new Date().toISOString(),
    counter: String(db.data.counter),
    users: (db.data.users ?? []).map((user) => ({
      id: user.id,
      name: user.name,
      email: user.email,
      passwordHash: user.passwordHash,
      emailVerified: user.emailVerified !== false,
      emailVerifiedAt: user.emailVerifiedAt ?? null,
      createdAt: user.createdAt,
    })),
    lines: (db.data.lines ?? []).map((line) => ({
      id: line.id,
      userId: line.userId,
      number: line.number,
      sequence: line.sequence,
      planId: line.planId,
      status: line.status,
      activatedAt: line.activatedAt,
      seed: line.seed,
      iccid: line.iccid,
      activationCode: line.activationCode,
      smdp: line.smdp,
      welcomeSent: Boolean(line.welcomeSent),
    })),
    messages: (db.data.messages ?? []).map((message) => ({
      id: message.id,
      lineId: message.lineId,
      userId: message.userId,
      direction: message.direction,
      from: message.from,
      to: message.to,
      body: message.body,
      createdAt: message.createdAt,
    })),
  };
}

function importSyncSnapshot(db, snapshot, { mirror = false } = {}) {
  const incoming = validateSyncSnapshot(snapshot);
  const working = {
    users: structuredClone(db.data.users ?? []),
    lines: structuredClone(db.data.lines ?? []),
    messages: structuredClone(db.data.messages ?? []),
    counter: String(db.data.counter),
  };

  const summary = {
    users: { created: 0, updated: 0 },
    lines: { created: 0, updated: 0 },
    messages: { created: 0, updated: 0, deleted: 0 },
    mirror: Boolean(mirror),
    counter: null,
  };

  const userMap = new Map();
  const lineMap = new Map();
  const syncedLineIds = new Set();
  const sourceMessageIds = new Set();

  for (const sourceUser of incoming.users) {
    const emailOwner = working.users.find((user) => user.email === sourceUser.email);
    let local = working.users.find((user) => user.id === sourceUser.id) ?? emailOwner;

    if (!local) {
      local = { ...sourceUser, emailConfirmation: null };
      working.users.push(local);
      summary.users.created += 1;
    } else {
      if (emailOwner && emailOwner.id !== local.id) {
        throw new ApiError(
          409,
          `O e-mail ${sourceUser.email} já pertence a outro usuário neste servidor.`
        );
      }
      if (assignSyncUser(local, sourceUser)) summary.users.updated += 1;
    }

    userMap.set(sourceUser.id, local.id);
  }

  for (const sourceLine of incoming.lines) {
    const mappedUserId = userMap.get(sourceLine.userId);
    if (!mappedUserId) {
      throw new ApiError(400, `A linha ${sourceLine.id} referencia um usuário ausente no snapshot.`);
    }

    let local = working.lines.find((line) => line.id === sourceLine.id);
    if (!local) {
      local = working.lines.find((line) => line.userId === mappedUserId);
    }

    const otherLineForUser = working.lines.find(
      (line) => line.userId === mappedUserId && (!local || line.id !== local.id)
    );
    if (otherLineForUser) {
      throw new ApiError(
        409,
        `O usuário ${sourceLine.userId} já possui outra linha neste servidor.`
      );
    }

    const numberOwner = working.lines.find(
      (line) => line.number === sourceLine.number && (!local || line.id !== local.id)
    );
    if (numberOwner) {
      throw new ApiError(409, `O número ${sourceLine.number} já está em uso neste servidor.`);
    }

    if (!local) {
      local = { ...sourceLine, userId: mappedUserId };
      working.lines.push(local);
      summary.lines.created += 1;
    } else if (assignSyncLine(local, sourceLine, mappedUserId)) {
      summary.lines.updated += 1;
    }

    lineMap.set(sourceLine.id, local.id);
    syncedLineIds.add(local.id);
  }

  for (const sourceMessage of incoming.messages) {
    const lineId = lineMap.get(sourceMessage.lineId);
    if (!lineId) {
      throw new ApiError(
        400,
        `A mensagem ${sourceMessage.id} referencia uma linha ausente no snapshot.`
      );
    }

    let userId = null;
    if (sourceMessage.userId) {
      userId = userMap.get(sourceMessage.userId);
      if (!userId) {
        throw new ApiError(
          400,
          `A mensagem ${sourceMessage.id} referencia um usuário ausente no snapshot.`
        );
      }
    } else {
      userId = working.lines.find((line) => line.id === lineId)?.userId ?? null;
    }

    let local = working.messages.find((message) => message.id === sourceMessage.id);
    if (!local) {
      local = { ...sourceMessage, lineId, userId };
      working.messages.push(local);
      summary.messages.created += 1;
    } else if (assignSyncMessage(local, sourceMessage, lineId, userId)) {
      summary.messages.updated += 1;
    }

    sourceMessageIds.add(sourceMessage.id);
  }

  if (mirror) {
    const before = working.messages.length;
    working.messages = working.messages.filter(
      (message) => !(syncedLineIds.has(message.lineId) && !sourceMessageIds.has(message.id))
    );
    summary.messages.deleted = before - working.messages.length;
  }

  summary.counter = advanceSyncCounter(working, incoming.counter);
  db.data.users = working.users;
  db.data.lines = working.lines;
  db.data.messages = working.messages;
  db.data.counter = working.counter;
  db.save();

  return summary;
}

function assignSyncUser(local, source) {
  let changed = false;
  const set = (field, value) => {
    if (local[field] !== value) {
      local[field] = value;
      changed = true;
    }
  };

  set('name', source.name);
  set('email', source.email);
  set('passwordHash', source.passwordHash);
  set('createdAt', source.createdAt);

  const verified = local.emailVerified !== false || source.emailVerified;
  set('emailVerified', verified);
  set('emailVerifiedAt', local.emailVerifiedAt ?? source.emailVerifiedAt ?? null);

  return changed;
}

function assignSyncLine(local, source, userId) {
  let changed = false;
  const set = (field, value) => {
    if (local[field] !== value) {
      local[field] = value;
      changed = true;
    }
  };

  set('userId', userId);
  set('number', source.number);
  set('sequence', source.sequence);
  set('planId', source.planId);
  set('status', source.status);
  set('activatedAt', source.activatedAt);
  set('seed', source.seed);
  set('iccid', source.iccid);
  set('activationCode', source.activationCode);
  set('smdp', source.smdp);
  set('welcomeSent', source.welcomeSent);

  return changed;
}

function assignSyncMessage(local, source, lineId, userId) {
  let changed = false;
  const set = (field, value) => {
    if (local[field] !== value) {
      local[field] = value;
      changed = true;
    }
  };

  set('lineId', lineId);
  set('userId', userId);
  set('direction', source.direction);
  set('from', source.from);
  set('to', source.to);
  set('body', source.body);
  set('createdAt', source.createdAt);

  return changed;
}

function advanceSyncCounter(working, sourceCounter) {
  let counter = BigInt(String(working.counter));
  const incomingCounter = BigInt(String(sourceCounter));
  if (incomingCounter > counter) counter = incomingCounter;

  for (const line of working.lines) {
    const next = BigInt(line.sequence) + 1n;
    if (next > counter) counter = next;
  }

  working.counter = counter.toString();
  return working.counter;
}

function validateSyncSnapshot(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ApiError(400, 'Snapshot de sincronização inválido.');
  }
  if (payload.version !== 1) {
    throw new ApiError(400, 'Versão de snapshot não suportada.');
  }
  if (!Array.isArray(payload.users) || payload.users.length > MAX_SYNC_USERS) {
    throw new ApiError(400, `O snapshot deve conter até ${MAX_SYNC_USERS} usuários.`);
  }
  if (!Array.isArray(payload.lines) || payload.lines.length > MAX_SYNC_LINES) {
    throw new ApiError(400, `O snapshot deve conter até ${MAX_SYNC_LINES} linhas.`);
  }
  if (!Array.isArray(payload.messages) || payload.messages.length > MAX_SYNC_MESSAGES) {
    throw new ApiError(400, `O snapshot deve conter até ${MAX_SYNC_MESSAGES} mensagens.`);
  }

  const counter = syncDigits(payload.counter, 'contador', 1, 100);
  const users = payload.users.map(normalizeSyncUser);
  const lines = payload.lines.map(normalizeSyncLine);
  const messages = payload.messages.map(normalizeSyncMessage);

  ensureUniqueValues(users.map((user) => user.id), 'IDs de usuários');
  ensureUniqueValues(users.map((user) => user.email), 'e-mails');
  ensureUniqueValues(lines.map((line) => line.id), 'IDs de linhas');
  ensureUniqueValues(lines.map((line) => line.number), 'números de linha');
  ensureUniqueValues(lines.map((line) => line.userId), 'linhas por usuário');
  ensureUniqueValues(messages.map((message) => message.id), 'IDs de mensagens');

  const userIds = new Set(users.map((user) => user.id));
  const lineIds = new Set(lines.map((line) => line.id));

  for (const line of lines) {
    if (!userIds.has(line.userId)) {
      throw new ApiError(400, `A linha ${line.id} referencia um usuário ausente no snapshot.`);
    }
  }
  for (const message of messages) {
    if (!lineIds.has(message.lineId)) {
      throw new ApiError(
        400,
        `A mensagem ${message.id} referencia uma linha ausente no snapshot.`
      );
    }
    if (message.userId && !userIds.has(message.userId)) {
      throw new ApiError(
        400,
        `A mensagem ${message.id} referencia um usuário ausente no snapshot.`
      );
    }
  }

  return { version: 1, counter, users, lines, messages };
}

function normalizeSyncUser(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'Usuário inválido no snapshot.');
  }

  const email = normalizeEmail(value.email);
  if (!isValidEmail(email)) {
    throw new ApiError(400, 'E-mail inválido no snapshot.');
  }
  if (typeof value.emailVerified !== 'boolean') {
    throw new ApiError(400, 'Situação de e-mail inválida no snapshot.');
  }
  if (!PASSWORD_HASH_PATTERN.test(String(value.passwordHash ?? ''))) {
    throw new ApiError(400, 'Hash de senha inválido no snapshot.');
  }

  return {
    id: syncId(value.id, 'usuário'),
    name: syncString(value.name, 'nome', 1, 80),
    email,
    passwordHash: String(value.passwordHash),
    emailVerified: value.emailVerified,
    emailVerifiedAt: value.emailVerifiedAt
      ? syncDate(value.emailVerifiedAt, 'data de verificação')
      : null,
    createdAt: syncDate(value.createdAt, 'data de criação'),
  };
}

function normalizeSyncLine(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'Linha inválida no snapshot.');
  }

  const planId = syncString(value.planId, 'plano', 1, 50);
  if (!getPlan(planId)) {
    throw new ApiError(400, `Plano desconhecido no snapshot: ${planId}.`);
  }
  if (typeof value.seed !== 'number' || !Number.isFinite(value.seed) || value.seed < 0 || value.seed > 1) {
    throw new ApiError(400, 'Seed inválida no snapshot.');
  }
  if (typeof value.welcomeSent !== 'boolean') {
    throw new ApiError(400, 'Situação de boas-vindas inválida no snapshot.');
  }

  return {
    id: syncId(value.id, 'linha'),
    userId: syncId(value.userId, 'usuário da linha'),
    number: syncDigits(value.number, 'número da linha', 47, 47),
    sequence: syncDigits(value.sequence, 'sequência da linha', 47, 47),
    planId,
    status: syncString(value.status, 'situação da linha', 1, 20),
    activatedAt: syncDate(value.activatedAt, 'data de ativação'),
    seed: value.seed,
    iccid: syncString(value.iccid, 'ICCID', 1, 32),
    activationCode: syncString(value.activationCode, 'código de ativação', 1, 200),
    smdp: syncString(value.smdp, 'SM-DP+', 1, 100),
    welcomeSent: value.welcomeSent,
  };
}

function normalizeSyncMessage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'Mensagem inválida no snapshot.');
  }

  const direction = String(value.direction ?? '').trim();
  if (direction !== 'in' && direction !== 'out') {
    throw new ApiError(400, 'Direção de mensagem inválida no snapshot.');
  }

  const body = String(value.body ?? '');
  if (body.length < 1 || body.length > MAX_SMS_BODY) {
    throw new ApiError(400, 'Corpo de mensagem inválido no snapshot.');
  }

  return {
    id: syncId(value.id, 'mensagem'),
    lineId: syncId(value.lineId, 'linha da mensagem'),
    userId: value.userId ? syncId(value.userId, 'usuário da mensagem') : null,
    direction,
    from: syncString(value.from, 'remetente', 1, 100),
    to: syncString(value.to, 'destinatário', 1, 100),
    body,
    createdAt: syncDate(value.createdAt, 'data da mensagem'),
  };
}

function syncId(value, label) {
  const text = String(value ?? '').trim();
  if (text.length < 1 || text.length > 100) {
    throw new ApiError(400, `Identificador inválido no snapshot (${label}).`);
  }
  return text;
}

function syncString(value, label, min, max) {
  const text = String(value ?? '').trim();
  if (text.length < min || text.length > max) {
    throw new ApiError(400, `Campo inválido no snapshot (${label}).`);
  }
  return text;
}

function syncDigits(value, label, min, max) {
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text) || text.length < min || text.length > max) {
    throw new ApiError(400, `Campo numérico inválido no snapshot (${label}).`);
  }
  return text;
}

function syncDate(value, label) {
  const text = String(value ?? '').trim();
  if (!text || Number.isNaN(Date.parse(text))) {
    throw new ApiError(400, `Data inválida no snapshot (${label}).`);
  }
  return text;
}

function ensureUniqueValues(values, label) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) {
      throw new ApiError(400, `Valor duplicado no snapshot (${label}).`);
    }
    seen.add(value);
  }
}

function requireUser(db, req) {
  const user = getSessionUser(db, req);
  if (!user) throw new ApiError(401, 'Faça login para continuar.');
  return user;
}

function getSessionUser(db, req) {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!token) return null;

  const tokenHash = hashToken(token);
  const session = db.data.sessions.find((candidate) => candidate.tokenHash === tokenHash);
  if (!session) return null;
  if (new Date(session.expiresAt).getTime() <= Date.now()) return null;

  return db.data.users.find((user) => user.id === session.userId) ?? null;
}

function issueSession(db, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  db.data.sessions.push({
    tokenHash: hashToken(token),
    userId,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + SESSION_TTL_MS).toISOString(),
  });
  return token;
}

function buildSessionPayload(db, user) {
  if (!user) return { user: null, line: null };
  const line = findLineByUser(db, user.id);
  return {
    user: buildPublicUser(user),
    line: line ? buildLinePayload(line) : null,
  };
}

function buildPublicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: user.emailVerified !== false,
    createdAt: user.createdAt,
  };
}

function buildLinePayload(line) {
  const plan = getPlan(line.planId);
  return {
    id: line.id,
    number: line.number,
    universal: true,
    conventional: conventionalNumberFromLine(line.number),
    planId: line.planId,
    planName: plan?.name ?? 'Plano',
    planPrice: plan?.price ?? 0,
    planKind: plan?.smsOnly ? 'sms' : 'data',
    planLifetime: Boolean(plan?.lifetime),
    status: line.status,
    activatedAt: line.activatedAt,
    activationCode: line.activationCode,
    iccid: line.iccid,
    smdp: line.smdp,
    usage: plan ? computeUsage(line, plan) : null,
  };
}

function findLineByUser(db, userId) {
  return db.data.lines.find((line) => line.userId === userId) ?? null;
}

async function readJson(req, maxBytes = MAX_BODY_BYTES) {
  const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
  if (!contentType.includes('application/json')) {
    throw new ApiError(415, 'Envie o conteúdo como application/json.');
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new ApiError(413, 'Requisição muito grande.');
    chunks.push(chunk);
  }

  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new ApiError(400, 'JSON inválido.');
  }
}

function parseCookies(header = '') {
  const cookies = {};
  for (const part of String(header).split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    const name = part.slice(0, separator).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      cookies[name] = '';
    }
  }
  return cookies;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function issueEmailConfirmation(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const code = String(crypto.randomInt(0, 100_000_000)).padStart(8, '0');
  const expiresAt = new Date(Date.now() + EMAIL_CONFIRMATION_TTL_MS).toISOString();

  user.emailConfirmation = {
    tokenHash: hashToken(token),
    codeHash: hashToken(code),
    attempts: 0,
    createdAt: new Date().toISOString(),
    expiresAt,
  };

  return {
    email: user.email,
    subject: 'Confirme seu e-mail na Luminal',
    expiresAt,
    confirmPath: `/#/confirmar/${token}`,
    code,
  };
}

async function deliverConfirmationEmail(user, verification, req) {
  const config = readSmtpConfig();
  if (!config) return { configured: false, sent: false };

  const link = `${resolvePublicOrigin(req)}${verification.confirmPath}`;
  const content = buildConfirmationEmail(user, verification, link);

  try {
    await sendMail({
      config,
      to: user.email,
      subject: verification.subject,
      text: content.text,
      html: content.html,
    });
    return { configured: true, sent: true, to: user.email };
  } catch (error) {
    console.error(`Falha ao enviar e-mail de confirmação para ${user.email}: ${error.message}`);
    return { configured: true, sent: false };
  }
}

function buildConfirmationEmail(user, verification, link) {
  const firstName = String(user.name ?? '').trim().split(/\s+/)[0] || 'tudo bem';
  const code = String(verification.code ?? '');
  const safeName = escapeHtml(firstName);
  const safeCode = escapeHtml(code);
  const safeLink = escapeHtml(link);

  const text = [
    `Olá, ${firstName}.`,
    '',
    'Bem-vindo à Luminal. Confirme seu e-mail para liberar a ativação da sua linha Free SMS.',
    '',
    `Código de confirmação: ${code}`,
    '',
    'Ou confirme pelo link:',
    link,
    '',
    'O link e o código expiram em 24 horas e só podem ser usados uma vez.',
    'Se você não criou uma conta, ignore esta mensagem.',
  ].join('\n');

  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<body style="margin:0;padding:0;background:#eef2ea;font-family:Arial,Helvetica,sans-serif;color:#111811;">
  <div style="max-width:560px;margin:0 auto;padding:32px 20px;">
    <div style="background:#0b120d;border-radius:24px;padding:32px;color:#f4f7f2;">
      <p style="margin:0 0 24px;font-size:12px;letter-spacing:3px;text-transform:uppercase;color:#b8ff6f;">Luminal</p>
      <h1 style="margin:0 0 16px;font-size:26px;line-height:1.2;color:#f4f7f2;">Confirme seu e-mail</h1>
      <p style="margin:0 0 12px;font-size:15px;line-height:1.6;color:#cdd6cb;">Olá, ${safeName}.</p>
      <p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#cdd6cb;">Confirme seu e-mail para liberar a ativação da sua linha Free SMS na Luminal.</p>
      <a href="${safeLink}" style="display:inline-block;background:#b8ff6f;color:#0b120d;text-decoration:none;font-weight:bold;font-size:15px;padding:14px 24px;border-radius:999px;">Confirmar meu e-mail</a>
      <p style="margin:28px 0 8px;font-size:13px;color:#8e9a8c;">Ou use o código de 8 dígitos:</p>
      <p style="margin:0 0 24px;font-size:32px;letter-spacing:8px;font-weight:bold;color:#f4f7f2;">${safeCode}</p>
      <p style="margin:0 0 8px;font-size:12px;line-height:1.6;color:#8e9a8c;">Se o botão não funcionar, copie este link:</p>
      <p style="margin:0 0 24px;font-size:12px;line-height:1.6;word-break:break-all;color:#b8ff6f;">${safeLink}</p>
      <p style="margin:0;padding-top:20px;border-top:1px solid #253026;font-size:12px;line-height:1.6;color:#8e9a8c;">O link e o código expiram em 24 horas e só podem ser usados uma vez. Se você não criou uma conta, ignore esta mensagem.</p>
    </div>
  </div>
</body>
</html>`;

  return { text, html };
}

function resolvePublicOrigin(req) {
  const configured = String(process.env.PUBLIC_URL ?? '').trim();
  if (/^https?:\/\/[^\s/?#]+$/i.test(configured)) return configured.replace(/\/+$/, '');

  const host = String(req.headers.host ?? '').trim();
  if (/^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(:\d{1,5})?$/i.test(host)) return `http://${host}`;
  return `http://127.0.0.1:${req.socket.localPort ?? 3000}`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`
  );
}

function buildIccid(number) {
  const digest = crypto.createHash('sha256').update(number).digest('hex');
  const tail = (BigInt(`0x${digest.slice(0, 16)}`) % 10n ** 15n)
    .toString()
    .padStart(15, '0');
  return `89455${tail}`;
}

function buildActivationCode() {
  return 'LPA:1$rsp.luminal.demo$' + crypto.randomBytes(8).toString('hex').toUpperCase();
}

function normalizeName(value) {
  return String(value ?? '').trim().replace(/\s+/g, ' ');
}

function normalizeEmail(value) {
  return String(value ?? '').trim().toLowerCase();
}

function isValidEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "img-src 'self' data:",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "connect-src 'self'",
    ].join('; ')
  );
}

function sendJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(payload);
}

async function serveStatic(req, res, url) {
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    throw new ApiError(400, 'Caminho inválido.');
  }

  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = path.resolve(PUBLIC_DIR, relative);

  if (filePath !== PUBLIC_DIR && !filePath.startsWith(PUBLIC_DIR + path.sep)) {
    throw new ApiError(403, 'Acesso negado.');
  }

  let content;
  try {
    content = await readFile(filePath);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Página não encontrada.');
    return;
  }

  const extension = path.extname(filePath).toLowerCase();
  res.writeHead(200, {
    'Content-Type': MIME_TYPES[extension] ?? 'application/octet-stream',
    'Content-Length': content.length,
    'Cache-Control': 'no-cache',
  });

  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  res.end(content);
}

const isMain = process.argv[1]
  ? path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  : false;

if (isMain) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  const server = createApp();
  server.listen(port, host, () => {
    console.log(`Luminal no ar em http://localhost:${port}`);
  });
}
