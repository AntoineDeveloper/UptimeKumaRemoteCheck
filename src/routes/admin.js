'use strict';

/**
 * Admin GUI backend: login + allowlist CRUD + a "test now" helper.
 *
 * Everything except the login endpoint requires a valid session cookie. The
 * GUI edits the same JSON file the check endpoint reads, and the file watcher
 * hot-reloads it — so changes are live immediately.
 */

const path = require('path');
const express = require('express');
const crypto = require('crypto');
const config = require('../lib/config');
const auth = require('../lib/auth');
const allowlist = require('../lib/allowlist');
const checks = require('../lib/checks');
const { createRateLimiter } = require('../lib/ratelimit');
const rootLogger = require('../lib/logger');

const router = express.Router();

const loginLimiter = createRateLimiter({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.LOGIN_RATE_LIMIT_MAX,
});

// Gate: every /admin/api/* route below this requires a session.
function requireSession(req, res, next) {
  const session = auth.getSession(req);
  if (!session) {
    return res.status(401).json({ error: 'not authenticated' });
  }
  req.session = session;
  next();
}

// ---------------------------------------------------------------------------
// Static GUI
// ---------------------------------------------------------------------------
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
router.get('/api/session', (req, res) => {
  res.json({ authenticated: !!auth.getSession(req) });
});

router.post('/api/login', (req, res) => {
  const log = rootLogger.child(`admin:${req.id}`);
  const ip = req.clientIp;

  const rl = loginLimiter.hit(ip);
  if (!rl.allowed) {
    log.warn(`login rate limited ip=${ip}`);
    res.setHeader('Retry-After', Math.ceil(rl.retryAfterMs / 1000));
    return res.status(429).json({ error: 'too many attempts, slow down' });
  }

  const password = (req.body && req.body.password) || '';
  if (!auth.verifyAdminPassword(password)) {
    log.warn(`failed admin login ip=${ip}`);
    return res.status(401).json({ error: 'invalid password' });
  }

  const token = auth.createSessionToken();
  auth.setSessionCookie(res, token);
  log.info(`admin login success ip=${ip}`);
  res.json({ ok: true });
});

router.post('/api/logout', (req, res) => {
  auth.clearSessionCookie(res);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Allowlist CRUD (session protected)
// ---------------------------------------------------------------------------
router.get('/api/allowlist', requireSession, (req, res) => {
  res.json({ entries: allowlist.list() });
});

router.post('/api/allowlist', requireSession, (req, res) => {
  const log = rootLogger.child(`admin:${req.id}`);
  const entries = allowlist.list();
  const entry = {
    id: crypto.randomBytes(8).toString('hex'),
    label: req.body.label,
    host: req.body.host,
    ports: req.body.ports,
    types: req.body.types,
  };
  try {
    const saved = allowlist.save([...entries, entry]);
    log.info(`admin added allowlist entry host=${entry.host} ip=${req.clientIp}`);
    res.json({ ok: true, entries: saved });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.put('/api/allowlist/:id', requireSession, (req, res) => {
  const log = rootLogger.child(`admin:${req.id}`);
  const entries = allowlist.list();
  const idx = entries.findIndex((e) => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'entry not found' });
  entries[idx] = {
    id: req.params.id,
    label: req.body.label,
    host: req.body.host,
    ports: req.body.ports,
    types: req.body.types,
  };
  try {
    const saved = allowlist.save(entries);
    log.info(`admin updated allowlist entry id=${req.params.id} ip=${req.clientIp}`);
    res.json({ ok: true, entries: saved });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/api/allowlist/:id', requireSession, (req, res) => {
  const log = rootLogger.child(`admin:${req.id}`);
  const entries = allowlist.list().filter((e) => e.id !== req.params.id);
  try {
    const saved = allowlist.save(entries);
    log.info(`admin deleted allowlist entry id=${req.params.id} ip=${req.clientIp}`);
    res.json({ ok: true, entries: saved });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// "Test now" — run a check straight from the GUI. Still enforces the allowlist,
// so the GUI can't be used to probe arbitrary hosts either.
// ---------------------------------------------------------------------------
router.post('/api/test', requireSession, async (req, res) => {
  const log = rootLogger.child(`admin:${req.id}`);
  const type = String(req.body.type || '').toLowerCase();
  const host = String(req.body.host || '').toLowerCase();
  const port = req.body.port ? parseInt(req.body.port, 10) : undefined;

  if (!['http', 'https', 'tcp', 'ping'].includes(type)) {
    return res.status(400).json({ error: 'invalid type' });
  }
  if (!host && !req.body.target) {
    return res.status(400).json({ error: 'host or target required' });
  }

  const decision = allowlist.isAllowed({ type, host, port });
  if (!decision.allowed) {
    return res.status(403).json({ error: 'target not allowed', reason: decision.reason });
  }

  log.info(`admin test ${type} host=${host} ip=${req.clientIp}`);
  let result;
  try {
    if (type === 'http' || type === 'https') {
      const target = req.body.target || `${type}://${host}${port ? `:${port}` : ''}/`;
      result = await checks.httpCheck(target, { ignoreTls: true });
    } else if (type === 'tcp') {
      result = await checks.tcpCheck(host, port);
    } else {
      result = await checks.pingCheck(host);
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
  res.json({ result });
});

module.exports = router;
