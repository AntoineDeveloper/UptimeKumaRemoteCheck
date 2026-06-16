'use strict';

/**
 * The public check endpoint that Uptime Kuma calls.
 *
 * Contract (per the chosen design):
 *   - 200 + JSON  => target is UP
 *   - 503 + JSON  => target is DOWN
 *   - 400         => bad request (missing/invalid params)
 *   - 401         => missing/invalid secret
 *   - 403         => target not in allowlist
 *   - 429         => rate limited
 *
 * A default Uptime Kuma "HTTP(s)" monitor pointed at this endpoint therefore
 * goes green/red automatically, no keyword config required.
 *
 * Example monitor URL:
 *   https://relay.example.com/check?type=tcp&host=192.168.1.10&port=5432
 * with custom header:
 *   X-Auth-Token: <your AUTH_SECRET>
 */

const express = require('express');
const config = require('../lib/config');
const auth = require('../lib/auth');
const allowlist = require('../lib/allowlist');
const checks = require('../lib/checks');
const { createRateLimiter } = require('../lib/ratelimit');
const rootLogger = require('../lib/logger');

const router = express.Router();

const limiter = createRateLimiter({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX,
});

// Merge query + body so the endpoint works with GET (query string) and POST.
function params(req) {
  return { ...(req.body || {}), ...req.query };
}

/**
 * Resolve the (type, host, port, target) tuple from the request and validate
 * it. Returns either { error } or the normalized request descriptor.
 */
function parseRequest(p) {
  let type = String(p.type || '').trim().toLowerCase();
  if (!type) return { error: 'missing "type" (http, https, tcp or ping)' };
  if (!['http', 'https', 'tcp', 'ping'].includes(type)) {
    return { error: `unsupported type "${type}"` };
  }

  if (type === 'http' || type === 'https') {
    // Accept either a full URL in "target"/"url", or host (+optional path).
    let target = String(p.target || p.url || '').trim();
    if (!target) {
      const host = String(p.host || '').trim();
      if (!host) return { error: 'missing "target" URL (or "host")' };
      const path = String(p.path || '/').trim();
      const port = p.port ? `:${parseInt(p.port, 10)}` : '';
      target = `${type}://${host}${port}${path.startsWith('/') ? '' : '/'}${path}`;
    }
    if (!/^https?:\/\//i.test(target)) {
      target = `${type}://${target}`;
    }
    let url;
    try {
      url = new URL(target);
    } catch {
      return { error: `invalid URL "${target}"` };
    }
    const port = url.port
      ? parseInt(url.port, 10)
      : url.protocol === 'https:'
      ? 443
      : 80;
    return {
      type: url.protocol === 'https:' ? 'https' : 'http',
      host: url.hostname.toLowerCase(),
      port,
      target: url.toString(),
      httpOpts: {
        method: p.method,
        acceptedStatus: p.accept || p.acceptedStatus,
        keyword: p.keyword,
        // ignoreTls defaults true; only an explicit "false"/"0" turns it off.
        ignoreTls: !['false', '0', 'no'].includes(String(p.ignoreTls || '').toLowerCase()),
        timeoutMs: p.timeout ? parseInt(p.timeout, 10) : undefined,
        body: p.requestBody,
      },
    };
  }

  // tcp / ping
  const host = String(p.host || p.target || '').trim().toLowerCase();
  if (!host) return { error: 'missing "host"' };
  if (!checks.isValidHost(host)) return { error: `invalid host "${host}"` };

  if (type === 'tcp') {
    const port = parseInt(p.port, 10);
    if (Number.isNaN(port) || port < 1 || port > 65535) {
      return { error: 'tcp checks require a valid "port" (1-65535)' };
    }
    return {
      type,
      host,
      port,
      timeoutMs: p.timeout ? parseInt(p.timeout, 10) : undefined,
    };
  }

  // ping
  return {
    type,
    host,
    port: undefined,
    timeoutMs: p.timeout ? parseInt(p.timeout, 10) : undefined,
  };
}

async function runCheck(desc) {
  switch (desc.type) {
    case 'http':
    case 'https':
      return checks.httpCheck(desc.target, desc.httpOpts);
    case 'tcp':
      return checks.tcpCheck(desc.host, desc.port, { timeoutMs: desc.timeoutMs });
    case 'ping':
      return checks.pingCheck(desc.host, { timeoutMs: desc.timeoutMs });
    default:
      return { up: false, message: 'unknown type', rttMs: null, details: {} };
  }
}

router.all('/', async (req, res) => {
  const log = rootLogger.child(`check:${req.id}`);
  const ip = req.clientIp;

  // 1) Rate limit (cheap, before any expensive work).
  const rl = limiter.hit(ip);
  if (!rl.allowed) {
    log.warn(`rate limited ip=${ip}`);
    res.setHeader('Retry-After', Math.ceil(rl.retryAfterMs / 1000));
    return res.status(429).json({ status: 'error', error: 'rate limited' });
  }

  // 2) Authenticate the secret.
  if (!auth.verifyCheckSecret(req)) {
    log.warn(`unauthorized check request ip=${ip} (missing/invalid ${config.AUTH_HEADER})`);
    return res.status(401).json({ status: 'error', error: 'unauthorized' });
  }

  // 3) Parse + validate.
  const p = params(req);
  const desc = parseRequest(p);
  if (desc.error) {
    log.info(`bad request ip=${ip}: ${desc.error}`);
    return res.status(400).json({ status: 'error', error: desc.error });
  }

  // 4) Allowlist enforcement — the key SSRF control.
  const decision = allowlist.isAllowed({ type: desc.type, host: desc.host, port: desc.port });
  if (!decision.allowed) {
    log.warn(`DENIED by allowlist ip=${ip} type=${desc.type} host=${desc.host} port=${desc.port || '-'}: ${decision.reason}`);
    return res.status(403).json({ status: 'error', error: 'target not allowed', reason: decision.reason });
  }

  log.info(
    `running ${desc.type} check host=${desc.host}${desc.port ? ` port=${desc.port}` : ''}` +
      `${desc.target ? ` target=${desc.target}` : ''} (allow="${decision.entry.label}")`
  );

  // 5) Run the probe.
  let result;
  try {
    result = await runCheck(desc);
  } catch (err) {
    log.error(`check threw unexpectedly: ${err.message}`, err);
    return res.status(503).json({ status: 'down', error: 'check failed', message: err.message });
  }

  const payload = {
    status: result.up ? 'up' : 'down',
    type: desc.type,
    host: desc.host,
    port: desc.port,
    target: desc.target,
    message: result.message,
    responseTimeMs: result.rttMs,
    details: result.details,
    checkedAt: new Date().toISOString(),
  };

  if (result.up) {
    log.info(`UP host=${desc.host} (${result.message}) rtt=${result.rttMs}ms`);
    return res.status(200).json(payload);
  }
  log.info(`DOWN host=${desc.host} (${result.message})`);
  return res.status(503).json(payload);
});

module.exports = router;
