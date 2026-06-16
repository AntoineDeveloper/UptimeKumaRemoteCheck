'use strict';

/**
 * Uptime Kuma Remote Check — entry point.
 *
 * A small Express app exposing:
 *   GET/POST /check        -> run a probe against an allowlisted internal target
 *   GET      /healthz      -> liveness probe (no auth)
 *   /admin, /admin/api/*   -> session-protected GUI to manage the allowlist
 *
 * Designed to sit on the public internet, so it fails closed: it won't boot
 * without a strong secret, and every probe must pass the allowlist.
 */

const crypto = require('crypto');
const express = require('express');

const config = require('./lib/config');
const logger = require('./lib/logger');
const allowlist = require('./lib/allowlist');
const checkRouter = require('./routes/check');
const adminRouter = require('./routes/admin');

const app = express();

// We're typically behind a reverse proxy (nginx/Caddy/Cloudflare) doing TLS, so
// trust X-Forwarded-For to log the real client IP. Disable via TRUST_PROXY=false
// if exposed directly.
app.set('trust proxy', config.TRUST_PROXY);
app.disable('x-powered-by');

// Strict, small JSON body limit — we never need large payloads.
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// Per-request id + real client IP + minimal security headers + access log.
app.use((req, res, next) => {
  req.id = crypto.randomBytes(4).toString('hex');
  req.clientIp =
    (config.TRUST_PROXY && (req.headers['x-forwarded-for'] || '').split(',')[0].trim()) ||
    req.ip ||
    req.socket.remoteAddress ||
    'unknown';

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  const start = Date.now();
  res.on('finish', () => {
    logger.child('http').debug(
      `${req.clientIp} ${req.method} ${req.originalUrl} -> ${res.statusCode} (${Date.now() - start}ms) [${req.id}]`
    );
  });
  next();
});

// Liveness probe for Docker healthchecks / load balancers. Intentionally tiny
// and unauthenticated; reveals nothing sensitive.
app.get('/healthz', (req, res) => res.json({ status: 'ok', uptimeSec: Math.floor(process.uptime()) }));

// Routes
app.use('/check', checkRouter);
if (config.ADMIN_ENABLED) {
  app.use('/admin', adminRouter);
  // Convenience redirect from root to the GUI.
  app.get('/', (req, res) => res.redirect('/admin'));
} else {
  app.get('/', (req, res) => res.json({ status: 'ok', admin: 'disabled' }));
  logger.warn('Admin GUI is DISABLED (ADMIN_ENABLED=false).');
}

// 404
app.use((req, res) => res.status(404).json({ error: 'not found' }));

// Error handler (e.g. body parser errors) — never leak internals.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.child('http').warn(`request error [${req.id}]: ${err.message}`);
  res.status(err.status || 400).json({ error: 'bad request' });
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
function start() {
  logger.info('========================================================');
  logger.info(' Uptime Kuma Remote Check starting');
  logger.info('========================================================');
  logger.info(`PORT=${config.PORT} HOST=${config.HOST}`);
  logger.info(`AUTH_HEADER=${config.AUTH_HEADER}`);
  logger.info(`ALLOWLIST_FILE=${config.ALLOWLIST_FILE}`);
  logger.info(`ADMIN_ENABLED=${config.ADMIN_ENABLED} COOKIE_SECURE=${config.COOKIE_SECURE} TRUST_PROXY=${config.TRUST_PROXY}`);
  logger.info(`LOG_LEVEL=${config.LOG_LEVEL}`);

  // Initial load + start hot-reload watcher.
  allowlist.load();
  allowlist.startWatching();

  const server = app.listen(config.PORT, config.HOST, () => {
    logger.info(`Listening on http://${config.HOST}:${config.PORT}`);
    logger.info('Ready. Point your Uptime Kuma monitors at /check.');
  });

  server.on('error', (err) => {
    logger.error(`Server failed to start: ${err.message}`);
    process.exit(1);
  });

  // Graceful shutdown.
  const shutdown = (signal) => {
    logger.info(`Received ${signal}, shutting down…`);
    server.close(() => {
      logger.info('HTTP server closed. Bye.');
      process.exit(0);
    });
    // Backstop in case connections hang.
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    logger.error(`Unhandled promise rejection: ${reason}`);
  });
  process.on('uncaughtException', (err) => {
    logger.error(`Uncaught exception: ${err.message}`, err);
  });
}

start();
