'use strict';

/**
 * Loads and validates configuration from `.env.local` (falling back to process
 * environment, which is how Docker injects values).
 *
 * This module throws on boot if the configuration is unsafe, so the server
 * never starts in an insecure state (e.g. missing / weak secret). Since the
 * service is exposed publicly, "fail closed" is the rule everywhere.
 */

const path = require('path');
const crypto = require('crypto');
const dotenv = require('dotenv');
const logger = require('./logger');

// Allow overriding the env file (handy for tests / multiple instances).
const envFile = process.env.ENV_FILE || '.env.local';
dotenv.config({ path: path.resolve(process.cwd(), envFile) });
// Also load a plain `.env` if present, without overriding `.env.local`.
dotenv.config();

function str(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

function int(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) {
    throw new Error(`Config error: ${name} must be an integer, got "${v}"`);
  }
  return n;
}

function bool(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

// ---------------------------------------------------------------------------
// Required: the shared secret Uptime Kuma must send on every check request.
// ---------------------------------------------------------------------------
const AUTH_SECRET = str('AUTH_SECRET');
if (!AUTH_SECRET) {
  throw new Error(
    'Config error: AUTH_SECRET is required. Generate one with:\n' +
      "  node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"\n" +
      'and put it in .env.local'
  );
}
if (AUTH_SECRET.length < 24) {
  throw new Error(
    `Config error: AUTH_SECRET is too short (${AUTH_SECRET.length} chars). ` +
      'Use at least 24 characters of random data for a publicly exposed service.'
  );
}

// The admin GUI password. Falls back to AUTH_SECRET if not set, but a separate
// one is recommended so the value you type in a browser differs from the value
// stored in Uptime Kuma.
const ADMIN_PASSWORD = str('ADMIN_PASSWORD', AUTH_SECRET);

// Secret used to sign admin session cookies. If not provided we generate a
// random one at boot (sessions then reset on restart, which is fine).
const SESSION_SECRET = str('SESSION_SECRET', crypto.randomBytes(32).toString('hex'));

const config = {
  PORT: int('PORT', 3010),
  HOST: str('HOST', '0.0.0.0'),

  // Auth
  AUTH_HEADER: str('AUTH_HEADER', 'x-auth-token').toLowerCase(),
  AUTH_SECRET,
  ADMIN_ENABLED: bool('ADMIN_ENABLED', true),
  ADMIN_PASSWORD,
  SESSION_SECRET,
  SESSION_TTL_MS: int('SESSION_TTL_MS', 8 * 60 * 60 * 1000), // 8h
  COOKIE_SECURE: bool('COOKIE_SECURE', false), // set true when served over HTTPS
  COOKIE_NAME: str('COOKIE_NAME', 'ukrc_session'),

  // Networking / proxy
  TRUST_PROXY: bool('TRUST_PROXY', true), // behind nginx/Caddy/Cloudflare by default

  // Allowlist
  ALLOWLIST_FILE: path.resolve(
    process.cwd(),
    str('ALLOWLIST_FILE', 'config/allowlist.json')
  ),

  // Check behaviour
  DEFAULT_TIMEOUT_MS: int('DEFAULT_TIMEOUT_MS', 10000),
  MAX_TIMEOUT_MS: int('MAX_TIMEOUT_MS', 60000),
  MAX_BODY_BYTES: int('MAX_BODY_BYTES', 65536), // cap response body read for keyword match
  PING_COUNT: int('PING_COUNT', 1),

  // Rate limiting (defense in depth — protects against secret brute force / abuse)
  RATE_LIMIT_WINDOW_MS: int('RATE_LIMIT_WINDOW_MS', 60000),
  RATE_LIMIT_MAX: int('RATE_LIMIT_MAX', 120), // per IP per window for /check
  LOGIN_RATE_LIMIT_MAX: int('LOGIN_RATE_LIMIT_MAX', 10), // per IP per window for /admin/login

  // Logging
  LOG_LEVEL: str('LOG_LEVEL', 'debug'),
};

// Make sure secrets never get printed.
logger.setLevel(config.LOG_LEVEL);
logger.addRedaction(config.AUTH_SECRET);
logger.addRedaction(config.ADMIN_PASSWORD);
logger.addRedaction(config.SESSION_SECRET);

module.exports = config;
