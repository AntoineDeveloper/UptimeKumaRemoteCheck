'use strict';

/**
 * Authentication helpers.
 *
 *  1. Check-endpoint auth: a shared secret carried in a configurable header,
 *     compared in constant time so the relay does not leak the secret through
 *     timing.
 *
 *  2. Admin-GUI auth: a browser can't easily attach a custom header to a normal
 *     navigation, so the GUI logs in with a password and receives an
 *     HMAC-signed, HttpOnly session cookie. No server-side session store needed
 *     — the cookie is self-contained and tamper-evident.
 */

const crypto = require('crypto');
const config = require('./config');

// ---------------------------------------------------------------------------
// Constant-time string comparison.
// timingSafeEqual requires equal-length buffers, so we hash both sides first.
// ---------------------------------------------------------------------------
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ---------------------------------------------------------------------------
// Check-endpoint auth
// ---------------------------------------------------------------------------
function getProvidedSecret(req) {
  // Primary: configured header (default x-auth-token).
  const headerVal = req.headers[config.AUTH_HEADER];
  if (typeof headerVal === 'string' && headerVal.length > 0) {
    return headerVal;
  }
  // Also accept Authorization: Bearer <secret> for convenience.
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim();
  }
  return '';
}

function verifyCheckSecret(req) {
  return safeEqual(getProvidedSecret(req), config.AUTH_SECRET);
}

// ---------------------------------------------------------------------------
// Admin session cookie: base64url(payload).base64url(hmac)
// ---------------------------------------------------------------------------
function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signSession(payload) {
  const body = b64url(JSON.stringify(payload));
  const mac = crypto
    .createHmac('sha256', config.SESSION_SECRET)
    .update(body)
    .digest();
  return `${body}.${b64url(mac)}`;
}

function verifySession(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;

  const expectedMac = crypto
    .createHmac('sha256', config.SESSION_SECRET)
    .update(body)
    .digest();
  let givenMac;
  try {
    givenMac = Buffer.from(mac, 'base64url');
  } catch {
    return null;
  }
  if (
    givenMac.length !== expectedMac.length ||
    !crypto.timingSafeEqual(givenMac, expectedMac)
  ) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload || typeof payload.exp !== 'number' || payload.exp < Date.now()) {
    return null;
  }
  return payload;
}

function createSessionToken() {
  return signSession({
    sub: 'admin',
    iat: Date.now(),
    exp: Date.now() + config.SESSION_TTL_MS,
    nonce: crypto.randomBytes(8).toString('hex'),
  });
}

// ---------------------------------------------------------------------------
// Cookie helpers (no cookie-parser dependency).
// ---------------------------------------------------------------------------
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

function setSessionCookie(res, token) {
  const attrs = [
    `${config.COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(config.SESSION_TTL_MS / 1000)}`,
  ];
  if (config.COOKIE_SECURE) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function clearSessionCookie(res) {
  const attrs = [
    `${config.COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=0',
  ];
  if (config.COOKIE_SECURE) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function getSession(req) {
  const cookies = parseCookies(req);
  return verifySession(cookies[config.COOKIE_NAME]);
}

function verifyAdminPassword(password) {
  return safeEqual(password, config.ADMIN_PASSWORD);
}

module.exports = {
  safeEqual,
  verifyCheckSecret,
  verifyAdminPassword,
  createSessionToken,
  setSessionCookie,
  clearSessionCookie,
  getSession,
};
