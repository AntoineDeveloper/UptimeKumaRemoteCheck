'use strict';

/**
 * Tiny dependency-free structured logger.
 *
 * Goals:
 *  - Very verbose by default (the user asked for this explicitly).
 *  - Safe: never print the configured secrets, even if they sneak into metadata.
 *  - Container friendly: single line per event, ISO timestamps, plain text so
 *    `docker logs` stays readable.
 */

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3, trace: 4 };

let currentLevel = LEVELS.debug;

/**
 * Strings that must never appear in the logs. Populated at boot by config.js so
 * that an accidental `log.debug('secret', secret)` cannot leak credentials.
 */
const redactions = new Set();

function setLevel(name) {
  if (name && Object.prototype.hasOwnProperty.call(LEVELS, name)) {
    currentLevel = LEVELS[name];
  }
}

function addRedaction(value) {
  if (typeof value === 'string' && value.length >= 4) {
    redactions.add(value);
  }
}

function redact(text) {
  let out = text;
  for (const secret of redactions) {
    if (secret && out.includes(secret)) {
      out = out.split(secret).join('***REDACTED***');
    }
  }
  return out;
}

function formatMeta(meta) {
  if (meta === undefined || meta === null) return '';
  if (meta instanceof Error) {
    return ` ${meta.stack || meta.message}`;
  }
  if (typeof meta === 'string') return ` ${meta}`;
  try {
    return ` ${JSON.stringify(meta)}`;
  } catch (err) {
    return ` [unserializable meta: ${err.message}]`;
  }
}

function emit(level, scope, message, meta) {
  if (LEVELS[level] > currentLevel) return;
  const line = redact(
    `${new Date().toISOString()} [${level.toUpperCase().padEnd(5)}] [${scope}] ${message}${formatMeta(meta)}`
  );
  // error/warn go to stderr, everything else to stdout.
  if (level === 'error' || level === 'warn') {
    process.stderr.write(line + '\n');
  } else {
    process.stdout.write(line + '\n');
  }
}

/**
 * Create a scoped logger. The scope is just a label, e.g. 'http-check' or a
 * per-request id, so related log lines are easy to grep.
 */
function child(scope) {
  return {
    error: (msg, meta) => emit('error', scope, msg, meta),
    warn: (msg, meta) => emit('warn', scope, msg, meta),
    info: (msg, meta) => emit('info', scope, msg, meta),
    debug: (msg, meta) => emit('debug', scope, msg, meta),
    trace: (msg, meta) => emit('trace', scope, msg, meta),
    child,
  };
}

module.exports = {
  LEVELS,
  setLevel,
  addRedaction,
  child,
  // default root logger
  ...child('app'),
};
