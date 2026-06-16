'use strict';

/**
 * Allowlist: the single most important security control in this service.
 *
 * Because the relay is exposed publicly, even with a valid secret a caller may
 * ONLY reach destinations that an operator has explicitly approved. This stops
 * the relay from becoming an open SSRF proxy into the private network if the
 * secret ever leaks.
 *
 * The list lives in a JSON file and is hot-reloaded: editing the file (on the
 * host, which is bind-mounted into the container) takes effect immediately with
 * no restart. The admin GUI edits the very same file.
 *
 * Entry shape:
 *   {
 *     "id":    "stable-unique-id",
 *     "label": "Human friendly name",
 *     "host":  "192.168.1.10" | "192.168.1.0/24" | "nas.lan",
 *     "ports": "any" | [80, 443, 5432],
 *     "types": "any" | ["http", "tcp", "ping"]
 *   }
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const logger = require('./logger').child('allowlist');

let entries = [];
let watcher = null;
let reloadTimer = null;

// ---------------------------------------------------------------------------
// IPv4 helpers for CIDR matching.
// ---------------------------------------------------------------------------
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpv4(s) {
  const m = IPV4_RE.exec(s);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) >= 0 && Number(o) <= 255);
}

function ipv4ToLong(ip) {
  return (
    ip.split('.').reduce((acc, oct) => (acc << 8) + (parseInt(oct, 10) & 255), 0) >>> 0
  );
}

function cidrContains(cidr, ip) {
  const [range, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  if (!isIpv4(range) || !isIpv4(ip) || Number.isNaN(bits) || bits < 0 || bits > 32) {
    return false;
  }
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToLong(ip) & mask) === (ipv4ToLong(range) & mask);
}

// ---------------------------------------------------------------------------
// Normalisation / validation of a single entry.
// ---------------------------------------------------------------------------
const VALID_TYPES = ['http', 'https', 'tcp', 'ping'];
const HOST_RE = /^[a-zA-Z0-9.\-_:/]+$/; // hostnames, IPv4, IPv6, optional /CIDR

function normalizeEntry(raw, index) {
  if (!raw || typeof raw !== 'object') {
    throw new Error(`entry #${index} is not an object`);
  }
  const host = String(raw.host || '').trim().toLowerCase();
  if (!host) throw new Error(`entry #${index} is missing "host"`);
  if (!HOST_RE.test(host)) {
    throw new Error(`entry #${index} has an invalid host "${host}"`);
  }

  let ports = raw.ports;
  if (ports === undefined || ports === null || ports === 'any' || ports === '*') {
    ports = 'any';
  } else if (Array.isArray(ports)) {
    ports = ports.map((p) => {
      const n = parseInt(p, 10);
      if (Number.isNaN(n) || n < 1 || n > 65535) {
        throw new Error(`entry #${index} has an invalid port "${p}"`);
      }
      return n;
    });
  } else {
    throw new Error(`entry #${index} "ports" must be "any" or an array of numbers`);
  }

  let types = raw.types;
  if (types === undefined || types === null || types === 'any' || types === '*') {
    types = 'any';
  } else if (Array.isArray(types)) {
    types = types.map((t) => String(t).trim().toLowerCase());
    for (const t of types) {
      if (!VALID_TYPES.includes(t)) {
        throw new Error(`entry #${index} has an unknown type "${t}"`);
      }
    }
  } else {
    throw new Error(`entry #${index} "types" must be "any" or an array`);
  }

  return {
    id: String(raw.id || crypto.randomBytes(8).toString('hex')),
    label: String(raw.label || host),
    host,
    ports,
    types,
  };
}

// ---------------------------------------------------------------------------
// Load / save.
// ---------------------------------------------------------------------------
function load() {
  let text;
  try {
    text = fs.readFileSync(config.ALLOWLIST_FILE, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      logger.warn(
        `Allowlist file not found at ${config.ALLOWLIST_FILE}; starting with an EMPTY allowlist (all checks will be denied until you add entries).`
      );
      entries = [];
      return;
    }
    throw err;
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    logger.error(
      `Allowlist file is not valid JSON — keeping previous allowlist (${entries.length} entries). ${err.message}`
    );
    return;
  }

  const rawEntries = Array.isArray(parsed) ? parsed : parsed.entries;
  if (!Array.isArray(rawEntries)) {
    logger.error('Allowlist file must be an array or an object with "entries" array — keeping previous allowlist.');
    return;
  }

  try {
    const next = rawEntries.map((e, i) => normalizeEntry(e, i));
    entries = next;
    logger.info(`Loaded ${entries.length} allowlist entr${entries.length === 1 ? 'y' : 'ies'}.`);
    for (const e of entries) {
      logger.debug(
        `  allow: label="${e.label}" host=${e.host} ports=${
          e.ports === 'any' ? 'any' : e.ports.join(',')
        } types=${e.types === 'any' ? 'any' : e.types.join(',')}`
      );
    }
  } catch (err) {
    logger.error(`Allowlist validation failed — keeping previous allowlist (${entries.length} entries). ${err.message}`);
  }
}

function save(newEntries) {
  // Validate everything before writing so a bad edit can't corrupt the file.
  const normalized = newEntries.map((e, i) => normalizeEntry(e, i));
  const payload = JSON.stringify({ entries: normalized }, null, 2) + '\n';

  fs.mkdirSync(path.dirname(config.ALLOWLIST_FILE), { recursive: true });
  // Atomic write: temp file + rename so readers never see a half-written file.
  const tmp = `${config.ALLOWLIST_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, payload, { mode: 0o600 });
  fs.renameSync(tmp, config.ALLOWLIST_FILE);

  entries = normalized; // update in-memory immediately; the watcher will also fire.
  logger.info(`Allowlist saved (${normalized.length} entries) to ${config.ALLOWLIST_FILE}.`);
  return normalized;
}

// ---------------------------------------------------------------------------
// Hot reload.
// ---------------------------------------------------------------------------
function startWatching() {
  const file = config.ALLOWLIST_FILE;
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true });

  // Watch the directory rather than the file: editors / Docker bind mounts often
  // replace the inode, which breaks a direct file watch.
  try {
    watcher = fs.watch(dir, (eventType, filename) => {
      if (!filename) return;
      if (path.basename(file) !== filename) return;
      if (reloadTimer) clearTimeout(reloadTimer);
      // Debounce: editors fire several events per save.
      reloadTimer = setTimeout(() => {
        logger.info(`Detected change to allowlist file (${eventType}); reloading…`);
        load();
      }, 200);
    });
    logger.info(`Watching ${dir} for allowlist changes (hot reload enabled).`);
  } catch (err) {
    logger.warn(`Could not start allowlist file watcher (${err.message}); falling back to 10s polling.`);
    // Fallback for filesystems where fs.watch is unreliable (some bind mounts).
    const poll = setInterval(load, 10000);
    if (poll.unref) poll.unref();
  }
}

// ---------------------------------------------------------------------------
// The matching decision used by every check.
// ---------------------------------------------------------------------------
function hostMatches(entryHost, targetHost) {
  if (entryHost.includes('/')) {
    // CIDR — only meaningful when the target is an IPv4 literal.
    return cidrContains(entryHost, targetHost);
  }
  return entryHost === targetHost;
}

function portMatches(entryPorts, port) {
  if (entryPorts === 'any') return true;
  if (port === undefined || port === null) return true; // e.g. ping has no port
  return entryPorts.includes(Number(port));
}

function typeMatches(entryTypes, type) {
  if (entryTypes === 'any') return true;
  // http/https are interchangeable for the purpose of allowlisting a host.
  if ((type === 'http' || type === 'https') &&
      (entryTypes.includes('http') || entryTypes.includes('https'))) {
    return true;
  }
  return entryTypes.includes(type);
}

/**
 * @returns {{ allowed: boolean, entry?: object, reason?: string }}
 */
function isAllowed({ type, host, port }) {
  const target = String(host || '').trim().toLowerCase();
  if (!target) return { allowed: false, reason: 'no target host' };

  for (const entry of entries) {
    if (
      typeMatches(entry.types, type) &&
      hostMatches(entry.host, target) &&
      portMatches(entry.ports, port)
    ) {
      return { allowed: true, entry };
    }
  }
  return {
    allowed: false,
    reason: `no allowlist entry matches type=${type} host=${target}${port ? ` port=${port}` : ''}`,
  };
}

function list() {
  // Return a copy so callers can't mutate internal state.
  return entries.map((e) => ({ ...e }));
}

module.exports = {
  load,
  save,
  startWatching,
  isAllowed,
  list,
  // exported for tests / reuse
  isIpv4,
  cidrContains,
  normalizeEntry,
  VALID_TYPES,
};
