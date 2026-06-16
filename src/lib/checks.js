'use strict';

/**
 * The actual probes. Each returns a normalized result:
 *
 *   {
 *     up: boolean,
 *     message: string,        // short human summary
 *     rttMs: number|null,     // round-trip / response time when available
 *     details: object         // extra diagnostics (status code, etc.)
 *   }
 *
 * Security notes:
 *  - HTTP: redirects are NOT followed by default (a redirect could point at a
 *    non-allowlisted host). The response body is read only up to MAX_BODY_BYTES
 *    so a malicious target can't exhaust memory.
 *  - Ping: executed with execFile + an argument array (never a shell), and the
 *    host is validated against a strict regex, so command injection is not
 *    possible.
 */

const http = require('http');
const https = require('https');
const net = require('net');
const dns = require('dns');
const { execFile } = require('child_process');
const os = require('os');
const config = require('./config');

// ---------------------------------------------------------------------------
// Shared validation
// ---------------------------------------------------------------------------
// Hostnames, IPv4 and IPv6 literals. Deliberately strict — anything outside
// this set is rejected before it can reach a network call or the ping binary.
const HOST_RE = /^[a-zA-Z0-9.\-_:]+$/;

function isValidHost(host) {
  return typeof host === 'string' && host.length > 0 && host.length <= 253 && HOST_RE.test(host);
}

function clampTimeout(ms) {
  const t = Number(ms) || config.DEFAULT_TIMEOUT_MS;
  return Math.min(Math.max(t, 100), config.MAX_TIMEOUT_MS);
}

// Parse an Uptime-Kuma-style accepted status spec like "200-299,301,418".
function parseStatusSpec(spec) {
  const ranges = [];
  for (const part of String(spec || '200-299').split(',')) {
    const p = part.trim();
    if (!p) continue;
    if (p.includes('-')) {
      const [a, b] = p.split('-').map((x) => parseInt(x, 10));
      if (!Number.isNaN(a) && !Number.isNaN(b)) ranges.push([a, b]);
    } else {
      const n = parseInt(p, 10);
      if (!Number.isNaN(n)) ranges.push([n, n]);
    }
  }
  if (ranges.length === 0) ranges.push([200, 299]);
  return (status) => ranges.some(([a, b]) => status >= a && status <= b);
}

// ---------------------------------------------------------------------------
// HTTP / HTTPS
// ---------------------------------------------------------------------------
function httpCheck(targetUrl, opts = {}) {
  return new Promise((resolve) => {
    let url;
    try {
      url = new URL(targetUrl);
    } catch {
      return resolve({ up: false, message: 'invalid URL', rttMs: null, details: {} });
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return resolve({
        up: false,
        message: `unsupported protocol ${url.protocol}`,
        rttMs: null,
        details: {},
      });
    }

    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;
    const timeoutMs = clampTimeout(opts.timeoutMs);
    const accepts = parseStatusSpec(opts.acceptedStatus);
    const keyword = opts.keyword ? String(opts.keyword) : null;
    const method = (opts.method || 'GET').toUpperCase();

    // ignoreTls defaults to TRUE — the user explicitly wants self-signed certs
    // on internal hosts to be accepted.
    const ignoreTls = opts.ignoreTls !== false;

    const requestOptions = {
      method,
      timeout: timeoutMs,
      // Identify ourselves honestly.
      headers: { 'User-Agent': 'UptimeKumaRemoteCheck/1.0' },
    };
    if (isHttps) {
      requestOptions.rejectUnauthorized = !ignoreTls;
    }

    const start = Date.now();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const req = lib.request(url, requestOptions, (res) => {
      const status = res.statusCode;
      const chunks = [];
      let received = 0;
      let truncated = false;

      res.on('data', (chunk) => {
        if (received < config.MAX_BODY_BYTES) {
          const remaining = config.MAX_BODY_BYTES - received;
          chunks.push(chunk.slice(0, remaining));
          received += Math.min(chunk.length, remaining);
        } else {
          truncated = true;
          // We have enough for keyword matching; stop reading the body.
          res.destroy();
        }
      });

      const finish = () => {
        const rttMs = Date.now() - start;
        const body = Buffer.concat(chunks).toString('utf8');
        const statusOk = accepts(status);
        let keywordOk = true;
        if (keyword) keywordOk = body.includes(keyword);

        const up = statusOk && keywordOk;
        let message;
        if (!statusOk) {
          message = `HTTP ${status} not in accepted range`;
        } else if (!keywordOk) {
          message = `HTTP ${status} but keyword "${keyword}" not found`;
        } else {
          message = `HTTP ${status} OK${keyword ? ` (keyword matched)` : ''}`;
        }

        done({
          up,
          message,
          rttMs,
          details: {
            status,
            statusOk,
            keywordOk,
            bytesRead: received,
            truncated,
            tlsIgnored: isHttps ? ignoreTls : undefined,
          },
        });
      };

      res.on('end', finish);
      // res.destroy() above emits 'close' rather than 'end'.
      res.on('close', finish);
      res.on('error', (err) =>
        done({ up: false, message: `response error: ${err.message}`, rttMs: Date.now() - start, details: { status } })
      );
    });

    req.on('timeout', () => {
      req.destroy();
      done({ up: false, message: `timeout after ${timeoutMs}ms`, rttMs: Date.now() - start, details: {} });
    });
    req.on('error', (err) => {
      done({ up: false, message: `request error: ${err.message}`, rttMs: Date.now() - start, details: { code: err.code } });
    });

    if (opts.body && method !== 'GET' && method !== 'HEAD') {
      req.write(String(opts.body));
    }
    req.end();
  });
}

// ---------------------------------------------------------------------------
// TCP port connect
// ---------------------------------------------------------------------------
function tcpCheck(host, port, opts = {}) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      return resolve({ up: false, message: 'invalid host', rttMs: null, details: {} });
    }
    const p = parseInt(port, 10);
    if (Number.isNaN(p) || p < 1 || p > 65535) {
      return resolve({ up: false, message: 'invalid port', rttMs: null, details: {} });
    }
    const timeoutMs = clampTimeout(opts.timeoutMs);
    const start = Date.now();
    let settled = false;

    const socket = new net.Socket();
    const done = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      done({
        up: true,
        message: `TCP connect to ${host}:${p} succeeded`,
        rttMs: Date.now() - start,
        details: { host, port: p },
      });
    });
    socket.once('timeout', () => {
      done({ up: false, message: `TCP connect timeout after ${timeoutMs}ms`, rttMs: Date.now() - start, details: { host, port: p } });
    });
    socket.once('error', (err) => {
      done({ up: false, message: `TCP connect failed: ${err.message}`, rttMs: Date.now() - start, details: { host, port: p, code: err.code } });
    });

    socket.connect(p, host);
  });
}

// ---------------------------------------------------------------------------
// ICMP ping (cross platform, no shell)
// ---------------------------------------------------------------------------
function buildPingArgs(host, timeoutMs) {
  const platform = os.platform();
  const count = String(Math.max(1, config.PING_COUNT));
  const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));

  if (platform === 'win32') {
    // -n count, -w timeout in milliseconds
    return ['-n', count, '-w', String(timeoutMs), host];
  }
  if (platform === 'darwin') {
    // macOS: -c count, -t total timeout in seconds
    return ['-c', count, '-t', String(timeoutSec), host];
  }
  // Linux / BusyBox (Alpine): -c count, -W per-reply timeout in seconds
  return ['-c', count, '-W', String(timeoutSec), host];
}

function parseRtt(stdout) {
  // Try to pull an average / time value out of typical ping output.
  const avg = /=\s*[\d.]+\/([\d.]+)\//.exec(stdout); // linux/mac rtt min/avg/max
  if (avg) return parseFloat(avg[1]);
  const time = /time[=<]\s*([\d.]+)\s*ms/i.exec(stdout); // windows / single reply
  if (time) return parseFloat(time[1]);
  return null;
}

function pingCheck(host, opts = {}) {
  return new Promise((resolve) => {
    if (!isValidHost(host)) {
      return resolve({ up: false, message: 'invalid host', rttMs: null, details: {} });
    }
    const timeoutMs = clampTimeout(opts.timeoutMs);
    const args = buildPingArgs(host, timeoutMs);
    const start = Date.now();

    // execFile (NOT exec) — args are passed as an array, never through a shell,
    // so the validated host cannot be used for command injection. We also set a
    // hard process timeout as a backstop.
    execFile(
      'ping',
      args,
      { timeout: timeoutMs + 2000, windowsHide: true, maxBuffer: 1024 * 64 },
      (err, stdout, stderr) => {
        const rttMs = parseRtt(stdout || '');
        const elapsed = Date.now() - start;
        if (err) {
          return resolve({
            up: false,
            message: `ping failed: ${(stderr || err.message || '').trim().split('\n')[0]}`,
            rttMs,
            details: { code: err.code, elapsedMs: elapsed },
          });
        }
        resolve({
          up: true,
          message: `ping to ${host} succeeded${rttMs !== null ? ` (${rttMs} ms)` : ''}`,
          rttMs: rttMs !== null ? rttMs : elapsed,
          details: { elapsedMs: elapsed },
        });
      }
    );
  });
}

module.exports = {
  httpCheck,
  tcpCheck,
  pingCheck,
  isValidHost,
  clampTimeout,
  parseStatusSpec,
};
