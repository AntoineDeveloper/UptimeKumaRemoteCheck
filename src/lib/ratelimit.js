'use strict';

/**
 * Minimal in-memory fixed-window rate limiter. No external store / dependency.
 *
 * Good enough for a single-instance relay: it slows down brute-forcing the
 * secret and abusive scanning. For multi-instance you'd want a shared store,
 * but that is out of scope for a small self-hosted tool.
 */

function createRateLimiter({ windowMs, max }) {
  /** @type {Map<string, { count: number, resetAt: number }>} */
  const buckets = new Map();

  // Periodically drop expired buckets so memory does not grow unbounded.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key);
    }
  }, Math.max(windowMs, 30000));
  // Don't keep the process alive just for the sweeper.
  if (sweep.unref) sweep.unref();

  /**
   * @returns {{ allowed: boolean, remaining: number, retryAfterMs: number }}
   */
  function hit(key) {
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    const allowed = bucket.count <= max;
    return {
      allowed,
      remaining: Math.max(0, max - bucket.count),
      retryAfterMs: Math.max(0, bucket.resetAt - now),
    };
  }

  return { hit };
}

module.exports = { createRateLimiter };
