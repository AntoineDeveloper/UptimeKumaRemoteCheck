# Uptime Kuma Remote Check

A small, **secure** relay that lets a **cloud-hosted [Uptime Kuma](https://github.com/louislam/uptime-kuma)** monitor hosts that live inside a **private network** it can't otherwise reach.

You run this service somewhere that *can* see your internal hosts (e.g. a box on your LAN), expose it to the internet, and point Uptime Kuma monitors at it. The relay performs the actual probe — **HTTP/HTTPS, TCP port, or ICMP ping** — and reports back, so the monitor behaves just like a native Uptime Kuma check.

Because it's exposed publicly, it's built to **fail closed**:

- 🔑 **Shared-secret auth** in a header, compared in constant time.
- ✅ **Allowlist** of permitted targets — even with the secret, callers can only reach destinations you explicitly approve (stops it becoming an open SSRF proxy).
- 🔁 **Hot-reloaded allowlist** + a simple **web GUI** to manage it.
- 🧱 No shell execution, redirect-following off by default, response-body size caps, request rate-limiting, strict input validation.
- 🐳 Ships with a Dockerfile + compose. Only two runtime dependencies (`express`, `dotenv`); everything else is Node built-ins.

---

## How it works

```
            (public internet)                         (your private LAN)
┌───────────────────────┐   X-Auth-Token   ┌────────────────────────┐   probe    ┌──────────────┐
│  Cloud Uptime Kuma     │ ───────────────► │  Uptime Kuma Remote    │ ─────────► │ 192.168.1.10 │
│  HTTP(s) monitor       │  GET /check?...  │  Check (this service)  │            │ NAS / DB / … │
│                        │ ◄─────────────── │  allowlist + auth      │ ◄───────── │              │
└───────────────────────┘  200 UP / 503 DN └────────────────────────┘            └──────────────┘
```

The relay maps the result to an HTTP status code:

| Result | Status | Meaning |
| --- | --- | --- |
| Target reachable | `200` | Uptime Kuma shows **UP** |
| Target unreachable | `503` | Uptime Kuma shows **DOWN** |
| Missing/invalid secret | `401` | |
| Target not allowlisted | `403` | |
| Bad parameters | `400` | |
| Rate limited | `429` | |

A default Uptime Kuma **HTTP(s)** monitor pointed at `/check?...` therefore goes green/red automatically — no keyword config needed.

---

## Quick start

```bash
git clone <your-fork-url> UptimeKumaRemoteCheck
cd UptimeKumaRemoteCheck

npm install
npm run setup        # generates .env.local with strong secrets + allowlist.json
npm start            # or: docker compose up -d --build
```

Then open **http://localhost:3010/admin**, log in with the admin password, and add allowlist entries.

> `npm run setup` prints your `AUTH_SECRET`. That's the value you put in the `X-Auth-Token` header in Uptime Kuma. You can re-display it any time by reading `.env.local`.

### Docker

```bash
npm run setup                       # create .env.local first
docker compose up -d --build
docker compose logs -f
```

The compose file bind-mounts the project, so editing `config/allowlist.json` on the host is **hot-reloaded** inside the container instantly.

---

## Configuring Uptime Kuma

Create a **Monitor** of type **HTTP(s)** for each thing you want to watch:

- **URL**: your relay's public URL + `/check` + query params (see below).
- **Method**: `GET`.
- **Headers** (Advanced → Headers): add your secret:
  ```json
  { "X-Auth-Token": "your-AUTH_SECRET-here" }
  ```
- Leave "Accepted Status Codes" at the default `200-299`.

### Check URLs by type

**Ping** an internal host:
```
https://relay.example.com/check?type=ping&host=192.168.1.1
```

**TCP port** (e.g. Postgres):
```
https://relay.example.com/check?type=tcp&host=192.168.1.20&port=5432
```

**HTTP/HTTPS** (self-signed certs are accepted by default):
```
https://relay.example.com/check?type=https&target=https://192.168.1.10:5000/health
```
or without a full URL:
```
https://relay.example.com/check?type=http&host=192.168.1.10&port=8080&path=/status
```

### Optional query parameters (HTTP/HTTPS)

| Param | Default | Description |
| --- | --- | --- |
| `target` / `url` | — | Full URL to probe (or use `host`/`port`/`path`). |
| `method` | `GET` | HTTP method. |
| `accept` | `200-299` | Accepted status codes, e.g. `200-299,301,418`. |
| `keyword` | — | Body must contain this string for **UP**. |
| `ignoreTls` | `true` | Set `false` to enforce valid certificates. |
| `timeout` | `10000` | Per-check timeout (ms), capped by `MAX_TIMEOUT_MS`. |

All types also accept `timeout`. Parameters work as query string (GET) or JSON body (POST).

---

## The allowlist

Stored in `config/allowlist.json`. Manage it via the **GUI** (`/admin`) or by editing the file directly — either way it's hot-reloaded.

```json
{
  "entries": [
    { "id": "nas",   "label": "NAS",      "host": "192.168.1.10",  "ports": [80, 443, 5000], "types": ["http", "https", "tcp"] },
    { "id": "db",    "label": "Postgres", "host": "192.168.1.20",  "ports": [5432],          "types": ["tcp"] },
    { "id": "rtr",   "label": "Router",   "host": "192.168.1.1",   "ports": "any",           "types": ["ping"] },
    { "id": "lab",   "label": "Lab /24",  "host": "10.0.0.0/24",   "ports": "any",           "types": ["ping", "tcp"] }
  ]
}
```

- **`host`** — exact hostname/IP, or an **IPv4 CIDR** (e.g. `10.0.0.0/24`). CIDR only matches IPv4 literal targets.
- **`ports`** — array of allowed ports, or `"any"`.
- **`types`** — array of `http`/`https`/`tcp`/`ping`, or `"any"`.

A check is allowed only if an entry matches **all three** of type, host, and port. An empty allowlist denies everything.

---

## Security notes (read this — it's on the public internet)

- **Always run it behind HTTPS** (a reverse proxy like Caddy/nginx/Cloudflare Tunnel). Set `COOKIE_SECURE=true` once you do.
- Keep `AUTH_SECRET` long and random (`npm run setup` does this). Rotate it if leaked.
- Use a **separate `ADMIN_PASSWORD`** so the value you type in a browser differs from the monitoring secret.
- The allowlist is your blast-radius control: scope it as tightly as possible (specific hosts/ports, not broad CIDRs) so a leaked secret can't be used to scan your network.
- Consider additionally restricting inbound access to your Uptime Kuma server's IP at the firewall / reverse-proxy layer.
- Redirects are **not** followed, response bodies are capped, ping/TCP inputs are strictly validated, and `ping` runs via `execFile` (no shell) — so there's no command injection.

---

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET/POST | `/check` | header secret | Run a probe; 200=up / 503=down. |
| GET | `/healthz` | none | Liveness probe. |
| GET | `/admin` | — | Web GUI (login page). |
| POST | `/admin/api/login` | password | Start a session. |
| GET/POST/PUT/DELETE | `/admin/api/allowlist` | session | Manage allowlist. |
| POST | `/admin/api/test` | session | Run an allowlisted check from the GUI. |

---

## Configuration reference

See [`.env.local.example`](.env.local.example) for every option. Highlights:

| Variable | Default | Notes |
| --- | --- | --- |
| `AUTH_SECRET` | *(required)* | Shared secret; min 24 chars. |
| `ADMIN_PASSWORD` | = `AUTH_SECRET` | GUI login. |
| `PORT` | `3010` | Listen port. |
| `AUTH_HEADER` | `x-auth-token` | Header carrying the secret. |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS. |
| `TRUST_PROXY` | `true` | Trust `X-Forwarded-For` for client IP. |
| `ALLOWLIST_FILE` | `config/allowlist.json` | Hot-reloaded. |
| `LOG_LEVEL` | `debug` | `error`→`trace`. |

---

## License

MIT
