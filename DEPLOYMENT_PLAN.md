# CC Toolkit — Deployment Plan (saved)

Living plan so we don't lose track. Update checkboxes as work lands. Phases are
strictly sequential — Phase 0 must be a clean `./up.sh` on the server before 1.

## Locked decisions

- **Layout**: single public domain, **path-based** (`/` dashboard, `/jupyter`,
  `/socket.io`; EDR consumed by the dashboard server-side and by agents over
  WireGuard). No per-service public ports except the edge.
- **Edge**: **nginx-proxy-manager** on 80/443 (recreated). Let's Encrypt issued
  there (Phase 1). NPM is a *container* → it CANNOT reach host `127.0.0.1:<port>`;
  it proxies to stack **service names on `cc-net`**.
- **Stack network**: shared external network **`cc-net`** (created by `./up.sh`
  if missing). All services talk by container name. Host publishings are
  `127.0.0.1` only.
- **Caido is NON-PUBLIC by design**: an open proxy would let strangers replay
  requests through it. No host publish beyond `127.0.0.1:8080`; reachable from
  the dashboard UI / cc-net / via WireGuard if ever needed.
- **EDR agent ingress**: over WireGuard (wg-easy, recreated), zero public EDR
  exposure. Exact wg→EDR plumbing is a documented Phase 2 decision.
- **Auth/WAF roadmap (0-cost, all self-hosted, no Google)**: NPM access rules →
  **Authelia** (2FA via TOTP/passkeys) → **CrowdSec**/fail2ban (nginx + host
  firewall bans) → **Cockpit** (host admin, optional PAM TOTP).

## Phase 0 — harden stack + rebuild edge  (IN PROGRESS)

- [x] Compose: all host ports bound to `127.0.0.1` (dashboard, jupyter 8383,
      caido 8080, edr 8900). Caido never public.
- [x] Shared external network `cc-net` in compose; `./up.sh` creates it if missing.
- [x] `.env`-driven URLs (`CC_JUPYTER_URL`, `CC_CAIDO_URL`, `EDR_SERVER_URL`)
      + `JUPYTER_BASE_URL` hook in the Kali image for later path proxying.
- [x] `edges/docker-compose.yml` (wg-easy + NPM on `cc-net`, admin UIs on
      `127.0.0.1`).
- [x] `DEPLOYMENT_PLAN.md` saved.
- [ ] Server: settle compose conflicts, `chmod +x up.sh down.sh`,
      `cp .env.example .env`, set secrets, `podman system prune -af`, `./up.sh`
      → first clean stack run.
- [ ] Recreate **wg-easy**:
      `docker run --rm weejewel/wg-easy wgpw '<password>'` for `WGEASY_PASSWORD_HASH`,
      set `WG_HOST=<server-public-ip-or-domain>`.
- [ ] Recreate **NPM**; add a throwaway proxy host target to confirm loopback +
      cc-net wiring before Phase 1.

## Phase 1 — reverse proxy + TLS + auth

- [ ] NPM proxy host (path-based):
      `/` → `http://cc-toolkit:5000`; custom location `/socket.io/` →
      `http://cc-toolkit:5001`; `/jupyter/` → `http://jupyter:8383` (WebSockets
      ON everywhere; trailing-slash rules).
- [ ] Set `JUPYTER_BASE_URL=/jupyter` in `.env` (Kali CMD already supports it).
- [ ] Open 80 (+443); Let's Encrypt via NPM (HTTP-01 needs :80; DNS-01 if the
      DNS provider supports API).
- [ ] `CC_DOMAIN`/`CC_JUPYTER_URL=https://<domain>/jupyter` in `.env`; caido
      stays internal.
- [ ] **Authelia** forward-auth + 2FA on public paths (TOTP/passkeys,
      self-hosted).
- [ ] Verify dashboard iframe + token flow end-to-end.

## Phase 2 — automated blocking + agents

- [ ] Push NPM access logs to **CrowdSec** (nginx bouncer + cs-firewall bouncer
      → nftables/iptables) and/or fail2ban.
- [ ] **wg→EDR ingress — FINAL DECISION**, pick exactly one:
      (a) DNAT in wg-easy container `tun0:8900` → `edr:8900` (cc-net);
      (b) EDR bound to host LAN IP, clients route full-tunnel;
      (c) loopback-only + SSH tunnel for admins.
      Then set agent config.yaml base URL accordingly.
- [ ] Install EDR agent (osquery) on a test device; verify ingest + dashboard
      correlation.

## Phase 3 — host administration (wish list)

- [ ] **Cockpit** (podman + firewall UI; optional PAM TOTP 2FA).
- [ ] Decide whether a combined web+host "firewall dashboard" is worth building,
      or Cockpit + CrowdSec already cover it (recommend: covered).
- [ ] Volume backup strategy (wg-easy and NPM were both deleted once).

## Open items / risks

- NPM(container) ↔ `127.0.0.1` is a trap: proxy hosts MUST target cc-net service
  names, never the host loopback.
- Path-based Caido is broken (absolute `/ws/` + `/api/`); caido intentionally
  stays cc-net/loopback-only, surfaced through the dashboard.
- Clients need full-tunnel `WG_ALLOWED_IPS=0.0.0.0/0` (wg-easy default) for any
  future cc-net/service reach.
- podman-compose 1.0.6 ignores `profiles`; enable/disable stays in `up.sh`
  flags / `.env`.
- Let's Encrypt: keep :80 open for HTTP-01; limits are generous for one domain.