# EDR — Endpoint Detection & Response

A self-contained EDR system built into the cc-toolkit. Agents run on each managed device, evaluate detection rules locally, and send compressed alert batches to a central server. The server stores alerts in SQLite, correlates across devices, and exposes a REST API consumed by the dashboard, MCP, and CLI.

## Architecture

```
Cloud Server (Podman)              Managed Devices (VPN or internet)
┌──────────────────────────┐       ┌──────────────────────────────┐
│  nginx (WireGuard-only)  │◄─────►│  edr-agent (Python daemon)   │
│  ├── /edr/* → server     │       │  ├── osquery (local queries)  │
│  ├── /cfg/* → config API │       │  ├── detection rules (YAML)   │
│  └── /ingest/* → ingest  │       │  ├── baseline store (JSON)    │
│                          │       │  └── alert queue (compressed) │
│  edr-server (FastAPI)    │       └──────────────────────────────┘
│  ├── SQLite (alerts,     │
│  │   devices, baselines) │
│  └── correlation engine  │
└──────────────────────────┘
```

## Components

| Component | Path | Purpose |
|-----------|------|---------|
| Requirements | `REQUIREMENTS.md` | 146 requirements across 7 sections |
| Rules | `rules/` | 34 YAML detection rules + Pydantic schema + loader |
| Agent | `agent/` | Self-contained Python daemon (zero deps) |
| Server | `server/` | FastAPI + SQLite + Podman deployment |
| MCP Tools | `mcp/` | 12 `edr_*` tools for the AI assistant |
| CLI | `cli/` | `cc-edr` command (15 subcommands) |
| Dashboard | `web_dashboard/edr_routes.py` | Flask blueprint + 5 HTML templates |

## Quick Start

### 1. Agent (on each device)

```bash
# First run — generates UUID, populates baselines
python -m edr.agent setup

# Start daemon (runs until SIGTERM)
python -m edr.agent run

# Test — run all rules once, print results
python -m edr.agent test

# Show status
python -m edr.agent status
```

Config lives at `/etc/cc-edr/config.yaml` (Linux) or `C:\ProgramData\cc-edr\config.yaml` (Windows).

### 2. Server (on cloud, via Podman)

```bash
cd edr/server

# Set secrets
export EDR_SECRET_KEY=$(openssl rand -hex 32)
export EDR_ADMIN_API_KEY=$(openssl rand -hex 32)

# Build and run
podman-compose up -d

# API is now at http://127.0.0.1:8900
# Configure nginx to proxy:
#   /edr/ → localhost:8900 (WireGuard-only)
#   /cfg/ → localhost:8900 (public port 9443)
```

### 3. Dashboard

Add to `web_dashboard/app.py`:
```python
from web_dashboard.edr_routes import edr_bp
app.register_blueprint(edr_bp, url_prefix="/edr")
```

Navigate to `/edr/agents` in the dashboard.

### 4. MCP Tools

Add to `cc_mcp_server.py`:
```python
from edr.mcp import register_edr_tools
register_edr_tools(mcp)
```

Tools: `edr_agents_list`, `edr_agent_detail`, `edr_alerts_list`, `edr_alert_detail`, `edr_alert_acknowledge`, `edr_alert_resolve`, `edr_quarantine`, `edr_unquarantine`, `edr_threat_hunt`, `edr_config_push`, `edr_alert_stats`, `edr_baseline_reset`

### 5. CLI

```bash
python edr/cli/edr_cli.py agents list
python edr/cli/edr_cli.py alerts list --severity critical
python edr/cli/edr_cli.py hunt "SELECT * FROM listening_ports WHERE port > 1024"
python edr/cli/edr_cli.py status
```

## Detection Rules

YAML-based, sigma-style. Each rule defines:

```yaml
id: edr-new-listening-port-linux
name: New Listening Port
severity: medium
platform: linux
osquery: "SELECT * FROM listening_ports WHERE port > 0"
detect:
  field: "port"
  op: new_in_baseline
response:
  - alert
```

### Operations
- `eq`, `neq` — exact match
- `gt`, `lt`, `gte`, `lte` — numeric comparison
- `contains`, `not_contains` — substring
- `regex` — regex match
- `new_in_baseline` — value not seen before (integrity check)
- `changed` — value differs from baseline hash

### Built-in Rules (34)

| Category | Rules |
|----------|-------|
| Baseline (new value) | ports, processes, users (linux + windows) |
| Access | SSH key added, empty password accounts |
| Persistence | cron changed, scheduled task changed, service changed |
| Privilege | sudo/pkexec, SUID binary, kernel module |
| Defense | firewall rule changed, registry modification |
| Execution | reverse shell, encoded PowerShell, WMI process creation |
| Network | DNS to suspicious TLD, unexpected outbound connections |
| Inventory | package installed, USB device, Docker container |
| Integrity | sensitive file modified, systemd unit changed |
| Threshold | process count >50, ports per process >20 |

## Config Delivery

Agent fetches config from server on a schedule (default 12h):

1. Try VPN endpoint (`{server_url}/cfg/{uuid}`) — 5s timeout
2. If VPN down, try public endpoint (`{public_endpoint}/cfg/{uuid}`)
3. If both fail, use locally cached config (valid for 72h)

Config response: compressed YAML containing detection rules, osquery packs, response actions, and device-specific overrides.

## Alert Transport

Agents queue alerts locally, send compressed batches on next checkin:

- **Only detection matches** sent (not raw osquery results)
- **Delta sync** — only changes since last checkin
- **zstd compression** (~10:1 ratio for structured alerts)
- **Batch delivery** — all queued alerts sent in one POST

WireGuard overhead: negligible (few KB per device per checkin).

## Development

```bash
# Run detection rules test locally
python -m edr.agent test

# Start server locally (no Podman)
cd edr/server && python -m edr.server

# Run CLI against local server
EDR_SERVER_URL=http://127.0.0.1:8900 python edr/cli/edr_cli.py agents list
```

## Dependencies

- **Agent**: Python 3.9+ stdlib only (no pip packages)
- **Server**: Python 3.9+, FastAPI, uvicorn
- **Agent binary**: osquery (optional, agent runs without it)
- **Deployment**: Podman (or Docker), nginx, WireGuard
