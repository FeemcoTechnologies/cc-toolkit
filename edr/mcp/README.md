# EDR MCP Tools

MCP tools exposing the EDR server admin API to AI agents.

## Setup

Add to `cc_mcp_server.py`:

```python
from edr.mcp import register_edr_tools
register_edr_tools(mcp)
```

## Env Vars

- `EDR_SERVER_URL` -- default `http://127.0.0.1:8900`
- `EDR_ADMIN_API_KEY` -- fallback from `~/.config/kali-command-center/config.json`

## Tools

`edr_agents_list`, `edr_agent_detail`, `edr_alerts_list`, `edr_alert_detail`,
`edr_alert_acknowledge`, `edr_alert_resolve`, `edr_quarantine`, `edr_unquarantine`,
`edr_threat_hunt`, `edr_config_push`, `edr_alert_stats`, `edr_baseline_reset`

stdlib only -- no third-party deps.
