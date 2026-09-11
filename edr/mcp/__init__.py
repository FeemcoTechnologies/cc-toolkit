"""EDR MCP tool registration.

Provides register_edr_tools(server) which adds all EDR tools to a FastMCP instance.
"""

from edr.mcp.edr_tools import (
    edr_agents_list,
    edr_agent_detail,
    edr_alerts_list,
    edr_alert_detail,
    edr_alert_acknowledge,
    edr_alert_resolve,
    edr_quarantine,
    edr_unquarantine,
    edr_threat_hunt,
    edr_config_push,
    edr_alert_stats,
    edr_baseline_reset,
)

__all__ = ["register_edr_tools"]

_ALL_TOOLS = [
    edr_agents_list,
    edr_agent_detail,
    edr_alerts_list,
    edr_alert_detail,
    edr_alert_acknowledge,
    edr_alert_resolve,
    edr_quarantine,
    edr_unquarantine,
    edr_threat_hunt,
    edr_config_push,
    edr_alert_stats,
    edr_baseline_reset,
]


def register_edr_tools(server) -> None:
    """Register all EDR MCP tools on a FastMCP server instance.

    Usage in cc_mcp_server.py:
        from edr.mcp import register_edr_tools
        register_edr_tools(mcp)
    """
    for tool_fn in _ALL_TOOLS:
        server.tool()(tool_fn)
