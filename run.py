#!/usr/bin/env python3
"""CC Toolkit — unified entry point.

Usage:
    python run.py web          Start the web dashboard
    python run.py cli          Start the interactive TUI/CLI
    python run.py mcp          Start the MCP server (stdio)
    python run.py shell        Start an interactive Python shell with toolkit loaded

Environment variables (all optional, see modules/config.py):
    CC_WORKSPACE       Root data directory (default: /workspace)
    CC_HOST            Dashboard listen address (default: 0.0.0.0)
    CC_PORT            Dashboard port (default: 5000)
    CC_API_KEY         API key for auth (default: none)
    CC_JUPYTER_URL     Jupyter server URL (default: http://localhost:8888)
    CC_CAIDO_URL       Caido proxy URL (default: http://localhost:8080)
    CC_SECRET          Flask secret key (default: auto-generated)
    CC_CONFIG_FILE     Path to JSON config file (default: {workspace}/config/settings.json)
"""

import os
import sys
import argparse

# Ensure the package root is on sys.path
_PKG_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)


def cmd_web(args):
    """Start the web dashboard."""
    from modules.config import DASHBOARD_HOST, DASHBOARD_PORT, DEBUG, ensure_dirs
    ensure_dirs()
    from web_dashboard.app import app
    print(f"[CC] Web dashboard starting on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=DEBUG, use_reloader=False)


def cmd_cli(args):
    """Start the interactive CLI/TUI."""
    from modules.config import ensure_dirs
    ensure_dirs()
    from cli import main
    sys.argv = [sys.argv[0]] + args.remainder
    main()


def cmd_mcp(args):
    """Start the MCP server (stdio mode)."""
    from modules.config import ensure_dirs
    ensure_dirs()
    from cc_mcp_server import main
    main()


def cmd_shell(args):
    """Start an interactive Python shell with toolkit modules preloaded."""
    from modules.config import ensure_dirs
    ensure_dirs()
    try:
        import IPython
    except ImportError:
        import code
        code.interact(
            banner="CC Toolkit — Python shell (install IPython for a richer experience)",
            local={"args": args}
        )
        return
    IPython.start_ipython(
        argv=[],
        banner="CC Toolkit — Python shell with toolkit modules loaded",
        user_ns={"args": args}
    )


def main():
    parser = argparse.ArgumentParser(prog="cc", description="CC Toolkit — pentest command center")
    sub = parser.add_subparsers(dest="mode", help="Operation mode")

    p_web = sub.add_parser("web", help="Start the web dashboard")
    p_web.set_defaults(func=cmd_web)

    p_cli = sub.add_parser("cli", help="Start the interactive CLI/TUI")
    p_cli.add_argument("remainder", nargs=argparse.REMAINDER, help="Args passed to CLI")
    p_cli.set_defaults(func=cmd_cli)

    p_mcp = sub.add_parser("mcp", help="Start the MCP server")
    p_mcp.set_defaults(func=cmd_mcp)

    p_shell = sub.add_parser("shell", help="Start interactive Python shell")
    p_shell.set_defaults(func=cmd_shell)

    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
