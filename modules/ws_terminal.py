"""WebSocket terminal server — bridges SSH/shell processes to browser.

Spawns interactive SSH or local shell sessions and bridges stdin/stdout
to WebSocket clients via the `websockets` library.

If `websockets` is not installed, the module degrades gracefully
and logs a warning.
"""

import asyncio
import json
import logging
import os
import struct
import threading
from typing import Optional

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    websockets = None  # type: ignore

# Unix-only modules — gracefully degrade on Windows
try:
    import pty
    import termios
    HAS_PTY = True
except ImportError:
    HAS_PTY = False
    pty = None  # type: ignore
    termios = None  # type: ignore

logger = logging.getLogger(__name__)

# Default SSH options for non-interactive key setup
SSH_BASE = [
    "ssh",
    "-t", "-t",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=3",
]


def _set_winsize(fd: int, rows: int, cols: int):
    """Set terminal window size on a PTY master fd."""
    try:
        buf = struct.pack("HHHH", rows, cols, 0, 0)
        import fcntl, termios as _t
        fcntl.ioctl(fd, _t.TIOCSWINSZ, buf)
    except Exception:

        logger.debug("Exception in ws_terminal.py", exc_info=True)


async def _bridge(websocket, cmd: list[str], target_desc: str, env=None):
    """Bridge a subprocess (PTY-attached) to a WebSocket."""
    if not HAS_PTY:
        await websocket.send(json.dumps({"type": "error", "message": "PTY not available on this platform"}))
        return
    import fcntl

    master_fd, slave_fd = pty.openpty()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=os.setsid,
            close_fds=True,
            env=env,
        )
    except Exception:
        os.close(slave_fd)
        os.close(master_fd)
        raise
    os.close(slave_fd)

    fcntl.fcntl(master_fd, fcntl.F_SETFL, fcntl.fcntl(master_fd, fcntl.F_GETFL) | os.O_NONBLOCK)

    connected = True

    async def reader():
        while connected:
            try:
                data = os.read(master_fd, 65536)
                if not data:
                    break
                await websocket.send(data)
            except BlockingIOError:
                await asyncio.sleep(0.01)
            except (ConnectionResetError, websockets.exceptions.ConnectionClosed):
                break
            except Exception as exc:
                logger.debug("pty reader error: %s", exc)
                break

    async def writer():
        nonlocal connected
        try:
            async for message in websocket:
                if isinstance(message, str):
                    try:
                        msg = json.loads(message)
                        if msg.get("type") == "resize":
                            _set_winsize(master_fd, msg.get("rows", 24), msg.get("cols", 80))
                            continue
                        if msg.get("type") == "stdin":
                            data = msg.get("data", "")
                            os.write(master_fd, data.encode())
                            continue
                    except (json.JSONDecodeError, KeyError):
                        pass
                    os.write(master_fd, message.encode())
                else:
                    os.write(master_fd, message)
        except (websockets.exceptions.ConnectionClosed, ConnectionResetError):
            pass
        finally:
            connected = False

    try:
        await asyncio.gather(reader(), writer())
    finally:
        if proc:
            try:
                proc.terminate()
                await asyncio.sleep(0.5)
                if proc.returncode is None:
                    proc.kill()
                await proc.wait()
            except Exception:

                logger.debug("Exception in ws_terminal.py", exc_info=True)
        os.close(master_fd)


# ---------------------------------------------------------------------------
# Connection manager — tracks active sessions
# ---------------------------------------------------------------------------

_connections: dict[str, dict] = {}
_conn_lock = threading.Lock()


def _session_id_str(websocket) -> str:
    try:
        return f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    except Exception:
        return "?"


async def _ws_handler(websocket):
    """Handle a single WebSocket connection.

    Expects first message to be JSON config:
      {"target": "user@host", "port": 22, "local": false}
    or {"local": true} for a local shell.
    """
    sid = _session_id_str(websocket)
    try:
        msg = await asyncio.wait_for(websocket.recv(), timeout=30)
    except asyncio.TimeoutError:
        await websocket.close(4000, "No config received within 30s")
        return

    try:
        cfg = json.loads(msg) if isinstance(msg, str) else json.loads(msg.decode())
    except (json.JSONDecodeError, ValueError):
        await websocket.close(4000, "Invalid config JSON")
        return

    if cfg.get("local"):
        cmd = [os.environ.get("SHELL", "/bin/bash")]
        target_desc = "local shell"
    elif cfg.get("tmux"):
        cmd = ["tmux", "attach-session", "-t", str(cfg.get("tmux"))]
        target_desc = f"tmux:{cfg.get('tmux')}"
    else:
        target = cfg.get("target", "")
        port = cfg.get("port", 22)
        username, _, host = target.partition("@")
        if not host:
            host = username
            username = os.environ.get("USER", "root")
        cmd = SSH_BASE + ["-p", str(port), f"{username}@{host}"]
        target_desc = f"{username}@{host}:{port}"

    env = {**os.environ, "TERM": os.environ.get("TERM") or "xterm-256color"}

    logger.info("WS terminal: %s → %s", sid, target_desc)
    try:
        await websocket.send(json.dumps({"type": "connected", "target": target_desc}))
    except Exception:
        return
    await _bridge(websocket, cmd, target_desc, env=env)
    logger.info("WS terminal: %s disconnected from %s", sid, target_desc)


if HAS_WEBSOCKETS:
    _HANDLER = _ws_handler
else:
    async def _HANDLER(websocket):
        await websocket.send(json.dumps({"type": "error", "message": "websockets library not installed. Run: pip install websockets"}))
        await websocket.close()


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

class WSTerminalServer:
    """Manages the WebSocket terminal server in a background thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5001):
        self.host = host
        self.port = port
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if not HAS_WEBSOCKETS:
            logger.warning("WS terminal: 'websockets' not installed — terminal unavailable")
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="ws-terminal")
        self._thread.start()
        logger.info("WS terminal server started on %s:%s", self.host, self.port)

    def _run(self):
        asyncio.run(self._serve())

    async def _serve(self):
        try:
            async with websockets.serve(
                _HANDLER,
                self.host,
                self.port,
                ping_interval=30,
                ping_timeout=10,
            ):
                await asyncio.Future()  # run forever
        except OSError as e:
            logger.error("WS terminal server failed: %s", e)

    def stop(self):
        pass
