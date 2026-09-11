"""Remote SSH runner — execute tools on remote hosts."""

import datetime
import json
import subprocess
from pathlib import Path
from shutil import which


class RemoteRunner:
    """Run commands and playbooks on remote hosts via SSH."""

    def __init__(self, host: str, user: str = "root",
                 port: int = 22, key_file: str = "",
                 password: str = "", timeout: int = 30):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.password = password
        self.timeout = timeout
        self._results_dir = Path.cwd() / "remote-runs"
        self._results_dir.mkdir(parents=True, exist_ok=True)

    def _ssh_cmd(self, extra_args: list = None) -> list:
        cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new",
               "-o", "ConnectTimeout=10",
               "-p", str(self.port)]
        if self.key_file:
            cmd.extend(["-i", self.key_file])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def exec(self, command: str, timeout: int = None) -> dict:
        """Run a command on the remote host."""
        ssh = self._ssh_cmd([f"{self.user}@{self.host}", command])
        try:
            r = subprocess.run(ssh, capture_output=True, text=True,
                               timeout=timeout or self.timeout)
            return {
                "rc": r.returncode,
                "stdout": r.stdout,
                "stderr": r.stderr,
                "command": command,
                "host": self.host,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        except subprocess.TimeoutExpired:
            return {"rc": -1, "error": f"Timed out after {timeout or self.timeout}s",
                    "command": command, "host": self.host}
        except FileNotFoundError:
            return {"rc": -1, "error": "ssh not found in PATH",
                    "host": self.host}
        except Exception as e:
            return {"rc": -1, "error": str(e), "host": self.host}

    def scp_put(self, local_path: str, remote_path: str) -> dict:
        """Copy a file to the remote host."""
        scp = which("scp")
        if not scp:
            return {"error": "scp not found"}
        cmd = [scp, "-P", str(self.port),
               "-o", "StrictHostKeyChecking=accept-new"]
        if self.key_file:
            cmd.extend(["-i", self.key_file])
        cmd.extend([local_path, f"{self.user}@{self.host}:{remote_path}"])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {"rc": r.returncode, "stdout": r.stdout[:500], "stderr": r.stderr[:500]}
        except Exception as e:
            return {"error": str(e)}

    def scp_get(self, remote_path: str, local_path: str) -> dict:
        """Copy a file from the remote host."""
        scp = which("scp")
        if not scp:
            return {"error": "scp not found"}
        cmd = [scp, "-P", str(self.port),
               "-o", "StrictHostKeyChecking=accept-new"]
        if self.key_file:
            cmd.extend(["-i", self.key_file])
        cmd.extend([f"{self.user}@{self.host}:{remote_path}", local_path])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {"rc": r.returncode, "stdout": r.stdout[:500], "stderr": r.stderr[:500]}
        except Exception as e:
            return {"error": str(e)}

    def run_tool(self, tool: str, args: list = None,
                 timeout: int = None) -> dict:
        """Run a tool on the remote host."""
        cmd_parts = [tool] + (args or [])
        return self.exec(" ".join(cmd_parts), timeout)

    def list_connections(self) -> list:
        """List recent remote runs from this session."""
        runs = []
        for f in sorted(self._results_dir.glob("remote_*.json")):
            try:
                runs.append(json.loads(f.read_text()))
            except (json.JSONDecodeError, OSError):
                continue
        return runs
