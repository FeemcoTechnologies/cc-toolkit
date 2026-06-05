import logging
"""Kerberos configuration & ticket management — time sync, krb5.conf, kinit."""

import os
import re
import subprocess
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional
logger = logging.getLogger(__name__)


def time_sync(server: str = "", method: str = "auto") -> Dict:
    """Sync system clock with a Kerberos KDC or NTP server.

    Methods tried in order (auto): ntpdate → chrony → rdate → faketime offset
    """
    target = server or ""
    result = {"server": target or "auto", "method": method}

    if method == "auto":
        methods = ["ntpdate", "chrony", "rdate", "manual_offset"]
    else:
        methods = [method]

    for m in methods:
        try:
            if m == "ntpdate":
                ntp = which("ntpdate")
                if ntp:
                    cmd = ["sudo", ntp, "-s", target or "pool.ntp.org"]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if r.returncode == 0:
                        result["status"] = "synced via ntpdate"
                        result["method_used"] = "ntpdate"
                        result["output"] = r.stdout[:500]
                        return result
            elif m == "chrony":
                chrony = which("chronyc")
                if chrony:
                    if target:
                        cmd = ["sudo", chrony, "-a", "burst", "4/4", target]
                    else:
                        cmd = ["sudo", chrony, "-a", "makestep"]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if r.returncode == 0:
                        result["status"] = "stepped via chrony"
                        result["method_used"] = "chrony"
                        result["output"] = r.stdout[:500]
                        return result
            elif m == "rdate":
                rd = which("rdate")
                if rd:
                    cmd = ["sudo", rd, "-n", "-s", target or "pool.ntp.org"]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if r.returncode == 0:
                        result["status"] = "synced via rdate"
                        result["method_used"] = "rdate"
                        return result
            elif m == "manual_offset":
                # Get KDC time via ntpdate -q or direct query
                if target:
                    ntp = which("ntpdate")
                    if ntp:
                        r = subprocess.run([ntp, "-q", target],
                                           capture_output=True, text=True, timeout=15)
                        # Parse offset from output
                        for line in r.stdout.splitlines():
                            m2 = re.search(r"offset\s+([-\d.]+)", line)
                            if m2:
                                offset = float(m2.group(1))
                                cmd = ["sudo", "date", "-s",
                                       f"{'+' if offset >= 0 else ''}{offset} seconds"]
                                subprocess.run(cmd, capture_output=True, timeout=10)
                                result["status"] = f"adjusted by {offset}s via date"
                                result["method_used"] = "manual_offset"
                                return result
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue

    result["error"] = "No time sync method succeeded"
    return result


def krb5_config(domain: str, kdc: str, dns_domain: str = "",
                admin_server: str = "", output_file: str = "") -> Dict:
    """Generate a krb5.conf file for a specific domain/realm.

    Uses uppercase realm (standard Kerberos convention).
    """
    realm = domain.upper()
    dns_domain = dns_domain or domain
    admin_server = admin_server or kdc

    conf = f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    clockskew = 300

[realms]
    {realm} = {{
        kdc = {kdc}
        admin_server = {admin_server}
        default_domain = {dns_domain}
    }}

[domain_realm]
    .{dns_domain} = {realm}
    {dns_domain} = {realm}
"""
    if output_file:
        out_path = Path(output_file)
    else:
        out_path = Path("/etc/krb5.conf")

    try:
        out_path.write_text(conf)
        return {
            "status": f"krb5.conf written to {out_path}",
            "realm": realm,
            "kdc": kdc,
            "admin_server": admin_server,
            "file": str(out_path),
        }
    except PermissionError:
        return {"error": f"Permission denied writing to {out_path}. Try sudo."}
    except Exception as e:
        return {"error": str(e)}


def kinit_user(principal: str, password: str = "",
               keytab: str = "", realm: str = "",
               lifetime: str = "24h", renew: bool = False) -> Dict:
    """Obtain a Kerberos TGT via kinit.

    Args:
        principal: User principal (user@REALM or just username)
        password: Password (omit for keytab or cached creds)
        keytab: Path to keytab file
        realm: Realm override (appended to principal if missing)
        lifetime: Ticket lifetime (e.g. 24h)
        renew: Request renewable tickets
    """
    k = which("kinit")
    if not k:
        return {"error": "kinit not found. Install krb5-user or heimdal-clients."}

    # Append realm if not present in principal
    if "@" not in principal and realm:
        principal = f"{principal}@{realm.upper()}"

    cmd = [k, "-l", lifetime]
    if renew:
        cmd.append("-r")
    if keytab:
        cmd.extend(["-k", "-t", keytab])
    cmd.append(principal)

    try:
        if password:
            r = subprocess.run(cmd, input=password + "\n",
                               capture_output=True, text=True, timeout=30)
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return {"status": f"TGT obtained for {principal}", "principal": principal}
        error_msg = r.stderr.strip() or r.stdout.strip() or "kinit failed"
        return {"error": error_msg[:500]}
    except subprocess.TimeoutExpired:
        return {"error": "kinit timed out"}
    except Exception as e:
        return {"error": str(e)}


def klist_tickets() -> Dict:
    """List current Kerberos ticket cache contents."""
    k = which("klist")
    if not k:
        return {"error": "klist not found"}
    try:
        r = subprocess.run([k, "-A"], capture_output=True, text=True, timeout=10)
        tickets = []
        if r.returncode == 0:
            current = {}
            for line in r.stdout.splitlines():
                line = line.strip()
                if "Principal:" in line:
                    current["principal"] = line.split(":", 1)[1].strip()
                elif "Issued" in line and "Expires" in line:
                    current["issued"] = line
                elif "krbtgt" in line:
                    current["krbtgt"] = line
                elif "Ticket cache" in line:
                    if current:
                        tickets.append(current)
                    current = {"cache": line.split(":", 1)[1].strip() if ":" in line else line}
            if current:
                tickets.append(current)
        return {
            "status": f"{len(tickets)} ticket(s) in cache",
            "tickets": tickets,
            "raw": r.stdout[:2000],
        }
    except Exception as e:
        return {"error": str(e)}


def kdestroy_all() -> Dict:
    """Destroy all Kerberos tickets."""
    k = which("kdestroy")
    if not k:
        return {"error": "kdestroy not found"}
    try:
        r = subprocess.run([k, "-A"], capture_output=True, text=True, timeout=10)
        return {"status": "All tickets destroyed", "rc": r.returncode}
    except Exception as e:
        return {"error": str(e)}


def setup_for_domain(domain: str, kdc: str, username: str = "",
                     password: str = "", dns_domain: str = "",
                     admin_server: str = "", time_sync_method: str = "auto",
                     skip_time_sync: bool = False) -> Dict:
    """Full Kerberos setup: time sync → krb5.conf → kinit (if creds)."""
    steps = {}
    result = {"domain": domain, "kdc": kdc, "steps": steps}

    # Step 1: time sync
    if not skip_time_sync:
        ts = time_sync(server=kdc, method=time_sync_method)
        steps["time_sync"] = ts

    # Step 2: krb5 config
    cfg = krb5_config(domain=domain, kdc=kdc,
                      dns_domain=dns_domain or domain.split(".", 1)[-1] if "." in domain else domain,
                      admin_server=admin_server or kdc)
    steps["krb5_config"] = cfg

    # Step 3: kinit (if credentials provided)
    if username:
        principal = username
        if "@" not in principal and "." in domain:
            principal = f"{username}@{domain.upper()}"
        ki = kinit_user(principal, password=password)
        steps["kinit"] = ki
        result["status"] = "setup complete" if not ki.get("error") else "config done, kinit failed"
    else:
        result["status"] = "config complete (no credentials provided)"

    # Step 4: verify
    steps["klist"] = klist_tickets()
    result["status"] = "setup complete"
    return result


# ~10 minute default for BloodHound collection
_BH_TIMEOUT = 600


def bloodhound_ingest(domain: str, username: str, password: str,
                      dc_ip: str = "", dns_server: str = "",
                      collection_method: str = "All",
                      output_dir: Optional[str] = None) -> Dict:
    """Run BloodHound.py Python ingestor against a domain.

    Searches /share/tools/BloodHound.py then falls back to PATH.
    """
    # Try to find bloodhound.py
    bh_script = None
    bh_dir = Path("/share/tools/BloodHound.py")
    if bh_dir.exists():
        bh_script = bh_dir / "bloodhound.py"
    if not bh_script or not bh_script.exists():
        # Try PATH
        which_bh = which("bloodhound-python") or which("bloodhound.py")
        if which_bh:
            bh_script = Path(which_bh)
    if not bh_script or not bh_script.exists():
        # Try pip-installed: python3 -m bloodhound
        try:
            r = subprocess.run(["python3", "-m", "bloodhound", "--help"],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                bh_script = Path("bloodhound_module")  # sentinel
        except Exception:

            logger.debug("Exception in kerberos_tools.py", exc_info=True)
    if not bh_script or not bh_script.exists() and str(bh_script) != "bloodhound_module":
        return {"error": "BloodHound.py not found. Install via pip or clone to /share/tools/BloodHound.py/"}

    out_dir = Path(output_dir or Path.cwd() / "bloodhound_output")
    out_dir.mkdir(parents=True, exist_ok=True)

    if str(bh_script) == "bloodhound_module":
        cmd = ["python3", "-m", "bloodhound"]
    else:
        cmd = ["python3", str(bh_script)]
        cmd_dir = str(bh_script.parent)

    cmd += ["-d", domain, "-u", username, "-p", password,
            "-c", collection_method, "--zip"]
    if dc_ip:
        cmd += ["--dc", dc_ip]
    if dns_server:
        cmd += ["--dns-server", dns_server]
    if output_dir:
        cmd += ["--output-dir", str(out_dir)]

    try:
        cwd = str(bh_script.parent) if not str(bh_script) == "bloodhound_module" else str(out_dir)
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=_BH_TIMEOUT)
        result = {"rc": r.returncode, "output_dir": str(out_dir)}
        # Find the zip file
        zips = list(out_dir.glob("*.zip"))
        if zips:
            result["zip_file"] = str(zips[-1])
        result["stdout"] = r.stdout[-2000:] if len(r.stdout) > 2000 else r.stdout
        result["stderr"] = r.stderr[-500:] if r.stderr else ""
        return result
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {_BH_TIMEOUT}s"}
    except Exception as e:
        return {"error": str(e)}