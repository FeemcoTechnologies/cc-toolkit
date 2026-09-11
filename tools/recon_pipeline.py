#!/usr/bin/env python3
"""Comprehensive recon pipeline: nmap scans → httpx → whatweb → eyewitness → katana → nuclei"""

import argparse
import json
import re
import subprocess
import time
from pathlib import Path
from shutil import which


def run(cmd, timeout=600, verbose=False):
    if verbose:
        print(f"[+] {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": f"Timed out after {timeout}s"}
    except FileNotFoundError:
        return {"rc": -2, "stdout": "", "stderr": f"Command not found: {cmd[0]}"}


def parse_nmap_ports(stdout):
    """Extract open TCP/UDP ports from nmap output."""
    ports = {"tcp": set(), "udp": set()}
    for line in stdout.splitlines():
        m = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
        if m:
            port, proto = m.group(1), m.group(2)
            ports[proto].add(int(port))
    return ports


def parse_greppable_ports(grep_output):
    """Extract open ports from nmap greppable (-oG) output."""
    ports = {"tcp": set(), "udp": set()}
    for line in grep_output.splitlines():
        if not line.startswith("Host:"):
            continue
        # Ports: 80/open/tcp//http///, 443/open/tcp//https///
        m = re.search(r'Ports:\s*(.+?)(?:\s*$|#)', line)
        if m:
            for part in m.group(1).split(","):
                part = part.strip()
                fields = part.split("/")
                if len(fields) >= 2:
                    try:
                        port = int(fields[0])
                        state = fields[1]
                        proto = fields[2] if len(fields) > 2 else "tcp"
                        if state == "open":
                            ports["tcp" if proto == "tcp" else "udp"].add(port)
                    except ValueError:
                        pass
    return ports


def main():
    parser = argparse.ArgumentParser(description="Comprehensive recon pipeline")
    parser.add_argument("--target", required=True, help="Target IP or CIDR")
    parser.add_argument("--case-dir", required=True, help="Case output directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--httpx-path", default="/root/.pdtm/go/bin/httpx",
                        help="Path to httpx binary")
    args = parser.parse_args()
    target = args.target
    case_dir = Path(args.case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    verbose = args.verbose
    httpx_bin = args.httpx_path

    # ---- Phase 1: Host Discovery ----
    print("Phase 1: Host discovery")
    phase1 = {}
    phase1["ping_arp"] = run(["nmap", "-sn", "-PR", target], timeout=120, verbose=verbose)
    time.sleep(1)
    phase1["syn_top"] = run(["nmap", "-sS", "--top-ports", "1000", "-Pn",
                             "-oG", str(case_dir / "syn_top.gnmap"), target], timeout=300, verbose=verbose)
    time.sleep(1)
    phase1["ack_scan"] = run(["nmap", "-sA", "-T5", "-Pn",
                              "-oG", str(case_dir / "ack_scan.gnmap"), target], timeout=300, verbose=verbose)
    time.sleep(1)
    phase1["syn_all"] = run(["nmap", "-sS", "-p-", "-T5", "-Pn", "--open",
                             "-oG", str(case_dir / "syn_all.gnmap"), target], timeout=900, verbose=verbose)
    time.sleep(1)
    phase1["udp_top"] = run(["nmap", "-sU", "--top-ports", "100", "-T5", "-Pn",
                             "-oG", str(case_dir / "udp_top.gnmap"), target], timeout=600, verbose=verbose)
    time.sleep(1)
    phase1["udp_all"] = run(["nmap", "-sU", "-p-", "-T5", "-Pn", "--open",
                             "-oG", str(case_dir / "udp_all.gnmap"), target], timeout=1200, verbose=verbose)

    # Save phase 1 results
    with open(case_dir / "phase1-results.json", "w") as f:
        json.dump({k: {"rc": v["rc"], "stderr": v["stderr"][-500:]}
                   for k, v in phase1.items()}, f, indent=2)

    # ---- Phase 2: Merge discovered ports ----
    print("Phase 2: Merging discovered ports")
    all_ports = {"tcp": set(), "udp": set()}
    greppable_files = ["syn_top.gnmap", "ack_scan.gnmap", "syn_all.gnmap",
                       "udp_top.gnmap", "udp_all.gnmap"]
    for gf in greppable_files:
        gf_path = case_dir / gf
        if gf_path.exists():
            ports = parse_greppable_ports(gf_path.read_text())
            all_ports["tcp"].update(ports["tcp"])
            all_ports["udp"].update(ports["udp"])

    if not all_ports["tcp"] and not all_ports["udp"]:
        print("No ports discovered from greppable output, trying -oN parse")
        for out in phase1.values():
            ports = parse_nmap_ports(out["stdout"])
            all_ports["tcp"].update(ports["tcp"])
            all_ports["udp"].update(ports["udp"])

    tcp_ports = sorted(all_ports["tcp"])
    udp_ports = sorted(all_ports["udp"])
    print(f"  Discovered: {len(tcp_ports)} TCP, {len(udp_ports)} UDP ports")

    # Write merged port lists
    port_info = {
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "tcp_csv": ",".join(str(p) for p in tcp_ports),
        "udp_csv": ",".join(str(p) for p in udp_ports),
    }
    with open(case_dir / "discovered-ports.json", "w") as f:
        json.dump(port_info, f, indent=2)

    # ---- Phase 3: Service scan ----
    print("Phase 3: Service scan on discovered ports")
    if tcp_ports:
        tcp_csv = ",".join(str(p) for p in tcp_ports)
        run(["nmap", "-sS", "-sV", "-T3", "-Pn", "-p", tcp_csv,
             "-oA", str(case_dir / "tcp_services"), target],
            timeout=1200, verbose=verbose)

    if udp_ports:
        udp_csv = ",".join(str(p) for p in udp_ports)
        run(["nmap", "-sU", "-sV", "-T3", "-Pn", "-p", udp_csv,
             "-oA", str(case_dir / "udp_services"), target],
            timeout=1200, verbose=verbose)

    # ---- Phase 4: Web discovery with httpx ----
    print("Phase 4: Web service discovery")
    httpx_results = []
    web_ports = []

    if which(httpx_bin) or which("httpx"):
        httpx_cmd = which(httpx_bin) or which("httpx")
        # Build httpx target list from open TCP ports (common web ports)
        web_port_candidates = [p for p in tcp_ports if p in
                               {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 9443,
                                10443, 4343, 7443, 9200, 5601, 9000, 9001, 8834, 3389}]
        if target.endswith("/24"):
            web_port_candidates = [80, 443, 8080, 8443]
        if web_port_candidates:
            targets = []
            for p in web_port_candidates:
                targets.append(f"{target}:{p}")
            r = run([httpx_cmd, "-silent", "-json"] + targets, timeout=120, verbose=verbose)
            if r["rc"] == 0 and r["stdout"]:
                for line in r["stdout"].splitlines():
                    try:
                        data = json.loads(line)
                        httpx_results.append(data)
                        if "url" in data:
                            web_ports.append(data["url"])
                    except json.JSONDecodeError:
                        web_ports.append(line.strip())

    # Write httpx results
    with open(case_dir / "httpx-results.json", "w") as f:
        json.dump(httpx_results, f, indent=2)
    with open(case_dir / "web_urls.txt", "w") as f:
        for url in web_ports:
            f.write(url + "\n")

    # ---- Phase 5: whatweb on discovered web services ----
    print("Phase 5: whatweb fingerprinting")
    whatweb_results = {}
    if web_ports:
        for url in web_ports:
            r = run(["whatweb", "-a3", url, "--log-verbose",
                     str(case_dir / f"whatweb-{url.replace('://','_').replace('/','_')}.txt")],
                    timeout=60, verbose=verbose)
            whatweb_results[url] = {"rc": r["rc"]}
    elif target:
        r = run(["whatweb", "-a3", target,
                 "--log-verbose", str(case_dir / "whatweb.txt")],
                timeout=60, verbose=verbose)
        whatweb_results[target] = {"rc": r["rc"]}

    # ---- Phase 6: eyewitness ----
    print("Phase 6: Eyewitness screenshots")
    if which("eyewitness") or which("EyeWitness"):
        ew = which("eyewitness") or which("EyeWitness")
        if web_ports:
            with open(case_dir / "ew-targets.txt", "w") as f:
                f.write("\n".join(web_ports))
            run([ew, "--web", "-f", str(case_dir / "ew-targets.txt"),
                 "-d", str(case_dir / "eyewitness"), "--no-prompt",
                 "--resolve", "--timeout", "30"],
                timeout=300, verbose=verbose)
        else:
            run([ew, "--web", "--single", target,
                 "-d", str(case_dir / "eyewitness"), "--no-prompt",
                 "--timeout", "30"],
                timeout=300, verbose=verbose)

    # ---- Phase 7: katana crawl ----
    print("Phase 7: Katana crawling")
    katana_urls = []
    if which("katana"):
        if web_ports:
            with open(case_dir / "katana-targets.txt", "w") as f:
                f.write("\n".join(web_ports))
            r = run(["katana", "-list", str(case_dir / "katana-targets.txt"),
                     "-silent", "-o", str(case_dir / "katana-urls.txt"),
                     "-d", "3", "-jc", "-kf", "-c", "30"],
                    timeout=300, verbose=verbose)
        else:
            r = run(["katana", "-u", target,
                     "-silent", "-o", str(case_dir / "katana-urls.txt"),
                     "-d", "3", "-jc", "-kf", "-c", "30"],
                    timeout=300, verbose=verbose)
        katana_urls = Path(case_dir / "katana-urls.txt").read_text().splitlines() \
            if Path(case_dir / "katana-urls.txt").exists() else []

    # ---- Phase 8: nuclei scans ----
    print("Phase 8: Nuclei scanning")
    nuclei_targets = [target]
    if web_ports:
        nuclei_targets.extend(web_ports)
    if katana_urls:
        nuclei_targets.extend(katana_urls[:50])  # cap at 50 URLs

    # Write deduplicated targets
    seen = set()
    deduped = []
    for t in nuclei_targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    with open(case_dir / "nuclei-targets.txt", "w") as f:
        f.write("\n".join(deduped))

    # nuclei >= v2 writes JSON lines to a FILE with -jsonl; the legacy -json
    # flag writes per-host files to a DIRECTORY. Use -jsonl unconditionally —
    # the previous version probe actually ran a live 10s nuclei scan against
    # the target on every pipeline run just to detect flag support.
    nuclei_flags = ["-jsonl"]

    if deduped:
        with open(case_dir / "nuclei-input.txt", "w") as f:
            f.write("\n".join(deduped))
        r = run(["nuclei"] + nuclei_flags + ["-l", str(case_dir / "nuclei-input.txt"),
                 "-o", str(case_dir / "nuclei.json"), "-c", "25", "-stats"],
                timeout=600, verbose=verbose)
        nuclei_cmd_result = r
    else:
        nuclei_cmd_result = {"rc": 0, "stdout": "No targets for nuclei", "stderr": ""}

    # Write final summary
    summary = {
        "target": target,
        "ports_tcp": tcp_ports,
        "ports_udp": udp_ports,
        "web_urls": web_ports,
        "nuclei_targets": len(deduped),
        "nuclei_rc": nuclei_cmd_result["rc"],
        "nuclei_flags": nuclei_flags,
    }
    with open(case_dir / "recon-summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nPipeline complete. Results in: {case_dir}")
    print(f"  TCP ports: {len(tcp_ports)}, UDP ports: {len(udp_ports)}")
    print(f"  Web URLs: {len(web_ports)}")
    print(f"  Katana URLs: {len(katana_urls)}")
    print(f"  Nuclei targets: {len(deduped)}")


if __name__ == "__main__":
    main()
