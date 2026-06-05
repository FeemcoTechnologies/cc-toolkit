#!/usr/bin/env python3
"""Interactive TUI dashboard — keyboard-driven menu wrapping CLI commands."""

import sys, os, datetime, yaml, shlex, subprocess
from pathlib import Path
from typing import Optional

from prompt_toolkit import Application
from prompt_toolkit.layout import Layout, HSplit, Window
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.shortcuts import input_dialog, message_dialog, yes_no_dialog

try:
    from modules.constants import load_config, CASES_DIR, CC_DIR, PLAYBOOKS_DIR
except ImportError:
    from modules.config import WORKSPACE as CC_DIR, PENTEST_DIR as CASES_DIR, load_config_file as load_config
    PLAYBOOKS_DIR = CC_DIR / "playbooks"
from modules.case_manager import CaseManager
from modules.findings_db import FindingsDB
from modules.playbook_engine import RunbookEngine
from modules.wifi_monitor import get_monitor_manager
from modules.dns_wrapper import resolve, list_monitors, start_monitor, stop_monitor, get_history, start_background_monitor

STYLE = Style([
    ("status", "bg:#3730a3 fg:white"),
    ("cursor", "bg:#6366f1 fg:white bold"),
    ("help", "italic fg:#9ca3af"),
    ("dim", "fg:#6b7280"),
    ("sep", "fg:#374151"),
    ("ok", "fg:#22c55e"),
    ("warn", "fg:#f59e0b"),
    ("err", "fg:#ef4444"),
    ("highlight", "fg:#a5b4fc"),
])

MENU_ITEMS = [
    ("1", "Cases", "List, create, view case details"),
    ("2", "Findings", "Browse findings by severity and status"),
    ("3", "Prompts", "AI prompt templates"),
    ("4", "DNS", "Resolve and monitor domains"),
    ("5", "WiFi", "Scan networks and manage sessions"),
    ("6", "Runbooks", "List and launch YAML playbooks"),
    ("7", "Tools", "Browse and run security tools"),
    ("8", "Monitor", "System resource monitor"),
    ("9", "Infra", "AI infra status (Jupyter/Caido/Ollama)"),
    ("0", "Shell", "Drop to a shell (exit to return)"),
]


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class TUIApp:
    def __init__(self):
        self.screen: str = "main"
        self.cursor: int = 0
        self.scroll: int = 0
        self.data: dict = {}
        self.cm = CaseManager()
        self.pe = RunbookEngine()
        self.config = load_config()
        start_background_monitor()
        self._refresh_data()

    def _refresh_data(self):
        try:
            self.data["cases"] = self.cm.list_cases()
        except Exception:
            self.data["cases"] = []
        self.data["prompts"] = self._load_prompts()
        try:
            self.data["monitors"] = list_monitors()
        except Exception:
            self.data["monitors"] = []
        try:
            self.data["runbooks"] = [p for p in self.pe.list_runbooks() if p.suffix in (".yaml", ".yml")]
        except Exception:
            self.data["runbooks"] = []

    def _load_prompts(self):
        prompts_dir = CC_DIR / "prompts"
        if not prompts_dir.exists():
            return []
        files = sorted(prompts_dir.glob("*.yaml"))
        result = []
        for f in files:
            try:
                d = yaml.safe_load(f.read_text())
                if d and isinstance(d, dict):
                    result.append({"id": f.stem, **d})
            except Exception as e:
                result.append({"id": f.stem, "title": f.stem, "error": str(e)})
        return result

    # ------------------------------------------------------------------
    # Dynamic content — called on every render
    # ------------------------------------------------------------------
    def _get_content(self):
        handler = getattr(self, f"_screen_{self.screen}", None)
        if handler is None:
            self.screen = "main"
            handler = self._screen_main
        return handler()

    def _get_status(self):
        label = self.screen.replace("_", " ").title()
        return [("", f"  {label:<50}"), ("class:dim", f"{_now():>30}")]

    # ------------------------------------------------------------------
    # Screens — each returns a list of (style, text) fragments
    # ------------------------------------------------------------------
    def _screen_main(self):
        items = [f"  [{k}] {t:<12} {d}" for k, t, d in MENU_ITEMS]
        frags = [("bold", "\n  CC Toolkit — Interactive Dashboard\n")]
        frags.append(("class:sep", f"  {'─'*56}\n\n"))
        for i, item in enumerate(items):
            style = "class:cursor" if i == self.cursor else "class:dim"
            frags.append((style, f"  {'▸' if i == self.cursor else ' '} {item}\n"))
        frags.append(("\n\n", ""))
        frags.append(("class:help", "  ↑↓ navigate · Enter select · Esc back · q quit · 0 shell"))
        return frags

    def _screen_cases(self):
        cases = self.data.get("cases", [])
        if not cases:
            frags = [("bold", "\n  Cases\n"), ("class:sep", "  ───────\n\n"), ("class:dim", "  No cases found\n")]
            frags.append(("class:help", "  c create · r refresh · Esc back"))
            return frags
        max_idx = len(cases) - 1
        idx = max(0, min(self.cursor, max_idx))
        if self.scroll > idx:
            self.scroll = idx
        if idx > self.scroll + 15:
            self.scroll = idx - 15
        visible = cases[self.scroll:self.scroll + 16]
        frags = [("bold", "\n  Cases\n"), ("class:sep", f"  {'─'*56}\n\n")]
        for i, c in enumerate(visible):
            real_i = self.scroll + i
            frags.append((
                "class:cursor" if real_i == idx else "",
                f"  {'▸' if real_i == idx else ' '}{c.get('case_id','?'):<24} {str(c.get('client',''))[:16]:<16} {c.get('case_type',''):<14} {c.get('status','open'):<6} {c.get('_findings_total',0)} findings\n"
            ))
        frags.append(("class:help", "\n  ↑↓ · Enter detail · c create · d delete · r refresh · Esc back"))
        return frags

    def _screen_case_detail(self):
        c = self.data.get("_case")
        if not c:
            self.screen = "cases"
            return self._screen_cases()
        cid = c.get("case_id", "?")
        info = self.cm.info(cid) or {}
        fdb = FindingsDB(CASES_DIR / cid)
        findings_list = fdb.list() if cid else []
        notes = self.cm.get_notes(cid) or []
        evidence = self.cm.get_evidence(cid) or []
        strengths = self.cm.list_strengths(cid) or []
        weaknesses = self.cm.list_weaknesses(cid) or []
        scope = (self.cm.scope_list(cid) or {}).get("in_scope", [])
        tasks = self.cm.task_list(cid) or []
        frags = [("bold", f"\n  {cid}\n"), ("class:sep", f"  {'─'*56}\n\n")]
        for k in ("client", "case_type", "status", "created"):
            frags.append(("class:highlight", f"  {k.title()+':':<12}"))
            frags.append(("", f"{info.get(k,'')}\n"))
        frags.append(("class:highlight", "  Description:"))
        frags.append(("class:dim", f" {str(info.get('description',''))[:80]}\n"))
        frags.append(("\n", ""))
        frags.append(("class:sep", f"  {'─'*56}\n\n"))
        frags.append(("bold", f"  Findings: {len(findings_list)}   Notes: {len(notes)}   Evidence: {len(evidence)}\n"))
        frags.append(("bold", f"  Scope: {len(scope)}   Tasks: {len(tasks)}   Strengths: {len(strengths)}   Weaknesses: {len(weaknesses)}\n"))
        if findings_list:
            frags.append(("class:sep", "\n  ─ Findings ─────\n"))
            for f_item in findings_list[:8]:
                sev = f_item.get("severity", "info")
                col = {"critical": "class:err", "high": "class:warn", "medium": "class:help", "low": "class:dim"}.get(sev, "class:dim")
                frags.append((col, f"  [{sev[0].upper()}] {f_item.get('title','')[:50]}\n"))
        frags.append(("class:help", "\n  Esc back · f findings · g report"))

    def _screen_findings(self):
        case_id = self.data.get("_findings_case_id", "")
        if not case_id:
            cases = self.data.get("cases", [])
            if not cases:
                return [("class:dim", "\n  No cases\n"), ("class:help", "\n  Esc back")]
            frags = [("bold", "\n  Select a case\n"), ("class:sep", f"  {'─'*40}\n\n")]
            for i, c in enumerate(cases):
                cid = c.get("case_id", "?")
                frags.append(("class:cursor" if i == self.cursor else "", f"  {'▸' if i == self.cursor else ' '} {cid}\n"))
            frags.append(("class:help", "\n  ↑↓ · Enter select · Esc back"))
            return frags
        fdb = FindingsDB(CASES_DIR / case_id)
        items = fdb.list() if case_id else []
        if not items:
            return [("bold", f"\n  Findings — {case_id}\n"), ("class:sep", "  ───────\n\n"), ("class:dim", "  No findings\n"), ("class:help", "\n  Esc back")]
        frags = [("bold", f"\n  Findings — {case_id}\n"), ("class:sep", f"  {'─'*56}\n\n")]
        for i, f_item in enumerate(items[:30]):
            sev = f_item.get("severity", "info")
            col = {"critical": "class:err", "high": "class:warn", "medium": "class:help", "low": "class:dim"}.get(sev, "class:dim")
            prefix = "▸" if i == self.cursor else " "
            frags.append(("class:cursor" if i == self.cursor else "", f"  {prefix} [{sev[0].upper()}] {str(f_item.get('title',''))[:50]:<50} {f_item.get('status','open')}\n"))
        frags.append(("class:help", "\n  ↑↓ · e edit severity/status · Esc back"))
        return frags

    def _screen_prompts(self):
        prompts = self.data.get("prompts", [])
        if not prompts:
            return [("bold", "\n  Prompts\n"), ("class:sep", "  ───────\n\n"), ("class:dim", "  No prompts found\n"), ("class:help", "\n  c create · Esc back")]
        max_idx = len(prompts) - 1
        idx = max(0, min(self.cursor, max_idx))
        p = prompts[idx]
        frags = [("bold", "\n  Prompts\n"), ("class:sep", f"  {'─'*56}\n\n")]
        for i, p_item in enumerate(prompts):
            frags.append(("class:cursor" if i == idx else "", f"  {'▸' if i == idx else ' '} {p_item.get('title', p_item['id'])}\n"))
            if i == idx:
                desc = p_item.get("description", "")
                if desc:
                    frags.append(("class:dim", f"     {desc}\n"))
                tags = p_item.get("tags", [])
                if tags:
                    frags.append(("class:highlight", f"     tags: {', '.join(tags)}\n"))
                prompt_text = p_item.get("prompt", "")
                if prompt_text:
                    frags.append(("class:sep", f"     {'─'*50}\n"))
                    frags.append(("class:dim", f"     {prompt_text[:600]}\n"))
        frags.append(("class:help", "\n  ↑↓ · v view full · c create · d delete · Esc back"))
        return frags

    def _screen_dns(self):
        monitors = self.data.get("monitors", [])
        frags = [("bold", "\n  DNS Monitor\n"), ("class:sep", f"  {'─'*56}\n\n")]
        if monitors:
            frags.append(("class:highlight", f"  Active monitors: {len(monitors)}\n"))
            for m in monitors[:10]:
                frags.append(("", f"    {m.get('domain','?'):<30} {m.get('history_count',0)} records\n"))
        else:
            frags.append(("class:dim", "  No active monitors\n"))
        frags.append(("class:help", "  r resolve · m monitor · l list history · Esc back"))
        return frags

    def _screen_wifi(self):
        mm = get_monitor_manager()
        sessions = mm.list_sessions()
        active = mm.get_active_session()
        frags = [("bold", "\n  WiFi Monitor\n"), ("class:sep", f"  {'─'*56}\n\n")]
        if active:
            s = active.status_info()
            frags.append(("class:ok", f"  Active: {s.get('session_id','?')}  Uptime: {s.get('uptime','')}  APs: {s.get('ap_count',0)}  Clients: {s.get('client_count',0)}\n"))
        else:
            frags.append(("class:dim", "  No active session\n"))
        if sessions:
            frags.append(("class:highlight", f"  Sessions on disk: {len(sessions)}\n"))
            for s_item in sessions[:8]:
                sid = s_item.get("session_id", s_item if isinstance(s_item, str) else "?")
                frags.append(("class:dim", f"    {sid}\n"))
        frags.append(("class:help", "\n  s scan · m monitor start · t stop · Esc back"))
        return frags

    def _screen_runbooks(self):
        runbooks = self.data.get("runbooks", [])
        if not runbooks:
            return [("bold", "\n  Runbooks\n"), ("class:sep", "  ────────\n\n"), ("class:dim", "  No runbooks found\n"), ("class:help", "\n  Esc back")]
        max_idx = len(runbooks) - 1
        idx = max(0, min(self.cursor, max_idx))
        frags = [("bold", "\n  Runbooks\n"), ("class:sep", f"  {'─'*56}\n\n")]
        for i, r_item in enumerate(runbooks):
            frags.append(("class:cursor" if i == idx else "", f"  {'▸' if i == idx else ' '} {r_item.stem}\n"))
            if i == idx:
                try:
                    d = yaml.safe_load(r_item.read_text()) or {}
                    desc = str(d.get("description", d.get("info", "")))[:80]
                    if desc:
                        frags.append(("class:dim", f"     {desc}\n"))
                except Exception:
                    pass
        frags.append(("class:help", "\n  ↑↓ · Enter run · Esc back"))
        return frags

    def _screen_tools(self):
        tools = [
            ("nuclei", "Vulnerability scanner"),
            ("ffuf", "Web fuzzer"),
            ("gobuster", "Directory enumeration"),
            ("nmap", "Port scanner"),
            ("hashcat", "Hash cracking"),
            ("john", "Password cracking"),
            ("sqlmap", "SQL injection"),
            ("metasploit", "Exploitation framework"),
            ("hydra", "Brute-force auth"),
            ("evil-winrm", "WinRM client"),
        ]
        idx = max(0, min(self.cursor, len(tools) - 1))
        frags = [("bold", "\n  Tools\n"), ("class:sep", f"  {'─'*56}\n\n")]
        for i, (name, desc) in enumerate(tools):
            frags.append(("class:cursor" if i == idx else "", f"  {'▸' if i == idx else ' '} {name:<14} {desc}\n"))
        frags.append(("class:help", "\n  ↑↓ · Enter run with args · Esc back"))
        return frags

    def _screen_monitor(self):
        import psutil
        frags = [("bold", f"\n  System Monitor — {_now()}\n"), ("class:sep", f"  {'─'*56}\n\n")]
        try:
            cpu = psutil.cpu_percent(interval=0.3)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            for label, pct, used, total in [
                ("CPU", cpu, 0, 100),
                ("Mem", mem.percent, mem.used, mem.total),
                ("Disk", disk.percent, disk.used, disk.total),
            ]:
                bar = "█" * int(pct // 5) + "░" * (20 - int(pct // 5))
                col = "class:ok" if pct < 50 else "class:warn" if pct < 80 else "class:err"
                frags.append(("class:highlight", f"  {label}:  "))
                frags.append((col, bar))
                if label == "CPU":
                    frags.append(("", f" {pct:.0f}%\n"))
                else:
                    frags.append(("", f" {pct:.0f}% ({used//2**30:.1f}/{total//2**30:.1f} GB)\n"))
        except Exception:
            frags.append(("class:dim", "  (psutil not available)\n"))
        frags.append(("class:dim", f"\n  Cases: {len(self.data.get('cases',[]))}  Prompts: {len(self.data.get('prompts',[]))}  "
                     f"DNS monitors: {len(self.data.get('monitors',[]))}  Runbooks: {len(self.data.get('runbooks',[]))}\n"))
        frags.append(("class:help", "\n  r refresh · Esc back · q quit"))
        return frags

    def _screen_infra(self):
        import urllib.request, json
        cfg = self.config if isinstance(self.config, dict) else {}
        jupyter_url = str(cfg.get("jupyter_url", "http://localhost:8888"))
        caido_url = str(cfg.get("caido_url", "http://localhost:8080"))
        ollama_host = str(cfg.get("ollama_host", "http://localhost:11434"))
        services = [
            ("JupyterLab", jupyter_url),
            ("Caido", caido_url),
            ("Ollama", f"{ollama_host}/api/tags"),
        ]
        frags = [("bold", f"\n  AI Infra Status — {_now()}\n"), ("class:sep", f"  {'─'*56}\n\n")]
        for name, url in services:
            if "api/tags" in url:
                check_url = url.replace("/api/tags", "")
            else:
                check_url = url
            status = "class:dim"
            text = "unknown"
            try:
                r = urllib.request.urlopen(check_url, timeout=3)
                if r.status == 200:
                    status = "class:ok"; text = "UP"
                else:
                    status = "class:warn"; text = f"HTTP {r.status}"
            except Exception as e:
                status = "class:err"; text = f"DOWN ({type(e).__name__})"
            frags.append((status, f"  {name:<14} {url:<40} {text}\n"))
        frags.append(("class:sep", "\n"))
        frags.append(("class:help", "  Esc back"))

    # ------------------------------------------------------------------
    # Key bindings
    # ------------------------------------------------------------------
    def _kb(self):
        kb = KeyBindings()

        @kb.add("up")
        def _(event):
            n = self._screen_item_count()
            if n > 0:
                self.cursor = max(0, self.cursor - 1)
            elif self.screen == "main":
                self.cursor = (self.cursor - 1) % len(MENU_ITEMS)
            self.app.invalidate()

        @kb.add("down")
        def _(event):
            n = self._screen_item_count()
            if n > 0:
                self.cursor = min(n - 1, self.cursor + 1)
            elif self.screen == "main":
                self.cursor = (self.cursor + 1) % len(MENU_ITEMS)
            self.app.invalidate()

        @kb.add("enter")
        def _(event):
            self._handle_enter()

        @kb.add("escape")
        def _(event):
            self._go_back()

        @kb.add("q")
        def _(event):
            if self.screen == "main":
                event.app.exit()
            else:
                self._go_back()

        @kb.add("c")
        def _(event):
            if self.screen == "cases": self._create_case()
            elif self.screen == "prompts": self._create_prompt()

        @kb.add("d")
        def _(event):
            if self.screen == "cases": self._delete_case()
            elif self.screen == "prompts": self._delete_prompt()

        @kb.add("r")
        def _(event):
            if self.screen in ("cases", "monitor", "case_detail"):
                self._refresh_data(); self.app.invalidate()

        @kb.add("f")
        def _(event):
            if self.screen == "case_detail":
                c = self.data.get("_case")
                if c:
                    self.data["_findings_case_id"] = c.get("case_id", "")
                    self.screen = "findings"; self.cursor = 0; self.app.invalidate()

        @kb.add("e")
        def _(event):
            if self.screen == "findings":
                self._edit_finding()

        @kb.add("g")
        def _(event):
            if self.screen == "case_detail":
                self._generate_report()

        @kb.add("v")
        def _(event):
            if self.screen == "prompts": self._view_prompt_full()

        for key, idx in [("1",0),("2",1),("3",2),("4",3),("5",4),("6",5),("7",6),("8",7),("9",8)]:
            @kb.add(key)
            def _(event, i=idx):
                if self.screen == "main":
                    self.cursor = i; self._handle_enter()

        @kb.add("0")
        def _(event):
            if self.screen == "main": self._shell()

        @kb.add("s")
        def _(event):
            if self.screen == "wifi": self._wifi_scan()

        @kb.add("m")
        def _(event):
            if self.screen == "wifi": self._wifi_monitor_start()

        @kb.add("t")
        def _(event):
            if self.screen == "wifi": self._wifi_monitor_stop()

        @kb.add("l")
        def _(event):
            if self.screen == "dns": self._dns_list_history()

        return kb

    def _screen_item_count(self):
        if self.screen == "cases":
            return len(self.data.get("cases", []))
        if self.screen == "findings":
            cid = self.data.get("_findings_case_id", "")
            if not cid:
                return len(self.data.get("cases", []))
            try:
                return len(FindingsDB(CASES_DIR / cid).list())
            except Exception:
                return 0
        if self.screen == "prompts":
            return len(self.data.get("prompts", []))
        if self.screen == "runbooks":
            return len(self.data.get("runbooks", []))
        if self.screen == "tools":
            return 10
        return 0

    def _handle_enter(self):
        if self.screen == "main":
            mapping = ["cases", "findings", "prompts", "dns", "wifi", "runbooks", "tools", "monitor", "infra", "_shell"]
            target = mapping[self.cursor] if self.cursor < len(mapping) else None
            if target == "_shell":
                self._shell(); return
            if target:
                self.screen = target; self.cursor = 0; self.scroll = 0
                self._refresh_data(); self.app.invalidate()
        elif self.screen == "cases":
            cases = self.data.get("cases", [])
            if cases and 0 <= self.cursor < len(cases):
                self.data["_case"] = cases[self.cursor]
                self.screen = "case_detail"; self.cursor = 0; self.app.invalidate()
        elif self.screen == "findings":
            cid = self.data.get("_findings_case_id", "")
            if not cid:
                cases = self.data.get("cases", [])
                if cases and 0 <= self.cursor < len(cases):
                    self.data["_findings_case_id"] = cases[self.cursor].get("case_id", "")
                    self.cursor = 0; self.app.invalidate()
        elif self.screen == "runbooks":
            self._run_runbook()
        elif self.screen == "tools":
            self._run_tool()

    def _go_back(self):
        if self.screen == "main":
            self.app.exit()
        elif self.screen == "case_detail":
            self.data["_case"] = None; self.screen = "cases"
        elif self.screen == "findings":
            if self.data.get("_findings_case_id", ""):
                self.data["_findings_case_id"] = ""
            else:
                self.screen = "main"
        else:
            self.screen = "main"
        self.cursor = 0; self.app.invalidate()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _create_case(self):
        cid = self._ask("Case ID", "Enter case ID")
        if not cid: return
        client = self._ask("Client", "Client name:", default="") or ""
        desc = self._ask("Description", "Description:", default="") or ""
        try:
            self.cm.create(cid, client=client, description=desc)
            self._msg("Success", f"Case '{cid}' created")
            self._refresh_data(); self.app.invalidate()
        except Exception as e:
            self._msg("Error", str(e))

    def _delete_case(self):
        cases = self.data.get("cases", [])
        if not cases or self.cursor >= len(cases): return
        cid = cases[self.cursor].get("case_id", "")
        if self._confirm(f"Delete '{cid}'?", "Undone?"):
            try:
                self.cm.delete(cid); self._msg("Deleted", cid)
                self._refresh_data(); self.app.invalidate()
            except Exception as e:
                self._msg("Error", str(e))

    def _create_prompt(self):
        title = self._ask("Title", "Prompt title:")
        if not title: return
        prompts_dir = CC_DIR / "prompts"
        prompts_dir.mkdir(parents=True, exist_ok=True)
        path = prompts_dir / f"{title.lower().replace(' ', '-')}.yaml"
        if path.exists():
            self._msg("Error", "Already exists"); return
        desc = self._ask("Description", "Short desc:", default="") or ""
        tags_s = self._ask("Tags", "Comma-separated:", default="") or ""
        text = self._ask("Prompt", "Prompt content:", multiline=True)
        if not text: return
        doc = {"title": title, "description": desc, "tags": [t.strip() for t in tags_s.split(",") if t.strip()], "prompt": text}
        path.write_text(yaml.dump(doc, default_flow_style=False, allow_unicode=True))
        self._msg("Created", f"Prompt '{title}' saved")
        self._refresh_data(); self.app.invalidate()

    def _delete_prompt(self):
        prompts = self.data.get("prompts", [])
        if not prompts or self.cursor >= len(prompts): return
        p = prompts[self.cursor]; pid = p.get("id", "")
        if self._confirm(f"Delete '{p.get('title',pid)}'?", ""):
            path = CC_DIR / "prompts" / f"{pid}.yaml"
            if path.exists(): path.unlink()
            self._msg("Deleted", pid)
            self._refresh_data(); self.app.invalidate()

    def _view_prompt_full(self):
        prompts = self.data.get("prompts", [])
        if not prompts or self.cursor >= len(prompts): return
        p = prompts[self.cursor]
        self._msg(p.get("title", p.get("id", "")), p.get("prompt", "(empty)"))

    def _edit_finding(self):
        cid = self.data.get("_findings_case_id", "")
        if not cid: return
        fdb = FindingsDB(CASES_DIR / cid)
        items = fdb.list()
        if not items or self.cursor >= len(items): return
        f = items[self.cursor]
        action = self._ask("Edit Finding", f"f) toggle severity  s) toggle status\n\n{f.get('title','')}\nseverity={f.get('severity','info')}  status={f.get('status','open')}", default="")
        if not action: return
        action = action.strip().lower()
        if action == "f":
            sev_cycle = ["info", "low", "medium", "high", "critical"]
            cur = f.get("severity", "info")
            new_sev = sev_cycle[(sev_cycle.index(cur) + 1) % len(sev_cycle)] if cur in sev_cycle else "info"
            fdb.update(f["id"], severity=new_sev)
            self._msg("Updated", f"severity → {new_sev}")
        elif action == "s":
            new_status = "closed_other" if f.get("status", "unvalidated") == "unvalidated" else "unvalidated"
            fdb.update(f["id"], status=new_status)
            self._msg("Updated", f"status → {new_status}")
        self.app.invalidate()

    def _generate_report(self):
        c = self.data.get("_case")
        if not c: return
        cid = c.get("case_id", "")
        fmt = self._ask("Report Format", "Format (md/html/docx/pdf):", default="md")
        if not fmt: return
        obj = self._ask("Report", "Obsidian report? (y/n):", default="n")
        self._msg("Generating", f"Generating {fmt} report for {cid}...")
        try:
            if obj and obj.strip().lower() == "y":
                from modules.report_generator import generate_obsidian_report
                result = generate_obsidian_report(cid, formats=fmt)
            else:
                from modules.report_generator import generate_engagement_report
                result = generate_engagement_report(cid)
            msg = result if isinstance(result, str) else str(result.get("path", "done"))
            self._msg("Report", f"Generated: {msg}")
        except Exception as e:
            self._msg("Error", f"Report failed: {e}")

    def _dns_list_history(self):
        domain = self._ask("History", "Domain:")
        if not domain: return
        try:
            records = get_history(domain, limit=30)
            if not records:
                self._msg("History", f"No records for {domain}"); return
            lines = "\n".join(f"{r.get('ts','')[:19]}  {r.get('type',''):6}  {r.get('value','')}" for r in records[:30])
            self._msg(f"DNS History — {domain}", lines)
        except Exception as e:
            self._msg("Error", str(e))

    def _wifi_scan(self):
        self._msg("Scan", "Scanning (45s)...")
        try:
            from modules.wifi_wrapper import wifi_scan
            result = wifi_scan(timeout=45)
            aps = result.get("aps", [])
            lines = "\n".join(f"{a.get('ssid','?'):<25} {a.get('bssid',''):<18} CH{a.get('channel','')} {a.get('signal','')}  {a.get('encryption','')}" for a in aps[:20])
            self._msg(f"WiFi Scan — {len(aps)} APs", lines or "No APs")
        except Exception as e:
            self._msg("Error", str(e))

    def _wifi_monitor_start(self):
        iface = self._ask("Interface", "WiFi iface:", default="wlan0")
        if not iface: return
        sid = f"tui-{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            get_monitor_manager().start_session(sid, iface)
            self._msg("Monitor", f"Session '{sid}' started")
        except Exception as e:
            self._msg("Error", str(e))

    def _wifi_monitor_stop(self):
        active = get_monitor_manager().get_active_session()
        if active:
            sid = active.status_info().get("session_id", "")
            active.stop()
            self._msg("Stopped", f"Session '{sid}' stopped")
        else:
            self._msg("Info", "No active session")

    def _run_runbook(self):
        runbooks = self.data.get("runbooks", [])
        if not runbooks or self.cursor >= len(runbooks): return
        path = runbooks[self.cursor]
        target = self._ask("Target", "Target:", default="localhost")
        if not target: return
        case_id = self._ask("Case ID", "Case ID (or empty):", default="") or ""
        try:
            self._msg("Running", f"'{path.stem}' vs {target}...")
            results = self.pe.run_file(str(path), [target], case_id, {}, verbose=False)
            summary = "\n".join(f"  {r.get('step','?')}: rc={r.get('rc',-1)}" for r in (results or []))
            self._msg(f"Done — {path.stem}", summary or "(no output)")
            self.app.invalidate()
        except Exception as e:
            self._msg("Error", str(e))

    def _run_tool(self):
        tools = ["nuclei", "ffuf", "gobuster", "nmap", "hashcat", "john", "sqlmap", "msfconsole", "hydra", "evil-winrm"]
        if self.cursor >= len(tools): return
        name = tools[self.cursor]
        args = self._ask("Args", f"Args for {name}:")
        if args is None or not args.strip():
            self._msg("Usage", f"Usage: {name} <args>"); return
        self._msg("Running", f"Running: {name} {args}")
        try:
            r = subprocess.run([name] + shlex.split(args), capture_output=True, text=True, timeout=120)
            out = (r.stdout[-2000:] + "\n" + r.stderr[-2000:]).strip()
            self._msg(f"{name} — rc={r.returncode}", out or "(no output)")
        except subprocess.TimeoutExpired:
            self._msg("Timeout", f"{name} timed out")
        except FileNotFoundError:
            self._msg("Error", f"{name} not installed")
        except Exception as e:
            self._msg("Error", str(e))

    def _shell(self):
        self._msg("Shell", "exit/Ctrl+D to return.\n")
        try:
            subprocess.run(os.environ.get("SHELL", "cmd.exe" if sys.platform == "win32" else "bash"), shell=True)
        except KeyboardInterrupt:
            pass
        self.app.invalidate()

    def _ask(self, title, text, default="", multiline=False):
        try:
            return input_dialog(title=title, text=text, default_text=default).run()
        except Exception:
            return None

    def _msg(self, title, text):
        try:
            message_dialog(title=title, text=text).run()
        except Exception:
            pass

    def _confirm(self, title, text):
        try:
            return yes_no_dialog(title=title, text=text).run()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------
    def run(self):
        body = Window(content=FormattedTextControl(self._get_content, focusable=True))
        status = Window(content=FormattedTextControl(self._get_status), height=1, style="class:status")
        self.app = Application(
            layout=Layout(HSplit([body, status])),
            key_bindings=self._kb(),
            style=STYLE,
            full_screen=True,
            mouse_support=True,
        )
        try:
            self.app.run()
        except KeyboardInterrupt:
            pass


def main():
    TUIApp().run()


if __name__ == "__main__":
    main()
