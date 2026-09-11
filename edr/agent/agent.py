"""Main EDR agent daemon -- ties all components together."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from pathlib import Path

from edr.agent.baseline import BaselineStore
from edr.agent.config import AgentConfig
from edr.agent.detector import Detector
from edr.agent.osquery import OsqueryRunner
from edr.agent.reporter import Reporter
from edr.agent.updater import ConfigUpdater

logger = logging.getLogger("edr.agent")

_SHUTDOWN = False


def _signal_handler(signum, frame):
    global _SHUTDOWN
    logger.info("Received signal %s, shutting down gracefully...", signum)
    _SHUTDOWN = True


class Agent:
    """Main EDR agent that coordinates all subsystems."""

    def __init__(self, config_path=None):
        self._config = AgentConfig(config_path)
        self._runner = OsqueryRunner(self._config.osquery_path)
        self._baseline = BaselineStore(self._config.baseline_dir)
        self._detector = Detector(
            self._runner, self._baseline,
            device_uuid=self._config.device_uuid,
        )
        self._reporter = Reporter(self._config)
        self._updater = ConfigUpdater(self._config)
        self._first_run = self._is_first_run()
        self._last_checkin = 0.0
        self._rules = []

    def _setup_logging(self, verbose=False):
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    def _is_first_run(self):
        baseline_dir = self._config.baseline_dir
        if not baseline_dir.exists():
            return True
        baseline_files = list(baseline_dir.glob("baseline_*.json"))
        return len(baseline_files) == 0

    def _load_rules_from_config(self, config):
        """Parse detection rules from fetched config."""
        from edr.rules.schema import DetectionRule
        raw_rules = config.get("rules", [])
        rules = []
        for r in raw_rules:
            if isinstance(r, dict):
                rules.append(DetectionRule.model_validate(r))
        return rules

    def _load_rules_from_disk(self):
        """Load rules from rules_dir YAML/JSON files."""
        from edr.rules.schema import DetectionRule
        rules = []
        rules_dir = self._config.rules_dir
        if not rules_dir.exists():
            return rules
        for fpath in rules_dir.iterdir():
            if fpath.suffix in (".yaml", ".yml", ".json"):
                try:
                    data = self._load_file(fpath)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                rules.append(DetectionRule.model_validate(item))
                    elif isinstance(data, dict):
                        for key, val in data.items():
                            if isinstance(val, dict):
                                val.setdefault("rule_id", key)
                                rules.append(DetectionRule.model_validate(val))
                except Exception as exc:
                    logger.error("Failed to load rules from %s: %s", fpath, exc)
        return rules

    def _load_file(self, path):
        """Load a YAML or JSON file."""
        if path.suffix == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        try:
            import yaml
            return yaml.safe_load(path.read_text(encoding="utf-8"))
        except ImportError:
            pass
        return self._basic_yaml_load(path)

    def _basic_yaml_load(self, path):
        """Minimal YAML loader for our rule format."""
        text = path.read_text(encoding="utf-8")
        if text.strip().startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return None
        result = {}
        current_key = None
        current_val = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if ":" not in stripped:
                continue
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if indent == 0:
                if current_key and current_val:
                    result[current_key] = current_val
                current_key = key
                if val:
                    current_val = self._yaml_value(val)
                else:
                    current_val = {}
            elif isinstance(current_val, dict):
                current_val[key] = self._yaml_value(val)
        if current_key and current_val:
            result[current_key] = current_val
        return result

    def _yaml_value(self, val):
        if val.lower() in ("true", "yes"):
            return True
        if val.lower() in ("false", "no"):
            return False
        if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
            return int(val)
        try:
            return float(val)
        except ValueError:
            pass
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            return val[1:-1]
        if val in ("null", "~"):
            return None
        return val

    def run_once(self):
        """Execute a single checkin cycle."""
        logger.info("Starting checkin cycle")
        effective = self._updater.get_effective_config()
        quarantined = self._updater.is_quarantined(effective)
        if quarantined:
            logger.warning("Device is quarantined -- read-only mode")
        remote_rules = self._load_rules_from_config(effective)
        if remote_rules:
            self._rules = remote_rules
            logger.info("Loaded %d rules from server config", len(self._rules))
        else:
            self._rules = self._load_rules_from_disk()
            logger.info("Loaded %d rules from local disk", len(self._rules))
        self._detector.set_rules(self._rules)
        if self._first_run:
            logger.info("First run: populating baselines (no alerts)")
            for rule in self._rules:
                if not rule.osquery.query:
                    continue
                rows = self._runner.run_query_safe(rule.osquery.query)
                if rows:
                    self._baseline.populate_initial(rule.id, rows)
            self._detector.mark_first_run_done()
            self._first_run = False
        else:
            results = self._detector.evaluate_all()
            if quarantined:
                results = [r for r in results if r.get("severity") in ("high", "critical")]
            for result in results:
                if quarantined:
                    result["response_actions_triggered"] = []
                self._reporter.queue_alert(result)
            sent = self._reporter.send_batch_retry()
            self._last_checkin = time.time()
            summary = {
                "rules_evaluated": len(self._rules),
                "detections": len(results),
                "alerts_sent": sent,
                "alerts_queued": self._reporter.queued_count,
                "device_uuid": self._config.device_uuid,
                "timestamp": self._last_checkin,
            }
            logger.info("Checkin complete: %s", json.dumps(summary))
            return summary
        return {"status": "first_run_complete", "rules_loaded": len(self._rules)}

    def run_daemon(self):
        """Run the agent as a daemon with configurable sleep interval."""
        global _SHUTDOWN
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
        logger.info(
            "Starting EDR agent daemon (interval=%ds, uuid=%s)",
            self._config.checkin_interval, self._config.device_uuid,
        )
        while not _SHUTDOWN:
            try:
                self.run_once()
            except Exception as exc:
                logger.error("Checkin cycle failed: %s", exc, exc_info=True)
            if _SHUTDOWN:
                break
            logger.info("Sleeping %ds until next checkin", self._config.checkin_interval)
            for _ in range(self._config.checkin_interval):
                if _SHUTDOWN:
                    break
                time.sleep(1)
        logger.info("Agent daemon stopped")

    def run_once_cli(self):
        """Run a single check and print results (no sending)."""
        logger.info("Running single check (CLI mode)")
        self._rules = self._load_rules_from_disk()
        self._detector.set_rules(self._rules)
        results = self._detector.evaluate_all()
        print(f"\nDevice UUID: {self._config.device_uuid}")
        print(f"Rules loaded: {len(self._rules)}")
        print(f"Detections: {len(results)}\n")
        for result in results:
            print(f"  [{result.get('severity', '?').upper()}] {result.get('rule_name', '?')}")
            print(f"    Rule: {result.get('rule_id', '?')}")
            matched = result.get("matched_rows", [])
            print(f"    Matched rows: {len(matched)}")
            new_vals = result.get("new_values", {})
            if new_vals:
                for field, vals in new_vals.items():
                    print(f"    New {field}: {', '.join(vals)}")
            actions = result.get("response_actions_triggered", [])
            if actions:
                print(f"    Actions: {', '.join(actions)}")
            print()
        if not results:
            print("  No detections.")
        return results

    def setup(self):
        """First-run setup: generate UUID, populate baselines, validate."""
        print("EDR Agent Setup")
        print("=" * 40)
        warnings = self._config.validate()
        print(f"Device UUID: {self._config.device_uuid}")
        print(f"Config path: {self._config.config_path}")
        print(f"Baseline dir: {self._config.baseline_dir}")
        print(f"Alert queue dir: {self._config.alert_queue_dir}")
        print(f"Rules dir: {self._config.rules_dir}")
        print(f"Osquery: {self._config.osquery_path}")
        if self._runner.available:
            print("Osquery status: available")
        else:
            print("Osquery status: NOT AVAILABLE (queries will be skipped)")
        if warnings:
            print("\nWarnings:")
            for w in warnings:
                print(f"  - {w}")
        if self._first_run:
            print("\nFirst run detected -- populating initial baselines...")
            rules = self._load_rules_from_disk()
            self._detector.set_rules(rules)
            for rule in rules:
                if not rule.osquery.query:
                    continue
                rows = self._runner.run_query_safe(rule.osquery.query)
                if rows:
                    self._baseline.populate_initial(rule.id, rows)
            self._first_run = False
            print(f"Baselines populated for {len(rules)} rules.")
        else:
            print("\nBaselines already exist, skipping initial population.")
        print("\nSetup complete.")

    def status(self):
        """Show current agent state."""
        print("EDR Agent Status")
        print("=" * 40)
        print(f"Device UUID: {self._config.device_uuid}")
        print(f"Server URL: {self._config.server_url or '(not configured)'}")
        print(f"Checkin interval: {self._config.checkin_interval}s")
        print(f"Offline mode: {self._config.offline_mode}")
        if self._last_checkin:
            age = time.time() - self._last_checkin
            print(f"Last checkin: {age:.0f}s ago")
        else:
            print("Last checkin: never")
        print(f"Queued alerts: {self._reporter.queued_count}")
        rules = self._load_rules_from_disk()
        print(f"Local rules: {len(rules)}")
        baseline_dir = self._config.baseline_dir
        if baseline_dir.exists():
            bl_files = list(baseline_dir.glob("baseline_*.json"))
            print(f"Baseline tables: {len(bl_files)}")
            for bf in bl_files:
                name = bf.stem.removeprefix("baseline_")
                try:
                    data = json.loads(bf.read_text(encoding="utf-8"))
                    fields = len(data)
                    values = sum(len(v) for v in data.values())
                    print(f"  {name}: {fields} fields, {values} values")
                except Exception:
                    print(f"  {name}: (unreadable)")
        else:
            print("Baseline tables: 0")


def main():
    """CLI entry point for python -m edr.agent."""
    parser = argparse.ArgumentParser(
        prog="edr.agent",
        description="CC-EDR Agent",
    )
    parser.add_argument(
        "command",
        choices=["run", "setup", "status", "test"],
        help="Command to execute",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to config YAML file",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()
    agent = Agent(args.config)
    agent._setup_logging(verbose=args.verbose)
    if args.command == "run":
        agent.run_daemon()
    elif args.command == "setup":
        agent.setup()
    elif args.command == "status":
        agent.status()
    elif args.command == "test":
        agent.run_once_cli()


if __name__ == "__main__":
    main()
