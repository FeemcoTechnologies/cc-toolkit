"""Per-binary fuzzing workflow tracker (JSON-backed) so the AI can
resume/pivot between targets with a single status call."""

import json
import os


STATE_FILE = os.environ.get(
    "FUZZ_GUIDE_STATE", "/tmp/fuzz_guide_workdir/state.json"
)


def _load() -> dict:
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=1)


def reset_all() -> None:
    _save({})


def get_binary_state(binary: str) -> dict:
    """Return tracked state for a binary (or empty)."""
    state = _load()
    return state.get(binary, {})


def update_binary_state(binary: str, **fields) -> dict:
    """Merge fields into a binary's state record."""
    state = _load()
    current = state.setdefault(binary, {})
    current.update(fields)
    _save(state)
    return current


def log_campaign(binary: str, campaign: dict) -> dict:
    """Append a campaign run to the binary's history."""
    state = _load()
    current = state.setdefault(binary, {})
    history = current.setdefault("campaigns", [])
    history.append(campaign)
    current["last_campaign"] = campaign.get("campaign_dir") or campaign.get("out_dir")
    current["times_run"] = len(history)
    _save(state)
    return current


def list_tracked_binaries() -> list[dict]:
    """Return list of all tracked binaries with workflow status."""
    state = _load()
    return [
        {
            "binary": b,
            "status": v.get("status", "new"),
            "classify": v.get("classify", {}).get("type", "?"),
            "input_methods": v.get("input_methods", []),
            "times_run": v.get("times_run", 0),
            "last_campaign": v.get("last_campaign"),
            "notes": v.get("notes", ""),
        }
        for b, v in sorted(state.items())
    ]


def get_status(binary: str) -> dict:
    """Full workflow status for one binary."""
    state = _load()
    return state.get(binary, {"binary": binary, "status": "new"})