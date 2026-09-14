"""Per-binary fuzzing workflow tracker (JSON-backed) so the AI can
resume/pivot between targets with a single status call."""

import json
import os
import tempfile


_WORK = os.environ.get("FUZZ_GUIDE_WORKDIR", "") or os.path.join(
    tempfile.gettempdir(), "fuzz_guide_workdir"
)
STATE_FILE = os.environ.get("FUZZ_GUIDE_STATE", os.path.join(_WORK, "state.json"))

_lock = None


def _thread_lock():
    """Lazily-created in-process lock serializing read-modify-write cycles."""
    global _lock
    if _lock is None:
        import threading
        _lock = threading.Lock()
    return _lock


def _load() -> dict:
    if not os.path.isfile(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(state: dict) -> None:
    # atomic replace: a crash mid-write can never corrupt the state file
    d = os.path.dirname(STATE_FILE)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, STATE_FILE)


def reset_all() -> None:
    with _thread_lock():
        _save({})


def get_binary_state(binary: str) -> dict:
    """Return tracked state for a binary (or empty)."""
    return _load().get(binary, {})


def update_binary_state(binary: str, **fields) -> dict:
    """Merge fields into a binary's state record."""
    with _thread_lock():
        state = _load()
        current = state.setdefault(binary, {})
        current.update(fields)
        _save(state)
    return current


def log_campaign(binary: str, campaign: dict) -> dict:
    """Append a campaign run to the binary's history."""
    with _thread_lock():
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
    return _load().get(binary, {"binary": binary, "status": "new"})