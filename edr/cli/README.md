# EDR CLI

Standalone CLI for interacting with the KCC EDR server or a local agent.

## Setup

Set environment variables:
```
export EDR_SERVER_URL=http://127.0.0.1:8900
export EDR_ADMIN_API_KEY=your-key-here
```
Or place them in `~/.config/kali-command-center/config.json`.

## Usage

```bash
python -m edr.cli agents list
python -m edr.cli alerts list --severity high
python -m edr.cli hunt "SELECT * FROM processes" --device <uuid>
python -m edr.cli status
```

Run `python -m edr.cli --help` for full command reference.
