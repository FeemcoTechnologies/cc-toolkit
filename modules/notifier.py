"""Webhook notifier — push messages to Slack, Discord, Telegram."""

import json
import urllib.request
import urllib.error
from typing import Optional


class Notifier:
    """Send notifications via webhook URLs (Slack, Discord, Telegram)."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def _post(self, url: str, payload: dict) -> dict:
        if not url:
            return {"sent": False, "error": "No webhook URL configured"}
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
            return {"sent": True}
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            return {"sent": False, "error": str(e)}

    def slack(self, message: str, level: str = "info") -> dict:
        url = self.config.get("slack_webhook", "")
        emoji = {"info": ":information_source:", "warn": ":warning:",
                 "critical": ":red_circle:", "success": ":white_check_mark:"}
        return self._post(url, {"text": f"{emoji.get(level, '')} {message}"})

    def discord(self, message: str, level: str = "info") -> dict:
        url = self.config.get("discord_webhook", "")
        colors = {"info": 3447003, "warn": 16776960,
                  "critical": 15548997, "success": 3066993}
        return self._post(url, {
            "embeds": [{
                "description": message,
                "color": colors.get(level, 3447003),
            }]
        })

    def telegram(self, message: str, level: str = "info") -> dict:
        token = self.config.get("telegram_token", "")
        chat_id = self.config.get("telegram_chat_id", "")
        if not token or not chat_id:
            return {"sent": False, "error": "Telegram token/chat_id not configured"}
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        return self._post(url, {"chat_id": chat_id, "text": message})

    def send(self, message: str, level: str = "info", targets: list = None) -> list:
        """Send to all configured targets. targets = ['slack','discord','telegram'] or None for all."""
        results = []
        targets = targets or [t for t in ("slack", "discord", "telegram")
                              if self.config.get(f"{t}_webhook") or
                                 self.config.get(f"{t}_token")]
        for t in targets:
            fn = getattr(self, t, None)
            if fn:
                results.append({t: fn(message, level)})
        return results
