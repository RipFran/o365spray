#!/usr/bin/env python3

import logging
from typing import Optional

import requests  # type: ignore


class TelegramNotifier:
    """Lightweight Telegram bot notifier for spray results."""

    def __init__(
        self,
        token: Optional[str] = None,
        chat_id: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.token = token
        self.chat_id = chat_id
        self.timeout = timeout
        self.enabled = bool(self.token and self.chat_id)
        self._api_url = (
            f"https://api.telegram.org/bot{self.token}/sendMessage"
            if self.enabled
            else None
        )

    def send_message(self, text: str) -> bool:
        """Send a message to the configured Telegram chat.

        Returns:
            True if the message was sent successfully, False otherwise.
        """
        if not self.enabled:
            return False

        try:
            response = requests.post(
                self._api_url,
                data={
                    "chat_id": self.chat_id,
                    "text": text,
                    "disable_web_page_preview": True,
                },
                timeout=(3.05, self.timeout),
            )
            if response.status_code != 200:
                logging.warning(
                    "Telegram notification failed (status=%s).",
                    response.status_code,
                )
                return False

            try:
                payload = response.json()
                if not payload.get("ok", False):
                    logging.warning(
                        "Telegram notification rejected (ok=false, status=%s).",
                        response.status_code,
                    )
                    return False
            except Exception:
                # If Telegram returns a non-JSON response, assume it was sent.
                pass

        except Exception as exc:
            logging.debug("Telegram notification error: %s", exc)
            return False

        return True
