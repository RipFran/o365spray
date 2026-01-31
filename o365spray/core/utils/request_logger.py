#!/usr/bin/env python3

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

from o365spray.core.utils.defaults import DefaultFiles


@dataclass
class RequestLogEntry:
    """Request log entry metadata."""

    path: Path
    start_time: datetime
    context: Dict[str, Any]
    method: str
    url: str


class RequestLogger:
    """Write one log file per HTTP request for traceability."""

    def __init__(self, output_dir: str, action: str = "request"):
        # Updated: initialize per-request log directory for professional audit trails.
        self.action = action
        self.log_dir = Path(output_dir) / DefaultFiles.HTTP_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize(self, value: Optional[str], limit: int = 80) -> str:
        # Updated: sanitize filenames for cross-platform safety.
        if not value:
            value = "unknown"
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
        return safe[:limit]

    def _write_kv(self, fh, label: str, value: Any):
        # Updated: helper to render structured metadata.
        fh.write(f"{label}: {value}\n")

    def start_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        json_data: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> RequestLogEntry:
        # Updated: write request details before the HTTP call to avoid data loss.
        now = datetime.now()
        context = context or {}
        target = self._sanitize(str(context.get("target") or context.get("user")))
        module = self._sanitize(str(context.get("module")))
        req_id = uuid4().hex[:8]
        timestamp = now.strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{timestamp}_{self.action}_{module}_{target}_{req_id}.log"
        path = self.log_dir / filename

        with path.open("w", encoding="utf-8") as fh:
            self._write_kv(fh, "REQUEST_ID", req_id)
            self._write_kv(fh, "ACTION", self.action)
            self._write_kv(fh, "MODULE", context.get("module"))
            self._write_kv(fh, "TARGET", context.get("target") or context.get("user"))
            self._write_kv(fh, "START_TIME", now.isoformat())
            for key, value in context.items():
                if key in {"module", "target", "user"}:
                    continue
                self._write_kv(fh, key.upper(), value)

            fh.write("\n=== REQUEST ===\n")
            fh.write(f"{method.upper()} {url} HTTP/1.1\n")
            if headers:
                for key, value in headers.items():
                    fh.write(f"{key}: {value}\n")
            fh.write("\n")

            if json_data is not None:
                fh.write("JSON:\n")
                fh.write(json.dumps(json_data, indent=2, ensure_ascii=True))
                fh.write("\n")
            elif data is not None:
                fh.write("BODY:\n")
                fh.write(str(data))
                fh.write("\n")

        return RequestLogEntry(
            path=path,
            start_time=now,
            context=context,
            method=method,
            url=url,
        )

    def log_response(self, entry: RequestLogEntry, response: Any):
        # Updated: append response details after a successful HTTP call.
        end_time = datetime.now()
        elapsed = (end_time - entry.start_time).total_seconds()
        with entry.path.open("a", encoding="utf-8") as fh:
            fh.write("\n=== RESPONSE ===\n")
            fh.write(f"STATUS: {response.status_code} {response.reason}\n")
            fh.write(f"END_TIME: {end_time.isoformat()}\n")
            fh.write(f"ELAPSED: {elapsed:.3f}s\n")
            for key, value in response.headers.items():
                fh.write(f"{key}: {value}\n")
            fh.write("\n")
            fh.write(response.text or "")

    def log_error(self, entry: RequestLogEntry, error: Exception):
        # Updated: append error details when a request fails before a response.
        end_time = datetime.now()
        elapsed = (end_time - entry.start_time).total_seconds()
        with entry.path.open("a", encoding="utf-8") as fh:
            fh.write("\n=== RESPONSE ===\n")
            fh.write("STATUS: ERROR\n")
            fh.write(f"END_TIME: {end_time.isoformat()}\n")
            fh.write(f"ELAPSED: {elapsed:.3f}s\n")
            fh.write(f"ERROR_TYPE: {type(error).__name__}\n")
            fh.write(f"ERROR: {error}\n")
