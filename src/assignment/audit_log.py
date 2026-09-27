"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        req_key = request_id or f"{user_id}_{len(self.logs)}_{datetime.now(timezone.utc).timestamp()}"
        import time
        self._open[req_key] = {
            "user_id": user_id,
            "text": text,
            "start_time": time.time(),
        }
        return req_key

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        import time
        input_text = ""
        latency_ms = 0.0
        req_key = request_id

        if not req_key:
            # Look up matching open key for user_id if any
            for k, v in list(self._open.items()):
                if v["user_id"] == user_id:
                    req_key = k
                    break

        if req_key and req_key in self._open:
            entry_info = self._open.pop(req_key)
            input_text = entry_info["text"]
            latency_ms = round((time.time() - entry_info["start_time"]) * 1000, 2)

        entry = {
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "request_id": req_key,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        out_path = Path(filepath or default_audit_log_path())
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return out_path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
