from __future__ import annotations

import asyncio
import datetime as dt
import json
import threading
from collections import defaultdict
from typing import Any

from app.database import SessionLocal
from app.models import AuditEvent
from app.services.vault import scrub_secrets


class RunEventBus:
    """Thread-safe + asyncio-friendly SSE broadcaster and cancellation coordinator."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]]] = defaultdict(list)
        self._cancel_events: dict[str, threading.Event] = {}
        self._active_procs: dict[str, list[Any]] = defaultdict(list)

    def create_cancel_token(self, run_id: str) -> threading.Event:
        with self._lock:
            ev = threading.Event()
            self._cancel_events[run_id] = ev
            return ev

    def is_cancelled(self, run_id: str) -> bool:
        with self._lock:
            ev = self._cancel_events.get(run_id)
            return ev.is_set() if ev else False

    def register_process(self, run_id: str, proc: Any) -> None:
        with self._lock:
            self._active_procs[run_id].append(proc)

    def unregister_process(self, run_id: str, proc: Any) -> None:
        with self._lock:
            procs = self._active_procs.get(run_id)
            if procs and proc in procs:
                procs.remove(proc)

    def cancel_run(self, run_id: str) -> bool:
        with self._lock:
            ev = self._cancel_events.get(run_id)
            if ev:
                ev.set()
            procs = list(self._active_procs.get(run_id, []))
        for proc in procs:
            try:
                proc.terminate()
            except Exception:
                pass
        return ev is not None

    def cleanup_run(self, run_id: str) -> None:
        with self._lock:
            self._cancel_events.pop(run_id, None)
            self._active_procs.pop(run_id, None)

    def subscribe(self, run_id: str) -> tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        with self._lock:
            self._subscribers[run_id].append((loop, queue))
        return loop, queue

    def unsubscribe(self, run_id: str, entry: tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]) -> None:
        with self._lock:
            subs = self._subscribers.get(run_id)
            if subs and entry in subs:
                subs.remove(entry)
            if subs is not None and len(subs) == 0:
                self._subscribers.pop(run_id, None)

    def _dispatch(self, run_id: str, payload: dict[str, Any]) -> None:
        with self._lock:
            targets = list(self._subscribers.get(run_id, []))
        for loop, queue in targets:
            if not loop.is_closed():
                def _put(q: asyncio.Queue[dict[str, Any]] = queue, item: dict[str, Any] = payload) -> None:
                    try:
                        q.put_nowait(item)
                    except asyncio.QueueFull:
                        pass
                loop.call_soon_threadsafe(_put)

    def emit_log(self, run_id: str, gate_number: int, message: str, level: str = "info") -> dict[str, Any]:
        safe_message = scrub_secrets(message)
        ts = dt.datetime.now(dt.timezone.utc)
        event_id = 0
        try:
            with SessionLocal() as db:
                row = AuditEvent(
                    run_id=run_id,
                    gate_number=gate_number,
                    level=level,
                    message=safe_message,
                    timestamp=ts,
                )
                db.add(row)
                db.commit()
                db.refresh(row)
                event_id = row.id
        except Exception:
            pass

        payload = {
            "event": "log",
            "data": {
                "id": event_id,
                "run_id": run_id,
                "gate_number": gate_number,
                "level": level,
                "message": safe_message,
                "timestamp": ts.isoformat(),
            },
        }
        self._dispatch(run_id, payload)
        return payload

    def emit_gate_update(self, run_id: str, gate_data: dict[str, Any]) -> None:
        self._dispatch(run_id, {"event": "gate_update", "data": gate_data})

    def emit_run_update(self, run_id: str, run_data: dict[str, Any]) -> None:
        self._dispatch(run_id, {"event": "run_update", "data": run_data})

    def emit_complete(self, run_id: str, status: str, readiness_score: int) -> None:
        self._dispatch(
            run_id,
            {
                "event": "complete",
                "data": {
                    "run_id": run_id,
                    "status": status,
                    "readiness_score": readiness_score,
                    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                },
            },
        )


def format_sse(event_name: str, data: dict[str, Any]) -> str:
    return f"event: {event_name}\ndata: {scrub_secrets(json.dumps(data, default=str))}\n\n"


event_bus = RunEventBus()
