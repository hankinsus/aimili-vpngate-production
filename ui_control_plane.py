from __future__ import annotations

import time
import uuid
from threading import RLock
from typing import Any


class UICommandPlane:
    """Small UI-only control plane.

    Read requests never acquire the command lock. Mutating UI commands receive a
    token so duplicate clicks cannot create a second operation. The application
    runtime remains responsible for the actual VPN/process locks.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._active: dict[str, Any] | None = None
        self._sequence = 0
        self._last_completed: dict[str, Any] = {}

    def begin(self, kind: str, target: str = "", *, allow_same: bool = False) -> dict[str, Any] | None:
        with self._lock:
            if self._active is not None:
                if allow_same and self._active.get("kind") == kind and self._active.get("target") == target:
                    return dict(self._active)
                return None
            self._sequence += 1
            token = uuid.uuid4().hex[:16]
            self._active = {
                "token": token,
                "sequence": self._sequence,
                "kind": str(kind or "command"),
                "target": str(target or ""),
                "started_at": time.time(),
            }
            return dict(self._active)

    def finish(self, token: str, *, ok: bool, message: str = "") -> bool:
        with self._lock:
            if not self._active or str(self._active.get("token")) != str(token):
                return False
            completed = dict(self._active)
            completed.update({"ok": bool(ok), "message": str(message or ""), "finished_at": time.time()})
            self._last_completed = completed
            self._active = None
            return True

    def active(self) -> dict[str, Any] | None:
        with self._lock:
            return dict(self._active) if self._active else None

    def is_busy(self) -> bool:
        with self._lock:
            return self._active is not None

    def ui_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active": dict(self._active) if self._active else None,
                "last_completed": dict(self._last_completed) if self._last_completed else None,
                "sequence": self._sequence,
            }


ui_command_plane = UICommandPlane()
