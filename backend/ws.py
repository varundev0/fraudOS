"""WebSocket connection manager for FraudOS real-time case updates."""

from __future__ import annotations

import json
import logging
from typing import Set

from fastapi import WebSocket

_logger = logging.getLogger(__name__)


class ConnectionManager:
    """Tracks all live WebSocket connections and broadcasts messages to them."""

    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        _logger.debug("WS client connected — total=%d", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)
        _logger.debug("WS client disconnected — total=%d", len(self._connections))

    async def broadcast(self, data: dict) -> None:
        """Send a JSON message to all connected clients, pruning dead connections."""
        if not self._connections:
            return

        payload = json.dumps(data, default=str)
        dead: Set[WebSocket] = set()

        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)

        if dead:
            self._connections -= dead
            _logger.debug("Pruned %d dead WS connections — total=%d", len(dead), len(self._connections))

    @property
    def connected_count(self) -> int:
        return len(self._connections)


# Module-level singleton used by main.py and webhook.py
manager = ConnectionManager()
