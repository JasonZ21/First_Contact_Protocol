"""
Transport testing harness.

Two simple transports:
- DirectTransport: immediate in-memory pairing (for happy-path tests)
- InterceptingTransport: supports scripts that can mutate / drop / replay frames

Transport contract:
- send(bytes) -> None
- recv() -> bytes  (blocking or raises on EOF)
"""

import queue
from typing import Callable, List, Tuple, Any

DROP = object()

class DirectTransport:
    def __init__(self):
        self._inbox = queue.Queue()

    def attach_peer(self, peer: "DirectTransport"):
        self._peer = peer

    def send(self, frame: bytes):
        # push to peer inbox
        self._peer._inbox.put(frame)

    def recv(self, timeout: float = 5.0) -> bytes:
        return self._inbox.get(timeout=timeout)

class InterceptingTransport:
    def __init__(self):
        self._inbox = queue.Queue()
        self.scripts: List[Tuple[str, Callable[[bytes], Any]]] = []  # (phase, action)

    def attach_peer(self, peer: "InterceptingTransport"):
        self._peer = peer

    def script(self, when: str, action: Callable[[bytes], Any]):
        """
        when: 'send' or 'recv' (applied on the local side), action(frame) -> frame | DROP | list(for replay)
        """
        self.scripts.append((when, action))

    def _apply(self, phase: str, frame: bytes):
        for p, action in self.scripts:
            if p == phase:
                r = action(frame)
                if r is DROP:
                    return DROP
                frame = r
        return frame

    def send(self, frame: bytes):
        r = self._apply('send', frame)
        if r is DROP:
            return
        # support replay lists
        if isinstance(r, list):
            for item in r:
                self._peer._inbox.put(item)
        else:
            self._peer._inbox.put(r)

    def recv(self, timeout: float = 5.0) -> bytes:
        frame = self._inbox.get(timeout=timeout)
        r = self._apply('recv', frame)
        if r is DROP:
            # simulate drop by blocking until next message
            return self.recv(timeout=timeout)
        if isinstance(r, list):
            # deliver first in list now and push remaining back to inbox
            first, *rest = r
            for item in rest:
                self._inbox.put(item)
            return first
        return r