from __future__ import annotations

import threading
from typing import Dict, Optional

import socket


class UserRegistry:
    """
    Thread-safe registry that maps usernames to client sockets.

    The server uses this to know which connected client should receive
    a given chat message.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sockets: Dict[str, socket.socket] = {}
        self._public_keys: Dict[str, str] = {}

    def register(self, username: str, sock: socket.socket, public_key_pem: Optional[str] = None) -> bool:
        """
        Register a username with a given socket and optional public key.

        Returns True if registration succeeded, False if the username
        is already taken.
        """
        with self._lock:
            if username in self._sockets:
                return False
            self._sockets[username] = sock
            if public_key_pem is not None:
                self._public_keys[username] = public_key_pem
            return True

    def unregister(self, username: str) -> None:
        """Remove a username from the registry."""
        with self._lock:
            self._sockets.pop(username, None)
            self._public_keys.pop(username, None)

    def get_socket(self, username: str) -> socket.socket | None:
        """Return the socket associated with a username, or None."""
        with self._lock:
            return self._sockets.get(username)

    def list_users(self) -> list[str]:
        """Return a list of currently registered usernames."""
        with self._lock:
            return list(self._sockets.keys())

    def set_public_key(self, username: str, public_key_pem: str) -> None:
        """Associate or update the public key for a user."""
        with self._lock:
            self._public_keys[username] = public_key_pem

    def get_public_key(self, username: str) -> Optional[str]:
        """Retrieve the stored public key for a user, if any."""
        with self._lock:
            return self._public_keys.get(username)

