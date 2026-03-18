import socket
import threading
from datetime import datetime
from typing import Optional

from shared.serialization import recv_json, send_json
from shared import message_types
from .registry import UserRegistry

# ---------------------------------------------------------------------------
# Server-side ANSI log helpers
# ---------------------------------------------------------------------------
_R   = "\033[0m"
_B   = "\033[1m"
_DIM = "\033[2m"
_RED     = "\033[31m"
_GREEN   = "\033[32m"
_YELLOW  = "\033[33m"
_BLUE    = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN    = "\033[36m"
_WHITE   = "\033[97m"


def _ts() -> str:
    return f"{_DIM}{datetime.now().strftime('%H:%M:%S')}{_R}"

def _log(label: str, color: str, text: str) -> None:
    print(f"{_ts()} {color}{_B}{label}{_R} {text}")

def _trim(b64: str, n: int = 20) -> str:
    """Show only the first n chars of a base64 payload to keep logs readable."""
    return b64[:n] + "…" if len(b64) > n else b64


class ClientHandler(threading.Thread):
    """
    One instance of this class runs in its own thread per connected client.

    It:
    - Handles the initial registration message.
    - Receives chat messages from this client.
    - Forwards them to the intended recipient via the shared UserRegistry.
    """

    def __init__(self, sock: socket.socket, address: tuple[str, int], registry: UserRegistry) -> None:
        super().__init__(daemon=True)
        self.sock = sock
        self.address = address
        self.registry = registry
        self.username: Optional[str] = None

    def run(self) -> None:
        try:
            self._handle_client()
        finally:
            if self.username:
                self.registry.unregister(self.username)
            try:
                self.sock.close()
            except OSError:
                pass

    def _handle_client(self) -> None:
        """
        Main loop for this client.

        The first message must be a "register" message with a username.
        After successful registration, the client can send "chat" messages.
        """
        first_msg = recv_json(self.sock)
        if first_msg is None or first_msg.get("type") != message_types.TYPE_REGISTER:
            return

        desired_username = first_msg.get("username")
        if not isinstance(desired_username, str) or not desired_username:
            send_json(
                self.sock,
                {
                    "type": message_types.TYPE_ERROR,
                    "error": "Invalid username.",
                },
            )
            return

        public_key_pem = first_msg.get("public_key")

        if not self.registry.register(desired_username, self.sock, public_key_pem=public_key_pem):
            send_json(
                self.sock,
                {
                    "type": message_types.TYPE_ERROR,
                    "error": f"Username '{desired_username}' is already taken.",
                },
            )
            return

        self.username = desired_username

        if public_key_pem is not None:
            _log("[REGISTER]", _GREEN, f"{_B}{self.username}{_R} joined — RSA public key stored automatically.")
            print(f"{_DIM}{public_key_pem}{_R}")
        else:
            _log("[REGISTER]", _YELLOW, f"{_B}{self.username}{_R} joined — no public key provided.")

        send_json(
            self.sock,
            {
                "type": message_types.TYPE_INFO,
                "message": f"Registered as '{self.username}'.",
                "users": self.registry.list_users(),
            },
        )

        while True:
            msg = recv_json(self.sock)
            if msg is None:
                _log("[DISCONNECT]", _RED, f"{_B}{self.username}{_R} disconnected.")
                break

            msg_type = msg.get("type")
            if msg_type == message_types.TYPE_CHAT:
                self._handle_chat(msg)
            elif msg_type == message_types.TYPE_GET_PUBLIC_KEY:
                self._handle_get_public_key(msg)
            elif msg_type == message_types.TYPE_SESSION_KEY:
                self._handle_session_key(msg)
            else:
                send_json(
                    self.sock,
                    {
                        "type": message_types.TYPE_ERROR,
                        "error": f"Unknown message type: {msg_type}",
                    },
                )

    def _handle_session_key(self, msg: dict) -> None:
        """
        Route an encrypted session key from one client to another.

        The message carries an AES key that has been encrypted with the
        recipient's RSA public key.  The server forwards it blindly —
        it cannot decrypt the AES key because it never has the private key.

        Expected message format:
        {
            "type": "session_key",
            "from": "<sender>",
            "to": "<recipient>",
            "encrypted_session_key": "<base64>"
        }
        """
        target_username = msg.get("to")
        if not isinstance(target_username, str) or not target_username:
            send_json(
                self.sock,
                {"type": message_types.TYPE_ERROR, "error": "session_key missing 'to' field."},
            )
            return

        target_sock = self.registry.get_socket(target_username)
        if target_sock is None:
            send_json(
                self.sock,
                {
                    "type": message_types.TYPE_ERROR,
                    "error": f"User '{target_username}' is not online.",
                },
            )
            return

        # Forward the message as-is. The encrypted payload is opaque to the server.
        outgoing = {
            "type": message_types.TYPE_SESSION_KEY,
            "from": self.username,
            "to": target_username,
            "encrypted_session_key": msg.get("encrypted_session_key", ""),
        }
        encrypted_b64 = msg.get("encrypted_session_key", "")
        send_json(target_sock, outgoing)
        _log("[SESSION KEY]", _CYAN,
             f"{_B}{self.username}{_R} → {_B}{target_username}{_R} "
             f"{_DIM}(server cannot decrypt){_R}")
        print(f"{_DIM}{encrypted_b64}{_R}")

    def _handle_get_public_key(self, msg: dict) -> None:
        """
        Respond to a public-key lookup request.

        The client sends:
            { "type": "get_public_key", "target": "<username>" }

        The server replies with the stored PEM public key, or an error if the
        user is unknown.  The server never learns anything new here — it only
        returns a value it was already trusted to store during registration.
        """
        target = msg.get("target")
        if not isinstance(target, str) or not target:
            send_json(
                self.sock,
                {"type": message_types.TYPE_ERROR, "error": "Missing 'target' field."},
            )
            return

        public_key_pem = self.registry.get_public_key(target)
        if public_key_pem is None:
            send_json(
                self.sock,
                {
                    "type": message_types.TYPE_ERROR,
                    "error": f"No public key registered for '{target}'.",
                },
            )
            return

        send_json(
            self.sock,
            {
                "type": message_types.TYPE_PUBLIC_KEY_RESPONSE,
                "target": target,
                "public_key": public_key_pem,
            },
        )
        _log("[KEY EXCHANGE]", _YELLOW,
             f"{_B}{self.username}{_R} requested RSA public key of {_B}{target}{_R} "
             f"— key sent, client can now encrypt the session key.")

    def _handle_chat(self, msg: dict) -> None:
        """
        Forward an AES-GCM encrypted chat message to the intended recipient.

        Phase 5: the message payload consists of three opaque base64 fields —
        nonce, ciphertext, and tag — produced by the sender's AES-GCM operation.
        The server forwards them verbatim without being able to read or modify
        the plaintext (it never holds the session key).
        """
        if self.username is None:
            return

        target_username = msg.get("to")
        if not isinstance(target_username, str) or not target_username:
            send_json(
                self.sock,
                {
                    "type": message_types.TYPE_ERROR,
                    "error": "Chat message missing 'to' field.",
                },
            )
            return

        target_sock = self.registry.get_socket(target_username)
        if target_sock is None:
            send_json(
                self.sock,
                {
                    "type": message_types.TYPE_ERROR,
                    "error": f"User '{target_username}' is not online.",
                },
            )
            return

        # Forward the encrypted fields as-is.
        # Enforcing "from" = self.username prevents sender spoofing.
        outgoing = {
            "type": message_types.TYPE_CHAT,
            "from": self.username,
            "to": target_username,
            "nonce": msg.get("nonce", ""),
            "ciphertext": msg.get("ciphertext", ""),
            "tag": msg.get("tag", ""),
        }
        send_json(target_sock, outgoing)
        _log("[MSG]", _MAGENTA,
             f"{_B}{self.username}{_R} → {_B}{target_username}{_R} "
             f"{_DIM}(server cannot decrypt){_R}")
        print(
            f"{_DIM}  nonce:      {msg.get('nonce', '')}\n"
            f"  ciphertext: {msg.get('ciphertext', '')}\n"
            f"  tag:        {msg.get('tag', '')}{_R}"
        )

