import socket
import threading
from typing import Optional

from shared.serialization import recv_json, send_json
from shared import message_types
from .registry import UserRegistry


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
                # Client disconnected.
                break

            msg_type = msg.get("type")
            if msg_type == message_types.TYPE_CHAT:
                self._handle_chat(msg)
            else:
                send_json(
                    self.sock,
                    {
                        "type": message_types.TYPE_ERROR,
                        "error": f"Unknown message type: {msg_type}",
                    },
                )

    def _handle_chat(self, msg: dict) -> None:
        """
        Forward a chat message from this client to another registered user.

        Expected message format:
        {
            "type": "chat",
            "from": "<sender_username>",
            "to": "<recipient_username>",
            "message": "<plaintext_message>"
        }
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

        # Normalize the outgoing message: enforce the correct "from" field.
        outgoing = {
            "type": message_types.TYPE_CHAT,
            "from": self.username,
            "to": target_username,
            "message": msg.get("message", ""),
        }
        send_json(target_sock, outgoing)

