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

        if public_key_pem is not None:
            print(f"[server] '{self.username}' registered with a public key {public_key_pem}.")
        else:
            print(f"[server] '{self.username}' registered without a public key.")

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
        print(
            f"[server] [SESSION KEY] Encrypted session key routed from '{self.username}' "
            f"to '{target_username}' — server cannot decrypt it.\n"
            f"[server]   Encrypted payload (base64): {encrypted_b64}"
        )

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
        print(
            f"[server] [STEP 1/2 - KEY EXCHANGE] '{self.username}' requested public key of '{target}'. "
            "Key sent — client can now encrypt the session key."
        )

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
        print(
            f"[server] [STEP 2/2 - MESSAGE ROUTING] '{self.username}' → '{target_username}' "
            f"| nonce={msg.get('nonce','')} ciphertext={msg.get('ciphertext','')} tag={msg.get('tag','')}"
            "(server cannot decrypt)"
        )

