import socket
from typing import Dict, Any

from chat_e2ee.shared.serialization import send_json
from chat_e2ee.shared import message_types


def send_register(sock: socket.socket, username: str, public_key_pem: str | None = None) -> None:
    """
    Send a registration message to the server.

    In Phase 2 the client includes its RSA public key so that the server
    can store it and later provide it to other clients. The key is sent
    as a PEM-formatted string.
    """
    message: Dict[str, Any] = {
        "type": message_types.TYPE_REGISTER,
        "username": username,
    }
    if public_key_pem is not None:
        message["public_key"] = public_key_pem
    send_json(sock, message)


def send_chat(sock: socket.socket, from_username: str, to_username: str, text: str) -> None:
    """Send a plaintext chat message."""
    message: Dict[str, Any] = {
        "type": message_types.TYPE_CHAT,
        "from": from_username,
        "to": to_username,
        "message": text,
    }
    send_json(sock, message)

