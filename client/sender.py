import socket
from typing import Dict, Any

from shared.serialization import send_json
from shared import message_types


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


def send_session_key(
    sock: socket.socket,
    from_username: str,
    to_username: str,
    encrypted_session_key_b64: str,
) -> None:
    """
    Send an encrypted AES session key to another user via the server.

    The session key has already been encrypted with the recipient's RSA public
    key (RSA-OAEP) and encoded as base64.  The server routes this message
    without being able to read or decrypt the key.
    """
    send_json(sock, {
        "type": message_types.TYPE_SESSION_KEY,
        "from": from_username,
        "to": to_username,
        "encrypted_session_key": encrypted_session_key_b64,
    })


def send_get_public_key(sock: socket.socket, target_username: str) -> None:
    """
    Ask the server for another user's RSA public key.

    The server will reply with a "public_key_response" message containing the
    PEM-encoded public key that was submitted by that user during registration.
    """
    send_json(sock, {
        "type": message_types.TYPE_GET_PUBLIC_KEY,
        "target": target_username,
    })


def send_encrypted_chat(
    sock: socket.socket,
    from_username: str,
    to_username: str,
    nonce_b64: str,
    ciphertext_b64: str,
    tag_b64: str,
) -> None:
    """
    Send an AES-GCM encrypted chat message.

    All three components (nonce, ciphertext, tag) are base64-encoded so they
    can be safely transported in JSON.  The server forwards them blindly and
    cannot decrypt the ciphertext without the session key.
    """
    send_json(sock, {
        "type": message_types.TYPE_CHAT,
        "from": from_username,
        "to": to_username,
        "nonce": nonce_b64,
        "ciphertext": ciphertext_b64,
        "tag": tag_b64,
    })

