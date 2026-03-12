import json
import socket
from typing import Any, Dict


def send_json(sock: socket.socket, message: Dict[str, Any]) -> None:
    """
    Serialize a Python dict as JSON and send it over a TCP socket.

    This implementation uses a simple length-prefixed protocol:
    - First 4 bytes: big-endian unsigned int with the payload length.
    - Followed by that many bytes of UTF-8 JSON data.
    """
    data = json.dumps(message).encode("utf-8")
    length = len(data).to_bytes(4, byteorder="big")
    sock.sendall(length + data)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly n bytes from the socket.

    Returns an empty bytes object if the connection is closed before n bytes
    are received.
    """
    chunks = []
    bytes_remaining = n

    while bytes_remaining > 0:
        chunk = sock.recv(bytes_remaining)
        if not chunk:
            # Connection closed by the peer.
            return b""
        chunks.append(chunk)
        bytes_remaining -= len(chunk)

    return b"".join(chunks)


def recv_json(sock: socket.socket) -> Dict[str, Any] | None:
    """
    Receive one JSON message from the socket.

    Returns:
        - A Python dict when a full message is successfully received.
        - None if the connection is closed cleanly.
    """
    # Read the 4-byte length prefix.
    length_data = _recv_exactly(sock, 4)
    if not length_data:
        return None

    length = int.from_bytes(length_data, byteorder="big")
    if length <= 0:
        return None

    payload = _recv_exactly(sock, length)
    if not payload:
        return None

    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        # In a teaching project we keep this simple and just treat invalid JSON
        # as a closed connection.
        return None

