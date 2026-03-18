import socket
import threading
from datetime import datetime

from .client_handler import ClientHandler, _log, _ts, _GREEN, _RED, _CYAN, _B, _R, _DIM
from .registry import UserRegistry


class ChatServer:
    """
    Simple multi-client chat server.

    For Phase 1 this server forwards plaintext chat messages between
    clients. In later phases the same networking foundation will carry
    end-to-end encrypted payloads.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5000) -> None:
        self.host = host
        self.port = port
        self.registry = UserRegistry()
        self._server_socket: socket.socket | None = None

    def start(self) -> None:
        """Start the server and begin accepting client connections."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow quick restart on the same port.
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen()

        w = 52
        print(f"\n{_CYAN}{'─' * w}{_R}")
        print(f"{_CYAN}  Secure E2EE Chat — Server{_R}")
        print(f"{_CYAN}  Listening on {_B}{self.host}:{self.port}{_R}")
        print(f"{_DIM}  Routes encrypted messages — cannot read content{_R}")
        print(f"{_CYAN}{'─' * w}{_R}\n")

        try:
            while True:
                client_sock, address = self._server_socket.accept()
                _log("[CONNECT]", _GREEN, f"New TCP connection from {_B}{address[0]}:{address[1]}{_R}")
                handler = ClientHandler(client_sock, address, self.registry)
                handler.start()
        except KeyboardInterrupt:
            print(f"\n{_RED}{'─' * w}{_R}")
            print(f"{_RED}  Server shutting down.{_R}")
            print(f"{_RED}{'─' * w}{_R}")
        finally:
            if self._server_socket:
                self._server_socket.close()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Simple multi-client chat server.")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Address to bind the server to (default: 0.0.0.0).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP port to listen on (default: 5000).",
    )
    args = parser.parse_args()

    server = ChatServer(host=args.host, port=args.port)
    server.start()


if __name__ == "__main__":
    main()

