import socket
from typing import Any, Dict

from chat_e2ee.client.receiver import Receiver
from chat_e2ee.client.sender import send_chat, send_register
from chat_e2ee.client.key_manager import KeyManager
from chat_e2ee.shared import message_types


class ChatClient:
    """
    Minimal interactive chat client for Phase 1.

    Usage:
        1. Start the server: python -m chat_e2ee.server.server
        2. Start two clients in separate terminals:
           python -m chat_e2ee.client.client alice
           python -m chat_e2ee.client.client bob
        3. In each client, type: <recipient_username>: <message text>
    """

    def __init__(self, username: str, host: str = "127.0.0.1", port: int = 5000) -> None:
        self.username = username
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.key_manager = KeyManager(username)

    def connect(self) -> None:
        """Connect to the server, prepare keys, and send registration."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        # Ensure we have a persistent RSA key pair and send the public part
        # to the server as part of registration.
        self.key_manager.load_or_create_keys()
        public_key_pem = self.key_manager.get_public_key_pem_str()
        send_register(self.sock, self.username, public_key_pem=public_key_pem)

        receiver = Receiver(self.sock, self._on_message)
        receiver.start()

    def _on_message(self, msg: Dict[str, Any]) -> None:
        """Handle messages coming from the server."""
        msg_type = msg.get("type")

        if msg_type == message_types.TYPE_INFO:
            print(f"[info] {msg.get('message')}")
            users = msg.get("users")
            if isinstance(users, list):
                print(f"[info] Online users: {', '.join(users)}")
        elif msg_type == message_types.TYPE_ERROR:
            print(f"[error] {msg.get('error')}")
        elif msg_type == message_types.TYPE_CHAT:
            sender = msg.get("from")
            text = msg.get("message")
            print(f"[chat] {sender}: {text}")
        else:
            print(f"[server] {msg}")

    def interactive_loop(self) -> None:
        """
        Simple input loop.

        User types lines in the form:
            bob: hello there
        which sends the message "hello there" to user "bob".
        """
        if self.sock is None:
            raise RuntimeError("Client is not connected.")

        print(
            f"Connected as '{self.username}'. "
            "Type messages as '<recipient>: <text>' or 'quit' to exit."
        )

        try:
            while True:
                line = input("> ").strip()
                if not line:
                    continue
                if line.lower() in {"quit", "exit"}:
                    break

                if ":" not in line:
                    print("Format: <recipient>: <message>")
                    continue

                target, text = line.split(":", 1)
                target = target.strip()
                text = text.strip()
                if not target or not text:
                    print("Format: <recipient>: <message>")
                    continue

                send_chat(self.sock, self.username, target, text)
        finally:
            try:
                if self.sock is not None:
                    self.sock.close()
            except OSError:
                pass


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Simple Phase 1 chat client (plaintext).")
    parser.add_argument("username", help="Your chat username (must be unique).")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=5000, help="Server port (default: 5000).")
    args = parser.parse_args()

    client = ChatClient(args.username, host=args.host, port=args.port)
    client.connect()
    client.interactive_loop()


if __name__ == "__main__":
    main()

