import base64
import socket
import threading
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

# ---------------------------------------------------------------------------
# ANSI color helpers — no external dependencies needed
# ---------------------------------------------------------------------------
_R  = "\033[0m"          # reset
_B  = "\033[1m"          # bold
_DIM = "\033[2m"         # dim
_RED  = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BLUE = "\033[34m"
_WHITE = "\033[97m"


def _fmt_info(text: str)    -> str: return f"{_BLUE}[i]{_R} {_DIM}{text}{_R}"
def _fmt_error(text: str)   -> str: return f"{_RED}[!]{_R} {_RED}{text}{_R}"
def _fmt_chat(sender: str, text: str) -> str:
    return f"{_GREEN}{_B}{sender}{_R}{_GREEN}:{_R} {text}"
def _fmt_key(text: str)     -> str: return f"{_YELLOW}[key]{_R} {_YELLOW}{text}{_R}"
def _fmt_session(text: str) -> str: return f"{_CYAN}[session]{_R} {_CYAN}{text}{_R}"

from client.receiver import Receiver
from client.sender import send_encrypted_chat, send_get_public_key, send_register, send_session_key
from client.key_manager import KeyManager
from client.crypto_utils import (
    decrypt_aes_gcm,
    decrypt_with_rsa_private_key,
    encrypt_aes_gcm,
    encrypt_with_rsa_public_key,
    generate_aes_key,
    load_public_key_from_pem,
)
from shared import message_types

_KEY_FETCH_TIMEOUT = 5.0  # seconds to wait for a public_key_response


class ChatClient:
    """
    Interactive chat client — Phases 1-4.

    Phase 4 adds a full session-key exchange:
      - When sending to a peer for the first time, the client fetches their
        RSA public key, generates a random 256-bit AES key, encrypts it with
        RSA-OAEP, and sends it through the server.
      - The recipient decrypts the AES key using their private key (which
        never leaves their machine) and stores it for the conversation.
      - Subsequent messages reuse the cached session key (Phase 5 will
        encrypt them with AES-GCM).

    Commands:
        <recipient>: <text>  — send a chat message (session key established automatically)
        key <username>       — manually inspect a peer's public key
        quit / exit          — disconnect
    """

    def _prompt(self) -> str:
        """The input prompt string, e.g.  alice ▶  """
        return f"{_GREEN}{_B}{self.username}{_R} {_WHITE}▶{_R}  "

    def _reprint_prompt(self) -> None:
        """Reprint the input prompt after an async message interrupts the line."""
        print(self._prompt(), end="", flush=True)

    def __init__(self, username: str, host: str = "127.0.0.1", port: int = 5000) -> None:
        self.username = username
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

        self.key_manager = KeyManager(username)
        self._private_key: Optional[rsa.RSAPrivateKey] = None

        # peer username → PEM string of their RSA public key
        self.peer_public_keys: Dict[str, str] = {}

        # peer username → shared AES session key (bytes)
        # Set by the initiator after generating the key; set by the recipient
        # after decrypting the incoming session_key message.
        self.session_keys: Dict[str, bytes] = {}

        # Used to block the sender thread until the key response arrives on
        # the receiver thread.  Maps peer username → threading.Event.
        self._pending_key_events: Dict[str, threading.Event] = {}

    def connect(self) -> None:
        """Connect to the server, load/generate RSA keys, and register."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        # Load (or generate) the persistent RSA key pair.
        # The private key is kept in memory only; the public key is sent to
        # the server so that other clients can encrypt session keys for us.
        self._private_key, _ = self.key_manager.load_or_create_keys()
        public_key_pem = self.key_manager.get_public_key_pem_str()
        send_register(self.sock, self.username, public_key_pem=public_key_pem)

        receiver = Receiver(self.sock, self._on_message)
        receiver.start()

    def _on_message(self, msg: Dict[str, Any]) -> None:
        """Dispatch an incoming server message to the appropriate handler."""
        msg_type = msg.get("type")

        if msg_type == message_types.TYPE_INFO:
            print(f"\n{_fmt_info(msg.get('message', ''))}")
            users = msg.get("users")
            if isinstance(users, list):
                print(_fmt_info(f"Online users: {_B}{', '.join(users)}{_R}"))

        elif msg_type == message_types.TYPE_ERROR:
            print(f"\n{_fmt_error(msg.get('error', ''))}")
            self._reprint_prompt()

        elif msg_type == message_types.TYPE_CHAT:
            self._handle_incoming_chat(msg)

        elif msg_type == message_types.TYPE_PUBLIC_KEY_RESPONSE:
            self._handle_public_key_response(msg)

        elif msg_type == message_types.TYPE_SESSION_KEY:
            self._handle_incoming_session_key(msg)

        else:
            print(f"\n{_fmt_info(str(msg))}")
            self._reprint_prompt()

    def _handle_public_key_response(self, msg: Dict[str, Any]) -> None:
        """
        Cache the received RSA public key and unblock any thread waiting for it.

        The threading.Event mechanism lets the sender thread (interactive_loop)
        block with event.wait() until this receiver thread delivers the key.
        """
        target = msg.get("target", "")
        pem = msg.get("public_key", "")
        self.peer_public_keys[target] = pem

        # Unblock the sender thread that is waiting to establish a session key.
        event = self._pending_key_events.pop(target, None)
        if event:
            event.set()
        else:
            # Manual `key` command — display the key.
            print(f"\n{_fmt_key(f'Public key for {repr(target)} received and cached.')}")
            print(f"{_DIM}{pem}{_R}")
            self._reprint_prompt()

    def _handle_incoming_session_key(self, msg: Dict[str, Any]) -> None:
        """
        Decrypt an incoming AES session key using our RSA private key.

        This is the recipient side of Phase 4:
        1. Decode the base64 payload.
        2. Decrypt with RSA-OAEP using our private key (never sent to the server).
        3. Store the AES key — Phase 5 will use it to decrypt messages.
        """
        from_user = msg.get("from", "")
        encrypted_b64 = msg.get("encrypted_session_key", "")

        encrypted_bytes = base64.b64decode(encrypted_b64)
        session_key = decrypt_with_rsa_private_key(self._private_key, encrypted_bytes)
        self.session_keys[from_user] = session_key

        print(
            f"\n{_fmt_session(f'Session key from {repr(from_user)} decrypted with your private key ({len(session_key)*8}-bit AES).')}"
            f"\n{_fmt_session(f'  Plaintext AES key (hex): {_B}{session_key.hex()}{_R}{_CYAN}')}"
        )
        self._reprint_prompt()

    def _handle_incoming_chat(self, msg: Dict[str, Any]) -> None:
        """
        Decrypt and display an incoming AES-GCM encrypted chat message.

        Steps:
        1. Look up the session key shared with the sender.
        2. Base64-decode the nonce, ciphertext, and tag from the message.
        3. Decrypt and verify with AES-GCM — raises if the message was tampered.
        4. Display the plaintext to the user.

        The server only ever saw the three encrypted fields; it never had
        access to the session key or the plaintext.
        """
        from_user = msg.get("from", "")
        session_key = self.session_keys.get(from_user)

        if session_key is None:
            print(f"\n{_fmt_error(f'Message from {repr(from_user)} cannot be decrypted (no session key).')}")
            self._reprint_prompt()
            return

        nonce = base64.b64decode(msg["nonce"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        tag = base64.b64decode(msg["tag"])

        plaintext = decrypt_aes_gcm(session_key, nonce, ciphertext, tag)
        print(f"\n{_fmt_chat(from_user, plaintext.decode('utf-8'))}")
        self._reprint_prompt()

    def _ensure_session_key(self, target: str) -> bool:
        """
        Guarantee a session key exists for `target` before sending a message.

        Steps:
        1. If the peer's RSA public key is not cached, request it and wait.
        2. Generate a fresh AES session key.
        3. Encrypt it with the peer's RSA public key (RSA-OAEP).
        4. Send the encrypted key through the server.
        5. Cache the key locally.

        Returns True on success, False if the public key could not be fetched.
        """
        # Already established (either we sent it or we received theirs).
        if target in self.session_keys:
            return True

        # Fetch the peer's public key if we don't have it yet.
        if target not in self.peer_public_keys:
            event = threading.Event()
            self._pending_key_events[target] = event
            send_get_public_key(self.sock, target)

            # Block until _handle_public_key_response signals us or we time out.
            if not event.wait(timeout=_KEY_FETCH_TIMEOUT):
                self._pending_key_events.pop(target, None)
                print(_fmt_error(f"Timed out waiting for public key of '{target}'."))
                return False

        # Generate a random 256-bit AES session key.
        aes_key = generate_aes_key()

        # Encrypt the AES key with the peer's RSA public key so that only
        # they can decrypt it.  RSA-OAEP with SHA-256 is used (see crypto_utils).
        peer_pub_key = load_public_key_from_pem(self.peer_public_keys[target].encode("utf-8"))
        encrypted_key = encrypt_with_rsa_public_key(peer_pub_key, aes_key)
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")

        send_session_key(self.sock, self.username, target, encrypted_key_b64)
        self.session_keys[target] = aes_key

        print(
            f"{_fmt_session(f'Session key generated and sent to {repr(target)} (RSA-OAEP encrypted).')}"
            f"\n{_fmt_session(f'  Plaintext AES key (hex): {_B}{aes_key.hex()}{_R}{_CYAN}')}"
        )
        return True

    def interactive_loop(self) -> None:
        """
        Read-eval loop for sending messages and issuing commands.

        Supported input formats:
            <recipient>: <text>  — send a chat message
            key <username>       — manually fetch and display a user's public key
            quit | exit          — close the connection
        """
        if self.sock is None:
            raise RuntimeError("Client is not connected.")

        w = 52
        print(f"\n{_CYAN}{'─' * w}{_R}")
        print(f"{_CYAN}  Secure E2EE Chat{_R}")
        print(f"{_CYAN}  Connected as: {_B}{_WHITE}{self.username}{_R}")
        print(f"{_DIM}  {_B}<recipient>: <text>{_R}{_DIM}  — send a message{_R}")
        print(f"{_DIM}  {_B}key <username>{_R}{_DIM}        — fetch a public key{_R}")
        print(f"{_DIM}  {_B}quit{_R}{_DIM}                  — exit{_R}")
        print(f"{_CYAN}{'─' * w}{_R}\n")

        try:
            while True:
                line = input(self._prompt()).strip()
                if not line:
                    continue

                if line.lower() in {"quit", "exit"}:
                    break

                # Command: key <username>
                if line.lower().startswith("key "):
                    target = line[4:].strip()
                    if not target:
                        print(_fmt_error("Usage: key <username>"))
                        continue
                    send_get_public_key(self.sock, target)
                    continue

                # Command: <recipient>: <message>
                if ":" not in line:
                    print(_fmt_error("Format: <recipient>: <message>  or  key <username>"))
                    continue

                target, text = line.split(":", 1)
                target = target.strip()
                text = text.strip()
                if not target or not text:
                    print(_fmt_error("Format: <recipient>: <message>"))
                    continue

                # Phase 4: ensure a session key is established before sending.
                if not self._ensure_session_key(target):
                    continue

                # Phase 5: encrypt the message with AES-GCM before it leaves
                # the client.  The server will only see nonce, ciphertext, tag.
                session_key = self.session_keys[target]
                nonce, ciphertext, tag = encrypt_aes_gcm(session_key, text.encode("utf-8"))

                nonce_b64 = base64.b64encode(nonce).decode("utf-8")
                ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
                tag_b64 = base64.b64encode(tag).decode("utf-8")

                send_encrypted_chat(self.sock, self.username, target, nonce_b64, ciphertext_b64, tag_b64)
        finally:
            if self.sock is not None:
                try:
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

