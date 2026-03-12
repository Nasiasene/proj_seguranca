import threading
from typing import Callable

import socket

from shared.serialization import recv_json


class Receiver(threading.Thread):
    """
    Background thread that continuously receives messages from the server
    and passes them to a callback for display or further processing.
    """

    def __init__(self, sock: socket.socket, on_message: Callable[[dict], None]) -> None:
        super().__init__(daemon=True)
        self.sock = sock
        self.on_message = on_message

    def run(self) -> None:
        while True:
            msg = recv_json(self.sock)
            if msg is None:
                # Connection closed by server.
                break
            self.on_message(msg)

