"""
Shared constants for message types used by both client and server.

All messages are JSON objects with a mandatory "type" field.
"""

TYPE_REGISTER = "register"
TYPE_CHAT = "chat"
TYPE_INFO = "info"  # simple server -> client informational messages
TYPE_ERROR = "error"  # simple server -> client error messages

