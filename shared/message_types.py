"""
Shared constants for message types used by both client and server.

All messages are JSON objects with a mandatory "type" field.
"""

TYPE_REGISTER = "register"
TYPE_CHAT = "chat"
TYPE_INFO = "info"          # server → client informational messages
TYPE_ERROR = "error"        # server → client error messages

# Phase 3 – public key retrieval
TYPE_GET_PUBLIC_KEY = "get_public_key"            # client → server
TYPE_PUBLIC_KEY_RESPONSE = "public_key_response"  # server → client

# Phase 4 – session key exchange
TYPE_SESSION_KEY = "session_key"  # client → server → client (routed, never read)

