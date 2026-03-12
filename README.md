## Secure E2EE Chat (Teaching Project)

This project is a step-by-step teaching implementation of a secure
end-to-end encrypted (E2EE) chat system in Python.

The code is intentionally written for clarity and modularity, with
each phase adding new security features on top of a simple networking
foundation.

### Phase 1 – Networking foundation (plaintext)

In this initial phase, we build:

- **TCP server**: accepts clients and runs one thread per connection.
- **User registry**: keeps track of which usernames are connected.
- **Message routing**: forwards JSON chat messages between clients.
- **Client**: simple command-line app that registers a username and
  sends plaintext messages via the server.

This phase does **not** provide security yet. All messages are
plaintext and visible to the server. Later phases will add RSA key
management and AES-GCM encryption while keeping the same protocol
structure.

