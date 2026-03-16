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

source venv/bin/activate

python -m server.server
python -m client.client alice
python -m client.client bob

### Running with friends on different networks

This app works across different networks when **one friend runs the server**
and the other clients connect to that machine.

#### Server host

On the friend acting as the server:

- Run the server on a reachable machine.
- Keep TCP port `5000` open in the firewall.
- If the machine is behind a home router, forward port `5000` to it.
- Share the server's public IP address with the other clients.

Example:

```bash
source venv/bin/activate
python -m server.server --host 0.0.0.0 --port 5000
```

#### Clients

On the two other friends' machines, connect to the server's public IP:

```bash
source venv/bin/activate
python -m client.client alice --host <SERVER_PUBLIC_IP> --port 5000
python -m client.client bob --host <SERVER_PUBLIC_IP> --port 5000
```

Replace `<SERVER_PUBLIC_IP>` with the IP address of the friend hosting the
server.

#### Notes

- If everyone is on the same Wi-Fi/LAN, use the host machine's local IP
  address instead of the public IP.
- If port forwarding is not possible, use a cloud VM/VPS or a tunnel service.
- The server must remain running the whole time for the chat to work.