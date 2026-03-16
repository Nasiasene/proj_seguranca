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

#### Optional: quick connectivity test

Before opening the chat client, each friend can test if the server is reachable:

```bash
source venv/bin/activate
python scripts/check_connectivity.py <SERVER_PUBLIC_IP> --port 5000
```

If it prints `[ok]`, network path is open.
If it prints `[error]`, check firewall and router forwarding settings below.

#### Notes

- If everyone is on the same Wi-Fi/LAN, use the host machine's local IP
  address instead of the public IP.
- If port forwarding is not possible, use a cloud VM/VPS or a tunnel service.
- The server must remain running the whole time for the chat to work.

### Allow TCP connections on port 5000

For internet access, you usually need to configure **both** firewall and router.

- **Firewall**: allow inbound TCP on port `5000` on the server machine.
- **Router/NAT**: forward external TCP `5000` to the server machine's local IP.

#### macOS (Application Firewall)

1. Open **System Settings → Network → Firewall**.
2. Go to **Options...** and add the terminal/Python app you use.
3. Set it to **Allow incoming connections**.

If needed, temporarily test with firewall disabled to confirm if it is the blocker,
then re-enable it after creating an allow rule.

#### Linux (UFW)

```bash
sudo ufw allow 5000/tcp
sudo ufw status
```

#### Windows (PowerShell as Administrator)

```powershell
New-NetFirewallRule -DisplayName "chat_e2ee_5000" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
Get-NetFirewallRule -DisplayName "chat_e2ee_5000"
```

#### Router port forwarding

- Forward **External Port** `5000` (TCP) to **Internal IP** of the server machine,
  **Internal Port** `5000`.
- Reserve or set a static local IP for the server machine so forwarding does not break.
- If your ISP uses CGNAT, direct port forwarding may not work; use a VPS or tunnel.