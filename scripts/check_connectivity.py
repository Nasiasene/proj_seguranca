import argparse
import socket
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check if a TCP host:port is reachable (useful before running chat clients)."
        )
    )
    parser.add_argument("host", help="Server hostname or IP to test.")
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="TCP port to test (default: 5000).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.port <= 0 or args.port > 65535:
        print(f"[error] Invalid TCP port: {args.port}")
        return 2

    print(
        f"[check] Testing TCP connectivity to {args.host}:{args.port} "
        f"(timeout={args.timeout:.1f}s)..."
    )

    start = time.perf_counter()
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
            elapsed_ms = (time.perf_counter() - start) * 1000
            remote_ip = sock.getpeername()[0]
            print(
                f"[ok] Connected to {args.host}:{args.port} "
                f"(resolved {remote_ip}) in {elapsed_ms:.1f} ms."
            )
            print("[ok] TCP path is open. You can now run the chat client.")
            return 0
    except TimeoutError:
        print(
            "[error] Connection timed out. Likely firewall, port forwarding, "
            "or server not listening."
        )
        return 1
    except ConnectionRefusedError:
        print(
            "[error] Connection refused. Host is reachable, but nothing is "
            "accepting TCP on this port."
        )
        return 1
    except OSError as exc:
        print(f"[error] Could not connect: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
