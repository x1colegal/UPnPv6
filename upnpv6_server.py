from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

from firewall_backends import FirewallError, select_backend


CONTROL_PORT = 255
BUFFER_SIZE = 4096
CHALLENGE_TIMEOUT = 5.0
PROTOCOLS = {"TCP", "UDP"}
SYSTEMD_UNIT_NAME = "upnpv6.service"
STATE_PATH = Path.home() / ".upnpv6_server_state.json"


@dataclass(frozen=True)
class Allocation:
    client_ipv4: str
    port: int
    proto: str
    local_ip: str
    gateway_ip: str
    token: str


class AllocationRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, int], Allocation] = {}
        self._tokens: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not STATE_PATH.exists():
            return
        try:
            payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self._tokens = payload.get("tokens", {})
        for entry in payload.get("allocations", []):
            allocation = Allocation(**entry)
            self._entries[(allocation.proto, allocation.port)] = allocation

    def _save(self) -> None:
        payload = {
            "tokens": self._tokens,
            "allocations": [asdict(allocation) for allocation in self._entries.values()],
        }
        STATE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def token_key(self, gateway_ip: str, local_ip: str) -> str:
        return f"{gateway_ip}|{local_ip}"

    def get_or_create_token(self, gateway_ip: str, local_ip: str) -> str:
        key = self.token_key(gateway_ip, local_ip)
        with self._lock:
            token = self._tokens.get(key)
            if token is None:
                token = generate_token()
                self._tokens[key] = token
                self._save()
            return token

    def is_in_use(self, proto: str, port: int) -> bool:
        with self._lock:
            return (proto, port) in self._entries

    def add(self, allocation: Allocation) -> None:
        with self._lock:
            self._entries[(allocation.proto, allocation.port)] = allocation
            self._save()

    def get(self, proto: str, port: int) -> Allocation | None:
        with self._lock:
            return self._entries.get((proto, port))

    def remove(self, proto: str, port: int) -> None:
        with self._lock:
            self._entries.pop((proto, port), None)
            self._save()


def recv_json_line(conn: socket.socket) -> dict:
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk
        if len(data) > 64 * 1024:
            raise ValueError("request too large")
    if not data:
        raise ValueError("empty request")
    return json.loads(data.split(b"\n", 1)[0].decode("utf-8"))


def send_json_line(conn: socket.socket, payload: dict) -> None:
    conn.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def validate_allocate_request(payload: dict) -> tuple[int, str, str, int, str, str]:
    port = int(payload["req_port"])
    proto = str(payload["req_proto"]).upper()
    local_ip = str(payload["local_ip"])
    challenge_port = int(payload["challenge_port"])
    gateway_ip = str(payload["gateway_ip"])
    client_ipv4 = str(payload["client_ipv4"])

    if proto not in PROTOCOLS:
        raise ValueError("invalid protocol")
    if not (1 <= port <= 65535):
        raise ValueError("invalid port")
    if not (1 <= challenge_port <= 65535):
        raise ValueError("invalid challenge port")
    ipaddress.IPv6Address(local_ip)
    ipaddress.IPv4Address(gateway_ip)
    ipaddress.IPv4Address(client_ipv4)
    if proto == "TCP" and port == CONTROL_PORT:
        raise PermissionError("UPNPV6_PORT_CANT_BE_ALLOCATED")
    return port, proto, local_ip, challenge_port, gateway_ip, client_ipv4


def validate_unallocate_request(payload: dict) -> tuple[int, str, str, str]:
    port = int(payload["req_port"])
    proto = str(payload["req_proto"]).upper()
    gateway_ip = str(payload["gateway_ip"])
    token = str(payload["token"])
    if proto not in PROTOCOLS:
        raise ValueError("invalid protocol")
    if not (1 <= port <= 65535):
        raise ValueError("invalid port")
    ipaddress.IPv4Address(gateway_ip)
    if not token:
        raise ValueError("missing token")
    return port, proto, gateway_ip, token


def generate_token() -> str:
    return base64.b64encode(secrets.token_bytes(24)).decode("ascii")


def verify_token_echo(local_ip: str, port: int, proto: str, token: str) -> bool:
    if proto == "UDP":
        return verify_udp_token_echo(local_ip, port, token)
    return verify_tcp_token_echo(local_ip, port, token)


def verify_tcp_token_echo(local_ip: str, port: int, token: str) -> bool:
    try:
        with socket.create_connection((local_ip, port), timeout=CHALLENGE_TIMEOUT) as sock:
            sock.sendall(token.encode("utf-8"))
            echoed = sock.recv(BUFFER_SIZE).decode("utf-8").strip()
            return echoed == token
    except OSError:
        return False


def verify_udp_token_echo(local_ip: str, port: int, token: str) -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.settimeout(CHALLENGE_TIMEOUT)
            sock.sendto(token.encode("utf-8"), (local_ip, port))
            echoed, _ = sock.recvfrom(BUFFER_SIZE)
            return echoed.decode("utf-8").strip() == token
    except OSError:
        return False


def handle_allocate(conn: socket.socket, addr, registry: AllocationRegistry, backend_name: str, payload: dict) -> None:
    client_ip = addr[0]
    port, proto, local_ip, challenge_port, gateway_ip, client_ipv4 = validate_allocate_request(payload)

    if registry.is_in_use(proto, port):
        send_json_line(conn, {"status": "ERROR_ALREADY_IN_USE"})
        return

    token = registry.get_or_create_token(gateway_ip, local_ip)
    send_json_line(conn, {"status": "CHALLENGE", "token": token})

    if not verify_token_echo(local_ip, challenge_port, proto, token):
        send_json_line(conn, {"status": "ERROR_TOKEN_ECHO_FAILED"})
        return

    backend = select_backend(backend_name)
    backend.allow_port(port, proto, local_ip)
    registry.add(Allocation(client_ipv4=client_ipv4 or client_ip, port=port, proto=proto, local_ip=local_ip, gateway_ip=gateway_ip, token=token))
    send_json_line(conn, {"status": "SUCCESSFUL_ALLOCATE", "public_ip": client_ip, "req_port": port, "req_proto": proto})


def handle_unallocate(conn: socket.socket, registry: AllocationRegistry, payload: dict) -> None:
    port, proto, gateway_ip, token = validate_unallocate_request(payload)
    allocation = registry.get(proto, port)
    if allocation is None:
        send_json_line(conn, {"status": "ERROR_NOT_ALLOCATED"})
        return
    if allocation.gateway_ip != gateway_ip or allocation.token != token:
        send_json_line(conn, {"status": "ERROR_INVALID_TOKEN"})
        return
    backend = select_backend(payload.get("backend", "iptables")) if payload.get("backend") else None
    removed_from_backend = True
    if backend is not None:
        removed_from_backend = backend.remove_port(port, proto, allocation.local_ip)
    if not removed_from_backend:
        send_json_line(conn, {"status": "ERROR_RULE_NOT_FOUND", "req_port": port, "req_proto": proto})
        return
    registry.remove(proto, port)
    send_json_line(conn, {"status": "SUCCESSFUL_UNALLOCATE", "req_port": port, "req_proto": proto})


def handle_client(conn: socket.socket, addr, registry: AllocationRegistry, backend_name: str) -> None:
    try:
        payload = recv_json_line(conn)
        action = str(payload.get("action", "")).upper()
        if action == "ALLOCATE":
            handle_allocate(conn, addr, registry, backend_name, payload)
        elif action == "UNALLOCATE":
            payload["backend"] = backend_name
            handle_unallocate(conn, registry, payload)
        else:
            raise ValueError("unsupported action")
    except PermissionError:
        send_json_line(conn, {"status": "ERROR=UPNPV6_PORT_CANT_BE_ALLOCATED"})
    except (ValueError, KeyError, json.JSONDecodeError):
        send_json_line(conn, {"status": "ERROR_INVALID_REQUEST"})
    except FirewallError:
        send_json_line(conn, {"status": "ERROR_BACKEND_FAILED"})
    finally:
        conn.close()


def ask_backend() -> str:
    while True:
        choice = input("Select firewall backend (iptables/nftables): ").strip().lower()
        if choice in {"iptables", "nftables"}:
            return choice
        print("Invalid backend. Please choose iptables or nftables.")


def ask_systemd_install() -> bool:
    while True:
        choice = input("Install and start as a systemd service? (y/n): ").strip().lower()
        if choice in {"y", "yes"}:
            return True
        if choice in {"n", "no"}:
            return False
        print("Invalid choice. Please answer y or n.")


def install_systemd_service(script_path: Path, listen: str, port: int, backend_name: str) -> None:
    unit_contents = f"""[Unit]
Description=UPnPv6 TCP allocation server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={script_path.parent}
ExecStart=/usr/bin/python3 {script_path} --listen {listen} --port {port} --backend {backend_name} --skip-systemd-prompt
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
"""
    unit_path = Path("/etc/systemd/system") / SYSTEMD_UNIT_NAME
    unit_path.write_text(unit_contents, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", SYSTEMD_UNIT_NAME], check=True)
    subprocess.run(["systemctl", "restart", SYSTEMD_UNIT_NAME], check=True)


def serve(listen: str, port: int, backend_name: str) -> None:
    registry = AllocationRegistry()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen, port))
        server.listen()
        print(f"UPnPv6 server listening on {listen}:{port} using {backend_name}")
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr, registry, backend_name), daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="UPnPv6 allocation server")
    parser.add_argument("--listen", default="0.0.0.0", help="IPv4 address to bind to")
    parser.add_argument("--port", type=int, default=CONTROL_PORT, help="TCP control port")
    parser.add_argument("--backend", choices=["iptables", "nftables"], help="Firewall backend")
    parser.add_argument("--skip-systemd-prompt", action="store_true", help="Skip the systemd installation prompt")
    args = parser.parse_args()

    backend_name = args.backend or ask_backend()
    if not args.skip_systemd_prompt and ask_systemd_install():
        if os.geteuid() != 0:
            raise SystemExit("Systemd installation requires root privileges.")
        install_systemd_service(Path(__file__).resolve(), args.listen, args.port, backend_name)
        print(f"Installed and started {SYSTEMD_UNIT_NAME}. Exiting.")
        return
    serve(args.listen, args.port, backend_name)


if __name__ == "__main__":
    main()
