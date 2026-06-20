from __future__ import annotations

import argparse
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


CONTROL_PORT = 255
DISCOVERY_TIMEOUT = 0.15
DISCOVERY_WORKERS = 64
STATE_PATH = Path.home() / ".upnpv6_client_state.json"


def load_state() -> dict:
    if not STATE_PATH.exists():
        return {"gateways": {}}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"gateways": {}}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def detect_local_ipv4() -> str:
    probes = [("8.8.8.8", 80), ("1.1.1.1", 80), ("192.0.2.1", 80)]
    for host, port in probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((host, port))
                return sock.getsockname()[0]
        except OSError:
            continue
    raise RuntimeError("could not detect local IPv4")


def detect_local_ipv6() -> str:
    probes = [("2001:4860:4860::8888", 80), ("2606:4700:4700::1111", 80), ("2001:db8::1", 80)]
    for host, port in probes:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.connect((host, port))
                return sock.getsockname()[0]
        except OSError:
            continue
    raise RuntimeError("could not detect local IPv6")


def host_has_control_port(ip: str) -> str | None:
    try:
        with socket.create_connection((ip, CONTROL_PORT), timeout=DISCOVERY_TIMEOUT):
            return ip
    except OSError:
        return None


def detect_gateway_ip() -> str:
    candidates = [f"192.168.{third}.{host}" for third in range(256) for host in (1, 254)]
    with ThreadPoolExecutor(max_workers=DISCOVERY_WORKERS) as executor:
        futures = [executor.submit(host_has_control_port, candidate) for candidate in candidates]
        for future in as_completed(futures):
            result = future.result()
            if result:
                return result
    raise RuntimeError("could not detect UPnPv6 gateway in 192.168.0.1-192.168.255.254")


def send_json_line(sock: socket.socket, payload: dict) -> None:
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def recv_json_line(sock: socket.socket) -> dict:
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    if not data:
        raise RuntimeError("server closed connection without response")
    return json.loads(data.split(b"\n", 1)[0].decode("utf-8"))


class EchoResponder:
    def __init__(self, bind_ip: str, port: int, proto: str) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.proto = proto
        self.ready = threading.Event()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=1.0):
            raise RuntimeError("echo responder did not start in time")

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=1.0)

    def _run(self) -> None:
        if self.proto == "TCP":
            self._run_tcp()
        else:
            self._run_udp()

    def _run_tcp(self) -> None:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_ip, self.port))
            server.listen(1)
            server.settimeout(0.2)
            self.ready.set()
            while not self.stop_event.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                with conn:
                    token = conn.recv(4096)
                    conn.sendall(token)
                return

    def _run_udp(self) -> None:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_ip, self.port))
            server.settimeout(0.2)
            self.ready.set()
            while not self.stop_event.is_set():
                try:
                    token, addr = server.recvfrom(4096)
                except socket.timeout:
                    continue
                server.sendto(token, addr)
                return


def reserve_challenge_port(local_ip: str, proto: str) -> int:
    sock_type = socket.SOCK_STREAM if proto == "TCP" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET6, sock_type) as sock:
        sock.bind((local_ip, 0))
        return int(sock.getsockname()[1])


def remember_allocation(gateway: str, token: str, port: int, proto: str, local_ipv6: str) -> None:
    state = load_state()
    gateway_state = state["gateways"].setdefault(gateway, {"token": token, "allocations": []})
    gateway_state["token"] = token
    gateway_state["local_ipv6"] = local_ipv6
    allocations = [entry for entry in gateway_state["allocations"] if not (entry["port"] == port and entry["proto"] == proto)]
    allocations.append({"port": port, "proto": proto})
    gateway_state["allocations"] = allocations
    save_state(state)


def forget_allocation(gateway: str, port: int) -> None:
    state = load_state()
    gateway_state = state["gateways"].get(gateway)
    if not gateway_state:
        return
    gateway_state["allocations"] = [entry for entry in gateway_state.get("allocations", []) if entry["port"] != port]
    save_state(state)


def find_saved_allocation(gateway: str, port: int) -> tuple[str, str]:
    state = load_state()
    gateway_state = state["gateways"].get(gateway)
    if not gateway_state:
        raise RuntimeError("no saved allocations for this gateway")
    for entry in gateway_state.get("allocations", []):
        if entry["port"] == port:
            return gateway_state["token"], entry["proto"]
    raise RuntimeError("requested port is not stored for this gateway")


def allocate_port(port: int, proto: str, gateway: str | None) -> None:
    gateway_ip = gateway or detect_gateway_ip()
    local_ipv6 = detect_local_ipv6()
    local_ipv4 = detect_local_ipv4()
    challenge_port = reserve_challenge_port(local_ipv6, proto)
    payload = {
        "action": "ALLOCATE",
        "req_port": port,
        "req_proto": proto,
        "local_ip": local_ipv6,
        "challenge_port": challenge_port,
        "gateway_ip": gateway_ip,
        "client_ipv4": local_ipv4,
    }

    responder = EchoResponder(local_ipv6, challenge_port, proto)
    responder.start()
    token = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((gateway_ip, CONTROL_PORT))
            send_json_line(sock, payload)
            print(json.dumps({"detected_gateway": gateway_ip, "detected_local_ipv4": local_ipv4, "detected_local_ipv6": local_ipv6}))
            while True:
                response = recv_json_line(sock)
                print(json.dumps(response))
                if response.get("status") == "CHALLENGE":
                    token = response["token"]
                    continue
                if response.get("status") == "SUCCESSFUL_ALLOCATE" and token:
                    remember_allocation(gateway_ip, token, port, proto, local_ipv6)
                break
    finally:
        responder.stop()


def unallocate_port(port: int, gateway: str | None) -> None:
    gateway_ip = gateway or detect_gateway_ip()
    token, proto = find_saved_allocation(gateway_ip, port)
    payload = {
        "action": "UNALLOCATE",
        "req_port": port,
        "req_proto": proto,
        "gateway_ip": gateway_ip,
        "token": token,
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((gateway_ip, CONTROL_PORT))
        send_json_line(sock, payload)
        response = recv_json_line(sock)
        print(json.dumps(response))
        if response.get("status") == "SUCCESSFUL_UNALLOCATE":
            forget_allocation(gateway_ip, port)


def main() -> None:
    parser = argparse.ArgumentParser(description="UPnPv6 client")
    parser.add_argument("--port", type=int, help="Requested service port")
    parser.add_argument("--proto", choices=["TCP", "UDP"], help="Requested protocol")
    parser.add_argument("--gateway", help="Optional IPv4 gateway/router address")
    parser.add_argument("--unalocate-port", type=int, help="De-allocate a previously allocated port")
    args = parser.parse_args()

    if args.unalocate_port is not None:
        unallocate_port(args.unalocate_port, args.gateway)
        return

    if args.port is None or args.proto is None:
        raise SystemExit("--port and --proto are required for allocation")
    allocate_port(args.port, args.proto, args.gateway)


if __name__ == "__main__":
    main()
