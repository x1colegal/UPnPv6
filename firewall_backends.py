from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess


class FirewallError(RuntimeError):
    pass


class FirewallBackend:
    name = "base"

    def allow_port(self, port: int, proto: str, local_ip: str) -> None:
        raise NotImplementedError

    def remove_port(self, port: int, proto: str, local_ip: str) -> bool:
        raise NotImplementedError

    @staticmethod
    def find_binary(name: str) -> str | None:
        candidates = [
            shutil.which(name),
            f"/usr/sbin/{name}",
            f"/sbin/{name}",
            f"/usr/bin/{name}",
            f"/bin/{name}",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None


class Ip6TablesBackend(FirewallBackend):
    name = "iptables"

    def allow_port(self, port: int, proto: str, local_ip: str) -> None:
        target_ip = ipaddress.ip_address(local_ip)
        if target_ip.version != 6:
            raise FirewallError("UPnPv6 only supports IPv6 targets")

        binary = self.find_binary("ip6tables")
        if not binary:
            raise FirewallError("ip6tables binary not found")

        dnat_check = [
            binary,
            "-t",
            "nat",
            "-C",
            "PREROUTING",
            "-p",
            proto.lower(),
            "--dport",
            str(port),
            "-j",
            "DNAT",
            "--to-destination",
            local_ip,
        ]
        dnat_result = subprocess.run(dnat_check, capture_output=True, text=True)
        if dnat_result.returncode != 0:
            dnat_add = [
                binary,
                "-t",
                "nat",
                "-I",
                "PREROUTING",
                "-p",
                proto.lower(),
                "--dport",
                str(port),
                "-j",
                "DNAT",
                "--to-destination",
                local_ip,
            ]
            add_result = subprocess.run(dnat_add, capture_output=True, text=True)
            if add_result.returncode != 0:
                raise FirewallError(add_result.stderr.strip() or "failed to add ip6tables DNAT rule")

        forward_check = [
            binary,
            "-C",
            "FORWARD",
            "-p",
            proto.lower(),
            "-d",
            local_ip,
            "--dport",
            str(port),
            "-j",
            "ACCEPT",
        ]
        check = subprocess.run(forward_check, capture_output=True, text=True)
        if check.returncode == 0:
            return

        add_cmd = [
            binary,
            "-I",
            "FORWARD",
            "-p",
            proto.lower(),
            "-d",
            local_ip,
            "--dport",
            str(port),
            "-j",
            "ACCEPT",
        ]
        result = subprocess.run(add_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise FirewallError(result.stderr.strip() or "failed to add ip6tables rule")

    def remove_port(self, port: int, proto: str, local_ip: str) -> bool:
        target_ip = ipaddress.ip_address(local_ip)
        if target_ip.version != 6:
            raise FirewallError("UPnPv6 only supports IPv6 targets")

        binary = self.find_binary("ip6tables")
        if not binary:
            raise FirewallError("ip6tables binary not found")

        dnat_check = subprocess.run(
            [
                binary,
                "-t",
                "nat",
                "-C",
                "PREROUTING",
                "-p",
                proto.lower(),
                "--dport",
                str(port),
                "-j",
                "DNAT",
                "--to-destination",
                local_ip,
            ],
            capture_output=True,
            text=True,
        )
        forward_check = subprocess.run(
            [
                binary,
                "-C",
                "FORWARD",
                "-p",
                proto.lower(),
                "-d",
                local_ip,
                "--dport",
                str(port),
                "-j",
                "ACCEPT",
            ],
            capture_output=True,
            text=True,
        )

        existed = dnat_check.returncode == 0 or forward_check.returncode == 0
        if dnat_check.returncode == 0:
            dnat_delete = subprocess.run(
                [
                    binary,
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-p",
                    proto.lower(),
                    "--dport",
                    str(port),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    local_ip,
                ],
                capture_output=True,
                text=True,
            )
            if dnat_delete.returncode != 0:
                raise FirewallError(dnat_delete.stderr.strip() or "failed to remove ip6tables DNAT rule")

        if forward_check.returncode == 0:
            forward_delete = subprocess.run(
                [
                    binary,
                    "-D",
                    "FORWARD",
                    "-p",
                    proto.lower(),
                    "-d",
                    local_ip,
                    "--dport",
                    str(port),
                    "-j",
                    "ACCEPT",
                ],
                capture_output=True,
                text=True,
            )
            if forward_delete.returncode != 0:
                raise FirewallError(forward_delete.stderr.strip() or "failed to remove ip6tables forward rule")

        return existed


class NftablesBackend(FirewallBackend):
    name = "nftables"

    def allow_port(self, port: int, proto: str, local_ip: str) -> None:
        binary = self.find_binary("nft")
        if not binary:
            raise FirewallError("nft binary not found")

        target_ip = ipaddress.ip_address(local_ip)
        if target_ip.version != 6:
            raise FirewallError("UPnPv6 only supports IPv6 targets")

        family = "ip6"
        address_key = "ip6"
        prerouting_expr = f"{proto.lower()} dport {port} dnat to {local_ip}"
        forward_expr = f"{proto.lower()} dport {port} {address_key} daddr {local_ip} accept"

        prerouting_list = subprocess.run(
            [binary, "list", "chain", family, "nat", "prerouting"],
            capture_output=True,
            text=True,
        )
        if prerouting_list.returncode == 0 and prerouting_expr not in prerouting_list.stdout:
            prerouting_add = [
                binary,
                "add",
                "rule",
                family,
                "nat",
                "prerouting",
                proto.lower(),
                "dport",
                str(port),
                "dnat",
                "to",
                local_ip,
            ]
            prerouting_result = subprocess.run(prerouting_add, capture_output=True, text=True)
            if prerouting_result.returncode != 0:
                raise FirewallError(prerouting_result.stderr.strip() or "failed to add nftables DNAT rule")

        forward_list = subprocess.run(
            [binary, "list", "chain", family, "filter", "forward"],
            capture_output=True,
            text=True,
        )
        if forward_list.returncode == 0 and forward_expr in forward_list.stdout:
            return

        add_cmd = [
            binary,
            "add",
            "rule",
            family,
            "filter",
            "forward",
            proto.lower(),
            "dport",
            str(port),
            address_key,
            "daddr",
            local_ip,
            "accept",
        ]
        result = subprocess.run(add_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise FirewallError(result.stderr.strip() or "failed to add nftables forward rule")

    def remove_port(self, port: int, proto: str, local_ip: str) -> bool:
        binary = self.find_binary("nft")
        if not binary:
            raise FirewallError("nft binary not found")

        target_ip = ipaddress.ip_address(local_ip)
        if target_ip.version != 6:
            raise FirewallError("UPnPv6 only supports IPv6 targets")

        family = "ip6"
        prerouting_expr = f"{proto.lower()} dport {port} dnat to {local_ip}"
        forward_expr = f"{proto.lower()} dport {port} ip6 daddr {local_ip} accept"
        prerouting_list = subprocess.run(
            [binary, "list", "chain", family, "nat", "prerouting"],
            capture_output=True,
            text=True,
        )
        forward_list = subprocess.run(
            [binary, "list", "chain", family, "filter", "forward"],
            capture_output=True,
            text=True,
        )
        existed = prerouting_expr in prerouting_list.stdout or forward_expr in forward_list.stdout
        if not existed:
            return False
        raise FirewallError("nftables rule removal is not implemented safely yet")


def select_backend(choice: str) -> FirewallBackend:
    normalized = choice.strip().lower()
    if normalized == "iptables":
        return Ip6TablesBackend()
    if normalized == "nftables":
        return NftablesBackend()
    raise FirewallError(f"unknown backend: {choice}")
