"""Decide whether security group rules already allow a flow. Pure logic, no AWS calls."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from netops.resolve import parse_networks


def port_in_range(port: str, rule_port: str) -> bool:
    port, rule_port = str(port).strip().lower(), str(rule_port).strip()
    if rule_port in ("-1", ""):
        return True
    if port == "any":
        return rule_port in ("-1", "0-65535")
    try:
        low, high = map(int, port.split("-")) if "-" in port else (int(port), int(port))
        rule_low, rule_high = (
            map(int, rule_port.split("-")) if "-" in rule_port else (int(rule_port), int(rule_port))
        )
    except ValueError:
        return False
    return rule_low <= low and high <= rule_high


def proto_match(protocol: str, rule_protocol: str) -> bool:
    protocol, rule_protocol = str(protocol).lower().strip(), str(rule_protocol).lower().strip()
    if rule_protocol in ("-1", "all"):
        return True
    if protocol == "any":
        return False
    return protocol == rule_protocol


def uncovered_networks(
    targets: Iterable[ipaddress.IPv4Network], rule_cidrs: Iterable[str]
) -> list[ipaddress.IPv4Network]:
    """The parts of the targets that no rule reaches."""
    remaining = list(targets)
    for cidr in rule_cidrs:
        try:
            rule = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        next_round: list[ipaddress.IPv4Network] = []
        for network in remaining:
            if network.subnet_of(rule):
                continue
            if rule.subnet_of(network):
                next_round.extend(network.address_exclude(rule))
            else:
                next_round.append(network)
        remaining = next_round
    return remaining


def _rule_cidrs(rule: dict[str, Any]) -> list[str]:
    cidrs = [r["CidrIp"] for r in rule.get("IpRanges", []) if r.get("CidrIp")]
    if not cidrs and rule.get("IpProtocol") == "-1" and not rule.get("UserIdGroupPairs"):
        cidrs = ["0.0.0.0/0"]
    return cidrs


def _rule_port(rule: dict[str, Any]) -> str:
    start = rule.get("FromPort")
    return f"{start}-{rule.get('ToPort')}" if start is not None else "-1"


@dataclass
class Coverage:
    allowed: bool
    matched: list[dict[str, str]] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)
    no_rules: bool = False
    port_mismatch: list[dict[str, str]] = field(default_factory=list)
    proto_mismatch: list[dict[str, str]] = field(default_factory=list)


def check_coverage(
    groups: list[dict[str, Any]], direction: str, target: str, port: str, proto: str
) -> Coverage:
    """direction is ingress or egress. A group needs IpPermissions and IpPermissionsEgress."""
    networks = parse_networks(target)
    if not networks:
        return Coverage(allowed=False, no_rules=True)
    key = "IpPermissions" if direction == "ingress" else "IpPermissionsEgress"
    rules = [(group, rule) for group in groups for rule in group.get(key, [])]
    if not rules:
        return Coverage(allowed=False, uncovered=[str(n) for n in networks], no_rules=True)

    result = Coverage(allowed=False)
    allowed: list[str] = []
    for group, rule in rules:
        rule_port = _rule_port(rule)
        protocol = str(rule.get("IpProtocol", ""))
        for cidr in _rule_cidrs(rule):
            parsed = ipaddress.IPv4Network(cidr, strict=False)
            if not any(n.overlaps(parsed) for n in networks):
                continue
            info = {"sg_id": group["GroupId"], "protocol": protocol, "port": rule_port, "cidr": cidr}
            port_hit, proto_hit = port_in_range(port, rule_port), proto_match(proto, protocol)
            if port_hit and proto_hit:
                allowed.append(cidr)
                result.matched.append(info)
            elif proto_hit:
                result.port_mismatch.append(info)
            elif port_hit:
                result.proto_mismatch.append(info)
    remaining = uncovered_networks(networks, allowed)
    result.uncovered = [str(n) for n in remaining]
    result.allowed = not remaining
    return result


def sg_reference_allows(
    groups: list[dict[str, Any]], direction: str, peer_sg_ids: list[str], port: str, proto: str
) -> bool:
    """True when a rule names one of the peer security groups instead of a CIDR."""
    key = "IpPermissions" if direction == "ingress" else "IpPermissionsEgress"
    wanted = set(peer_sg_ids)
    for group in groups:
        for rule in group.get(key, []):
            if not (port_in_range(port, _rule_port(rule)) and proto_match(proto, rule.get("IpProtocol", ""))):
                continue
            if wanted & {pair.get("GroupId") for pair in rule.get("UserIdGroupPairs", [])}:
                return True
    return False
