"""Step 2: build the exact rule changes, show them, and apply only when asked."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from netops.aws.session import SessionFactory
from netops.config import Settings
from netops.io.excel import ModifyRequest
from netops.resolve import Resolver, Resource, parse_networks


def build_ip_permissions(port: str, proto: str, cidrs: list[str], description: str) -> list[dict[str, Any]]:
    proto, port = proto.lower().strip(), str(port).strip()
    permissions: list[dict[str, Any]] = []
    for cidr in cidrs:
        ip_range = {"CidrIp": cidr, "Description": description}
        if proto == "any":
            permissions.append({"IpProtocol": "-1", "IpRanges": [ip_range]})
        elif proto == "icmp":
            permissions.append({"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": [ip_range]})
        else:
            if port.lower() == "any":
                low, high = 0, 65535
            elif "-" in port:
                low, high = (int(p) for p in port.split("-"))
            else:
                low = high = int(port)
            permissions.append({"IpProtocol": proto, "FromPort": low, "ToPort": high, "IpRanges": [ip_range]})
    return permissions


def rule_count(group: dict[str, Any]) -> int:
    def weight(rules: list[dict[str, Any]]) -> int:
        return sum(
            len(r.get("IpRanges", [])) + len(r.get("Ipv6Ranges", [])) + len(r.get("UserIdGroupPairs", []))
            for r in rules
        )

    return weight(group.get("IpPermissions", [])) + weight(group.get("IpPermissionsEgress", []))


def common_token(names: list[str]) -> str | None:
    """The longest word every name shares, for example proxy in a-proxy1 and a-proxy2."""
    sets = [{t for t in re.split(r"[-_.]", re.sub(r"\d+", "", n.lower())) if len(t) >= 3} for n in names]
    if not sets:
        return None
    shared = set.intersection(*sets)
    return max(shared, key=len) if shared else None


@dataclass
class Candidate:
    sg_id: str
    sg_name: str
    members: list[str]
    reasons: list[str]
    free_slots: int


def rank_candidates(
    resources: list[Resource], groups: dict[str, dict[str, Any]], settings: Settings
) -> list[Candidate]:
    """Recommend shared security groups first, then the ones used by the most resources."""
    members: dict[str, list[str]] = defaultdict(list)
    names: dict[str, str] = {}
    for resource in resources:
        for group in resource.security_groups:
            members[group["id"]].append(resource.name)
            names[group["id"]] = group["name"]
    overall = common_token([r.name for r in resources])
    ranked: list[Candidate] = []
    for sg_id, member_names in members.items():
        name = groups.get(sg_id, {}).get("GroupName", names[sg_id])
        lowered = name.lower()
        reasons = [f"shared ({p})" for p in settings.common_patterns if p in lowered][:1]
        token = common_token(member_names) or overall
        if token and token in lowered:
            reasons.append(f"role ({token})")
        free = settings.sg_max_rules - rule_count(groups.get(sg_id, {}))
        ranked.append(Candidate(sg_id, name, member_names, reasons, free))
    ranked.sort(key=lambda c: (bool(c.reasons), len(c.members)), reverse=True)
    return ranked


@dataclass
class Change:
    account: str
    sg_id: str
    sg_name: str
    direction: str
    permissions: list[dict[str, Any]]
    impact: list[str]
    note: str = ""


@dataclass
class Plan:
    request: ModifyRequest
    changes: list[Change] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


class Modifier:
    def __init__(self, sessions: SessionFactory, settings: Settings) -> None:
        self.sessions = sessions
        self.settings = settings
        self.resolver = Resolver(sessions)

    def _groups(self, account: str, sg_ids: list[str]) -> dict[str, dict[str, Any]]:
        if not sg_ids:
            return {}
        ec2 = self.sessions.client("ec2", account)
        return {g["GroupId"]: g for g in ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]}

    def _side(self, plan: Plan, value: str, account: str, direction: str, peer: str) -> None:
        request = plan.request
        resolved = self.resolver.resolve(value, account)
        if not resolved.resources:
            plan.problems.append(f"{direction}: no AWS resource for {value}; nothing to change on this side")
            return
        peer_cidrs = [str(n) for n in parse_networks(peer)]
        if not peer_cidrs and resolved.resources:
            other = self.resolver.resolve(peer)
            peer_cidrs = [c for r in other.resources for c in r.subnet_cidrs]
        if not peer_cidrs:
            plan.problems.append(f"{direction}: could not turn {peer} into an address range")
            return
        by_account: dict[str, list[Resource]] = defaultdict(list)
        for resource in resolved.resources:
            by_account[resource.account].append(resource)
        permissions = build_ip_permissions(request.port, request.proto, peer_cidrs, request.description)
        for owner, resources in by_account.items():
            groups = self._groups(owner, sorted({s for r in resources for s in r.sg_ids}))
            candidates = rank_candidates(resources, groups, self.settings)
            usable = next((c for c in candidates if c.free_slots >= len(permissions)), None)
            if usable is None:
                plan.problems.append(
                    f"{direction}: no security group with {len(permissions)} free rule slots in {owner}"
                )
                continue
            note = ", ".join(usable.reasons) or "most widely used"
            plan.changes.append(
                Change(owner, usable.sg_id, usable.sg_name, direction, permissions, usable.members, note)
            )

    def plan(self, request: ModifyRequest) -> Plan:
        plan = Plan(request)
        self._side(plan, request.src, request.src_account, "egress", request.dst)
        self._side(plan, request.dst, request.dst_account, "ingress", request.src)
        return plan

    def apply(self, change: Change) -> str:
        ec2 = self.sessions.client("ec2", change.account)
        call = (
            ec2.authorize_security_group_ingress
            if change.direction == "ingress"
            else ec2.authorize_security_group_egress
        )
        try:
            call(GroupId=change.sg_id, IpPermissions=change.permissions)
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                return "already present"
            raise
        return "applied"


def merge_by_group(plans: list[Plan]) -> list[Change]:
    """Bundle changes by security group so each group is written once."""
    merged: dict[tuple[str, str, str], Change] = {}
    for plan in plans:
        for change in plan.changes:
            key = (change.account, change.sg_id, change.direction)
            if key in merged:
                merged[key].permissions.extend(change.permissions)
            else:
                merged[key] = Change(
                    change.account,
                    change.sg_id,
                    change.sg_name,
                    change.direction,
                    list(change.permissions),
                    change.impact,
                    change.note,
                )
    return list(merged.values())


def describe(change: Change) -> list[str]:
    lines = [f"{change.account}  {change.sg_name} ({change.sg_id})  {change.direction}  [{change.note}]"]
    for permission in change.permissions:
        cidr = permission["IpRanges"][0]["CidrIp"]
        low, high = permission.get("FromPort", "all"), permission.get("ToPort", "all")
        ports = low if low == high else f"{low}-{high}"
        lines.append(f"    + {permission['IpProtocol']}/{ports}  {cidr}")
    lines.append(f"    affects: {', '.join(change.impact)}")
    return lines
