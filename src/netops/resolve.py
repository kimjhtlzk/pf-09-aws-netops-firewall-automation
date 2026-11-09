"""Turn an IP, CIDR, IP range, or RDS address into the AWS resources behind it."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any

from netops.aws.session import SessionFactory

IPV4_RANGE = re.compile(r"^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$")
DOMAIN = re.compile(r"^(?!\d+\.\d+\.\d+\.\d+$)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def is_ip_range(value: str) -> bool:
    return bool(IPV4_RANGE.match(value))


def is_cidr(value: str) -> bool:
    if "/" not in value:
        return False
    try:
        ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return False
    return True


def is_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def is_domain(value: str) -> bool:
    return bool(DOMAIN.match(value)) and not is_cidr(value)


def parse_networks(value: str) -> list[ipaddress.IPv4Network]:
    """Every input format becomes a list of networks. Domains become an empty list."""
    value = str(value).strip()
    try:
        if is_ip_range(value):
            start, end = (part.strip() for part in value.split("-"))
            return list(
                ipaddress.summarize_address_range(ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))
            )
        if is_cidr(value):
            return [ipaddress.IPv4Network(value, strict=False)]
        if is_ip(value):
            return [ipaddress.IPv4Network(f"{value}/32")]
    except ValueError:
        return []
    return []


@dataclass
class Resource:
    kind: str
    account: str
    identifier: str
    name: str
    ip: str
    vpc_id: str = ""
    subnet_id: str = ""
    security_groups: list[dict[str, str]] = field(default_factory=list)
    subnet_cidrs: list[str] = field(default_factory=list)

    @property
    def sg_ids(self) -> list[str]:
        return [g["id"] for g in self.security_groups]

    @property
    def label(self) -> str:
        return f"{self.kind} {self.name} ({self.identifier})"


@dataclass
class Resolved:
    value: str
    kind: str
    resources: list[Resource] = field(default_factory=list)


def _tag_name(item: dict[str, Any], default: str = "-") -> str:
    return next((t["Value"] for t in item.get("Tags", []) if t["Key"].upper() == "NAME"), default)


class Resolver:
    def __init__(self, sessions: SessionFactory) -> None:
        self.sessions = sessions

    def _ec2_resource(self, account: str, item: dict[str, Any]) -> Resource:
        return Resource(
            kind="EC2",
            account=account,
            identifier=item["InstanceId"],
            name=_tag_name(item),
            ip=item.get("PrivateIpAddress", ""),
            vpc_id=item.get("VpcId", ""),
            subnet_id=item.get("SubnetId", ""),
            security_groups=[
                {"id": g["GroupId"], "name": g["GroupName"]} for g in item.get("SecurityGroups", [])
            ],
        )

    def _eni_resource(self, account: str, eni: dict[str, Any]) -> Resource:
        return Resource(
            kind="ENI",
            account=account,
            identifier=eni["NetworkInterfaceId"],
            name=eni.get("Description") or "-",
            ip=eni.get("PrivateIpAddress", ""),
            vpc_id=eni.get("VpcId", ""),
            subnet_id=eni.get("SubnetId", ""),
            security_groups=[{"id": g["GroupId"], "name": g["GroupName"]} for g in eni.get("Groups", [])],
        )

    def _rds_resource(self, account: str, db: dict[str, Any], ip: str) -> Resource:
        group = db.get("DBSubnetGroup", {})
        subnet_ids = [s["SubnetIdentifier"] for s in group.get("Subnets", [])]
        cidrs: list[str] = []
        if subnet_ids:
            ec2 = self.sessions.client("ec2", account)
            cidrs = [s["CidrBlock"] for s in ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]]
        return Resource(
            kind="RDS",
            account=account,
            identifier=db["DBInstanceIdentifier"],
            name=db["DBInstanceIdentifier"],
            ip=ip,
            vpc_id=group.get("VpcId", ""),
            security_groups=[
                {"id": g["VpcSecurityGroupId"], "name": g["VpcSecurityGroupId"]}
                for g in db.get("VpcSecurityGroups", [])
            ],
            subnet_cidrs=cidrs,
        )

    def _instances(self, account: str, filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pages = (
            self.sessions.client("ec2", account).get_paginator("describe_instances").paginate(Filters=filters)
        )
        return [i for page in pages for r in page["Reservations"] for i in r["Instances"]]

    def find_by_ip(self, ip: str, accounts: list[str] | None = None) -> list[Resource]:
        """Identify an IP in the order EC2, load balancer ENI, RDS, then any other ENI."""
        for account in accounts or self.sessions.accounts():
            instances = self._instances(account, [{"Name": "private-ip-address", "Values": [ip]}])
            if instances:
                return [self._ec2_resource(account, i) for i in instances]
            enis = (
                self.sessions.client("ec2", account)
                .describe_network_interfaces(
                    Filters=[{"Name": "addresses.private-ip-address", "Values": [ip]}]
                )
                .get("NetworkInterfaces", [])
            )
            if enis:
                eni = enis[0]
                resource = self._eni_resource(account, eni)
                if eni.get("InterfaceType") == "network_load_balancer" or "ELB" in (
                    eni.get("Description") or ""
                ):
                    resource.kind = "LB"
                return [resource]
            for db in self.sessions.client("rds", account).describe_db_instances()["DBInstances"]:
                address = db.get("Endpoint", {}).get("Address", "")
                if address and _resolve_ip(address) == ip:
                    return [self._rds_resource(account, db, ip)]
        return []

    def find_rds_by_endpoint(self, endpoint: str) -> list[Resource]:
        for account in self.sessions.accounts():
            for db in self.sessions.client("rds", account).describe_db_instances()["DBInstances"]:
                if db.get("Endpoint", {}).get("Address", "").lower() == endpoint.lower():
                    return [self._rds_resource(account, db, "")]
        return []

    def find_in_networks(
        self, networks: list[ipaddress.IPv4Network], accounts: list[str] | None = None
    ) -> list[Resource]:
        found: list[Resource] = []
        for account in accounts or self.sessions.accounts():
            for item in self._instances(account, []):
                address = item.get("PrivateIpAddress")
                if address and any(ipaddress.ip_address(address) in n for n in networks):
                    found.append(self._ec2_resource(account, item))
        return found

    def resolve(self, value: str, account: str = "") -> Resolved:
        value = value.strip()
        accounts = [account] if account else None
        if is_domain(value):
            return Resolved(value, "endpoint", self.find_rds_by_endpoint(value))
        if is_ip(value):
            return Resolved(value, "ip", self.find_by_ip(value, accounts))
        networks = parse_networks(value)
        return Resolved(value, "cidr" if networks else "unknown", self.find_in_networks(networks, accounts))


def _resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""
