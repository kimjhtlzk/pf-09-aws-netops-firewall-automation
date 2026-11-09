"""Diagnose whether a subnet has a route to a destination."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from netops.resolve import parse_networks


@dataclass
class RouteResult:
    ok: bool
    table_id: str = ""
    table_name: str = ""
    routes: list[dict[str, Any]] = field(default_factory=list)


def _name(table: dict[str, Any]) -> str:
    return next((t["Value"] for t in table.get("Tags", []) if t["Key"].upper() == "NAME"), "-")


def find_table(ec2: Any, subnet_id: str, vpc_id: str) -> dict[str, Any] | None:
    """The explicit association wins. Otherwise the VPC main table applies."""
    tables = ec2.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])[
        "RouteTables"
    ]
    if tables:
        return tables[0]
    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "association.main", "Values": ["true"]}]
    )["RouteTables"]
    return tables[0] if tables else None


def evaluate(table: dict[str, Any] | None, destination: str) -> RouteResult:
    if table is None:
        return RouteResult(ok=False)
    targets = parse_networks(destination)
    matched: list[dict[str, Any]] = []
    for route in table.get("Routes", []):
        if route.get("State") == "blackhole" or not route.get("DestinationCidrBlock"):
            continue
        network = ipaddress.IPv4Network(route["DestinationCidrBlock"], strict=False)
        if any(t.overlaps(network) for t in targets):
            matched.append(route)
    matched.sort(key=lambda r: ipaddress.IPv4Network(r["DestinationCidrBlock"]).prefixlen, reverse=True)
    return RouteResult(
        ok=bool(matched), table_id=table.get("RouteTableId", ""), table_name=_name(table), routes=matched
    )


def next_hop(route: dict[str, Any]) -> str:
    for key in (
        "GatewayId",
        "NatGatewayId",
        "TransitGatewayId",
        "VpcPeeringConnectionId",
        "NetworkInterfaceId",
    ):
        if route.get(key):
            return route[key]
    return "-"
