from __future__ import annotations

from typing import Any

HEADERS = [
    "CLOUD",
    "PROJECT",
    "RT_NAME",
    "RT_ID",
    "VPC_ID",
    "IS_MAIN",
    "SUBNETS",
    "DESTINATION",
    "TARGET",
    "STATE",
]


def _name(item: dict[str, Any]) -> str:
    return next((t["Value"] for t in item.get("Tags", []) if t["Key"].upper() == "NAME"), "-")


def _target(route: dict[str, Any]) -> str:
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


def rows(client: Any, account: str) -> list[list[Any]]:
    result: list[list[Any]] = []
    for table in client.describe_route_tables()["RouteTables"]:
        associations = table.get("Associations", [])
        is_main = any(a.get("Main") for a in associations)
        subnets = ", ".join(a["SubnetId"] for a in associations if a.get("SubnetId"))
        for route in table.get("Routes", []):
            result.append(
                [
                    "AWS",
                    account,
                    _name(table),
                    table["RouteTableId"],
                    table["VpcId"],
                    is_main,
                    subnets,
                    route.get("DestinationCidrBlock", ""),
                    _target(route),
                    route.get("State", ""),
                ]
            )
    return result
