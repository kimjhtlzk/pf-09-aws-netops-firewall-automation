from __future__ import annotations

from typing import Any

HEADERS = [
    "CLOUD",
    "PROJECT",
    "VPC_NAME",
    "VPC_ID",
    "VPC_CIDR",
    "SUBNET_NAME",
    "SUBNET_ID",
    "SUBNET_CIDR",
    "AZ",
]


def _name(item: dict[str, Any]) -> str:
    return next((t["Value"] for t in item.get("Tags", []) if t["Key"].upper() == "NAME"), "-")


def rows(client: Any, account: str) -> list[list[Any]]:
    vpcs = {v["VpcId"]: v for v in client.describe_vpcs()["Vpcs"]}
    return [
        [
            "AWS",
            account,
            _name(vpcs[s["VpcId"]]),
            s["VpcId"],
            vpcs[s["VpcId"]]["CidrBlock"],
            _name(s),
            s["SubnetId"],
            s["CidrBlock"],
            s["AvailabilityZone"],
        ]
        for s in client.describe_subnets()["Subnets"]
    ]
