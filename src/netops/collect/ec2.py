from __future__ import annotations

from typing import Any

HEADERS = [
    "CLOUD",
    "PROJECT",
    "INSTANCE_NAME",
    "INSTANCE_ID",
    "INSTANCE_TYPE",
    "STATE",
    "PRIVATE_IP",
    "PUBLIC_IP",
    "VPC_ID",
    "SUBNET_ID",
    "SECURITY_GROUPS",
]


def _name(item: dict[str, Any]) -> str:
    return next((t["Value"] for t in item.get("Tags", []) if t["Key"].upper() == "NAME"), "-")


def rows(client: Any, account: str) -> list[list[Any]]:
    return [
        [
            "AWS",
            account,
            _name(i),
            i["InstanceId"],
            i["InstanceType"],
            i["State"]["Name"],
            i.get("PrivateIpAddress", ""),
            i.get("PublicIpAddress", ""),
            i.get("VpcId", ""),
            i.get("SubnetId", ""),
            ", ".join(g["GroupId"] for g in i.get("SecurityGroups", [])),
        ]
        for page in client.get_paginator("describe_instances").paginate()
        for r in page["Reservations"]
        for i in r["Instances"]
    ]
