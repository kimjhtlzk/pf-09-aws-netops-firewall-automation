from __future__ import annotations

from typing import Any

HEADERS = [
    "CLOUD",
    "PROJECT",
    "SG_NAME",
    "SG_ID",
    "VPC_ID",
    "DIRECTION",
    "PROTOCOL",
    "PORT",
    "PEER",
    "DESCRIPTION",
]


def _port(rule: dict[str, Any]) -> str:
    start = rule.get("FromPort")
    return (
        "all"
        if start is None
        else (str(start) if start == rule.get("ToPort") else f"{start}-{rule.get('ToPort')}")
    )


def rows(client: Any, account: str) -> list[list[Any]]:
    result: list[list[Any]] = []
    for page in client.get_paginator("describe_security_groups").paginate():
        for group in page["SecurityGroups"]:
            for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
                for rule in group.get(key, []):
                    peers = [(r["CidrIp"], r.get("Description", "")) for r in rule.get("IpRanges", [])]
                    peers += [
                        (p["GroupId"], p.get("Description", "")) for p in rule.get("UserIdGroupPairs", [])
                    ]
                    for peer, description in peers:
                        result.append(
                            [
                                "AWS",
                                account,
                                group["GroupName"],
                                group["GroupId"],
                                group.get("VpcId", ""),
                                direction,
                                rule.get("IpProtocol"),
                                _port(rule),
                                peer,
                                description,
                            ]
                        )
    return result
