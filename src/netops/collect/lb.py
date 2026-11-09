from __future__ import annotations

from typing import Any

HEADERS = [
    "CLOUD",
    "PROJECT",
    "LB_NAME",
    "LB_TYPE",
    "SCHEME",
    "DNS_NAME",
    "VPC_ID",
    "SECURITY_GROUPS",
    "LISTENERS",
    "TARGET_GROUPS",
]


def rows(client: Any, account: str) -> list[list[Any]]:
    result: list[list[Any]] = []
    for page in client.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            arn = lb["LoadBalancerArn"]
            listeners = client.describe_listeners(LoadBalancerArn=arn)["Listeners"]
            groups = client.describe_target_groups(LoadBalancerArn=arn)["TargetGroups"]
            result.append(
                [
                    "AWS",
                    account,
                    lb["LoadBalancerName"],
                    lb.get("Type", ""),
                    lb.get("Scheme", ""),
                    lb.get("DNSName", ""),
                    lb.get("VpcId", ""),
                    ", ".join(lb.get("SecurityGroups", [])),
                    ", ".join(f"{x['Protocol']}:{x['Port']}" for x in listeners),
                    ", ".join(g["TargetGroupName"] for g in groups),
                ]
            )
    return result
