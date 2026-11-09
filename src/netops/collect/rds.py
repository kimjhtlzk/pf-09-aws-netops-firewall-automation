from __future__ import annotations

from typing import Any

HEADERS = [
    "CLOUD",
    "PROJECT",
    "DB_IDENTIFIER",
    "ENGINE",
    "ENGINE_VERSION",
    "INSTANCE_CLASS",
    "ENDPOINT",
    "PORT",
    "VPC_ID",
    "SECURITY_GROUPS",
    "MULTI_AZ",
]


def rows(client: Any, account: str) -> list[list[Any]]:
    return [
        [
            "AWS",
            account,
            db["DBInstanceIdentifier"],
            db["Engine"],
            db.get("EngineVersion", ""),
            db["DBInstanceClass"],
            db.get("Endpoint", {}).get("Address", ""),
            db.get("Endpoint", {}).get("Port", ""),
            db.get("DBSubnetGroup", {}).get("VpcId", ""),
            ", ".join(g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])),
            db.get("MultiAZ", False),
        ]
        for page in client.get_paginator("describe_db_instances").paginate()
        for db in page["DBInstances"]
    ]
