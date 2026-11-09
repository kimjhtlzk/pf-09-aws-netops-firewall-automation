"""A fake multi-account environment on moto. It needs no credentials and touches no real AWS API."""

from __future__ import annotations

import os
from typing import Any

import boto3

from netops.aws.session import SessionFactory
from netops.config import Settings
from netops.io.excel import ConfirmRequest

ACCOUNTS = {"svc-a-dev": "111111111111", "svc-b-prd": "000000000000"}
REGION = "ap-northeast-2"
REQUESTS = [
    ConfirmRequest("10.0.1.10", "10.1.1.20", "443"),
    ConfirmRequest("10.0.1.10", "10.1.1.20", "8443"),
    ConfirmRequest("10.0.1.10", "203.0.113.50", "443"),
]


def fake_environment() -> None:
    os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION=REGION)


class DemoSessions(SessionFactory):
    """Each profile assumes a role, which moto maps to a separate fake account."""

    def accounts(self) -> list[str]:
        return list(ACCOUNTS)

    def _session(self, account: str) -> Any:
        role = f"arn:aws:iam::{ACCOUNTS[account]}:role/demo"
        creds = boto3.client("sts", region_name=REGION).assume_role(RoleArn=role, RoleSessionName="demo")[
            "Credentials"
        ]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=REGION,
        )


def _build_account(
    sessions: DemoSessions, account: str, cidr: str, subnet: str, ip: str, name: str, group: str
) -> str:
    ec2 = sessions.client("ec2", account)
    vpc = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc, CidrBlock=subnet, AvailabilityZone=f"{REGION}a")["Subnet"][
        "SubnetId"
    ]
    sg_id = ec2.create_security_group(GroupName=group, Description=group, VpcId=vpc)["GroupId"]
    ec2.revoke_security_group_egress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    image = ec2.describe_images()["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.small",
        SubnetId=subnet_id,
        PrivateIpAddress=ip,
        SecurityGroupIds=[sg_id],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    return sg_id


def seed(sessions: DemoSessions) -> None:
    """svc-a-dev may reach svc-b-prd on 443 only."""
    allow = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}
    source = _build_account(
        sessions, "svc-a-dev", "10.0.0.0/16", "10.0.1.0/24", "10.0.1.10", "app-1", "svc-a-comm"
    )
    target = _build_account(
        sessions, "svc-b-prd", "10.1.0.0/16", "10.1.1.0/24", "10.1.1.20", "web-1", "svc-b-web"
    )
    sessions.client("ec2", "svc-a-dev").authorize_security_group_egress(
        GroupId=source, IpPermissions=[{**allow, "IpRanges": [{"CidrIp": "10.1.0.0/16"}]}]
    )
    sessions.client("ec2", "svc-b-prd").authorize_security_group_ingress(
        GroupId=target, IpPermissions=[{**allow, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}]
    )


def start(settings: Settings) -> tuple[Any, DemoSessions]:
    """Returns the running moto mock, which the caller must stop."""
    from moto import mock_aws

    fake_environment()
    mock = mock_aws()
    mock.start()
    sessions = DemoSessions(settings)
    seed(sessions)
    return mock, sessions
