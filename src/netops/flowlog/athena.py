"""Step 3: look at real traffic in VPC Flow Logs, in CloudWatch or through Athena."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from netops.aws.session import SessionFactory
from netops.config import Settings

FIELDS = ["start", "srcaddr", "dstaddr", "dstport", "protocol", "action"]
SAFE_TABLE = re.compile(r"^[A-Za-z0-9_]+$")
SAFE_ADDRESS = re.compile(r"^[0-9.]+$")


def parse_interval(value: str) -> int:
    """30m, 2h, or 1d in minutes. A bare number means minutes."""
    match = re.fullmatch(r"(\d+)\s*([mhd]?)", value.strip().lower())
    if not match:
        raise ValueError(f"Invalid interval: {value}")
    return int(match.group(1)) * {"": 1, "m": 1, "h": 60, "d": 1440}[match.group(2)]


def flow_logs_for_vpc(ec2: Any, vpc_id: str) -> list[dict[str, Any]]:
    return ec2.describe_flow_logs(Filter=[{"Name": "resource-id", "Values": [vpc_id]}])["FlowLogs"]


def build_query(table: str, database: str, address: str, minutes: int, now: datetime | None = None) -> str:
    """Identifiers cannot be bound as parameters, so they must pass strict patterns first."""
    if not SAFE_TABLE.match(table) or not SAFE_TABLE.match(database):
        raise ValueError("Invalid Athena table or database name")
    if not SAFE_ADDRESS.match(address):
        raise ValueError("Address must be an IPv4 address")
    since = int(((now or datetime.now(UTC)) - timedelta(minutes=minutes)).timestamp())
    columns = ", ".join(FIELDS)
    return (
        f"SELECT {columns} FROM {database}.{table} "  # noqa: S608 - both identifiers are validated above
        f"WHERE start > {since} AND (srcaddr = '{address}' OR dstaddr = '{address}') "
        "ORDER BY start DESC LIMIT 200"
    )


def query_athena(
    client: Any, query: str, database: str, output: str, poll: float = 1.0, attempts: int = 120
) -> list[dict[str, str]]:
    execution = client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output},
    )["QueryExecutionId"]
    for _ in range(attempts):
        state = client.get_query_execution(QueryExecutionId=execution)["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(poll)
    else:
        raise TimeoutError("Athena query did not finish")
    if state != "SUCCEEDED":
        raise RuntimeError(f"Athena query ended as {state}")
    rows = client.get_query_results(QueryExecutionId=execution)["ResultSet"]["Rows"]
    header = [c.get("VarCharValue", "") for c in rows[0]["Data"]]
    return [
        dict(zip(header, (c.get("VarCharValue", "") for c in row["Data"]), strict=False)) for row in rows[1:]
    ]


def query_cloudwatch(
    client: Any, log_group: str, address: str, minutes: int, poll: float = 1.0
) -> list[dict[str, str]]:
    end = int(time.time())
    query = (
        f"fields {', '.join(FIELDS)} | filter srcAddr = '{address}' or dstAddr = '{address}' "
        "| sort @timestamp desc | limit 200"
    )
    query_id = client.start_query(
        logGroupName=log_group, startTime=end - minutes * 60, endTime=end, queryString=query
    )["queryId"]
    while True:
        response = client.get_query_results(queryId=query_id)
        if response["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(poll)
    return [{f["field"]: f["value"] for f in row} for row in response.get("results", [])]


def search(
    sessions: SessionFactory,
    settings: Settings,
    account: str,
    vpc_id: str,
    table: str,
    address: str,
    minutes: int,
) -> list[dict[str, str]]:
    """Use CloudWatch when the VPC logs there, otherwise the central Athena table."""
    if not SAFE_ADDRESS.match(address):
        raise ValueError("Address must be an IPv4 address")
    for flow_log in flow_logs_for_vpc(sessions.client("ec2", account), vpc_id):
        if flow_log.get("LogDestinationType") == "cloud-watch-logs":
            return query_cloudwatch(
                sessions.client("logs", account), flow_log["LogGroupName"], address, minutes
            )
    query = build_query(table, settings.athena_database, address, minutes)
    client = sessions.client("athena", settings.log_archive_profile)
    return query_athena(client, query, settings.athena_database, settings.athena_output_location)
