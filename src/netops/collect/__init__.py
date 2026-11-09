"""Inventory workbooks, one per resource type."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from netops.aws.session import SessionFactory
from netops.collect import ec2, lb, rds, route_table, sg, vpc
from netops.config import Settings
from netops.io.excel import write_rows

Collector = tuple[list[str], Callable[[Any, str], list[list[Any]]], str]
COLLECTORS: dict[str, Collector] = {
    "ec2": (ec2.HEADERS, ec2.rows, "ec2"),
    "sg": (sg.HEADERS, sg.rows, "ec2"),
    "route_table": (route_table.HEADERS, route_table.rows, "ec2"),
    "vpc": (vpc.HEADERS, vpc.rows, "ec2"),
    "lb": (lb.HEADERS, lb.rows, "elbv2"),
    "rds": (rds.HEADERS, rds.rows, "rds"),
}


def output_name(prefix: str, kind: str, when: datetime | None = None) -> str:
    return f"{prefix}_{kind}_inventory_{(when or datetime.now()).strftime('%Y%m%d')}.xlsx"


def run(sessions: SessionFactory, settings: Settings, kinds: list[str] | None = None) -> list[Path]:
    written: list[Path] = []
    for kind in kinds or list(COLLECTORS):
        headers, collect, service = COLLECTORS[kind]
        rows = [
            row
            for account in sessions.accounts()
            for row in collect(sessions.client(service, account), account)
        ]
        path = settings.workspace_path / output_name(settings.output_prefix, kind)
        written.append(write_rows(path, kind.upper(), headers, rows))
    return written
