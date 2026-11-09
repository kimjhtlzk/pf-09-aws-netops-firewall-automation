"""Input and output workbooks. Column order matches the forms people already fill in."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

CONFIRM_SHEET = "확인목록"
CONFIRM_HEADERS = [
    "출발지 IP/CIDR/IP범위",
    "목적지 IP/CIDR/RDS접속주소",
    "포트",
    "프로토콜(tcp/udp/icmp/any)",
]
MODIFY_SHEET = "작업목록"
MODIFY_HEADERS = [
    "출발지 어카운트",
    "출발지 IP/CIDR/RDS접속주소",
    "목적지 어카운트",
    "목적지 IP/CIDR/RDS접속주소",
    "포트",
    "프로토콜(tcp/udp/icmp/any)",
    "Description",
]


@dataclass(frozen=True)
class ConfirmRequest:
    src: str
    dst: str
    port: str
    proto: str = "tcp"


@dataclass(frozen=True)
class ModifyRequest:
    src_account: str
    src: str
    dst_account: str
    dst: str
    port: str
    proto: str = "tcp"
    description: str = ""


def _text(row: Sequence[Any], index: int) -> str:
    return str(row[index]).strip() if len(row) > index and row[index] is not None else ""


def read_confirm(path: str | Path) -> list[ConfirmRequest]:
    sheet = load_workbook(path, data_only=True).active
    requests = []
    for row in sheet.iter_rows(min_row=2, values_only=True):
        src, dst, port = _text(row, 0), _text(row, 1), _text(row, 2)
        if src and dst and port:
            requests.append(ConfirmRequest(src, dst, port, _text(row, 3).lower() or "tcp"))
    return requests


def read_modify(path: str | Path) -> list[ModifyRequest]:
    sheet = load_workbook(path, data_only=True).active
    requests = []
    for row in sheet.iter_rows(min_row=2, values_only=True):
        src, dst, port = _text(row, 1), _text(row, 3), _text(row, 4)
        if src and dst and port:
            requests.append(
                ModifyRequest(
                    _text(row, 0),
                    src,
                    _text(row, 2),
                    dst,
                    port,
                    _text(row, 5).lower() or "tcp",
                    _text(row, 6),
                )
            )
    return requests


def _styled_book(title: str, headers: list[str]) -> tuple[Workbook, Any]:
    book = Workbook()
    book.properties.creator = ""
    book.properties.lastModifiedBy = ""
    sheet = book.active
    sheet.title = title
    side = Side(style="thin")
    for column, header in enumerate(headers, start=1):
        cell = sheet.cell(row=1, column=column, value=header)
        cell.font = Font(name="Arial", bold=True, color="FFFFFF", size=10)
        cell.fill = PatternFill("solid", start_color="1F4E79")
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = Border(left=side, right=side, top=side, bottom=side)
        sheet.column_dimensions[get_column_letter(column)].width = max(14, len(header) * 2)
    return book, sheet


def write_rows(path: str | Path, title: str, headers: list[str], rows: Sequence[Sequence[Any]]) -> Path:
    book, sheet = _styled_book(title, headers)
    for row in rows:
        sheet.append(list(row))
    sheet.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{max(1, len(rows) + 1)}"
    sheet.freeze_panes = "A2"
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    book.save(target)
    return target


def write_confirm_template(path: str | Path, rows: Sequence[ConfirmRequest] = ()) -> Path:
    return write_rows(path, CONFIRM_SHEET, CONFIRM_HEADERS, [(r.src, r.dst, r.port, r.proto) for r in rows])


def write_modify(path: str | Path, rows: Sequence[ModifyRequest] = ()) -> Path:
    data = [(r.src_account, r.src, r.dst_account, r.dst, r.port, r.proto, r.description) for r in rows]
    return write_rows(path, MODIFY_SHEET, MODIFY_HEADERS, data)
