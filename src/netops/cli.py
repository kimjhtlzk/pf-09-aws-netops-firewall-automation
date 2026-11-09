"""Command line entry point: netops confirm | modify | flowlog | collect | sso-login."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from netops import config as settings_module
from netops.analyze.confirm import Confirmer, Verdict
from netops.apply.modify import Modifier, describe, merge_by_group
from netops.aws.session import SessionFactory
from netops.config import Settings
from netops.io import excel


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netops", description=__doc__)
    parser.add_argument("--config", help="Path to the YAML settings file")
    sub = parser.add_subparsers(dest="command", required=True)

    confirm = sub.add_parser("confirm", help="Check whether requested flows can already pass")
    confirm.add_argument("--file", help="Input workbook")
    confirm.add_argument("--demo", action="store_true", help="Use a fake environment. No credentials needed")

    modify = sub.add_parser("modify", help="Preview rule changes, and apply them with --apply")
    modify.add_argument("--file", help="Input workbook")
    modify.add_argument(
        "--apply", action="store_true", help="Make the changes. Without this flag nothing changes"
    )
    modify.add_argument("--yes", action="store_true", help="Skip the typed confirmation")
    modify.add_argument("--demo", action="store_true", help="Use a fake environment. No credentials needed")

    flowlog = sub.add_parser("flowlog", help="Search real traffic in VPC Flow Logs")
    flowlog.add_argument("--account", required=True)
    flowlog.add_argument("--vpc", required=True)
    flowlog.add_argument("--table", required=True, help="Athena table")
    flowlog.add_argument("--address", required=True)
    flowlog.add_argument("--interval", default="1h", help="For example 30m, 2h, or 1d")

    collect = sub.add_parser("collect", help="Write inventory workbooks")
    collect.add_argument("--kind", action="append", choices=("ec2", "sg", "route_table", "vpc", "lb", "rds"))

    sso = sub.add_parser("sso-login", help="Sign in with IAM Identity Center")
    sso.add_argument("--role", required=True, help="Permission set name")
    sso.add_argument("--once", action="store_true", help="Exit after one sign-in instead of refreshing")
    return parser


def print_verdict(index: int, total: int, verdict: Verdict) -> None:
    print(f"\n[{index}/{total}] {verdict.src} -> {verdict.dst}  {verdict.proto}/{verdict.port}")
    for check in verdict.checks:
        print(f"  {'ok ' if check.ok else 'NO '} {check.side:<8} {check.resource}: {check.detail}")
    print(f"  => {'NO WORK NEEDED' if verdict.ok else 'NEEDS WORK: ' + '; '.join(verdict.issues)}")


def _modify_requests(verdicts: Sequence[Verdict]) -> list[excel.ModifyRequest]:
    return [
        excel.ModifyRequest(
            v.src_account, v.src, v.dst_account, v.dst, v.port, v.proto, "added after netops confirm"
        )
        for v in verdicts
        if not v.ok
    ]


def run_confirm(
    args: argparse.Namespace, settings: Settings, sessions: SessionFactory, requests: Sequence[Any]
) -> int:
    confirmer = Confirmer(sessions)
    verdicts = [confirmer.analyze(r.src, r.dst, r.port, r.proto) for r in requests]
    for index, verdict in enumerate(verdicts, start=1):
        print_verdict(index, len(verdicts), verdict)
    blocked = _modify_requests(verdicts)
    print(f"\n{len(verdicts) - len(blocked)} open, {len(blocked)} blocked")
    if blocked and not args.demo:
        path = settings.workspace_path / "modify_from_confirm" / "FW_Modify.xlsx"
        excel.write_modify(path, blocked)
        print(f"wrote {path}")
    return 0


def run_modify(
    args: argparse.Namespace,
    settings: Settings,
    sessions: SessionFactory,
    requests: Sequence[excel.ModifyRequest],
) -> int:
    modifier = Modifier(sessions, settings)
    plans = [modifier.plan(r) for r in requests]
    for plan in plans:
        for problem in plan.problems:
            print(f"warning: {problem}")
    changes = merge_by_group(plans)
    print("\nPlanned changes:")
    for change in changes:
        for line in describe(change):
            print(f"  {line}")
    if not args.apply:
        print("\nDry run. Nothing was changed. Add --apply to make these changes.")
        return 0
    if not args.yes and input("\nType apply to continue: ").strip() != "apply":
        print("Cancelled. Nothing was changed.")
        return 1
    for change in changes:
        print(f"{change.sg_id} {change.direction}: {modifier.apply(change)}")
    return 0


def load_input(path: str | None, default: Path, reader: Any, template: Any) -> list[Any] | None:
    target = Path(path) if path else default
    if not target.exists():
        template(target)
        print(f"Created an empty form at {target}. Fill it in and run again.", file=sys.stderr)
        return None
    return reader(target)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = settings_module.load(args.config)

    if getattr(args, "demo", False):
        from netops import demo

        mock, sessions = demo.start(settings)
        try:
            if args.command == "confirm":
                return run_confirm(args, settings, sessions, demo.REQUESTS)
            confirmer = Confirmer(sessions)
            verdicts = [confirmer.analyze(r.src, r.dst, r.port, r.proto) for r in demo.REQUESTS]
            return run_modify(args, settings, sessions, _modify_requests(verdicts))
        finally:
            mock.stop()

    if args.command == "sso-login":
        from netops.auth import sso

        sso.run(settings, args.role, keep_alive=not args.once)
        return 0

    live: SessionFactory = SessionFactory(settings)
    if args.command == "collect":
        from netops import collect

        for path in collect.run(live, settings, args.kind):
            print(f"wrote {path}")
        return 0
    if args.command == "flowlog":
        from netops.flowlog import athena

        minutes = athena.parse_interval(args.interval)
        for row in athena.search(
            sessions, settings, args.account, args.vpc, args.table, args.address, minutes
        ):
            print("  ".join(str(row.get(field, "-")) for field in athena.FIELDS))
        return 0

    workspace = settings.workspace_path
    if args.command == "confirm":
        requests = load_input(
            args.file, workspace / "FW_RT_Confirm.xlsx", excel.read_confirm, excel.write_confirm_template
        )
        return 2 if requests is None else run_confirm(args, settings, live, requests)
    requests = load_input(args.file, workspace / "FW_Modify.xlsx", excel.read_modify, excel.write_modify)
    return 2 if requests is None else run_modify(args, settings, live, requests)


if __name__ == "__main__":
    raise SystemExit(main())
