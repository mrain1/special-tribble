"""Command line entry point for the vulnerability manager."""
from __future__ import annotations

import argparse
import logging
import sys
from typing import Dict, Iterable, List, Optional

from .config import Config, load_config
from .database import VulnerabilityDatabase
from .sync import synchronize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberCNS vulnerability manager")
    parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="Path to configuration YAML file (default: config.yaml)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help="Log level for console output",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser("sync", help="Fetch vulnerabilities via the API")
    sync_parser.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Extra query parameters to pass to the API endpoint",
    )

    list_parser = subparsers.add_parser("list", help="Display vulnerabilities from the database")
    list_parser.add_argument(
        "--status",
        default="open",
        help="Filter by status (default: open)",
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit the number of rows displayed",
    )

    update_parser = subparsers.add_parser("update-status", help="Change the remediation status")
    update_parser.add_argument("vulnerability_id", help="Identifier of the vulnerability")
    update_parser.add_argument("status", help="New status value")
    update_parser.add_argument("--note", help="Optional note for the history log")

    return parser


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def parse_params(values: Iterable[str]) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Invalid parameter '{value}'. Expected KEY=VALUE")
        key, val = value.split("=", 1)
        params[key] = val
    return params


def load_database(config: Config) -> VulnerabilityDatabase:
    db = VulnerabilityDatabase(config.database.path)
    db.initialize()
    return db


def render_table(rows: List[Dict[str, str]]) -> str:
    if not rows:
        return "No results"
    headers = rows[0].keys()
    widths = {header: max(len(header), *(len(str(row[header])) for row in rows)) for header in headers}
    lines = []
    header_line = " | ".join(f"{header:{widths[header]}}" for header in headers)
    separator = "-+-".join("-" * widths[header] for header in headers)
    lines.append(header_line)
    lines.append(separator)
    for row in rows:
        lines.append(" | ".join(f"{str(row[header]):{widths[header]}}" for header in headers))
    return "\n".join(lines)


def command_sync(config: Config, args: argparse.Namespace) -> int:
    params = parse_params(args.param) if args.param else None
    count = synchronize(config, params=params)
    print(f"Synced {count} vulnerabilities")
    return count


def command_list(config: Config, args: argparse.Namespace) -> int:
    with load_database(config) as db:
        vulnerabilities = db.fetch_vulnerabilities(status=args.status)
    if args.limit is not None:
        vulnerabilities = vulnerabilities[: args.limit]
    rows: List[Dict[str, str]] = []
    for vuln in vulnerabilities:
        rows.append(
            {
                "ID": vuln.vulnerability_id,
                "Asset": vuln.asset_name or vuln.asset_id,
                "Title": (vuln.title[:60] + "…") if len(vuln.title) > 60 else vuln.title,
                "Severity": vuln.severity or "",
                "Score": f"{vuln.risk_score:.2f}" if vuln.risk_score is not None else "",
                "Level": vuln.risk_level or "",
                "Status": vuln.status,
                "Target": vuln.target_date.isoformat() if vuln.target_date else "",
            }
        )
    print(render_table(rows))
    return len(rows)


def command_update_status(config: Config, args: argparse.Namespace) -> int:
    with load_database(config) as db:
        db.mark_status(args.vulnerability_id, args.status, note=args.note)
    print(f"Updated {args.vulnerability_id} to {args.status}")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.log_level)
    try:
        config = load_config(args.config)
    except Exception as exc:  # pragma: no cover - user input path issues
        parser.error(str(exc))

    if args.command == "sync":
        try:
            command_sync(config, args)
        except ValueError as exc:
            parser.error(str(exc))
    elif args.command == "list":
        command_list(config, args)
    elif args.command == "update-status":
        command_update_status(config, args)
    else:  # pragma: no cover - argparse prevents this
        parser.error(f"Unknown command {args.command}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main", "build_parser"]
