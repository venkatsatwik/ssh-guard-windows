from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .dashboard import scan_dashboard
from .monitor import monitor
from .scanner import assess_file, iter_files

console = Console()


def scan_command(root: Path) -> int:
    if not root.exists():
        console.print(f"[red]Path does not exist:[/red] {root}")
        return 2
    table = Table("Severity", "Score", "Path", "Reasons")
    totals = {"clean": 0, "suspicious": 0, "high-risk": 0, "unreadable": 0}
    for path in iter_files(root):
        result = assess_file(path)
        if not result.readable:
            totals["unreadable"] += 1
            continue
        if result.score >= 70:
            totals["high-risk"] += 1
        elif result.score:
            totals["suspicious"] += 1
        else:
            totals["clean"] += 1
        if result.score:
            table.add_row(
                result.severity,
                str(result.score),
                str(result.path),
                "; ".join(item.reason for item in result.findings),
            )
    console.print(table)
    console.print(
        f"Files: {sum(totals.values())} | clean={totals['clean']} "
        f"suspicious={totals['suspicious']} high-risk={totals['high-risk']} "
        f"unreadable={totals['unreadable']}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="sshguard", description="Defensive, local Windows security monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Recursively scan a local file or directory")
    scan.add_argument("path", type=Path)
    scan.add_argument("--dashboard", action="store_true", help="Show every file and detection in a live dashboard")
    dashboard = subparsers.add_parser("dashboard", help="Scan with a live table showing every file")
    dashboard.add_argument("path", type=Path)
    watch = subparsers.add_parser("watch", help="Monitor a local directory for file changes")
    watch.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "scan":
        if args.dashboard:
            if not args.path.exists():
                console.print(f"[red]Path does not exist:[/red] {args.path}")
                return 2
            return scan_dashboard(args.path)
        return scan_command(args.path)
    if args.command == "dashboard":
        if not args.path.exists():
            console.print(f"[red]Path does not exist:[/red] {args.path}")
            return 2
        return scan_dashboard(args.path)
    if not args.path.is_dir():
        console.print("[red]Watch path must be a directory.[/red]")
        return 2
    monitor(args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
