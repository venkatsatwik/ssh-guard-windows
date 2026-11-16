from __future__ import annotations

from pathlib import Path

from rich.live import Live
from rich.table import Table

from .scanner import assess_file, iter_files


def _table(root: Path, rows: list[tuple[str, str, str, str]]) -> Table:
    table = Table(
        title=f"SSH Guard - file scan: {root}",
        caption="Press Ctrl+C to stop. No files are changed.",
        expand=True,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("File", overflow="fold")
    table.add_column("Detected", overflow="fold")
    for row in rows:
        table.add_row(*row)
    return table


def scan_dashboard(root: Path) -> int:
    rows: list[tuple[str, str, str, str]] = []
    totals = {"clean": 0, "suspicious": 0, "high-risk": 0, "unreadable": 0}
    with Live(_table(root, rows), refresh_per_second=10) as live:
        try:
            for index, path in enumerate(iter_files(root), start=1):
                result = assess_file(path)
                if not result.readable:
                    totals["unreadable"] += 1
                    severity = "UNREADABLE"
                    detected = result.error or "Access denied or file disappeared"
                else:
                    severity = result.severity
                    detected = "; ".join(item.reason for item in result.findings) or "No indicators detected"
                    if result.score >= 70:
                        totals["high-risk"] += 1
                    elif result.score:
                        totals["suspicious"] += 1
                    else:
                        totals["clean"] += 1
                rows.append((str(index), severity, str(result.score), str(result.path), detected))
                live.update(_table(root, rows))
        except KeyboardInterrupt:
            pass
    total = sum(totals.values())
    print(
        f"Files: {total} | clean={totals['clean']} suspicious={totals['suspicious']} "
        f"high-risk={totals['high-risk']} unreadable={totals['unreadable']}"
    )
    return 0
