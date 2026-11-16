from __future__ import annotations

from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    name: str
    executable: str
    command_line: str
    parent_pid: int | None
    cpu_percent: float
    memory_mb: float


@dataclass(frozen=True)
class ConnectionRecord:
    status: str
    local: str
    remote: str
    pid: int | None
    process: str
    suspicious: bool


def process_records() -> list[ProcessRecord]:
    records: list[ProcessRecord] = []
    for process in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            info = process.info
            records.append(
                ProcessRecord(
                    pid=info["pid"],
                    name=info.get("name") or "Unknown",
                    executable=info.get("exe") or "Unavailable",
                    command_line=" ".join(info.get("cmdline") or []),
                    parent_pid=info.get("ppid"),
                    cpu_percent=process.cpu_percent(interval=None),
                    memory_mb=process.memory_info().rss / (1024 * 1024),
                )
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue
    return sorted(records, key=lambda item: item.memory_mb, reverse=True)


def connection_records() -> list[ConnectionRecord]:
    names: dict[int, str] = {}
    for process in psutil.process_iter(["pid", "name"]):
        try:
            names[process.info["pid"]] = process.info.get("name") or "Unknown"
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    records: list[ConnectionRecord] = []
    for connection in psutil.net_connections(kind="inet"):
        local = _endpoint(connection.laddr)
        remote = _endpoint(connection.raddr)
        process = names.get(connection.pid or -1, "Unavailable")
        command = f"{process} {local} {remote}".lower()
        suspicious = connection.status == "LISTEN" or any(
            indicator in command
            for indicator in ("nc.exe", "ncat", "netcat", "socat", "bash -i", "powershell -enc")
        )
        records.append(
            ConnectionRecord(
                status=connection.status,
                local=local,
                remote=remote or "—",
                pid=connection.pid,
                process=process,
                suspicious=suspicious,
            )
        )
    return sorted(records, key=lambda item: (item.status != "LISTEN", item.local))


def _endpoint(address) -> str:
    if not address:
        return ""
    try:
        return f"{address.ip}:{address.port}"
    except AttributeError:
        return str(address)
