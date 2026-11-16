from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

QUARANTINE_DIR = Path.home() / "AppData" / "Local" / "SSHGuard" / "Quarantine"
RETENTION_DAYS = 15
NOTICE_DAYS = 7


def _metadata_path(item_id: str) -> Path:
    return QUARANTINE_DIR / f"{item_id}.json"


def quarantine_file(source: Path) -> dict[str, str]:
    if not source.is_file():
        raise FileNotFoundError(f"File no longer exists: {source}")
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    item_id = uuid.uuid4().hex
    destination = QUARANTINE_DIR / f"{item_id}_{source.name}"
    now = datetime.now(timezone.utc)
    record = {
        "id": item_id,
        "original_path": str(source),
        "quarantine_path": str(destination),
        "quarantined_at": now.isoformat(),
        "notify_at": (now + timedelta(days=RETENTION_DAYS - NOTICE_DAYS)).isoformat(),
        "delete_after": (now + timedelta(days=RETENTION_DAYS)).isoformat(),
        "notified": "false",
    }
    shutil.move(str(source), str(destination))
    _metadata_path(item_id).write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def pending_notifications() -> list[dict[str, str]]:
    if not QUARANTINE_DIR.exists():
        return []
    now = datetime.now(timezone.utc)
    notices: list[dict[str, str]] = []
    for metadata in QUARANTINE_DIR.glob("*.json"):
        try:
            record = json.loads(metadata.read_text(encoding="utf-8"))
            if record.get("notified") == "true":
                continue
            if now >= datetime.fromisoformat(record["notify_at"]):
                record["notified"] = "true"
                metadata.write_text(json.dumps(record, indent=2), encoding="utf-8")
                notices.append(record)
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            continue
    return notices


def expired_items() -> list[dict[str, str]]:
    if not QUARANTINE_DIR.exists():
        return []
    now = datetime.now(timezone.utc)
    expired: list[dict[str, str]] = []
    for metadata in QUARANTINE_DIR.glob("*.json"):
        try:
            record = json.loads(metadata.read_text(encoding="utf-8"))
            if now >= datetime.fromisoformat(record["delete_after"]):
                expired.append(record)
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            continue
    return expired


def permanently_delete(record: dict[str, str]) -> None:
    Path(record["quarantine_path"]).unlink(missing_ok=True)
    _metadata_path(record["id"]).unlink(missing_ok=True)


def quarantined_items() -> list[dict[str, str]]:
    if not QUARANTINE_DIR.exists():
        return []
    records: list[dict[str, str]] = []
    for metadata in QUARANTINE_DIR.glob("*.json"):
        try:
            record = json.loads(metadata.read_text(encoding="utf-8"))
            if Path(record["quarantine_path"]).is_file():
                records.append(record)
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            continue
    return sorted(records, key=lambda item: item.get("quarantined_at", ""), reverse=True)


def restore_file(record: dict[str, str]) -> None:
    source = Path(record["quarantine_path"])
    destination = Path(record["original_path"])
    if not source.is_file():
        raise FileNotFoundError(f"Quarantined file is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"Restore destination already exists: {destination}")
    shutil.move(str(source), str(destination))
    _metadata_path(record["id"]).unlink(missing_ok=True)
