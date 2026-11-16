from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Iterable

from .models import FileAssessment, Finding

MAX_READ_BYTES = 2 * 1024 * 1024
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".sh"}
INDICATORS: tuple[tuple[str, int], ...] = (
    (r"(?i)\b(?:curl|wget)\b[^\r\n|]{0,300}\|\s*(?:bash|sh|pwsh|powershell)", 35),
    (r"(?i)\b(?:nc|ncat|netcat)\b.{0,100}\s-e(?:\s|=)", 45),
    (r"(?i)(?:/dev/tcp/|bash\s+-i\b)", 45),
    (r"(?i)\b(?:eval|exec)\s*\(\s*(?:base64|frombase64string)", 30),
    (r"(?i)-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----", 40),
    (r"(?i)\b(?:chmod\s+\+x|chattr\s+[+-][ia])\b", 20),
)


def _is_hidden(path: Path) -> bool:
    if any(part.startswith(".") for part in path.parts if part not in {".", ".."}) or path.name.startswith("~$"):
        return True
    if os.name == "nt":
        try:
            import ctypes

            attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            return attributes != -1 and bool(attributes & 0x2)
        except (AttributeError, OSError):
            return False
    return False


def _has_double_extension(path: Path) -> bool:
    return len(path.suffixes) >= 2 and path.suffixes[-1].lower() in SUSPICIOUS_EXTENSIONS


def _looks_like_script(path: Path, content: str) -> bool:
    return path.suffix.lower() in SCRIPT_EXTENSIONS or content.startswith(("#!", "MZ"))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _read_sample_and_hash(path: Path, compute_hash: bool) -> tuple[bytes, str | None]:
    digest = hashlib.sha256() if compute_hash else None
    sample = bytearray()
    with path.open("rb") as stream:
        while len(sample) < MAX_READ_BYTES:
            chunk = stream.read(min(1024 * 1024, MAX_READ_BYTES - len(sample)))
            if not chunk:
                break
            if digest is not None:
                digest.update(chunk)
            if len(sample) < MAX_READ_BYTES:
                sample.extend(chunk[: MAX_READ_BYTES - len(sample)])
        if digest is not None:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return bytes(sample), digest.hexdigest() if digest is not None else None


def assess_file(
    path: Path,
    blocklist: set[str] | None = None,
    *,
    compute_hash: bool = True,
) -> FileAssessment:
    path = path.expanduser()
    findings: list[Finding] = []
    try:
        sample, digest = _read_sample_and_hash(path, compute_hash or blocklist is not None)
    except (OSError, PermissionError) as exc:
        return FileAssessment(path, None, 0, readable=False, error=str(exc))

    if digest is not None and blocklist and digest.lower() in {item.lower() for item in blocklist}:
        findings.append(Finding("SHA-256 matches the local blocklist", 100))
    if _is_hidden(path):
        findings.append(Finding("Hidden or dot-prefixed file", 15))
    if _has_double_extension(path):
        findings.append(Finding("Executable or script uses a double extension", 25))
    if path.suffix.lower() in SUSPICIOUS_EXTENSIONS and any(
        name.lower() in str(path).lower() for name in ("downloads", "desktop", "\\temp", "/tmp")
    ):
        findings.append(Finding("Executable or script is in a commonly abused user/temp location", 25))

    text = sample.decode("utf-8", errors="ignore")
    if _looks_like_script(path, text):
        for pattern, points in INDICATORS:
            if re.search(pattern, text):
                findings.append(Finding("Suspicious script indicator detected", points))
    if len(sample) >= 4096 and _entropy(sample) >= 7.5:
        findings.append(Finding("High-entropy content may be packed or encrypted", 20))

    return FileAssessment(
        path=path,
        sha256=digest,
        score=min(100, sum(item.points for item in findings)),
        findings=findings,
    )


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                        elif entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                    except OSError:
                        continue
        except OSError:
            continue
