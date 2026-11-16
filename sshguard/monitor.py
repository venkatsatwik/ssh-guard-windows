from __future__ import annotations

from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .scanner import assess_file


class SecurityFileHandler(FileSystemEventHandler):
    def _scan(self, path: str) -> None:
        candidate = Path(path)
        if candidate.is_file():
            assessment = assess_file(candidate)
            print(
                f"[{assessment.severity}] {candidate} "
                f"score={assessment.score} "
                f"reasons={'; '.join(item.reason for item in assessment.findings) or 'none'}"
            )

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._scan(event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._scan(event.src_path)


def monitor(path: Path) -> None:
    observer = Observer()
    observer.schedule(SecurityFileHandler(), str(path), recursive=True)
    observer.start()
    print(f"Monitoring {path} (Ctrl+C to stop)")
    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
