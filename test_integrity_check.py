import json

import pytest

import baseline
import checker
import updater


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Give every test its own empty baseline so it never touches your real one."""
    state = tmp_path / "state"
    monkeypatch.setattr(baseline, "BASE_DIR", state)
    monkeypatch.setattr(baseline, "DB_PATH", state / "baseline.json")
    monkeypatch.setattr(baseline, "SALT_PATH", state / "salt")
    monkeypatch.setattr(baseline, "_key", None)
    monkeypatch.setenv("INTEGRITY_PASSPHRASE", "test-pass")


@pytest.fixture
def logs(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "app.log").write_text("line1 ok\nline2 failed ip=10.0.0.5\nline3 done\n")
    return d


def test_clean_check_passes(logs):
    baseline.init(str(logs))
    assert checker.check(str(logs)) == 0


def test_append_is_not_tampering(logs, capsys):
    baseline.init(str(logs))
    with open(logs / "app.log", "a") as f:
        f.write("line4 new entry\n")
    assert checker.check(str(logs)) == 0
    assert "Appended" in capsys.readouterr().out


def test_edited_line_is_detected(logs, capsys):
    baseline.init(str(logs))
    p = logs / "app.log"
    p.write_text(p.read_text().replace("10.0.0.5", "10.0.0.9"))  # same length
    assert checker.check(str(logs)) == 1
    assert "Modified" in capsys.readouterr().out


def test_deleted_line_is_detected(logs, capsys):
    baseline.init(str(logs))
    (logs / "app.log").write_text("line1 ok\n")
    assert checker.check(str(logs)) == 1
    assert "Truncated" in capsys.readouterr().out


def test_deleted_file_is_detected(logs, capsys):
    baseline.init(str(logs))
    (logs / "app.log").unlink()
    assert checker.check(str(logs)) == 1
    assert "Missing" in capsys.readouterr().out


def test_new_file_is_detected(logs, capsys):
    baseline.init(str(logs))
    (logs / "evil.log").write_text("backdoor\n")
    assert checker.check(str(logs)) == 1
    assert "New" in capsys.readouterr().out


def test_nonexistent_path_is_an_error_not_clean(logs, tmp_path):
    baseline.init(str(logs))
    assert checker.check(str(tmp_path / "nope")) == 2


def test_tampered_baseline_is_rejected(logs):
    baseline.init(str(logs))
    doc = json.loads(baseline.DB_PATH.read_text())
    first = next(iter(doc["files"]))
    doc["files"][first]["sha256"] = "0" * 64
    baseline.DB_PATH.write_text(json.dumps(doc))
    with pytest.raises(baseline.BaselineError):
        checker.check(str(logs))


def test_wrong_passphrase_is_rejected(logs, monkeypatch):
    baseline.init(str(logs))
    monkeypatch.setenv("INTEGRITY_PASSPHRASE", "wrong-pass")
    monkeypatch.setattr(baseline, "_key", None)
    with pytest.raises(baseline.BaselineError):
        checker.check(str(logs))


def test_update_accepts_a_legitimate_change(logs, monkeypatch):
    baseline.init(str(logs))
    p = logs / "app.log"
    p.write_text("rewritten after log rotation\n")
    assert checker.check(str(logs)) == 1
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert updater.update(str(logs)) == 0
    assert checker.check(str(logs)) == 0


def test_update_can_be_cancelled(logs, monkeypatch):
    baseline.init(str(logs))
    (logs / "app.log").write_text("something else\n")
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert updater.update(str(logs)) == 1
    assert checker.check(str(logs)) == 1  # still flagged
