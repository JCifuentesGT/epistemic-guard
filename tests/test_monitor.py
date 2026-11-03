import pytest

from epistemic_guard import hashchain, monitor


@pytest.fixture
def setup(tmp_path):
    rules = tmp_path / "RULES.md"
    rules.write_text("1. No implicit commits.\n", encoding="utf-8")
    log = tmp_path / "log.jsonl"
    monitor.baseline([rules], log)
    return rules, log


def _types(log):
    return [r["event"]["type"] for r in hashchain.read_records(log)]


def test_unchanged_file_is_clean(setup):
    rules, log = setup
    assert monitor.check([rules], log) == []
    assert _types(log) == ["baseline"]


def test_modified_file_raises_one_alert(setup):
    rules, log = setup
    rules.write_text("1. No implicit commits.\ncanary-was-here\n", encoding="utf-8")
    findings = monitor.check([rules], log)
    assert [f["kind"] for f in findings] == ["modified"] and findings[0]["new"]
    assert _types(log) == ["baseline", "alert"]


def test_same_deviation_is_reported_but_logged_once(setup):
    rules, log = setup
    rules.write_text("changed\n", encoding="utf-8")
    monitor.check([rules], log)
    second = monitor.check([rules], log)
    assert second and not second[0]["new"]          # still deviating, not new
    assert _types(log) == ["baseline", "alert"]     # but no second alert line


def test_a_second_different_change_is_a_new_alert(setup):
    rules, log = setup
    rules.write_text("change one\n", encoding="utf-8")
    monitor.check([rules], log)
    rules.write_text("change two\n", encoding="utf-8")
    assert monitor.check([rules], log)[0]["new"]
    assert _types(log) == ["baseline", "alert", "alert"]


def test_deleted_file_is_missing(setup):
    rules, log = setup
    rules.unlink()
    findings = monitor.check([rules], log)
    assert findings[0]["kind"] == "missing" and findings[0]["observed"] is None


def test_restoring_the_file_is_logged_and_a_repeat_alerts_again(setup):
    rules, log = setup
    original = rules.read_text(encoding="utf-8")
    rules.write_text("bad\n", encoding="utf-8")
    monitor.check([rules], log)
    rules.write_text(original, encoding="utf-8")
    assert monitor.check([rules], log) == []
    assert _types(log) == ["baseline", "alert", "restored"]
    rules.write_text("bad\n", encoding="utf-8")      # the exact same bad content again
    assert monitor.check([rules], log)[0]["new"]


def test_approved_change_becomes_the_new_expected_state(setup):
    rules, log = setup
    rules.write_text("1. No implicit commits.\n2. Always roll back.\n", encoding="utf-8")
    monitor.approve(rules, log, reason="owner added rule 2")
    assert monitor.check([rules], log) == []
    events = [r["event"] for r in hashchain.read_records(log)]
    assert events[-1]["reason"] == "owner added rule 2"
    assert events[-1]["previous"] == events[0]["sha256"]     # the log keeps the old hash for the audit trail


def test_approve_requires_a_reason_and_a_baseline(setup, tmp_path):
    rules, log = setup
    with pytest.raises(ValueError):
        monitor.approve(rules, log, reason="  ")
    other = tmp_path / "other.md"
    other.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        monitor.approve(other, log, reason="no baseline yet")


def test_baseline_cannot_be_silently_reset(setup):
    rules, log = setup
    with pytest.raises(ValueError):
        monitor.baseline([rules], log)


def test_baseline_of_missing_file_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        monitor.baseline([tmp_path / "ghost.md"], tmp_path / "log.jsonl")


def test_file_without_baseline_is_a_warning_not_an_alert(tmp_path):
    other = tmp_path / "other.md"
    other.write_text("x", encoding="utf-8")
    log = tmp_path / "log.jsonl"
    findings = monitor.check([other], log)
    assert findings[0]["kind"] == "no_baseline"
    assert not log.exists()


def test_tampered_log_is_reported_and_not_appended_to(setup):
    rules, log = setup
    monitor.approve(rules, log, reason="legit")
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text(lines[1] + "\n", encoding="utf-8")        # drop the first record
    before = log.read_text(encoding="utf-8")
    findings = monitor.check([rules], log)
    assert findings[0]["kind"] == "log_tampered"
    assert log.read_text(encoding="utf-8") == before


def test_relative_and_absolute_paths_are_the_same_file(setup, monkeypatch):
    rules, log = setup
    monkeypatch.chdir(rules.parent)
    assert monitor.check(["RULES.md"], log) == []
