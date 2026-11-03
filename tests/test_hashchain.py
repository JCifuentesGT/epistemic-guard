import json

import pytest

from epistemic_guard import hashchain


def _fill(log, n=3):
    for i in range(n):
        hashchain.append(log, {"type": "test", "i": i})


def _rewrite(log, transform):
    """Load the lines, let `transform` change them, write them back (simulates tampering)."""
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(transform(lines)) + "\n", encoding="utf-8")


def test_missing_log_is_a_valid_empty_chain(tmp_path):
    result = hashchain.verify(tmp_path / "nope.jsonl")
    assert result.ok and result.count == 0 and result.head == hashchain.GENESIS


def test_records_are_linked_and_verify_ok(tmp_path):
    log = tmp_path / "log.jsonl"
    _fill(log)
    records = hashchain.read_records(log)
    assert [r["seq"] for r in records] == [0, 1, 2]
    assert records[0]["prev_hash"] == hashchain.GENESIS
    assert records[1]["prev_hash"] == records[0]["hash"]
    result = hashchain.verify(log)
    assert result.ok and result.count == 3 and result.head == records[2]["hash"]


def test_editing_a_middle_record_is_detected(tmp_path):
    log = tmp_path / "log.jsonl"
    _fill(log)

    def edit(lines):
        record = json.loads(lines[1])
        record["event"]["i"] = 999
        lines[1] = json.dumps(record, sort_keys=True)
        return lines

    _rewrite(log, edit)
    result = hashchain.verify(log)
    assert not result.ok and "record 1" in result.error


def test_deleting_a_middle_record_is_detected(tmp_path):
    log = tmp_path / "log.jsonl"
    _fill(log)
    _rewrite(log, lambda lines: [lines[0], lines[2]])
    assert not hashchain.verify(log).ok


def test_reordering_records_is_detected(tmp_path):
    log = tmp_path / "log.jsonl"
    _fill(log)
    _rewrite(log, lambda lines: [lines[0], lines[2], lines[1]])
    assert not hashchain.verify(log).ok


def test_a_record_that_does_not_link_to_the_previous_one_is_detected(tmp_path):
    """Even if an attacker recomputes a record's own hash, a wrong prev_hash still breaks the chain."""
    log = tmp_path / "log.jsonl"
    _fill(log)

    def relink_badly(lines):
        record = json.loads(lines[1])
        record.pop("hash")
        record["prev_hash"] = "f" * 64
        record["hash"] = hashchain._digest(record)           # self-consistent, but not linked
        lines[1] = json.dumps(record, sort_keys=True)
        return lines

    _rewrite(log, relink_badly)
    result = hashchain.verify(log)
    assert not result.ok and "prev_hash" in result.error


def test_garbage_line_is_detected(tmp_path):
    log = tmp_path / "log.jsonl"
    _fill(log, 1)
    with log.open("a", encoding="utf-8") as f:
        f.write("not json\n")
    assert not hashchain.verify(log).ok


def test_known_limit_removing_the_tail_is_not_detected(tmp_path):
    """Documents a real gap: dropping the last records leaves a shorter but valid chain.
    The mitigation is to keep the `head` hash somewhere else; see the module docstring."""
    log = tmp_path / "log.jsonl"
    _fill(log)
    _rewrite(log, lambda lines: lines[:2])
    assert hashchain.verify(log).ok


def test_append_refuses_a_broken_log(tmp_path):
    log = tmp_path / "log.jsonl"
    _fill(log)
    _rewrite(log, lambda lines: [lines[0], lines[2]])
    with pytest.raises(hashchain.ChainError):
        hashchain.append(log, {"type": "test"})
